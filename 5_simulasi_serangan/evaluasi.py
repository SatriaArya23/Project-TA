# -*- coding: utf-8 -*-
"""
Evaluasi hasil deteksi pada VPS uji: log deteksi (SQLite) dicocokkan dengan jadwal simulasi serangan.

Pelabelan setiap aliran di tabel `aliran` log deteksi:
  serangan  : IP sumber = IP skenario serangan DAN aliran selesai dalam [mulai, selesai + MARGIN]
  normal    : IP sumber = IP skenario "normal" (pengunjung web dari laptop) dalam rentang skenario itu
  latar     : semua aliran lain (bot internet, akses admin di luar jendela skenario). Dianggap normal,
              karena model dilatih dari lalu lintas semacam ini.
MARGIN = 130 detik: aliran baru "selesai" paling lambat 120 detik (timeout) setelah paket terakhirnya.

Metrik (per aliran, prediksi = aliran ditandai anomali oleh Model A atau C):
  precision = TP / (TP + FP),  recall = TP / (TP + FN),  F1,  FPR = FP / (FP + TN)
Metrik per skenario: aliran tertangkap (%), waktu sampai deteksi pertama, latensi notifikasi Telegram.
"""
import csv
import sqlite3

import pandas as pd

MARGIN_US = 130 * 1_000_000


def muat_jadwal(path):
    with open(path, encoding="utf-8") as f:
        j = pd.DataFrame(list(csv.DictReader(f)))
    for k in ("id", "mulai_us", "selesai_us", "jumlah", "berhasil"):
        j[k] = pd.to_numeric(j[k])
    return j


def muat_log(path, dari_us=None, sampai_us=None):
    con = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
    syarat, nilai = "", []
    if dari_us is not None:
        syarat, nilai = " WHERE waktu_selesai_us BETWEEN ? AND ?", [int(dari_us), int(sampai_us)]
    aliran = pd.read_sql_query("SELECT * FROM aliran" + syarat, con, params=nilai)
    anomali = pd.read_sql_query("SELECT * FROM anomali" + syarat, con, params=nilai)
    notif = pd.read_sql_query("SELECT * FROM notifikasi", con)
    model = pd.read_sql_query("SELECT id, versi, aktif_sejak_us FROM model", con)
    con.close()
    return aliran, anomali, notif, model


def beri_label(aliran, jadwal, margin_us=MARGIN_US):
    df = aliran.copy()
    df["label"], df["skenario_id"] = "latar", 0
    for _, j in jadwal.iterrows():
        m = (df.src_ip == j.ip_sumber) & df.waktu_selesai_us.between(j.mulai_us, j.selesai_us + margin_us)
        df.loc[m, "label"] = "serangan" if j.label == "serangan" else "normal"
        df.loc[m, "skenario_id"] = int(j.id)
    df["ditandai"] = df.oleh.fillna("") != ""
    return df


def metrik(df, negatif=("normal", "latar")):
    pos, neg = df[df.label == "serangan"], df[df.label.isin(negatif)]
    tp, fn = int(pos.ditandai.sum()), int((~pos.ditandai).sum())
    fp, tn = int(neg.ditandai.sum()), int((~neg.ditandai).sum())
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn, "precision": p, "recall": r,
            "F1": 2 * p * r / (p + r) if p + r else 0.0, "FPR": fp / (fp + tn) if fp + tn else 0.0}


def per_skenario(df, anomali, notif, jadwal):
    hasil = []
    for _, j in jadwal.iterrows():
        a = df[df.skenario_id == j.id]
        an = anomali[(anomali.src_ip == j.ip_sumber) &
                     anomali.waktu_selesai_us.between(j.mulai_us, j.selesai_us + MARGIN_US)]
        no = notif[(notif.src_ip == j.ip_sumber) & notif.waktu_log_us.between(j.mulai_us, j.selesai_us + MARGIN_US)]
        no_ok = no[no.berhasil == 1]
        pertama = an.waktu_log_us.min() if len(an) else None
        hasil.append({
            "id": int(j.id), "skenario": j.skenario, "label": j.label, "mulai (WITA)": j.mulai_wita,
            "durasi (s)": round((j.selesai_us - j.mulai_us) / 1e6, 1), "aliran": len(a),
            "ditandai": int(a.ditandai.sum()),
            "tertangkap (%)": round(100 * a.ditandai.mean(), 1) if len(a) else None,
            "terdeteksi": bool(len(an)) if j.label == "serangan" else None,
            "model": ",".join(sorted(set(an.oleh))) if len(an) else "",
            "deteksi pertama (s sejak mulai)": round((pertama - j.mulai_us) / 1e6, 1) if pertama else None,
            "notifikasi": len(no_ok),
            "latensi notifikasi (s)": round(((no_ok.waktu_terima_us - no_ok.waktu_log_us) / 1e6).median(), 2)
            if len(no_ok) else None,
        })
    return pd.DataFrame(hasil)
