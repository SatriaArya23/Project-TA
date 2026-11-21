# -*- coding: utf-8 -*-
"""
Latih model A+C dari fitur hasil putar ulang rekaman server.

  python deteksi.py putar-ulang REKAMAN/ --fitur fitur.parquet
  python latih_model.py fitur.parquet --keluar model.joblib [--sampai 2026-10-27] [--server-ip IP ...]

Langkah (sama dengan notebook 03/04, hasil penalaan notebook 07):
  1. Ambil aliran sebelum tanggal --sampai (bila diberikan) sebagai data latih.
  2. Pembersihan baseline (mencegah efek masking):
     a. sumber luar yang dalam satu jendela pernah menghubungi >= 20 port berbeda atau membuat >= 20 koneksi SSH;
     b. subnet luar (/24 IPv4, /64 IPv6) yang dalam satu jendela menghubungi >= 20 port berbeda atau terdiri
        dari >= 20 IP berbeda (pemindaian terdistribusi).
  3. Latih Model A (68 fitur aliran) dan Model C (7 fitur agregasi) dengan transformasi log,
     contamination A = 0,001 dan C = 0,0075 (dipilih pada data validasi VPS perusahaan, notebook 07).

MODUL PELATIHAN ULANG (loop umpan balik, alur laptop peneliti):
  python latih_model.py fitur.parquet --keluar model_v2.joblib --umpan-balik kasus.json
  kasus.json = ekspor dari dashboard (Umpan balik -> "Unduh kasus pelatihan ulang"). Untuk setiap kasus:
    * "lolos" (serangan tidak terdeteksi): alirannya dikeluarkan dari data latih dan dipakai sebagai
      data validasi serangan;
    * "palsu" (alarm palsu): alirannya tetap di data latih walaupun terkena aturan pembersihan,
      sehingga pola tersebut dipelajari sebagai lalu lintas normal.
  Setelah melatih, contamination A dan C dipilih dari kisi GRID_A x GRID_C: kasus "lolos" terdeteksi
  sebanyak mungkin, lalu aliran alarm palsu sesedikit mungkin, lalu proporsi data latih yang ditandai
  sekecil mungkin. Hasil evaluasinya disimpan di dalam model dan tampil di dashboard.
"""
import argparse
import json
import os
import sys
from collections import Counter

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nids.agregasi import subnet   # noqa: E402
from nids.model import CONTAMINATION_A, CONTAMINATION_C, SatuModel, latih   # noqa: E402

AMBANG_SCAN, AMBANG_SSH = 20, 20
GRID_A = [0.0005, 0.001, 0.002, 0.005]
GRID_C = [0.005, 0.0075, 0.01, 0.02, 0.05]


def cocok_kasus(df, kasus):
    """Mask aliran yang termasuk salah satu kasus (IP sumber sama, waktu selesai dalam rentang)."""
    m = pd.Series(False, index=df.index)
    for k in kasus:
        m |= (df["Source IP"] == k["src_ip"]) & df["Waktu Selesai"].between(int(k["mulai_us"]), int(k["akhir_us"]))
    return m


def skor(paket, nama, df):
    return SatuModel(paket[nama]).skor(df)          # jalur yang sama dengan modul deteksi (termasuk transformasi)


def pilih_contamination(paket, latih_df, df_lolos, lolos, df_palsu):
    """Kisi contamination A x C dievaluasi pada kasus umpan balik. Kembalikan (pilihan, tabel)."""
    sa, sc = skor(paket, "A", latih_df), skor(paket, "C", latih_df)
    la, lc = (skor(paket, "A", df_lolos), skor(paket, "C", df_lolos)) if len(df_lolos) else (np.array([]),) * 2
    pa, pc = (skor(paket, "A", df_palsu), skor(paket, "C", df_palsu)) if len(df_palsu) else (np.array([]),) * 2
    tabel = []
    for ca in GRID_A:
        for cc in GRID_C:
            ta, tc = float(np.quantile(sa, 1 - ca)), float(np.quantile(sc, 1 - cc))
            tanda_lolos = (la > ta) | (lc > tc)
            kena = [k["id"] for k in lolos if tanda_lolos[cocok_kasus(df_lolos, [k]).to_numpy()].any()]
            tabel.append({"contamination_a": ca, "contamination_c": cc, "ambang_a": ta, "ambang_c": tc,
                          "kasus_lolos_terdeteksi": len(kena), "id_terdeteksi": kena,
                          "aliran_lolos_tertangkap": int(tanda_lolos.sum()), "aliran_lolos": int(len(df_lolos)),
                          "aliran_palsu_ditandai": int(((pa > ta) | (pc > tc)).sum()), "aliran_palsu": int(len(df_palsu)),
                          "proporsi_latih_ditandai": float(((sa > ta) | (sc > tc)).mean())})
    pilihan = max(tabel, key=lambda r: (r["kasus_lolos_terdeteksi"], -r["aliran_palsu_ditandai"],
                                        -r["proporsi_latih_ditandai"]))
    return pilihan, tabel


def tebak_server(df):
    """Alamat IPv4 & IPv6 yang paling sering muncul (setiap aliran melibatkan server)."""
    v4, v6 = Counter(), Counter()
    for kol in ("Source IP", "Destination IP"):
        for ip, n in df[kol].value_counts().items():
            (v6 if ":" in ip else v4)[ip] += n
    return {c.most_common(1)[0][0] for c in (v4, v6) if c}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("fitur", nargs="+", help="berkas parquet hasil 'deteksi.py putar-ulang --fitur'")
    ap.add_argument("--keluar", required=True)
    ap.add_argument("--sampai", help="hanya aliran sebelum tanggal UTC ini (YYYY-MM-DD) yang dipakai latih")
    ap.add_argument("--server-ip", nargs="*", help="alamat server (bawaan: ditebak otomatis)")
    ap.add_argument("--contamination-a", type=float, default=CONTAMINATION_A)
    ap.add_argument("--contamination-c", type=float, default=CONTAMINATION_C)
    ap.add_argument("--tanpa-log", action="store_true", help="rancangan awal: tanpa transformasi log")
    ap.add_argument("--tanpa-bersih-subnet", action="store_true", help="jangan buang pemindaian terdistribusi per subnet")
    ap.add_argument("--jendela", type=int, default=300)
    ap.add_argument("--tanpa-pembersihan", action="store_true")
    ap.add_argument("--umpan-balik", help="JSON kasus dari dashboard (modul pelatihan ulang)")
    ap.add_argument("--evaluasi", help="JSON hasil evaluasi (mis. uji simulasi serangan) untuk ditampilkan di dashboard")
    a = ap.parse_args()

    df = pd.concat([pd.read_parquet(f) for f in a.fitur], ignore_index=True)
    kasus = json.load(open(a.umpan_balik, encoding="utf-8"))["kasus"] if a.umpan_balik else []
    lolos = [k for k in kasus if k["jenis"] == "lolos"]
    palsu = [k for k in kasus if k["jenis"] == "palsu"]
    df_lolos, df_palsu = df[cocok_kasus(df, lolos)], df[cocok_kasus(df, palsu)]   # sebelum dipotong --sampai
    waktu = pd.to_datetime(df["Waktu Selesai"], unit="us", utc=True)
    if a.sampai:
        df, waktu = df[waktu < pd.Timestamp(a.sampai, tz="UTC")], waktu[waktu < pd.Timestamp(a.sampai, tz="UTC")]
    server = set(a.server_ip) if a.server_ip else tebak_server(df)
    luar = ~df["Source IP"].isin(server)
    intens = set(df.loc[luar & ((df.agg_ip_port_unik >= AMBANG_SCAN) | (df.agg_ip_aliran_ssh >= AMBANG_SSH)),
                        "Source IP"])
    sub = df["Source IP"].map(subnet)
    sub_scan = set() if a.tanpa_bersih_subnet else set(
        sub[luar & ((df.agg_s24_port_unik >= AMBANG_SCAN) | (df.agg_s24_ip_unik >= AMBANG_SCAN))])
    dibuang = (df["Source IP"].isin(intens) | (luar & sub.isin(sub_scan))) & ~cocok_kasus(df, palsu)   # palsu tetap dipelajari
    # Model dilatih dari seluruh lalu lintas normal (masuk & keluar): koneksi keluar memperkaya gambaran normal.
    # Saat deteksi hanya koneksi masuk yang dinilai (Detektor). Melatih hanya dengan koneksi masuk justru
    # menaikkan alarm palsu pada pengunjung (notebook 03/04).
    latih_df = df if a.tanpa_pembersihan else df[~dibuang]
    latih_df = latih_df[~cocok_kasus(latih_df, lolos)]                     # serangan lolos bukan data normal
    print("Aliran periode latih : %d (%s s.d. %s UTC)" % (len(df), waktu.min(), waktu.max()))
    print("Alamat server        : %s (koneksi dari alamat ini tidak dinilai saat deteksi)" % ", ".join(sorted(server)))
    print("Dibuang dari data latih: %d IP intens + %d subnet pemindai terdistribusi = %d aliran%s" % (
        len(intens), len(sub_scan), int(dibuang.sum()), " (DILEWATI)" if a.tanpa_pembersihan else ""))
    paket = latih(latih_df, a.contamination_a, a.contamination_c, a.jendela,
                  transformasi=None if a.tanpa_log else "log", info={
        "server_ip": sorted(server), "cara_latih": "apa adanya" if a.tanpa_pembersihan else "dibersihkan",
        "periode_latih": [str(waktu.min()), str(waktu.max())], "jumlah_aliran_latih": int(len(latih_df)),
        "aturan_pembersihan": {"ambang_scan": AMBANG_SCAN, "ambang_ssh": AMBANG_SSH, "subnet": not a.tanpa_bersih_subnet},
        "transformasi": None if a.tanpa_log else "log", "sumber_intens": sorted(intens),
        "subnet_dibersihkan": len(sub_scan)})
    if a.evaluasi:
        paket["evaluasi"] = json.load(open(a.evaluasi, encoding="utf-8"))
    if kasus:
        print("Kasus umpan balik   : %d lolos (%d aliran), %d alarm palsu (%d aliran)" % (
            len(lolos), len(df_lolos), len(palsu), len(df_palsu)))
        pilihan, tabel = pilih_contamination(paket, latih_df, df_lolos, lolos, df_palsu)
        print("  cA     cC     lolos terdeteksi  palsu ditandai  latih ditandai")
        for r in tabel:
            print("  %-6g %-6g %3d/%-3d %12d/%-6d %13.2f%%%s" % (
                r["contamination_a"], r["contamination_c"], r["kasus_lolos_terdeteksi"], len(lolos),
                r["aliran_palsu_ditandai"], r["aliran_palsu"], r["proporsi_latih_ditandai"] * 100,
                "  <- dipilih" if r is pilihan else ""))
        for nama, kc, ka in (("A", "contamination_a", "ambang_a"), ("C", "contamination_c", "ambang_c")):
            paket[nama]["contamination"], paket[nama]["threshold"] = pilihan[kc], pilihan[ka]
        paket["evaluasi_umpan_balik"] = {"kasus": [k["id"] for k in kasus], "jumlah_lolos": len(lolos),
                                         "jumlah_palsu": len(palsu), "pilihan": pilihan, "kisi": tabel}
    joblib.dump(paket, a.keluar)
    print("Ambang A = %.4f | ambang C = %.4f" % (paket["A"]["threshold"], paket["C"]["threshold"]))
    print("Model disimpan: %s (versi %s)" % (a.keluar, paket["versi"]))


if __name__ == "__main__":
    main()
