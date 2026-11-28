# -*- coding: utf-8 -*-
"""Dashboard hasil deteksi + loop umpan balik.

Membaca log SQLite modul deteksi (nids-deteksi, /var/lib/nids-deteksi/deteksi.db) dalam mode
BACA-SAJA. Laporan umpan balik disimpan di basis data penerima sendiri (tabel umpan_balik).

Halaman:
  /deteksi                    ringkasan 24 jam / 7 hari: jenis anomali, model penanda, grafik per jam,
                              notifikasi, kondisi server, IP teratas, anomali terbaru
  /deteksi/anomali            daftar anomali (saring IP / tanggal / model); ?cari=<ip> membuka rincian IP apa pun
  /deteksi/hampir             IP "hampir anomali": tidak ditandai, tetapi skornya di atas batas aman umpan balik
                              -> titik awal mencari serangan yang lolos
  /deteksi/tepercaya          daftar IP tepercaya (whitelist) bersama modul deteksi; ubah khusus administrator
  /deteksi/ip/<ip>            rincian satu IP sumber
  /deteksi/model              model aktif, evaluasi, riwayat versi
  /deteksi/umpan-balik        laporan "serangan lolos" / "alarm palsu" -> periksa ulang -> hasil
"""
import hashlib
import ipaddress
import json
import os
import sqlite3
import statistics
import subprocess
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from flask import Blueprint, Response, abort, current_app, g, redirect, render_template, request, session, url_for

from . import grafik, harian, sistem, statistik, waktu  # noqa: F401  (statistik menyiapkan sys.path untuk nids)
from .db import catat_audit, koneksi, sekarang
from .keamanan import boleh, cek_csrf, ip_klien, pengguna_aktif, wajib_hak, wajib_login
from nids.dugaan import dugaan  # noqa: E402
from nids.umpan_balik import (BATAS_CONTAMINATION, TEKS_STATUS, ambang_model, hampir_anomali,  # noqa: E402
                              kedekatan, periksa_ulang)
from nids import adaptasi  # noqa: E402
from nids import asisten_ai  # noqa: E402
from nids import blokir as daftar_blokir  # noqa: E402
from nids import katalog_model  # noqa: E402
from nids import tepercaya as daftar_tepercaya  # noqa: E402

bp = Blueprint("deteksi", __name__, url_prefix="/deteksi")
PER_HALAMAN = 50
JAM = 3600 * 1_000_000
HARI = 24 * JAM
BATAS_AKTIF_US = 180 * 1_000_000           # detak jantung modul ditulis tiap 60 detik
MAKS_RENTANG_HARI = 7


# ------------------------------------------------------------------ bantuan
def db_deteksi():
    """Koneksi baca-saja ke log deteksi, atau None bila belum ada."""
    if "db_deteksi" in g:
        return g.db_deteksi
    path = current_app.config.get("DETEKSI_DB")
    con = None
    if path and os.path.exists(path):
        try:
            con = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
            con.row_factory = sqlite3.Row
            con.execute("SELECT 1 FROM aliran LIMIT 1")
        except sqlite3.Error:
            con = None
    g.db_deteksi = con
    return con


def tutup_deteksi(_=None):
    con = g.pop("db_deteksi", None)
    if con is not None:
        con.close()


def dt_us(us):
    return datetime.fromtimestamp(us / 1e6, timezone.utc) if us else None


def sekarang_us():
    return int(datetime.now(timezone.utc).timestamp() * 1e6)


def wajib_lapor():
    wajib_hak("lapor", "Hanya administrator dan analis yang dapat mengirim umpan balik.")


def wajib_putuskan():
    wajib_hak("putuskan", "Hanya administrator yang dapat memutuskan laporan umpan balik.")


def ip_valid(teks):
    try:
        return str(ipaddress.ip_address((teks or "").strip()))
    except ValueError:
        return None


def baca_wita(teks):
    """'YYYY-MM-DDTHH:MM' (input datetime-local, WITA) -> mikrodetik UTC."""
    try:
        d = datetime.strptime((teks or "").strip()[:16], "%Y-%m-%dT%H:%M").replace(tzinfo=waktu.WITA)
    except ValueError:
        return None
    return int(d.timestamp() * 1e6)


def isi_wita(us):
    return dt_us(us).astimezone(waktu.WITA).strftime("%Y-%m-%dT%H:%M") if us else ""


def status_modul(db):
    s = {r["kunci"]: r["nilai"] for r in db.execute("SELECT kunci, nilai FROM status")}
    terakhir = int(s.get("terakhir_us") or 0)
    s["aktif"] = s.get("berhenti") != "ya" and terakhir and sekarang_us() - terakhir < BATAS_AKTIF_US
    s["terakhir_us"] = terakhir
    return s


def akhir_data(db):
    """Acuan 'sekarang' untuk grafik: waktu data terakhir (sama dengan jam dinding bila modul berjalan)."""
    t = db.execute("SELECT MAX(waktu_selesai_us) FROM aliran").fetchone()[0]
    return min(t, sekarang_us()) if t else sekarang_us()


def model_aktif(db):
    r = db.execute("SELECT * FROM model ORDER BY id DESC LIMIT 1").fetchone()
    return (dict(r), json.loads(r["info_json"])) if r else (None, None)


def grafik_jam(db, akhir_us, jam=48, src_ip=None):
    """Aliran diperiksa & anomali per jam (WITA), `jam` jam sampai akhir_us."""
    akhir = dt_us(akhir_us).replace(minute=0, second=0, microsecond=0)
    awal = akhir - timedelta(hours=jam - 1)
    a0 = int(awal.timestamp())
    if src_ip:
        rows = db.execute("SELECT waktu_selesai_us / 3600000000 * 3600 AS j, COUNT(*), SUM(oleh != '') FROM aliran "
                          "WHERE src_ip = ? AND waktu_selesai_us >= ? GROUP BY j", (src_ip, a0 * 1_000_000))
    else:
        rows = db.execute("SELECT menit_utc / 3600 * 3600 AS j, SUM(aliran), SUM(anomali) FROM ringkasan "
                          "WHERE menit_utc >= ? GROUP BY j", (a0,))
    per = {r[0]: (r[1] or 0, r[2] or 0) for r in rows}
    t_aliran, t_anomali = [], []
    for i in range(jam):
        k = awal + timedelta(hours=i)
        n, m = per.get(int(k.timestamp()), (0, 0))
        w = k.astimezone(waktu.WITA)
        lab = "%02d.00" % w.hour if w.hour % 6 == 0 else ""
        kapan = "%d %s %02d.00 WITA" % (w.day, waktu.BULAN[w.month - 1], w.hour)
        t_aliran.append((lab, n, "%s: %s aliran diperiksa" % (kapan, angka(n))))
        t_anomali.append((lab, m, "%s: %s anomali dari %s aliran (%s)" % (kapan, angka(m), angka(n), filter_persen(m / n if n else 0))))
    hasil = []
    for t in (t_aliran, t_anomali):
        gr = harian.grafik(t)
        gr["label"] = [x for x in gr["label"] if x["teks"]]
        hasil.append(gr)
    return hasil


def angka(n):
    return "{:,}".format(int(n or 0)).replace(",", ".")


def persen(x, d=2):
    return ("%." + str(d) + "f%%") % ((x or 0) * 100) if x is not None else "—"


# ------------------------------------------------------------------ filter template
@bp.app_template_filter("wita_us")
def filter_wita_us(us):
    if not us:
        return "—"
    d = dt_us(int(us)).astimezone(waktu.WITA)
    return "%d %s %d, %02d.%02d.%02d" % (d.day, waktu.BULAN[d.month - 1], d.year, d.hour, d.minute, d.second)


@bp.app_template_filter("lalu_us")
def filter_lalu_us(us):
    return waktu.teks_lalu(dt_us(int(us))) if us else ""


@bp.app_template_filter("persen")
def filter_persen(x, d=2):
    return persen(x, d).replace(".", ",")


@bp.app_template_filter("desimal")
def filter_desimal(x, d=4):
    return ("%." + str(d) + "f") % x if isinstance(x, (int, float)) else (x if x is not None else "—")


@bp.app_template_filter("teks_status")
def filter_teks_status(s):
    return TEKS_STATUS.get(s, s)


NAMA_MODEL = {"A": "IF-Flow", "C": "IF-Agg", "A+C": "Dual-IF"}


@bp.app_template_filter("nama_model")
def filter_nama_model(kode):
    if not kode:
        return ""
    bagian = [NAMA_MODEL.get(x.strip(), x.strip()) for x in str(kode).split(",") if x.strip()]
    return ", ".join(dict.fromkeys(bagian))


def status_bar():
    """Status singkat modul deteksi untuk bilah atas setiap halaman (None bila log belum ada)."""
    db = db_deteksi()
    if db is None:
        return None
    try:
        return status_modul(db)
    except sqlite3.Error:
        return None


def entri_tepercaya():
    """Isi daftar IP tepercaya (kosong bila berkas belum ada / tidak terbaca)."""
    try:
        return daftar_tepercaya.baca(current_app.config["TEPERCAYA_PATH"])
    except (OSError, ValueError):
        return []


def blokir_siap():
    path = current_app.config.get("BLOKIR_PATH")
    if not path:
        return False
    folder = os.path.dirname(os.path.abspath(path))
    return os.path.isdir(folder) and os.access(folder, os.W_OK)


def katalog_siap():
    folder = current_app.config.get("MODEL_DIR")
    return bool(folder) and os.path.isdir(folder) and os.access(folder, os.W_OK)


def ai_siap():
    path = current_app.config.get("AI_CONFIG_PATH")
    if not path:
        return False
    folder = os.path.dirname(os.path.abspath(path))
    return os.path.isdir(folder) and os.access(folder, os.W_OK)


def daftar_ai():
    path = current_app.config.get("AI_CONFIG_PATH")
    if not path:
        return {"aktif": None, "profil": []}
    try:
        return asisten_ai.daftar_aman(path)
    except (OSError, ValueError):
        return {"aktif": None, "profil": []}


def _ai_transport_kw():
    tr = current_app.config.get("AI_TRANSPORT")
    return {"transport": tr} if tr is not None else {}


def _model_terpilih(form):
    mk = (form.get("model_kustom") or "").strip()
    if mk:
        return mk
    mp = (form.get("model_pilih") or "").strip()
    if mp and mp != "__kustom__":
        return mp
    return None


def _aturan_adaptasi_aktif():
    if katalog_siap():
        kat = baca_katalog()
        aktif = katalog_model.cari(kat, kat.get("aktif"))
        if aktif:
            return list(aktif.get("adaptasi") or []), aktif
    db = db_deteksi()
    if db is not None:
        _, info = model_aktif(db)
        if info:
            return list(info.get("adaptasi") or []), info
    return [], None


def baca_katalog():
    folder = current_app.config.get("MODEL_DIR")
    if not folder or not os.path.isdir(folder):
        return {"aktif": None, "mode": "A+C", "revisi": 0, "model": []}
    try:
        return katalog_model.baca(folder)
    except (OSError, ValueError):
        return {"aktif": None, "mode": "A+C", "revisi": 0, "model": []}


def _parse_persen(teks, label):
    t = (teks or "").strip().replace(",", ".")
    if not t:
        return None
    try:
        v = float(t)
    except ValueError:
        raise ValueError("Nilai contamination %s bukan angka yang valid." % label)
    return v / 100.0


def entri_diblokir():
    """Isi daftar IP diblokir aktif (cached per-request di g)."""
    if "entri_diblokir" not in g:
        path = current_app.config.get("BLOKIR_PATH")
        try:
            g.entri_diblokir = daftar_blokir.baca(path) if path else []
        except (OSError, ValueError):
            g.entri_diblokir = []
    return g.entri_diblokir


def blokir_ip(ip):
    return daftar_blokir.cocok_dengan(entri_diblokir(), ip)


def _kilas():
    return session.pop("_kilas_ok", None), session.pop("_kilas_galat", None)


def _ip_dilindungi(db):
    hasil = [ip_klien()]
    if db is not None:
        try:
            r = db.execute("SELECT nilai FROM status WHERE kunci = 'server_ip'").fetchone()
            if r and r[0]:
                hasil.extend(x.strip() for x in r[0].split(",") if x.strip())
        except sqlite3.Error:
            pass
    try:
        r = subprocess.run(["ip", "-o", "addr", "show"], capture_output=True, text=True, timeout=3)
        for baris in r.stdout.splitlines():
            bagian = baris.split()
            for i, tok in enumerate(bagian):
                if tok in ("inet", "inet6") and i + 1 < len(bagian):
                    hasil.append(bagian[i + 1].split("/")[0])
    except Exception:
        pass
    return hasil


@bp.app_context_processor
def isi_template():
    return {"boleh_lapor": boleh("lapor"), "boleh_putuskan": boleh("putuskan"),
            "boleh_tepercaya": boleh("kelola_tepercaya"), "boleh_blokir": boleh("kelola_blokir"),
            "boleh_model": boleh("kelola_model"), "boleh_ai": boleh("kelola_ai"),
            "boleh_pakai_ai": boleh("pakai_ai"), "katalog_siap": katalog_siap,
            "ai_siap": ai_siap, "daftar_ai": daftar_ai,
            "blokir_siap": blokir_siap, "blokir_ip": blokir_ip, "status_bar": status_bar}


# ------------------------------------------------------------------ halaman
RENTANG = {"24j": ("24 jam", 1), "7h": ("7 hari", 7)}
# dugaan jenis kejadian (sama dengan pesan Telegram) -> kelompok di grafik, dengan kelas warna tetap
KELOMPOK = [("Pemindaian port", "s1"), ("Brute force SSH", "s2"), ("Banjir koneksi (DoS)", "s3"), ("Lainnya", "s4")]
_KE_KELOMPOK = {"Pemindaian port": "Pemindaian port",
                "Percobaan login SSH berulang (brute force)": "Brute force SSH",
                "Banjir koneksi (indikasi DoS)": "Banjir koneksi (DoS)"}
MODEL_PENANDA = [("A", "IF-Flow", "aliran (68 fitur)", "s1"), ("C", "IF-Agg", "perilaku IP (7 fitur)", "s2"),
                 ("A+C", "Dual-IF", "kedua model sepakat", "s3")]


def grafik_garis_jam(db, akhir_us, hari):
    """Aliran diperiksa & anomali per jam (WITA) selama `hari` hari sampai akhir_us -> dua grafik garis."""
    jam = 24 * hari
    akhir = dt_us(akhir_us).replace(minute=0, second=0, microsecond=0)
    awal = akhir - timedelta(hours=jam - 1)
    per = {r[0]: (r[1] or 0, r[2] or 0) for r in db.execute(
        "SELECT menit_utc / 3600 * 3600 AS j, SUM(aliran), SUM(anomali) FROM ringkasan WHERE menit_utc >= ? "
        "GROUP BY j", (int(awal.timestamp()),))}
    t_aliran, t_anomali = [], []
    for i in range(jam):
        k = awal + timedelta(hours=i)
        n, m = per.get(int(k.timestamp()), (0, 0))
        w = k.astimezone(waktu.WITA)
        if hari == 1:
            lab = "%02d.00" % w.hour if w.hour % 3 == 0 else ""
        else:
            lab = "%d %s" % (w.day, waktu.BULAN[w.month - 1]) if w.hour == 0 else ""
        kapan = "%d %s, %02d.00–%02d.59" % (w.day, waktu.BULAN[w.month - 1], w.hour, w.hour)
        t_aliran.append((lab, n, "%s|%s aliran diperiksa" % (kapan, angka(n))))
        t_anomali.append((lab, m, "%s|%s anomali" % (kapan, angka(m))))
    return grafik.garis(t_aliran), grafik.garis(t_anomali, tinggi=150)


def kelompok_anomali(rows):
    """Anomali per dugaan jenis kejadian dan per model penanda."""
    kel = {n: {"nama": n, "kelas": k, "aliran": 0, "ip": set(), "terakhir": 0} for n, k in KELOMPOK}
    model = {k: 0 for k, *_ in MODEL_PENANDA}
    for r in rows:
        f = {k: r[k] or 0 for k in ("agg_ip_aliran", "agg_ip_port_unik", "agg_ip_aliran_ssh")}
        g = kel[_KE_KELOMPOK.get(dugaan(f), "Lainnya")]
        g["aliran"] += 1
        g["ip"].add(r["src_ip"])
        g["terakhir"] = max(g["terakhir"], r["waktu_selesai_us"])
        if r["oleh"] in model:
            model[r["oleh"]] += 1
    daftar = [dict(g, ip=len(g["ip"])) for g in kel.values()]
    total = sum(g["aliran"] for g in daftar)
    for g in daftar:
        g["persen"] = g["aliran"] / total if total else 0
    bag_model = [dict(kode=k, nama=n, ket=ket, kelas=c, nilai=model[k], persen=model[k] / total if total else 0)
                 for k, n, ket, c in MODEL_PENANDA]
    return (daftar, grafik.segmen([(g["nama"], g["aliran"], g["kelas"]) for g in daftar]) if total else None,
            bag_model, grafik.donat([(b["nama"], b["nilai"], b["kelas"]) for b in bag_model]) if total else None)


def _render_ringkasan(rentang_req=None, hasil_ai=None, galat_ai=None):
    db = db_deteksi()
    if db is None:
        return render_template("deteksi/belum.html", path=current_app.config.get("DETEKSI_DB"))
    rentang = rentang_req if rentang_req in RENTANG else "24j"
    nama_rentang, hari = RENTANG[rentang]
    akhir = akhir_data(db)
    awal = akhir - hari * HARI
    s = status_modul(db)
    n = db.execute("SELECT COALESCE(SUM(aliran), 0), COALESCE(SUM(anomali), 0) FROM ringkasan WHERE menit_utc >= ?",
                   (awal // 1_000_000,)).fetchone()
    rows = db.execute("SELECT src_ip, oleh, waktu_selesai_us, agg_ip_aliran, agg_ip_port_unik, agg_ip_aliran_ssh "
                      "FROM anomali WHERE waktu_selesai_us >= ?", (awal,)).fetchall()
    kelompok, seg, model_penanda, donat = kelompok_anomali(rows)
    ip_anomali = len({r["src_ip"] for r in rows})
    notif = db.execute("SELECT COUNT(*), COALESCE(SUM(berhasil), 0), COUNT(DISTINCT src_ip) FROM notifikasi "
                       "WHERE waktu_kirim_us >= ?", (awal,)).fetchone()
    lat = [r[0] / 1e6 for r in db.execute(
        "SELECT waktu_terima_us - waktu_log_us FROM notifikasi WHERE berhasil = 1 AND waktu_terima_us IS NOT NULL "
        "AND waktu_kirim_us >= ?", (awal,))]
    top = db.execute(
        "SELECT src_ip, COUNT(*) AS n, GROUP_CONCAT(DISTINCT oleh) AS oleh, MIN(waktu_selesai_us) AS awal, "
        "MAX(waktu_selesai_us) AS akhir, COUNT(DISTINCT dst_port) AS port, MAX(agg_ip_port_unik) AS port_unik, "
        "MAX(agg_ip_aliran_ssh) AS ssh FROM anomali WHERE waktu_selesai_us >= ? GROUP BY src_ip "
        "ORDER BY n DESC LIMIT 10", (awal,)).fetchall()
    terbaru = db.execute("SELECT * FROM anomali ORDER BY waktu_selesai_us DESC LIMIT 10").fetchall()
    g_aliran, g_anomali = grafik_garis_jam(db, akhir, hari)
    m, info = model_aktif(db)
    terbuka = koneksi().execute("SELECT COUNT(*) FROM umpan_balik WHERE status != 'selesai'").fetchone()[0]
    ok_pesan, galat_kilas = _kilas()
    galat_pesan = galat_ai or galat_kilas
    return render_template("deteksi/ringkasan.html", s=s, akhir=akhir, n=n, rentang=rentang, nama_rentang=nama_rentang,
                           semua_rentang=RENTANG, kelompok=kelompok, seg=seg, model_penanda=model_penanda,
                           donat=donat, ip_anomali=ip_anomali, notif=notif,
                           lat_median=statistics.median(lat) if lat else None, lat_maks=max(lat) if lat else None,
                           top=top, terbaru=terbaru, g_aliran=g_aliran, g_anomali=g_anomali, model=m, info=info,
                           terbuka=terbuka, server=sistem.kondisi(), tertinggal=sekarang_us() - akhir > 2 * HARI,
                           ok_pesan=ok_pesan, galat_pesan=galat_pesan, hasil_ai=hasil_ai, ai_list=daftar_ai())


@bp.get("")
@wajib_login
def ringkasan():
    return _render_ringkasan(request.args.get("rentang"))


@bp.post("/ringkas-ai")
@wajib_login
def ringkas_ai():
    cek_csrf()
    wajib_hak("pakai_ai", "Hanya administrator dan analis yang dapat menggunakan asisten analisis AI.")
    db = db_deteksi()
    if db is None:
        return redirect(url_for("deteksi.ringkasan"))
    rentang = request.form.get("rentang") if request.form.get("rentang") in RENTANG else "24j"
    hari = RENTANG[rentang][1]
    profil_id = request.form.get("profil_id", "").strip() or None
    model_req = _model_terpilih(request.form)
    paksa = request.form.get("paksa") == "1"
    p = pengguna_aktif()
    try:
        hasil = asisten_ai.analisis_ringkasan(
            current_app.config["AI_CONFIG_PATH"], db, hari=hari, profil_id=profil_id,
            model_override=model_req, paksa_baru=paksa, **_ai_transport_kw(),
        )
        catat_audit("AI_RINGKAS", aktor=p["username"], ip=ip_klien(), kode=200,
                    ket="%s · %s (%s)" % (rentang, hasil["profil_nama"], hasil["model"]))
        return _render_ringkasan(rentang, hasil_ai=hasil)
    except (ValueError, RuntimeError) as e:
        catat_audit("AI_GAGAL", aktor=p["username"], ip=ip_klien(), kode=400, ket="ringkas: " + str(e))
        return _render_ringkasan(rentang, galat_ai=str(e)), 400


def cari_ip(db, teks):
    """-> (ip, pesan galat). ip berisi alamat bila pernah tercatat di log deteksi."""
    ip = ip_valid(teks)
    if ip is None:
        return None, "“%s” bukan alamat IP yang valid." % teks[:64]
    if db.execute("SELECT 1 FROM aliran WHERE src_ip = ? LIMIT 1", (ip,)).fetchone() is None:
        return None, ("IP %s belum pernah tercatat oleh modul deteksi: belum pernah membuka koneksi ke server "
                      "sejak log dimulai, atau lalu lintasnya tidak tertangkap." % ip)
    return ip, None


@bp.get("/hampir")
@wajib_login
def hampir():
    db = db_deteksi()
    if db is None:
        return redirect(url_for("deteksi.ringkasan"))
    rentang = request.args.get("rentang") if request.args.get("rentang") in RENTANG else "24j"
    nama_rentang, hari = RENTANG[rentang]
    akhir = akhir_data(db)
    tp = entri_tepercaya()
    aturan_aktif, _ = _aturan_adaptasi_aktif()
    kasus_selesai = [dict(x) for x in koneksi().execute(
        "SELECT src_ip, mulai_us, akhir_us FROM umpan_balik WHERE status = 'selesai'").fetchall()]
    daftar = hampir_anomali(
        db, akhir - hari * HARI,
        abaikan=(lambda ip: daftar_tepercaya.cocok_dengan(tp, ip) is not None) if tp else None,
        aturan_adaptasi=aturan_aktif,
        kasus_selesai=kasus_selesai,
    )
    tampil = daftar[:30]
    for p in tampil:
        p["port"] = db.execute("SELECT dst_port, COUNT(*) FROM aliran WHERE src_ip = ? AND waktu_selesai_us >= ? "
                               "GROUP BY dst_port ORDER BY 2 DESC LIMIT 3", (p["src_ip"], p["awal"])).fetchall()
        p["isi_mulai"], p["isi_akhir"] = isi_wita(p["awal"] - 60_000_000), isi_wita(p["akhir"] + 60_000_000)
        p["awal_us"], p["akhir_us"] = p["awal"] - 60_000_000, p["akhir"] + 60_000_000
    ok_pesan, galat_pesan = _kilas()
    return render_template("deteksi/hampir.html", daftar=tampil, total=len(daftar), rentang=rentang,
                           nama_rentang=nama_rentang, semua_rentang=RENTANG, akhir=akhir,
                           batas=BATAS_CONTAMINATION, ok_pesan=ok_pesan, galat_pesan=galat_pesan)


@bp.post("/hampir/putuskan")
@wajib_login
def hampir_putuskan():
    cek_csrf()
    wajib_hak("kelola_model", "Hanya administrator yang dapat mengadaptasikan model langsung dari hampir anomali.")
    if not katalog_siap():
        abort(503, "Folder katalog model belum tersedia di server ini (jalankan pasang-deteksi.sh).")
    db, db_pen = db_deteksi(), koneksi()
    if db is None:
        return redirect(url_for("deteksi.ringkasan"))
    f, p = request.form, pengguna_aktif()
    ip = ip_valid(f.get("ip"))
    keputusan = f.get("keputusan", "").strip()
    try:
        mulai, akhir = int(f.get("mulai_us", "0")), int(f.get("akhir_us", "0"))
    except ValueError:
        mulai = akhir = 0
    if ip is None or keputusan not in ("anomali", "normal") or akhir <= mulai:
        session["_kilas_galat"] = "Parameter keputusan hampir anomali tidak valid."
        return redirect(url_for("deteksi.hampir"))

    jenis_ub = "lolos" if keputusan == "anomali" else "palsu"
    catatan = f.get("catatan", "").strip()[:160] or (
        "verifikasi hampir anomali: ternyata anomali" if keputusan == "anomali"
        else "verifikasi hampir anomali: bukan anomali (normal)")
    cur = db_pen.execute(
        "INSERT INTO umpan_balik (dibuat_utc, pelapor, jenis, src_ip, mulai_us, akhir_us, keterangan, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 'baru')", (sekarang(), p["username"], jenis_ub, ip, mulai, akhir, catatan))
    ub_id = cur.lastrowid

    aturan_aktif, info_aktif = _aturan_adaptasi_aktif()
    hasil = periksa_ulang(db, jenis_ub, ip, mulai, akhir, aturan_adaptasi=aturan_aktif)
    simpan_hasil(db_pen, ub_id, hasil)
    try:
        aturan = adaptasi.ekstrak_prototipe(
            db, ip, mulai, akhir, label=keputusan, model_info=info_aktif,
            oleh=p["username"], catatan=catatan, ub_id=ub_id,
        )
        kw_amb = {}
        if keputusan == "anomali" and hasil.get("status") == "terdeteksi_penyesuaian" and hasil.get("usulan"):
            u = hasil["usulan"]
            kw_amb = {"ambang_a": u["ambang_baru"]} if u["model"] == "A" else {"ambang_c": u["ambang_baru"]}
        baru = katalog_model.tambah_adaptasi(
            current_app.config["MODEL_DIR"], aturan,
            nama="Umpan balik #%d" % ub_id,
            alasan="umpan balik #%d (%s · %s)" % (ub_id, keputusan, ip),
            oleh=p["username"], **kw_amb,
        )
    except ValueError as e:
        catat_audit("ADAPTASI_GAGAL", aktor=p["username"], ip=ip_klien(), kode=400,
                    ket="#%d %s: %s" % (ub_id, ip, e))
        session["_kilas_galat"] = str(e)
        return redirect(url_for("deteksi.hampir"))

    catatan_ok = "diadaptasi (%s) pada model %s" % (keputusan, baru["versi"])
    db_pen.execute("UPDATE umpan_balik SET status = 'selesai', selesai_utc = ?, catatan_selesai = ? WHERE id = ?",
                   (sekarang(), catatan_ok, ub_id))
    db_pen.commit()
    catat_audit("ADAPTASI_TAMBAH", aktor=p["username"], ip=ip_klien(), kode=200,
                ket="#%d %s -> %s (%s, mode=%s)" % (ub_id, ip, keputusan, baru["versi"], aturan["mode_cocok"]))
    session["_kilas_ok"] = (
        "Pola %s ditetapkan sebagai %s pada model %s. Kejadian serupa berikutnya otomatis dikenali (%s)."
        % (ip, "ANOMALI" if keputusan == "anomali" else "BUKAN ANOMALI (Normal)", baru["versi"], aturan["mode_cocok"])
    )
    return redirect(url_for("deteksi.hampir", rentang=f.get("rentang") or "24j"))


@bp.get("/anomali")
@wajib_login
def anomali():
    db = db_deteksi()
    if db is None:
        return redirect(url_for("deteksi.ringkasan"))
    pesan = None
    if request.args.get("cari", "").strip():
        ip_cari, pesan = cari_ip(db, request.args["cari"].strip())
        if ip_cari:
            return redirect(url_for("deteksi.rincian_ip", ip=ip_cari))
    try:
        hal = max(1, int(request.args.get("hal", 1)))
    except ValueError:
        hal = 1
    syarat, nilai = [], []
    ip = ip_valid(request.args.get("ip"))
    if ip:
        syarat.append("src_ip = ?"); nilai.append(ip)
    if request.args.get("oleh") in ("A", "C", "A+C"):
        syarat.append("oleh = ?"); nilai.append(request.args["oleh"])
    t = baca_wita((request.args.get("tanggal") or "") + "T00:00")
    if t:
        syarat.append("waktu_selesai_us >= ? AND waktu_selesai_us < ?"); nilai += [t, t + HARI]
    where = (" WHERE " + " AND ".join(syarat)) if syarat else ""
    total = db.execute("SELECT COUNT(*) FROM anomali" + where, nilai).fetchone()[0]
    rows = db.execute("SELECT * FROM anomali" + where + " ORDER BY waktu_selesai_us DESC LIMIT ? OFFSET ?",
                      nilai + [PER_HALAMAN, (hal - 1) * PER_HALAMAN]).fetchall()
    ok_pesan, galat_pesan = _kilas()
    return render_template("deteksi/anomali.html", rows=rows, total=total, hal=hal, per=PER_HALAMAN,
                           pesan=pesan or galat_pesan, ok_pesan=ok_pesan,
                           cari=request.args.get("cari", "") if pesan else "",
                           ip=ip or "", oleh=request.args.get("oleh", ""), tanggal=request.args.get("tanggal", ""))


def _render_ip(ip, hasil_ai=None, galat_ai=None):
    ip = ip_valid(ip)
    db = db_deteksi()
    if ip is None or db is None:
        abort(404)
    r = db.execute("SELECT COUNT(*) AS aliran, SUM(oleh != '') AS ditandai, MIN(waktu_selesai_us) AS awal, "
                   "MAX(waktu_selesai_us) AS akhir, COUNT(DISTINCT dst_port) AS port FROM aliran WHERE src_ip = ?",
                   (ip,)).fetchone()
    if not r["aliran"]:
        abort(404)
    port = db.execute("SELECT dst_port, COUNT(*) AS n, SUM(oleh != '') AS ditandai FROM aliran WHERE src_ip = ? "
                      "GROUP BY dst_port ORDER BY n DESC LIMIT 10", (ip,)).fetchall()
    anom = db.execute("SELECT * FROM anomali WHERE src_ip = ? ORDER BY waktu_selesai_us DESC LIMIT 50", (ip,)).fetchall()
    notif = db.execute("SELECT * FROM notifikasi WHERE src_ip = ? ORDER BY id DESC LIMIT 20", (ip,)).fetchall()
    g_aliran, g_anomali = grafik_jam(db, r["akhir"], src_ip=ip)
    ub = koneksi().execute("SELECT * FROM umpan_balik WHERE src_ip = ? ORDER BY id DESC", (ip,)).fetchall()
    am, skor = ambang_model(db), {}
    for mid, ma, mc in db.execute("SELECT model_id, MAX(skor_a), MAX(skor_c) FROM aliran WHERE src_ip = ? "
                                  "GROUP BY model_id", (ip,)):
        for s in kedekatan(am, mid, ma, mc):
            if s["model"] not in skor or s["persentil"] > skor[s["model"]]["persentil"]:
                skor[s["model"]] = s
    ok_pesan, galat_kilas = _kilas()
    galat_pesan = galat_ai or galat_kilas
    return render_template("deteksi/ip.html", ip=ip, r=r, port=port, anom=anom, notif=notif, g_aliran=g_aliran,
                           g_anomali=g_anomali, ub=ub, skor=[skor[k] for k in ("A", "C") if k in skor],
                           tepercaya=daftar_tepercaya.cocok_dengan(entri_tepercaya(), ip),
                           diblokir=blokir_ip(ip), durasi_opsi=daftar_blokir.DURASI_OPSI,
                           ok_pesan=ok_pesan, galat_pesan=galat_pesan,
                           hasil_ai=hasil_ai, ai_list=daftar_ai(),
                           isi_mulai=isi_wita(r["awal"]),
                           isi_akhir=isi_wita(r["akhir"] + 60_000_000))


@bp.get("/ip/<ip>")
@wajib_login
def rincian_ip(ip):
    return _render_ip(ip)


@bp.post("/ip/<ip>/analisis-ai")
@wajib_login
def analisis_ip_ai(ip):
    cek_csrf()
    wajib_hak("pakai_ai", "Hanya administrator dan analis yang dapat menggunakan asisten analisis AI.")
    db = db_deteksi()
    ip_norm = ip_valid(ip)
    if db is None or ip_norm is None:
        abort(404)
    profil_id = request.form.get("profil_id", "").strip() or None
    model_req = _model_terpilih(request.form)
    paksa = request.form.get("paksa") == "1"
    p = pengguna_aktif()
    try:
        hasil = asisten_ai.analisis_ip(
            current_app.config["AI_CONFIG_PATH"], db, ip_norm, profil_id=profil_id,
            model_override=model_req,
            diblokir=bool(blokir_ip(ip_norm)),
            tepercaya=bool(daftar_tepercaya.cocok_dengan(entri_tepercaya(), ip_norm)),
            paksa_baru=paksa, **_ai_transport_kw(),
        )
        catat_audit("AI_ANALISIS_IP", aktor=p["username"], ip=ip_klien(), kode=200,
                    ket="%s · %s (%s)" % (ip_norm, hasil["profil_nama"], hasil["model"]))
        return _render_ip(ip_norm, hasil_ai=hasil)
    except (ValueError, RuntimeError) as e:
        catat_audit("AI_GAGAL", aktor=p["username"], ip=ip_klien(), kode=400, ket="ip %s: %s" % (ip_norm, e))
        return _render_ip(ip_norm, galat_ai=str(e)), 400


@bp.route("/model", methods=["GET", "POST"])
@wajib_login
def model():
    db = db_deteksi()
    siap = katalog_siap()
    folder = current_app.config.get("MODEL_DIR")
    if db is None and not siap:
        return redirect(url_for("deteksi.ringkasan"))

    galat_form = None
    isi_ambang = None
    if request.method == "POST":
        cek_csrf()
        wajib_hak("kelola_model", "Hanya administrator yang dapat mengubah pengaturan model.")
        if not siap:
            abort(503, "Folder katalog model belum tersedia di server ini (jalankan pasang-deteksi.sh).")
        f, p = request.form, pengguna_aktif()
        aksi = f.get("aksi", "")
        try:
            if aksi == "mode":
                mode = f.get("mode", "")
                katalog_model.atur_mode(folder, mode, oleh=p["username"])
                label = katalog_model.MODE_LABEL.get(mode, mode)
                catat_audit("MODEL_MODE", aktor=p["username"], ip=ip_klien(), kode=200, ket=label)
                session["_kilas_ok"] = "Mode deteksi diubah ke %s. Modul deteksi memuatnya otomatis dalam beberapa detik." % label
            elif aksi == "aktifkan":
                versi = f.get("versi", "").strip()
                entri = katalog_model.aktifkan(folder, versi, oleh=p["username"])
                catat_audit("MODEL_AKTIFKAN", aktor=p["username"], ip=ip_klien(), kode=200,
                            ket="%s (%s)" % (entri["versi"], entri.get("nama") or "-"))
                session["_kilas_ok"] = "Model %s (%s) diaktifkan. Modul deteksi memuatnya otomatis tanpa restart." % (
                    entri.get("nama") or entri["versi"], entri["versi"])
            elif aksi == "nama":
                versi = f.get("versi", "").strip()
                nama = f.get("nama", "").strip()
                entri = katalog_model.ubah_nama(folder, versi, nama, oleh=p["username"])
                catat_audit("MODEL_NAMA", aktor=p["username"], ip=ip_klien(), kode=200,
                            ket="%s -> %s" % (entri["versi"], entri["nama"]))
                session["_kilas_ok"] = "Nama profil model %s diperbarui menjadi “%s”." % (entri["versi"], entri["nama"])
            elif aksi == "hapus":
                versi = f.get("versi", "").strip()
                dihapus = katalog_model.hapus(folder, versi, oleh=p["username"])
                if dihapus is None:
                    raise ValueError("Versi model tidak ditemukan di katalog.")
                catat_audit("MODEL_HAPUS", aktor=p["username"], ip=ip_klien(), kode=200, ket=dihapus["versi"])
                session["_kilas_ok"] = "Model %s dihapus dari katalog." % dihapus["versi"]
            elif aksi == "hapus_adaptasi":
                id_at = f.get("id_aturan", "").strip()
                baru = katalog_model.hapus_adaptasi(folder, id_at, oleh=p["username"])
                if baru is None:
                    raise ValueError("Aturan adaptasi tidak ditemukan pada model aktif.")
                catat_audit("ADAPTASI_HAPUS", aktor=p["username"], ip=ip_klien(), kode=200,
                            ket="%s (model %s)" % (id_at, baru["versi"]))
                session["_kilas_ok"] = "Aturan adaptasi %s dihapus pada versi %s." % (id_at, baru["versi"])
            elif aksi == "ambang":
                isi_ambang = {"cont_a": f.get("cont_a", "").strip(), "cont_c": f.get("cont_c", "").strip(),
                              "nama": f.get("nama", "").strip()[:80], "alasan": f.get("alasan", "").strip()[:200]}
                ca = _parse_persen(isi_ambang["cont_a"], "IF-Flow")
                cc = _parse_persen(isi_ambang["cont_c"], "IF-Agg")
                baru = katalog_model.buat_turunan_ambang(
                    folder, versi_sumber=f.get("versi_sumber") or None,
                    contamination_a=ca, contamination_c=cc,
                    nama=isi_ambang["nama"], alasan=isi_ambang["alasan"],
                    oleh=p["username"], aktifkan_langsung=True,
                )
                catat_audit("MODEL_AMBANG", aktor=p["username"], ip=ip_klien(), kode=200,
                            ket="%s <- %s (A=%s, C=%s)" % (
                                baru["versi"], baru.get("induk") or "-",
                                baru["A"].get("contamination"), baru["C"].get("contamination")))
                session["_kilas_ok"] = "Versi baru %s berhasil dibuat dan diaktifkan. Versi sebelumnya tetap tersimpan untuk rollback." % baru["versi"]
            else:
                raise ValueError("Aksi pengaturan model tidak dikenal.")
        except ValueError as e:
            catat_audit("MODEL_GAGAL", aktor=p["username"], ip=ip_klien(), kode=400, ket="%s: %s" % (aksi, e))
            galat_form = str(e)
        else:
            return redirect(url_for("deteksi.model"))

    riwayat = []
    live_versi = live_mode = None
    if db is not None:
        for r in db.execute("SELECT * FROM model ORDER BY id DESC").fetchall():
            info_r = json.loads(r["info_json"])
            n = db.execute("SELECT COUNT(*), SUM(oleh != '') FROM aliran WHERE model_id = ?", (r["id"],)).fetchone()
            riwayat.append({"id": r["id"], "versi": r["versi"], "aktif_sejak_us": r["aktif_sejak_us"], "info": info_r,
                            "aliran": n[0], "ditandai": n[1] or 0})
        st = status_modul(db)
        live_versi = st.get("model_versi") or (riwayat[0]["versi"] if riwayat else None)
        live_mode = st.get("model_mode") or (riwayat[0]["info"].get("mode") if riwayat else "A+C")

    katalog = baca_katalog() if siap else {"aktif": None, "mode": live_mode or "A+C", "revisi": 0, "model": []}
    aktif_katalog = katalog_model.cari(katalog, katalog.get("aktif")) if katalog["model"] else None
    info = aktif_katalog or (riwayat[0]["info"] if riwayat else None)
    mode_aktif = katalog.get("mode") if katalog["model"] else (info.get("mode", "A+C") if info else "A+C")
    sinkron = (not aktif_katalog or live_versi is None
               or (live_versi == aktif_katalog["versi"] and (live_mode or "A+C") == mode_aktif))

    if isi_ambang is None:
        ca_def = info["A"].get("contamination") if (info and isinstance(info.get("A"), dict)) else None
        cc_def = info["C"].get("contamination") if (info and isinstance(info.get("C"), dict)) else None
        isi_ambang = {
            "cont_a": ("%.2f" % (ca_def * 100)) if ca_def is not None else "",
            "cont_c": ("%.2f" % (cc_def * 100)) if cc_def is not None else "",
            "nama": "",
            "alasan": "",
        }

    ok_pesan, galat_kilas = _kilas()
    galat_pesan = galat_form or galat_kilas
    status_impor = katalog_model.baca_status_impor(folder) if siap else None

    # Gabungkan katalog & riwayat log menjadi satu daftar terpadu (tanpa tabel duplikat)
    stat_versi = {}
    for r in riwayat:
        v = r["versi"]
        if v not in stat_versi:
            stat_versi[v] = {"aliran": 0, "ditandai": 0, "aktif_sejak_us": r["aktif_sejak_us"]}
        stat_versi[v]["aliran"] += r["aliran"]
        stat_versi[v]["ditandai"] += r["ditandai"]

    daftar_model = []
    if siap and katalog["model"]:
        for m in katalog["model"]:
            st_v = stat_versi.get(m["versi"]) or {}
            daftar_model.append({
                "versi": m["versi"],
                "nama": m.get("nama") or m["versi"],
                "induk": m.get("induk"),
                "alasan": m.get("alasan") or "pelatihan awal",
                "oleh": m.get("oleh") or "",
                "aktif": (m["versi"] == katalog.get("aktif")),
                "dalam_katalog": True,
                "jumlah_aliran_latih": m.get("jumlah_aliran_latih"),
                "periode_latih": m.get("periode_latih"),
                "aktif_sejak_us": st_v.get("aktif_sejak_us"),
                "aliran": st_v.get("aliran", 0),
                "ditandai": st_v.get("ditandai", 0),
                "A": m.get("A") or {},
                "C": m.get("C") or {},
            })
    else:
        for i, r in enumerate(riwayat):
            inf = r["info"]
            daftar_model.append({
                "versi": r["versi"],
                "nama": inf.get("nama") or r["versi"],
                "induk": inf.get("induk"),
                "alasan": inf.get("alasan") or ("pelatihan ulang" if inf.get("evaluasi_umpan_balik") else "pelatihan awal"),
                "oleh": inf.get("oleh") or "",
                "aktif": (i == 0),
                "dalam_katalog": False,
                "jumlah_aliran_latih": inf.get("jumlah_aliran_latih"),
                "periode_latih": inf.get("periode_latih"),
                "aktif_sejak_us": r["aktif_sejak_us"],
                "aliran": r["aliran"],
                "ditandai": r["ditandai"],
                "A": inf.get("A") or {},
                "C": inf.get("C") or {},
            })

    return render_template(
        "deteksi/model.html",
        riwayat=riwayat, daftar_model=daftar_model, info=info, katalog=katalog, siap=siap,
        aturan_aktif=(info.get("adaptasi") or []) if info else [],
        mode_aktif=mode_aktif, mode_opsi=katalog_model.MODE_OPSI, mode_label=katalog_model.MODE_LABEL,
        batas_min=katalog_model.BATAS_CONTAMINATION_MIN, batas_maks=katalog_model.BATAS_CONTAMINATION_MAKS,
        isi_ambang=isi_ambang, sinkron=sinkron, live_versi=live_versi,
        status_impor=status_impor, maks_mb=katalog_model.MAKS_UKURAN_MODEL // (1024 * 1024),
        ok_pesan=ok_pesan, galat_pesan=galat_pesan,
    ), (400 if galat_form else 200)


@bp.post("/model/unggah")
@wajib_login
def unggah_model():
    cek_csrf()
    wajib_hak("kelola_model", "Hanya administrator yang dapat mengunggah berkas model.")
    if not katalog_siap():
        abort(503, "Folder katalog model belum tersedia di server ini (jalankan pasang-deteksi.sh).")
    folder = current_app.config["MODEL_DIR"]
    berkas = request.files.get("berkas")
    nama = request.form.get("nama", "").strip()[:80]
    alasan = request.form.get("alasan", "").strip()[:200]
    sha_harap = request.form.get("sha256", "").strip()
    aktifkan = request.form.get("aktifkan") == "1"

    if berkas is None or not (berkas.filename or "").strip():
        session["_kilas_galat"] = "Pilih berkas model berformat .joblib terlebih dahulu."
        return redirect(url_for("deteksi.model"))
    if not berkas.filename.lower().endswith(".joblib"):
        session["_kilas_galat"] = "Berkas harus berekstensi .joblib."
        return redirect(url_for("deteksi.model"))

    masuk_dir = katalog_model.dir_masuk(folder)
    os.makedirs(masuk_dir, exist_ok=True)
    nama_sementara = "unggah_%s.joblib" % uuid.uuid4().hex[:12]
    tujuan = os.path.join(masuk_dir, nama_sementara)
    h = hashlib.sha256()
    total = 0
    try:
        with open(tujuan, "wb") as out:
            while True:
                pot = berkas.stream.read(1 << 16)
                if not pot:
                    break
                total += len(pot)
                if total > katalog_model.MAKS_UKURAN_MODEL:
                    raise ValueError("Ukuran berkas melebihi batas %d MB." % (katalog_model.MAKS_UKURAN_MODEL // (1024 * 1024)))
                h.update(pot)
                out.write(pot)
        if total == 0:
            raise ValueError("Berkas .joblib kosong.")
        try:
            os.chmod(tujuan, 0o660)
        except OSError:
            pass
        sha = h.hexdigest()
        p = pengguna_aktif()
        katalog_model.antre_impor(
            folder, nama_sementara, sha, nama=nama, alasan=alasan, oleh=p["username"],
            sha_diharapkan=sha_harap, aktifkan=aktifkan,
        )
        catat_audit("MODEL_UNGGAH", aktor=p["username"], ip=ip_klien(), sha=sha, ukuran=total, kode=200,
                    ket="%s (%s)" % (nama or berkas.filename[:60], "langsung aktif" if aktifkan else "tersimpan"))
        session["_kilas_ok"] = "Berkas model diterima (SHA-256 %s…). Sedang divalidasi & diuji otomatis oleh layanan nids-model; muat ulang beberapa detik lagi." % sha[:12]
    except ValueError as e:
        if os.path.exists(tujuan):
            try:
                os.unlink(tujuan)
            except OSError:
                pass
        session["_kilas_galat"] = str(e)
    return redirect(url_for("deteksi.model"))


# ------------------------------------------------------------------ Asisten Multi-AI Dinamis & Chat
def _riwayat_chat_user(db_pen, username):
    return [dict(r) for r in db_pen.execute(
        "SELECT id, waktu_utc, role, koneksi_nama, model, konten FROM ai_chat "
        "WHERE username = ? ORDER BY id DESC LIMIT 20", (username,)).fetchall()][::-1]


@bp.route("/ai", methods=["GET", "POST"])
@wajib_login
def ai_halaman():
    path = current_app.config.get("AI_CONFIG_PATH")
    siap = ai_siap()
    db_pen = koneksi()
    p_aktif = pengguna_aktif()
    pesan = ok = None
    hasil_tanya = None
    isi = {"nama": "", "provider": "openai", "model": "", "base_url": "", "tanya": "",
           "profil_id": "", "model_pilih": ""}

    if request.method == "POST":
        cek_csrf()
        f, p = request.form, p_aktif
        aksi = f.get("aksi", "")
        try:
            if aksi == "chat_baru":
                wajib_hak("pakai_ai", "Hanya administrator dan analis yang dapat mengelola riwayat chat AI.")
                db_pen.execute("DELETE FROM ai_chat WHERE username = ?", (p["username"],))
                db_pen.commit()
                catat_audit("AI_CHAT_RESET", aktor=p["username"], ip=ip_klien(), kode=200, ket="percakapan baru")
                session["_kilas_ok"] = "Percakapan chat baru dimulai."
                return redirect(url_for("deteksi.ai_halaman"))
            if aksi == "tanya":
                wajib_hak("pakai_ai", "Hanya administrator dan analis yang dapat menggunakan asisten analisis AI.")
                db = db_deteksi()
                isi["tanya"] = f.get("pertanyaan", "").strip()[:1000]
                isi["profil_id"] = f.get("profil_id", "").strip()
                model_req = _model_terpilih(f)
                isi["model_pilih"] = model_req or ""
                hist_db = _riwayat_chat_user(db_pen, p["username"])
                riwayat_kirim = [{"role": m["role"], "content": m["konten"]} for m in hist_db[-10:]]
                hasil_tanya = asisten_ai.chat_keamanan(
                    path, db, isi["tanya"], riwayat_chat=riwayat_kirim,
                    profil_id=(isi["profil_id"] or None), model_override=model_req,
                    **_ai_transport_kw(),
                )
                wkt = sekarang()
                db_pen.execute(
                    "INSERT INTO ai_chat (username, waktu_utc, role, koneksi_nama, model, konten) VALUES (?,?,?,?,?,?)",
                    (p["username"], wkt, "user", hasil_tanya["profil_nama"], hasil_tanya["model"], isi["tanya"]))
                db_pen.execute(
                    "INSERT INTO ai_chat (username, waktu_utc, role, koneksi_nama, model, konten) VALUES (?,?,?,?,?,?)",
                    (p["username"], hasil_tanya["waktu_utc"], "assistant",
                     hasil_tanya["profil_nama"], hasil_tanya["model"], hasil_tanya["teks"]))
                db_pen.commit()
                isi["tanya"] = ""
                catat_audit("AI_TANYA", aktor=p["username"], ip=ip_klien(), kode=200,
                            ket="%s (%s): %s" % (hasil_tanya["profil_nama"], hasil_tanya["model"],
                                                 f.get("pertanyaan", "").strip()[:80]))
            else:
                wajib_hak("kelola_ai", "Hanya administrator yang dapat mengelola konfigurasi AI.")
                if not siap:
                    abort(503, "Folder konfigurasi bersama belum tersedia di server ini (jalankan pasang-deteksi.sh).")
                if aksi == "tambah":
                    isi.update({
                        "nama": f.get("nama", "").strip()[:60],
                        "provider": f.get("provider", "openai").strip(),
                        "model": f.get("model", "").strip()[:120],
                        "base_url": f.get("base_url", "").strip()[:240],
                    })
                    baru = asisten_ai.tambah_profil(
                        path, nama=isi["nama"], provider=isi["provider"], model=isi["model"],
                        api_key=f.get("api_key", ""), base_url=isi["base_url"],
                        oleh=p["username"], jadikan_aktif=(f.get("aktifkan") == "1"),
                        **_ai_transport_kw(),
                    )
                    catat_audit("AI_TAMBAH", aktor=p["username"], ip=ip_klien(), kode=200,
                                ket="%s (%s · %d model)" % (baru["nama"], baru["provider"], len(baru.get("models") or [])))
                    session["_kilas_ok"] = "Koneksi AI “%s” disimpan (%d model tersedia; default: %s)." % (
                        baru["nama"], len(baru.get("models") or []), baru["model"])
                    return redirect(url_for("deteksi.ai_halaman"))
                elif aksi == "segarkan":
                    seg = asisten_ai.segarkan_model(path, f.get("id", ""), **_ai_transport_kw())
                    catat_audit("AI_SYNC_MODEL", aktor=p["username"], ip=ip_klien(), kode=200,
                                ket="%s -> %d model" % (seg["nama"], len(seg.get("models") or [])))
                    session["_kilas_ok"] = "Daftar model “%s” diperbarui (%d model ditemukan)." % (
                        seg["nama"], len(seg.get("models") or []))
                    return redirect(url_for("deteksi.ai_halaman"))
                elif aksi == "aktifkan":
                    dipilih = asisten_ai.aktifkan_profil(path, f.get("id", ""))
                    catat_audit("AI_AKTIFKAN", aktor=p["username"], ip=ip_klien(), kode=200, ket=dipilih["nama"])
                    session["_kilas_ok"] = "Koneksi AI default diubah ke “%s”." % dipilih["nama"]
                    return redirect(url_for("deteksi.ai_halaman"))
                elif aksi == "hapus":
                    dihapus = asisten_ai.hapus_profil(path, f.get("id", ""))
                    if not dihapus:
                        raise ValueError("Koneksi AI tidak ditemukan.")
                    catat_audit("AI_HAPUS", aktor=p["username"], ip=ip_klien(), kode=200, ket=dihapus["nama"])
                    session["_kilas_ok"] = "Koneksi AI “%s” dihapus." % dihapus["nama"]
                    return redirect(url_for("deteksi.ai_halaman"))
                elif aksi == "uji":
                    res = asisten_ai.uji_profil(path, f.get("id", ""), **_ai_transport_kw())
                    catat_audit("AI_UJI", aktor=p["username"], ip=ip_klien(), kode=200,
                                ket="%s (%s · %.2fs)" % (res["profil"], res["model"], res["latensi_detik"]))
                    session["_kilas_ok"] = "Koneksi ke “%s” (%s) berhasil dalam %.2f detik: %s" % (
                        res["profil"], res["model"], res["latensi_detik"], res["balasan"])
                    return redirect(url_for("deteksi.ai_halaman"))
                else:
                    raise ValueError("Aksi konfigurasi AI tidak dikenal.")
        except (ValueError, RuntimeError) as e:
            catat_audit("AI_GAGAL", aktor=p["username"], ip=ip_klien(), kode=400, ket="%s: %s" % (aksi or "-", e))
            pesan = str(e)

    ok_kilas, galat_kilas = _kilas()
    ai_list = daftar_ai()
    riwayat_chat = _riwayat_chat_user(db_pen, p_aktif["username"])
    return render_template(
        "deteksi/ai.html",
        ai_list=ai_list, siap=siap, provider_opsi=asisten_ai.PROVIDER_OPSI,
        isi=isi, hasil_tanya=hasil_tanya, riwayat_chat=riwayat_chat,
        ok_pesan=ok or ok_kilas, galat_pesan=pesan or galat_kilas,
    ), (400 if pesan else 200)


# ------------------------------------------------------------------ umpan balik
def simpan_hasil(db_pen, ub_id, hasil):
    db_pen.execute("UPDATE umpan_balik SET status = ?, hasil_json = ?, diperiksa_utc = ? WHERE id = ?",
                   (hasil["status"], json.dumps(hasil), sekarang(), ub_id))
    db_pen.commit()


@bp.route("/umpan-balik", methods=["GET", "POST"])
@wajib_login
def umpan_balik():
    db_pen = koneksi()
    pesan = None
    isi = {"jenis": request.args.get("jenis", "lolos"), "ip": request.args.get("ip", ""),
           "mulai": request.args.get("mulai", ""), "akhir": request.args.get("akhir", ""), "ket": ""}
    if request.method == "POST":
        cek_csrf()
        wajib_lapor()
        f = request.form
        isi = {"jenis": f.get("jenis"), "ip": f.get("ip", "")[:64], "mulai": f.get("mulai", ""),
               "akhir": f.get("akhir", ""), "ket": f.get("ket", "")[:500]}
        ip, mulai, akhir = ip_valid(isi["ip"]), baca_wita(isi["mulai"]), baca_wita(isi["akhir"])
        db = db_deteksi()
        if isi["jenis"] not in ("lolos", "palsu"):
            pesan = "Pilih jenis laporan."
        elif ip is None:
            pesan = "Alamat IP sumber tidak valid."
        elif mulai is None or akhir is None or akhir <= mulai:
            pesan = "Rentang waktu tidak valid (waktu akhir harus setelah waktu mulai)."
        elif akhir - mulai > MAKS_RENTANG_HARI * HARI:
            pesan = "Rentang waktu paling panjang %d hari." % MAKS_RENTANG_HARI
        elif db is None:
            pesan = "Log modul deteksi belum tersedia."
        else:
            p = pengguna_aktif()
            cur = db_pen.execute(
                "INSERT INTO umpan_balik (dibuat_utc, pelapor, jenis, src_ip, mulai_us, akhir_us, keterangan, status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 'baru')", (sekarang(), p["username"], isi["jenis"], ip, mulai, akhir,
                                                        isi["ket"].strip() or None))
            ub_id = cur.lastrowid
            aturan_aktif, _ = _aturan_adaptasi_aktif()
            hasil = periksa_ulang(db, isi["jenis"], ip, mulai, akhir, aturan_adaptasi=aturan_aktif)
            simpan_hasil(db_pen, ub_id, hasil)
            catat_audit("UMPAN_BALIK", aktor=p["username"], ip=ip_klien(), kode=200,
                        ket="#%d %s %s -> %s" % (ub_id, isi["jenis"], ip, hasil["status"]))
            return redirect(url_for("deteksi.rincian_umpan_balik", ub_id=ub_id))
    rows = db_pen.execute("SELECT * FROM umpan_balik ORDER BY id DESC LIMIT 200").fetchall()
    antre = sum(1 for r in rows if r["status"] == "pelatihan_ulang")
    return render_template("deteksi/umpan_balik.html", rows=rows, isi=isi, pesan=pesan, antre=antre,
                           batas=BATAS_CONTAMINATION), (400 if pesan else 200)


@bp.get("/umpan-balik/<int:ub_id>")
@wajib_login
def rincian_umpan_balik(ub_id):
    r = koneksi().execute("SELECT * FROM umpan_balik WHERE id = ?", (ub_id,)).fetchone()
    if r is None:
        abort(404)
    hasil = json.loads(r["hasil_json"]) if r["hasil_json"] else None
    ok_pesan, galat_pesan = _kilas()
    model_diterapkan = None
    kat_mode = "A+C"
    kat_aktif = None
    if katalog_siap():
        kat = baca_katalog()
        kat_mode = kat.get("mode", "A+C")
        kat_aktif = kat.get("aktif")
        tanda = "umpan balik #%d" % ub_id
        cat = r["catatan_selesai"] or ""
        for m in kat.get("model", []):
            if tanda in (m.get("alasan") or "").lower() or (m.get("versi") and m["versi"] in cat):
                model_diterapkan = m
                break
    return render_template("deteksi/umpan_balik_rincian.html", r=r, h=hasil,
                           model_diterapkan=model_diterapkan,
                           model_aktif_katalog=(model_diterapkan is not None and model_diterapkan.get("versi") == kat_aktif),
                           mode_label=katalog_model.MODE_LABEL.get(kat_mode, kat_mode),
                           ok_pesan=ok_pesan, galat_pesan=galat_pesan)


@bp.post("/umpan-balik/<int:ub_id>/terapkan")
@wajib_login
def terapkan_umpan_balik(ub_id):
    cek_csrf()
    wajib_hak("kelola_model", "Hanya administrator yang dapat menerapkan adaptasi/ambang model.")
    if not katalog_siap():
        abort(503, "Folder katalog model belum tersedia di server ini (jalankan pasang-deteksi.sh).")
    db_pen, db = koneksi(), db_deteksi()
    r = db_pen.execute("SELECT * FROM umpan_balik WHERE id = ?", (ub_id,)).fetchone()
    if r is None:
        abort(404)
    hasil = json.loads(r["hasil_json"]) if r["hasil_json"] else None
    mode_t = request.form.get("mode_terapkan", "").strip()
    p = pengguna_aktif()

    # Tentukan label adaptasi ('anomali' atau 'normal') & opsional penyesuaian ambang global
    label_ad = None
    kw_amb = {}
    if mode_t in ("anomali", "normal"):
        label_ad = mode_t
    elif hasil and hasil.get("status") == "terdeteksi_penyesuaian" and hasil.get("usulan"):
        label_ad = "anomali"
        u = hasil["usulan"]
        kw_amb = {"ambang_a": u["ambang_baru"]} if u["model"] == "A" else {"ambang_c": u["ambang_baru"]}
    elif hasil and hasil.get("status") in ("dapat_diadaptasi_normal", "pelatihan_ulang") and r["jenis"] == "palsu":
        label_ad = "normal"
    elif hasil and hasil.get("status") in ("pelatihan_ulang", "sudah_terdeteksi") and r["jenis"] == "lolos":
        label_ad = "anomali"

    if label_ad is None:
        session["_kilas_galat"] = "Laporan ini belum dapat diterapkan secara otomatis ke model."
        return redirect(url_for("deteksi.rincian_umpan_balik", ub_id=ub_id))

    if mode_t == "anomali" and hasil and hasil.get("status") == "terdeteksi_penyesuaian" and hasil.get("usulan"):
        u = hasil["usulan"]
        kw_amb = {"ambang_a": u["ambang_baru"]} if u["model"] == "A" else {"ambang_c": u["ambang_baru"]}

    _, info_aktif = _aturan_adaptasi_aktif()
    try:
        if db is not None:
            aturan = adaptasi.ekstrak_prototipe(
                db, r["src_ip"], r["mulai_us"], r["akhir_us"], label=label_ad,
                model_info=info_aktif, oleh=p["username"],
                catatan=r["keterangan"] or ("umpan balik #%d" % ub_id), ub_id=ub_id,
            )
            baru = katalog_model.tambah_adaptasi(
                current_app.config["MODEL_DIR"], aturan,
                nama="Umpan balik #%d" % ub_id,
                alasan="umpan balik #%d (%s · %s)" % (ub_id, label_ad, r["src_ip"]),
                oleh=p["username"], **kw_amb,
            )
            audit_jenis = "ADAPTASI_TAMBAH"
            audit_ket = "#%d %s -> %s (model %s, mode=%s)" % (ub_id, r["src_ip"], label_ad, baru["versi"], aturan["mode_cocok"])
        else:
            if not kw_amb:
                raise ValueError("Log deteksi belum tersedia untuk ekstraksi fitur adaptasi.")
            baru = katalog_model.buat_turunan_ambang(
                current_app.config["MODEL_DIR"],
                nama="Umpan balik #%d" % ub_id,
                alasan="umpan balik #%d (%s)" % (ub_id, r["src_ip"]),
                oleh=p["username"], aktifkan_langsung=True, **kw_amb,
            )
            audit_jenis = "MODEL_AMBANG"
            audit_ket = "umpan balik #%d -> %s" % (ub_id, baru["versi"])
    except ValueError as e:
        catat_audit("ADAPTASI_GAGAL", aktor=p["username"], ip=ip_klien(), kode=400, ket="#%d: %s" % (ub_id, e))
        session["_kilas_galat"] = str(e)
        return redirect(url_for("deteksi.rincian_umpan_balik", ub_id=ub_id))

    catatan = "diterapkan otomatis pada model %s (%s)" % (baru["versi"], label_ad)
    db_pen.execute("UPDATE umpan_balik SET status = 'selesai', selesai_utc = ?, catatan_selesai = ? WHERE id = ?",
                   (sekarang(), catatan, ub_id))
    db_pen.commit()
    catat_audit(audit_jenis, aktor=p["username"], ip=ip_klien(), kode=200, ket=audit_ket)
    session["_kilas_ok"] = (
        "Adaptasi (%s) & pembaruan diterapkan sebagai versi model %s. Kejadian serupa berikutnya otomatis dikenali."
        % ("ANOMALI" if label_ad == "anomali" else "BUKAN ANOMALI", baru["versi"])
    )
    return redirect(url_for("deteksi.rincian_umpan_balik", ub_id=ub_id))


@bp.post("/umpan-balik/<int:ub_id>/periksa")
@wajib_login
def periksa_lagi(ub_id):
    cek_csrf()
    wajib_lapor()
    db_pen, db = koneksi(), db_deteksi()
    r = db_pen.execute("SELECT * FROM umpan_balik WHERE id = ?", (ub_id,)).fetchone()
    if r is None or db is None:
        abort(404)
    aturan_aktif, _ = _aturan_adaptasi_aktif()
    hasil = periksa_ulang(db, r["jenis"], r["src_ip"], r["mulai_us"], r["akhir_us"], aturan_adaptasi=aturan_aktif)
    simpan_hasil(db_pen, ub_id, hasil)
    catat_audit("UMPAN_BALIK", aktor=pengguna_aktif()["username"], ip=ip_klien(), kode=200,
                ket="#%d diperiksa ulang -> %s" % (ub_id, hasil["status"]))
    return redirect(url_for("deteksi.rincian_umpan_balik", ub_id=ub_id))


@bp.post("/umpan-balik/<int:ub_id>/selesai")
@wajib_login
def tandai_selesai(ub_id):
    cek_csrf()
    wajib_putuskan()
    db_pen = koneksi()
    if db_pen.execute("SELECT 1 FROM umpan_balik WHERE id = ?", (ub_id,)).fetchone() is None:
        abort(404)
    catatan = request.form.get("catatan", "")[:300].strip() or None
    db_pen.execute("UPDATE umpan_balik SET status = 'selesai', selesai_utc = ?, catatan_selesai = ? WHERE id = ?",
                   (sekarang(), catatan, ub_id))
    db_pen.commit()
    catat_audit("UMPAN_BALIK", aktor=pengguna_aktif()["username"], ip=ip_klien(), kode=200,
                ket="#%d selesai: %s" % (ub_id, catatan or "-"))
    return redirect(url_for("deteksi.rincian_umpan_balik", ub_id=ub_id))


@bp.get("/umpan-balik/kasus.json")
@wajib_login
def ekspor_kasus():
    """Kasus antrean pelatihan ulang -> masukan `latih_model.py --umpan-balik` di laptop peneliti."""
    wajib_putuskan()
    rows = koneksi().execute("SELECT * FROM umpan_balik WHERE status = 'pelatihan_ulang' ORDER BY id").fetchall()
    data = {"diekspor_utc": sekarang(), "kasus": [
        {"id": r["id"], "jenis": r["jenis"], "src_ip": r["src_ip"], "mulai_us": r["mulai_us"],
         "akhir_us": r["akhir_us"], "keterangan": r["keterangan"]} for r in rows]}
    catat_audit("UNDUH_KASUS", aktor=pengguna_aktif()["username"], ip=ip_klien(), kode=200,
                ket="%d kasus pelatihan ulang" % len(rows))
    return Response(json.dumps(data, indent=2, ensure_ascii=False), mimetype="application/json",
                    headers={"Content-Disposition": 'attachment; filename="kasus_pelatihan_ulang.json"'})


# ------------------------------------------------------------------ IP tepercaya
@bp.route("/tepercaya", methods=["GET", "POST"])
@wajib_login
def tepercaya():
    path = current_app.config["TEPERCAYA_PATH"]
    folder = os.path.dirname(os.path.abspath(path))
    siap = os.path.isdir(folder) and os.access(folder, os.W_OK)
    pesan = ok = None
    isi = {"ip": request.args.get("ip", ""), "ket": ""}
    if request.method == "POST":
        cek_csrf()
        wajib_hak("kelola_tepercaya", "Hanya administrator yang dapat mengubah daftar IP tepercaya.")
        if not siap:
            abort(503, "Folder bersama modul deteksi belum ada (jalankan pasang-deteksi.sh).")
        f, p = request.form, pengguna_aktif()
        if f.get("aksi") == "hapus":
            if daftar_tepercaya.hapus(path, f.get("cidr", "")):
                catat_audit("TEPERCAYA_HAPUS", aktor=p["username"], ip=ip_klien(), kode=200, ket=f.get("cidr"))
                ok = "%s dihapus dari daftar. Lalu lintasnya kembali dinilai normal oleh model." % f.get("cidr")
            else:
                pesan = "Entri tidak ditemukan."
        else:
            isi = {"ip": f.get("ip", "")[:64], "ket": f.get("ket", "")[:120]}
            try:
                cidr = daftar_tepercaya.tambah(path, isi["ip"], isi["ket"], p["username"])
            except ValueError as e:
                catat_audit("TEPERCAYA_GAGAL", aktor=p["username"], ip=ip_klien(), kode=400, ket=str(e))
                pesan = str(e)
            else:
                catat_audit("TEPERCAYA_TAMBAH", aktor=p["username"], ip=ip_klien(), kode=200,
                            ket="%s (%s)" % (cidr, isi["ket"] or "-"))
                ok = "%s ditambahkan. Modul deteksi memakainya paling lambat 30 detik lagi." % cidr
                isi = {"ip": "", "ket": ""}
    entri = entri_tepercaya()
    db = db_deteksi()
    for e in entri:                       # aktivitas 7 hari terakhir tiap entri (dari log deteksi)
        e["aliran"] = None
        if db is not None:
            try:
                n = ipaddress.ip_network(e["cidr"], strict=False)
                if n.num_addresses == 1:
                    e["aliran"] = db.execute("SELECT COUNT(*) FROM aliran WHERE src_ip = ? AND waktu_selesai_us >= ?",
                                             (str(n.network_address), sekarang_us() - 7 * HARI)).fetchone()[0]
            except ValueError:
                pass
    return render_template("deteksi/tepercaya.html", entri=entri, pesan=pesan, ok=ok, isi=isi, siap=siap,
                           prefiks=daftar_tepercaya.PREFIKS_MIN), (400 if pesan else 200)


# ------------------------------------------------------------------ IP diblokir (firewall manual)
def _tujuan_aman(lanjut):
    if not lanjut or not lanjut.startswith("/deteksi") or lanjut.startswith("//"):
        return None
    u = urlsplit(lanjut)
    return lanjut if not u.scheme and not u.netloc else None


@bp.route("/blokir", methods=["GET", "POST"])
@wajib_login
def blokir():
    path = current_app.config.get("BLOKIR_PATH")
    siap = blokir_siap()
    pesan = ok = None
    isi = {"ip": request.args.get("ip", ""), "durasi": request.args.get("durasi", "1j"), "ket": ""}
    if request.method == "POST":
        cek_csrf()
        wajib_hak("kelola_blokir", "Hanya administrator yang dapat memblokir atau membuka blokir IP.")
        if not siap:
            abort(503, "Folder bersama modul deteksi belum ada (jalankan pasang-deteksi.sh).")
        f, p = request.form, pengguna_aktif()
        lanjut = _tujuan_aman(f.get("lanjut", "").strip())
        if f.get("aksi") == "hapus":
            cidr = f.get("cidr", "")
            dihapus = daftar_blokir.hapus(path, cidr)
            g.pop("entri_diblokir", None)
            if dihapus:
                catat_audit("BLOKIR_HAPUS", aktor=p["username"], ip=ip_klien(), kode=200, ket=dihapus["cidr"])
                ok = "Blokir %s dibuka. Aturan firewall dicabut dalam beberapa detik." % dihapus["cidr"]
            else:
                pesan = "Entri blokir tidak ditemukan atau sudah kedaluwarsa."
        else:
            isi = {"ip": f.get("ip", "")[:64], "durasi": f.get("durasi", "permanen")[:16],
                   "ket": f.get("ket", "")[:120]}
            try:
                baru = daftar_blokir.tambah(
                    path, isi["ip"], durasi=isi["durasi"], keterangan=isi["ket"], oleh=p["username"],
                    path_tepercaya=current_app.config.get("TEPERCAYA_PATH"),
                    ip_dilindungi=_ip_dilindungi(db_deteksi()),
                )
            except ValueError as e:
                catat_audit("BLOKIR_GAGAL", aktor=p["username"], ip=ip_klien(), kode=400, ket="%s: %s" % (isi["ip"], e))
                pesan = str(e)
            else:
                g.pop("entri_diblokir", None)
                catat_audit("BLOKIR_TAMBAH", aktor=p["username"], ip=ip_klien(), kode=200,
                            ket="%s [%s] (%s)" % (baru["cidr"], baru["durasi_label"], baru["keterangan"] or "-"))
                ok = "IP %s diblokir (%s). Firewall disinkronkan dalam beberapa detik." % (
                    baru["cidr"], baru["durasi_label"])
                isi = {"ip": "", "durasi": "1j", "ket": ""}
        if lanjut:
            if ok:
                session["_kilas_ok"] = ok
            if pesan:
                session["_kilas_galat"] = pesan
            return redirect(lanjut)
    entri = entri_diblokir()
    db = db_deteksi()
    for e in entri:
        e["aliran"] = None
        if db is not None:
            try:
                n = ipaddress.ip_network(e["cidr"], strict=False)
                if n.num_addresses == 1:
                    e["aliran"] = db.execute("SELECT COUNT(*) FROM aliran WHERE src_ip = ? AND waktu_selesai_us >= ?",
                                             (str(n.network_address), sekarang_us() - 7 * HARI)).fetchone()[0]
            except ValueError:
                pass
    fw_status = daftar_blokir.baca_status(current_app.config.get("BLOKIR_STATUS_PATH"))
    return render_template("deteksi/blokir.html", entri=entri, pesan=pesan, ok=ok, isi=isi, siap=siap,
                           durasi_opsi=daftar_blokir.DURASI_OPSI, prefiks=daftar_blokir.PREFIKS_MIN,
                           fw_status=fw_status), (400 if pesan else 200)
