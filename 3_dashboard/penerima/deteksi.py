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
import ipaddress
import json
import os
import sqlite3
import statistics
import subprocess
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
from nids import blokir as daftar_blokir  # noqa: E402
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


@bp.get("")
@wajib_login
def ringkasan():
    db = db_deteksi()
    if db is None:
        return render_template("deteksi/belum.html", path=current_app.config.get("DETEKSI_DB"))
    rentang = request.args.get("rentang") if request.args.get("rentang") in RENTANG else "24j"
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
    ok_pesan, galat_pesan = _kilas()
    return render_template("deteksi/ringkasan.html", s=s, akhir=akhir, n=n, rentang=rentang, nama_rentang=nama_rentang,
                           semua_rentang=RENTANG, kelompok=kelompok, seg=seg, model_penanda=model_penanda,
                           donat=donat, ip_anomali=ip_anomali, notif=notif,
                           lat_median=statistics.median(lat) if lat else None, lat_maks=max(lat) if lat else None,
                           top=top, terbaru=terbaru, g_aliran=g_aliran, g_anomali=g_anomali, model=m, info=info,
                           terbuka=terbuka, server=sistem.kondisi(), tertinggal=sekarang_us() - akhir > 2 * HARI,
                           ok_pesan=ok_pesan, galat_pesan=galat_pesan)


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
    daftar = hampir_anomali(db, akhir - hari * HARI,
                            abaikan=(lambda ip: daftar_tepercaya.cocok_dengan(tp, ip) is not None) if tp else None)
    tampil = daftar[:30]
    for p in tampil:
        p["port"] = db.execute("SELECT dst_port, COUNT(*) FROM aliran WHERE src_ip = ? AND waktu_selesai_us >= ? "
                               "GROUP BY dst_port ORDER BY 2 DESC LIMIT 3", (p["src_ip"], p["awal"])).fetchall()
        p["isi_mulai"], p["isi_akhir"] = isi_wita(p["awal"] - 60_000_000), isi_wita(p["akhir"] + 60_000_000)
    return render_template("deteksi/hampir.html", daftar=tampil, total=len(daftar), rentang=rentang,
                           nama_rentang=nama_rentang, semua_rentang=RENTANG, akhir=akhir, batas=BATAS_CONTAMINATION)


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


@bp.get("/ip/<ip>")
@wajib_login
def rincian_ip(ip):
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
    # skor tertinggi IP ini per model, dibanding ambang & data latih (ambil yang paling tidak biasa per model)
    am, skor = ambang_model(db), {}
    for mid, ma, mc in db.execute("SELECT model_id, MAX(skor_a), MAX(skor_c) FROM aliran WHERE src_ip = ? "
                                  "GROUP BY model_id", (ip,)):
        for s in kedekatan(am, mid, ma, mc):
            if s["model"] not in skor or s["persentil"] > skor[s["model"]]["persentil"]:
                skor[s["model"]] = s
    ok_pesan, galat_pesan = _kilas()
    return render_template("deteksi/ip.html", ip=ip, r=r, port=port, anom=anom, notif=notif, g_aliran=g_aliran,
                           g_anomali=g_anomali, ub=ub, skor=[skor[k] for k in ("A", "C") if k in skor],
                           tepercaya=daftar_tepercaya.cocok_dengan(entri_tepercaya(), ip),
                           diblokir=blokir_ip(ip), durasi_opsi=daftar_blokir.DURASI_OPSI,
                           ok_pesan=ok_pesan, galat_pesan=galat_pesan,
                           isi_mulai=isi_wita(r["awal"]),
                           isi_akhir=isi_wita(r["akhir"] + 60_000_000))


@bp.get("/model")
@wajib_login
def model():
    db = db_deteksi()
    if db is None:
        return redirect(url_for("deteksi.ringkasan"))
    riwayat = []
    for r in db.execute("SELECT * FROM model ORDER BY id DESC").fetchall():
        info = json.loads(r["info_json"])
        n = db.execute("SELECT COUNT(*), SUM(oleh != '') FROM aliran WHERE model_id = ?", (r["id"],)).fetchone()
        riwayat.append({"id": r["id"], "versi": r["versi"], "aktif_sejak_us": r["aktif_sejak_us"], "info": info,
                        "aliran": n[0], "ditandai": n[1] or 0})
    return render_template("deteksi/model.html", riwayat=riwayat, info=riwayat[0]["info"] if riwayat else None)


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
            hasil = periksa_ulang(db, isi["jenis"], ip, mulai, akhir)
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
    return render_template("deteksi/umpan_balik_rincian.html", r=r, h=hasil)


@bp.post("/umpan-balik/<int:ub_id>/periksa")
@wajib_login
def periksa_lagi(ub_id):
    cek_csrf()
    wajib_lapor()
    db_pen, db = koneksi(), db_deteksi()
    r = db_pen.execute("SELECT * FROM umpan_balik WHERE id = ?", (ub_id,)).fetchone()
    if r is None or db is None:
        abort(404)
    hasil = periksa_ulang(db, r["jenis"], r["src_ip"], r["mulai_us"], r["akhir_us"])
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
