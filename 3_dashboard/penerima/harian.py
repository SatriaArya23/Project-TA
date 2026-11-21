# -*- coding: utf-8 -*-
"""Pengelompokan rekaman per hari (WITA) dan data grafik untuk dashboard.

Perekam tetap mengirim satu berkas per jam (bila terjadi gangguan, paling banyak
satu jam data yang hilang, dan setiap kiriman punya checksum sendiri). Dashboard
menampilkannya per hari, dan satu hari dapat diunduh sebagai satu berkas gabungan.
"""
import json
from collections import Counter, OrderedDict
from datetime import datetime, timedelta, timezone

from . import waktu

KOLOM = ("SELECT b.id, b.nama, b.ukuran, b.sha256, b.diterima_utc, i.nama AS instalasi, b.instalasi_id, "
         "s.paket, s.syn_masuk, s.syn_ssh, s.rst_keluar, s.ip_luar, s.ip_luar_json, s.port_json, s.galat "
         "FROM berkas b JOIN instalasi i ON i.id = b.instalasi_id LEFT JOIN statistik s ON s.berkas_id = b.id ")


def tanggal_wita(nama):
    dt = waktu.mulai_rekam(nama)
    return dt.astimezone(waktu.WITA).date() if dt else None


def baris(db, instalasi_id=None, nama_instalasi=None):
    syarat, nilai = [], []
    if instalasi_id is not None:
        syarat.append("b.instalasi_id = ?"); nilai.append(instalasi_id)
    if nama_instalasi:
        syarat.append("i.nama = ?"); nilai.append(nama_instalasi)
    where = ("WHERE " + " AND ".join(syarat)) if syarat else ""
    return db.execute(KOLOM + where + " ORDER BY b.nama", nilai).fetchall()


def per_hari(rows):
    """[(instalasi, tanggal) -> ringkasan hari], terbaru dulu."""
    hari = OrderedDict()
    for r in rows:
        t = tanggal_wita(r["nama"])
        if t is None:
            continue
        k = (r["instalasi"], t)
        h = hari.setdefault(k, {"instalasi": r["instalasi"], "tanggal": t, "berkas": 0, "ukuran": 0,
                                "paket": 0, "syn_masuk": 0, "syn_ssh": 0, "rst_keluar": 0,
                                "_ip": set(), "_port": Counter(), "terakhir": None, "dihitung": 0})
        h["berkas"] += 1
        h["ukuran"] += r["ukuran"] or 0
        h["terakhir"] = max(h["terakhir"] or "", r["diterima_utc"])
        if r["paket"] is not None:
            h["dihitung"] += 1
            for c in ("paket", "syn_masuk", "syn_ssh", "rst_keluar"):
                h[c] += r[c] or 0
            h["_ip"].update(json.loads(r["ip_luar_json"] or "[]"))
            h["_port"].update({int(p): n for p, n in json.loads(r["port_json"] or "[]")})
    hasil = []
    for h in hari.values():
        h["ip_luar"] = len(h.pop("_ip"))
        h["port"] = h.pop("_port").most_common(5)
        hasil.append(h)
    return sorted(hasil, key=lambda h: (h["tanggal"], h["instalasi"]), reverse=True)


def total(hari):
    return {"hari": len(hari), "berkas": sum(h["berkas"] for h in hari),
            "paket": sum(h["paket"] for h in hari), "syn_masuk": sum(h["syn_masuk"] for h in hari),
            "syn_ssh": sum(h["syn_ssh"] for h in hari), "ukuran": sum(h["ukuran"] for h in hari)}


def teks_tanggal(t):
    return "%d %s %d" % (t.day, waktu.BULAN[t.month - 1], t.year)


# ------------------------------------------------------------------ grafik batang (SVG)
def _bulat(n):
    """Batas atas sumbu yang 'rapi' (1, 2, 5 x 10^k)."""
    if n <= 0:
        return 1
    k = 1
    while k * 10 <= n:
        k *= 10
    for m in (1, 2, 5, 10):
        if n <= m * k:
            return m * k
    return 10 * k


def grafik(titik, tinggi=170, lebar=720, label_setiap=1):
    """titik = [(label_sumbu, nilai, teks_tooltip)] -> geometri batang untuk template SVG.

    Batang tipis dengan ujung atas membulat 4 px dan rata di garis dasar; jarak antarbatang
    2 px; garis bantu tipis dan redup."""
    kiri, kanan, atas, bawah = 44, 8, 10, 26
    w, h = lebar - kiri - kanan, tinggi - atas - bawah
    n = max(len(titik), 1)
    maks = _bulat(max([v for _, v, _ in titik] + [0]))
    slot = w / n
    lebar_batang = max(min(slot - 2, 28), 2)
    batang, label = [], []
    for i, (lab, v, tip) in enumerate(titik):
        x = kiri + i * slot + (slot - lebar_batang) / 2
        tb = h * v / maks if maks else 0
        y = atas + h - tb
        r = min(4, lebar_batang / 2, tb)
        if tb > 0:
            d = ("M%.1f,%.1f V%.1f Q%.1f,%.1f %.1f,%.1f H%.1f Q%.1f,%.1f %.1f,%.1f V%.1f Z" % (
                x, atas + h, y + r, x, y, x + r, y, x + lebar_batang - r, x + lebar_batang, y,
                x + lebar_batang, y + r, atas + h))
        else:
            d = ""
        batang.append({"d": d, "tip": tip, "x": x, "w": lebar_batang, "y_atas": atas, "h_penuh": h})
        if i % label_setiap == 0:
            label.append({"x": x + lebar_batang / 2, "teks": lab})
    garis = [{"y": atas + h - h * f, "teks": "{:,}".format(int(maks * f)).replace(",", ".")} for f in (0, 0.5, 1)]
    return {"lebar": lebar, "tinggi": tinggi, "batang": batang, "label": label, "garis": garis,
            "kiri": kiri, "kanan": lebar - kanan, "dasar": atas + h, "y_label": tinggi - 8}


def grafik_harian(hari, n=14):
    pilih = sorted(hari, key=lambda h: h["tanggal"])[-n:]
    return grafik([("%d/%d" % (h["tanggal"].day, h["tanggal"].month), h["syn_masuk"],
                    "%s: %s percobaan koneksi dari %s IP luar" % (
                        teks_tanggal(h["tanggal"]), "{:,}".format(h["syn_masuk"]).replace(",", "."),
                        "{:,}".format(h["ip_luar"]).replace(",", ".")))
                   for h in pilih])


def grafik_per_jam(rows, jam=48, sekarang=None):
    """Percobaan koneksi per jam rekaman, jam terakhir."""
    akhir = (sekarang or datetime.now(timezone.utc)).replace(minute=0, second=0, microsecond=0)
    awal = akhir - timedelta(hours=jam - 1)
    slot = OrderedDict((awal + timedelta(hours=i), None) for i in range(jam))
    for r in rows:
        dt = waktu.mulai_rekam(r["nama"])
        if dt is None or r["paket"] is None:
            continue
        k = dt.replace(minute=0, second=0, microsecond=0)
        if k in slot:
            slot[k] = (slot[k] or 0) + (r["syn_masuk"] or 0)
    titik = []
    for k, v in slot.items():
        w = k.astimezone(waktu.WITA)
        lab = "%02d.00" % w.hour if w.hour % 6 == 0 else ""
        tip = "%d %s %02d.00 WITA: %s" % (w.day, waktu.BULAN[w.month - 1], w.hour,
                                          "tidak ada rekaman" if v is None else "%d percobaan koneksi" % v)
        titik.append((lab, v or 0, tip))
    g = grafik(titik)
    g["label"] = [l for l in g["label"] if l["teks"]]
    return g
