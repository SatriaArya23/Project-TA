# -*- coding: utf-8 -*-
"""Konversi waktu untuk tampilan: basis data & API memakai UTC, dashboard memakai WITA.

Nama berkas perekam selalu memakai UTC (layanan perekam diset TZ=UTC), mis.
cap_20261023_200451 = mulai direkam 23 Okt 20:04:51 UTC = 24 Okt 04.04 WITA.
"""
import re
from datetime import date, datetime, timedelta, timezone

WITA = timezone(timedelta(hours=8), "WITA")
BULAN = ["Jan", "Feb", "Mar", "Apr", "Mei", "Jun", "Jul", "Agu", "Sep", "Okt", "Nov", "Des"]
POLA_NAMA = re.compile(r"^cap_(\d{8})_(\d{6})")
BATAS_MACET = timedelta(hours=2)        # tanpa kiriman selama ini -> peringatan


def dari_iso(s):
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def mulai_rekam(nama):
    m = POLA_NAMA.match(nama or "")
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def teks_wita(dt):
    if dt is None:
        return "—"
    d = dt.astimezone(WITA)
    return "%d %s %d, %02d.%02d" % (d.day, BULAN[d.month - 1], d.year, d.hour, d.minute)


def teks_lalu(dt, sekarang=None):
    if dt is None:
        return ""
    detik = int(((sekarang or datetime.now(timezone.utc)) - dt).total_seconds())
    if detik < 60:
        return "baru saja"
    if detik < 3600:
        return "%d menit lalu" % (detik // 60)
    if detik < 86400:
        return "%d jam lalu" % (detik // 3600)
    return "%d hari lalu" % (detik // 86400)


def macet(dt, sekarang=None):
    return dt is not None and (sekarang or datetime.now(timezone.utc)) - dt > BATAS_MACET


def rentang_nama_untuk_tanggal_wita(teks):
    """Tanggal WITA 'YYYY-MM-DD' -> (nama_awal, nama_akhir) berkas yang mulai direkam pada tanggal itu."""
    try:
        d = date.fromisoformat(teks)
    except (TypeError, ValueError):
        return None
    awal = datetime(d.year, d.month, d.day, tzinfo=WITA).astimezone(timezone.utc)
    akhir = awal + timedelta(days=1)
    return awal.strftime("cap_%Y%m%d_%H%M%S"), akhir.strftime("cap_%Y%m%d_%H%M%S")
