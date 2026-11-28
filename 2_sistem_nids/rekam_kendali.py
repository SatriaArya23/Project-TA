#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Worker kendali layanan `traffic-recorder.service` & `traffic-uploader.service` untuk Tab Rekaman.

Dijalankan sebagai root oleh `nids-rekam-kendali.path` (instan saat admin klik Mulai/Hentikan)
dan `nids-rekam-kendali.timer` (tiap 60 detik untuk memantau batas durasi & status layanan).
"""
import argparse
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nids import rekam_kendali as rk   # noqa: E402

RECORDER_UNIT = "traffic-recorder.service"
UPLOADER_UNIT = "traffic-uploader.service"


def _systemctl(*args):
    return subprocess.run(["systemctl", *args], capture_output=True, text=True, timeout=30)


def _layanan_aktif():
    r = _systemctl("is-active", RECORDER_UNIT)
    return r.returncode == 0 and r.stdout.strip() == "active"


def _layanan_terpasang():
    r = _systemctl("list-unit-files", RECORDER_UNIT)
    return RECORDER_UNIT in (r.stdout or "")


def sinkron(path_perintah=rk.PATH_PERINTAH, path_status=rk.PATH_STATUS, kini=None,
            cek_aktif=_layanan_aktif, cek_terpasang=_layanan_terpasang, jalankan=_systemctl):
    t0 = time.time() if kini is None else float(kini)
    st_lama = rk.baca_status(path_status) or {}
    cmd = rk.baca_perintah(path_perintah)

    if not cek_terpasang():
        st = {
            "terpasang": False,
            "aktif": False,
            "diperbarui_utc": rk.sekarang_utc(t0),
            "pesan": "Layanan traffic-recorder.service belum terpasang di server ini.",
        }
        rk.simpan_status(path_status, st)
        return st

    last_id = st_lama.get("perintah_id")
    pesan = st_lama.get("pesan") or ""
    batas_utc = st_lama.get("batas_utc")
    durasi_label = st_lama.get("durasi_label") or ""
    oleh = st_lama.get("oleh") or ""
    mulai_utc = st_lama.get("mulai_utc")
    catatan = st_lama.get("catatan") or ""

    if cmd and cmd.get("id") and cmd.get("id") != last_id:
        last_id = cmd["id"]
        aksi = cmd.get("aksi")
        oleh = cmd.get("oleh") or ""
        if aksi == "mulai":
            r = jalankan("start", RECORDER_UNIT)
            if r.returncode == 0:
                mulai_utc = rk.sekarang_utc(t0)
                batas_utc = cmd.get("batas_utc")
                durasi_label = cmd.get("durasi_label") or ""
                catatan = cmd.get("catatan") or ""
                pesan = "Perekaman dimulai (%s) oleh %s." % (durasi_label or "aktif", oleh or "admin")
            else:
                pesan = "Gagal memulai traffic-recorder: %s" % ((r.stderr or r.stdout or "galat").strip()[:160])
        elif aksi == "berhenti":
            jalankan("stop", RECORDER_UNIT)
            jalankan("start", "--no-block", UPLOADER_UNIT)
            batas_utc = None
            pesan = "Perekaman dihentikan oleh %s; berkas sedang diproses dan dikirim ke arsip." % (oleh or "admin")

    aktif = cek_aktif()

    # Auto-stop jika batas durasi sudah terlewati
    if aktif and batas_utc:
        ts_batas = rk.parse_utc(batas_utc)
        if ts_batas is not None and t0 >= ts_batas:
            jalankan("stop", RECORDER_UNIT)
            jalankan("start", "--no-block", UPLOADER_UNIT)
            aktif = cek_aktif()
            batas_utc = None
            pesan = "Durasi perekaman (%s) selesai otomatis; berkas sedang dikirim ke arsip." % (durasi_label or "terjadwal")

    st = {
        "terpasang": True,
        "aktif": bool(aktif),
        "perintah_id": last_id,
        "mulai_utc": mulai_utc if aktif else st_lama.get("mulai_utc"),
        "batas_utc": batas_utc if aktif else None,
        "durasi_label": durasi_label if aktif else "",
        "catatan": catatan if aktif else "",
        "oleh": oleh,
        "diperbarui_utc": rk.sekarang_utc(t0),
        "pesan": pesan,
    }
    rk.simpan_status(path_status, st)
    return st


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--perintah", default=rk.PATH_PERINTAH)
    ap.add_argument("--status", default=rk.PATH_STATUS)
    a = ap.parse_args()
    st = sinkron(a.perintah, a.status)
    print("rekam aktif=%s pesan=%s" % (st.get("aktif"), st.get("pesan") or "-"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
