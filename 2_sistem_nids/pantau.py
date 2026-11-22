# -*- coding: utf-8 -*-
"""
Pemantau kesehatan NIDS (layanan nids-pantau, dijalankan timer systemd tiap 2 menit).

Mengirim peringatan Telegram bila sistem pemantauan sendiri bermasalah, supaya administrator tidak
mengira server aman padahal sensornya mati diam-diam:

  • layanan nids-deteksi / nids-bot / ta-nids-server tidak berjalan
  • modul deteksi tidak menulis detak (macet) lebih dari 3 menit
  • tidak ada lalu lintas masuk yang tertangkap selama --sepi-menit (penangkap paket bermasalah)
  • disk hampir penuh (--disk-maks) atau RAM hampir habis (--ram-maks)

Pesan dikirim saat masalah BARU muncul, diulang tiap --ingatkan-jam selama belum selesai, dan pesan
"pulih" dikirim saat masalah hilang. Bila pengiriman gagal, dicoba lagi pada putaran berikutnya.
Keterbatasan: bila seluruh VPS mati, pemantau ini ikut mati; untuk itu perlu pemantau dari luar.

  python pantau.py [--uji]       --uji = kirim pesan uji sekarang lalu keluar
"""
import argparse
import html
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nids.laporan import buka_baca, kini_us, lalu, persen, status_modul   # noqa: E402
from nids.sistem import kondisi                                           # noqa: E402
from nids.telegram import kirim_telegram                                  # noqa: E402


def cetak(*a):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), *a, flush=True)


def keadaan_layanan(nama):
    """-> 'active' / 'failed' / 'inactive' / ... ; None bila layanan tidak terpasang di server ini."""
    try:
        out = subprocess.run(["systemctl", "show", "-p", "LoadState", "-p", "ActiveState", nama],
                             capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    d = dict(b.split("=", 1) for b in out.splitlines() if "=" in b)
    return None if d.get("LoadState") in (None, "not-found") else d.get("ActiveState")


def periksa(a, layanan=keadaan_layanan, kondisi_server=kondisi, kini=None):
    """-> {kode: teks masalah}."""
    kini = kini or kini_us()
    masalah = {}
    for nama in [x.strip() for x in a.layanan.split(",") if x.strip()]:
        st = layanan(nama)
        if st is not None and st != "active":
            masalah["layanan:" + nama] = "Layanan <b>%s</b> tidak berjalan (status: %s)" % (html.escape(nama), st)
    try:
        db = buka_baca(a.log)
        try:
            s = status_modul(db, kini)
            deteksi_jalan = layanan("nids-deteksi") in (None, "active")
            if not s["aktif"] and deteksi_jalan and s.get("berhenti") != "ya":
                masalah["detak"] = ("Modul deteksi tidak menulis detak sejak %s (macet?)" % lalu(s["terakhir_us"], kini)
                                    if s["terakhir_us"] else "Modul deteksi belum pernah menulis detak")
            if s["aktif"]:
                t = db.execute("SELECT MAX(waktu_selesai_us) FROM aliran").fetchone()[0]
                if t is None or kini - t > a.sepi_menit * 60_000_000:
                    masalah["sepi"] = ("Tidak ada lalu lintas masuk yang tertangkap sejak %s (periksa antarmuka / tcpdump)"
                                       % (lalu(t, kini) if t else "modul dimulai"))
        finally:
            db.close()
    except Exception as ex:
        masalah["log"] = "Log deteksi tidak bisa dibaca (%s)" % type(ex).__name__
    k = kondisi_server()
    if k:
        if k["disk_persen"] >= a.disk_maks:
            masalah["disk"] = "Disk hampir penuh: %s terpakai" % persen(k["disk_persen"])
        if k["ram_persen"] >= a.ram_maks:
            masalah["ram"] = "RAM hampir habis: %s terpakai" % persen(k["ram_persen"])
    return masalah


def baca_keadaan(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"aktif": {}, "dikirim": 0}


def simpan_keadaan(path, k):
    sementara = path + ".baru"
    with open(sementara, "w", encoding="utf-8") as f:
        json.dump(k, f, ensure_ascii=False)
    os.replace(sementara, path)


def putaran(a, kirim, masalah, keadaan, kini_detik):
    """Bandingkan masalah sekarang dengan keadaan tersimpan; kirim pesan bila perlu. -> keadaan baru."""
    aktif = dict(keadaan.get("aktif") or {})
    nama = html.escape(a.nama_server or "server")
    baru = [k for k in masalah if k not in aktif]
    pulih = [k for k in aktif if k not in masalah]
    ingat = bool(masalah) and not baru and kini_detik - keadaan.get("dikirim", 0) >= a.ingatkan_jam * 3600
    if baru or ingat:
        baris = ["⚠️ <b>ASUNA · masalah sistem</b> · %s" % nama, ""]
        baris += ["• %s%s" % (t, "  <i>(baru)</i>" if k in baru and not ingat else "") for k, t in masalah.items()]
        baris += ["", "Selama masalah ini ada, deteksi serangan bisa tidak berjalan. Pesan diulang tiap %d jam "
                      "sampai pulih." % a.ingatkan_jam]
        ok, _, ket = kirim("\n".join(baris))
        cetak("peringatan %s: %s" % ("terkirim" if ok else "GAGAL (%s)" % ket, ", ".join(masalah)))
        if ok:
            for k in masalah:
                aktif.setdefault(k, {"sejak": kini_detik, "teks": masalah[k]})
            keadaan["dikirim"] = kini_detik
    if pulih:
        baris = ["✅ <b>ASUNA · pulih</b> · %s" % nama, ""]
        baris += ["• %s" % aktif[k]["teks"] for k in pulih]
        if masalah:
            baris += ["", "Masih ada: %s" % ", ".join(masalah)]
        ok, _, ket = kirim("\n".join(baris))
        cetak("pulih %s: %s" % ("terkirim" if ok else "GAGAL (%s)" % ket, ", ".join(pulih)))
        if ok:
            for k in pulih:
                aktif.pop(k, None)
    keadaan["aktif"] = aktif
    return keadaan


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log", default="/var/lib/nids-deteksi/deteksi.db")
    ap.add_argument("--keadaan", default="/var/lib/nids-deteksi/pantau.json")
    ap.add_argument("--nama-server", default=os.environ.get("NAMA_SERVER", ""))
    ap.add_argument("--layanan", default="nids-deteksi,nids-bot,ta-nids-server")
    ap.add_argument("--sepi-menit", type=int, default=30)
    ap.add_argument("--disk-maks", type=float, default=0.90)
    ap.add_argument("--ram-maks", type=float, default=0.95)
    ap.add_argument("--ingatkan-jam", type=int, default=6)
    ap.add_argument("--uji", action="store_true", help="kirim pesan uji lalu keluar")
    a = ap.parse_args()

    token = (os.environ.get("TELEGRAM_TOKEN") or "").strip()
    chat = (os.environ.get("TELEGRAM_CHAT_ID") or "").strip()

    def kirim(teks):
        if not token or not chat:
            return False, None, "Telegram belum diatur"
        return kirim_telegram(token, chat, teks)

    masalah = periksa(a)
    if a.uji:
        teks = "🧪 <b>NIDS · uji pemantau</b> · %s\n%s" % (
            html.escape(a.nama_server or "server"),
            "\n".join("• " + t for t in masalah.values()) if masalah else "Semua pemeriksaan normal ✅")
        ok, _, ket = kirim(teks)
        cetak("uji:", "terkirim" if ok else ket)
        return 0 if ok else 1
    if masalah:
        cetak("masalah:", "; ".join("%s" % k for k in masalah))
    keadaan = putaran(a, kirim, masalah, baca_keadaan(a.keadaan), int(time.time()))
    simpan_keadaan(a.keadaan, keadaan)
    return 0


if __name__ == "__main__":
    sys.exit(main())
