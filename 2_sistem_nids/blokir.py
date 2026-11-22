# -*- coding: utf-8 -*-
"""
Layanan sinkronisasi firewall (nftables) untuk daftar IP diblokir (nids-blokir.service).

Dijalankan oleh systemd sebagai root secara otomatis saat /var/lib/nids-bersama/ip_diblokir.json
berubah (nids-blokir.path) dan secara berkala tiap menit (nids-blokir.timer) untuk membersihkan
blokir sementara yang sudah kedaluwarsa.

  python blokir.py [--berkas /var/lib/nids-bersama/ip_diblokir.json]
"""
import argparse
import ipaddress
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nids import blokir as bk                                       # noqa: E402
from nids import tepercaya as tp                                    # noqa: E402


def ip_lokal():
    """Kumpulkan alamat IP milik server ini sendiri (pertahanan berlapis agar tidak memblokir diri sendiri)."""
    hasil = []
    try:
        r = subprocess.run(["ip", "-o", "addr", "show"], capture_output=True, text=True, timeout=5)
        for baris in r.stdout.splitlines():
            bagian = baris.split()
            for i, tok in enumerate(bagian):
                if tok in ("inet", "inet6") and i + 1 < len(bagian):
                    hasil.append(bagian[i + 1].split("/")[0])
    except Exception:
        pass
    return hasil


def jalankan_nft(skrip):
    """Terapkan skrip nftables secara atomik."""
    subprocess.run(["nft", "-f", "-"], input=skrip, text=True, capture_output=True, check=True, timeout=15)


def sinkron(path=bk.PATH_BAWAAN, path_status=bk.STATUS_BAWAAN, path_tepercaya=tp.PATH_BAWAAN,
            runner=jalankan_nft, ip_server=None, kini=None):
    aktif, _ = bk.bersihkan_kedaluwarsa(path, kini=kini)
    lokal = ip_lokal() if ip_server is None else list(ip_server)
    aman = []
    dilewati = []
    for e in aktif:
        try:
            net = bk.jaringan(e["cidr"])
            bk.periksa_dilindungi(net, path_tepercaya=path_tepercaya, ip_dilindungi=lokal)
            aman.append(e)
        except ValueError as ex:
            dilewati.append("%s (%s)" % (e.get("cidr"), ex))
    skrip = bk.skrip_nft(aman)
    try:
        runner(skrip)
        st = {
            "ok": True,
            "alat": "nftables",
            "tabel": "inet nids_blokir",
            "jumlah": len(aman),
            "cidr": [e["cidr"] for e in aman],
            "dilewati": dilewati,
            "terakhir_utc": bk.sekarang_utc(kini),
            "galat": None,
        }
        bk.tulis_status(path_status, st)
        return st
    except Exception as ex:
        ket = getattr(ex, "stderr", None) or str(ex)
        st = {
            "ok": False,
            "alat": "nftables",
            "tabel": "inet nids_blokir",
            "jumlah": len(aman),
            "cidr": [e["cidr"] for e in aman],
            "dilewati": dilewati,
            "terakhir_utc": bk.sekarang_utc(kini),
            "galat": str(ket).strip()[:300],
        }
        try:
            bk.tulis_status(path_status, st)
        except OSError:
            pass
        raise


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--berkas", default=bk.PATH_BAWAAN)
    ap.add_argument("--status", default=bk.STATUS_BAWAAN)
    ap.add_argument("--tepercaya", default=tp.PATH_BAWAAN)
    a = ap.parse_args()
    st = sinkron(a.berkas, a.status, a.tepercaya)
    print("firewall sinkron (%s): %d aturan aktif" % (st["alat"], st["jumlah"]), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
