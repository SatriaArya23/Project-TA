# -*- coding: utf-8 -*-
"""
Salin log deteksi dari VPS uji ke laptop (untuk notebook 06_Evaluasi_VPS_Uji.ipynb).

  python ambil_log.py            -> 05_Data_Eksperimen/Server-Uji/hasil/deteksi_vps_uji.db

Log di server sedang dipakai modul deteksi, jadi disalin lewat fungsi backup SQLite (salinan utuh dan konsisten),
baru kemudian diunduh.
"""
import os
import subprocess
import sys

TARGET = os.environ.get("NIDS_TARGET_UJI", "192.0.2.10")   # atur env NIDS_TARGET_UJI=<IP VPS uji>
KUNCI = os.path.join(os.path.expanduser("~"), ".ssh", "vps_ta_ed25519")
FOLDER = os.path.dirname(os.path.abspath(__file__))
TUJUAN = os.path.abspath(os.path.join(FOLDER, "..", "..", "05_Data_Eksperimen", "Server-Uji", "hasil", "deteksi_vps_uji.db"))
SALIN = ("/opt/nids-deteksi/venv/bin/python -c \"import sqlite3; "
         "sqlite3.connect('file:/var/lib/nids-deteksi/deteksi.db?mode=ro', uri=True)"
         ".backup(sqlite3.connect('/tmp/deteksi_salinan.db'))\"")


def main():
    ssh = ["-i", KUNCI, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15"]
    subprocess.run(["ssh"] + ssh + ["root@" + TARGET, SALIN], check=True)
    os.makedirs(os.path.dirname(TUJUAN), exist_ok=True)
    subprocess.run(["scp", "-q"] + ssh + ["root@%s:/tmp/deteksi_salinan.db" % TARGET, TUJUAN], check=True)
    subprocess.run(["ssh"] + ssh + ["root@" + TARGET, "rm -f /tmp/deteksi_salinan.db"], check=True)
    print("Log deteksi disalin ke", TUJUAN, "(%.1f MB)" % (os.path.getsize(TUJUAN) / 1e6))


if __name__ == "__main__":
    sys.exit(main())
