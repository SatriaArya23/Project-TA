# -*- coding: utf-8 -*-
"""
Simulasi serangan TERKENDALI ke VPS uji milik peneliti (pengujian sistem NIDS).

HANYA boleh diarahkan ke server milik sendiri: target dibatasi oleh TARGET_DIIZINKAN di bawah.
Setiap skenario dicatat ke jadwal_serangan.csv (waktu mulai/selesai + IP sumber) sebagai
"kunci jawaban" (ground truth) untuk menghitung precision, recall, F1, FPR, dan latensi.

  python simulasi.py normal            pengunjung web biasa (dicatat sebagai lalu lintas NORMAL)
  python simulasi.py portscan          pemindaian port cepat (TCP connect)
  python simulasi.py portscan-lambat   pemindaian port pelan
  python simulasi.py ssh-bruteforce    percobaan login SSH berulang dengan sandi salah
  python simulasi.py dos-http          banjir permintaan HTTP skala kecil (durasi & laju dibatasi)
  python simulasi.py jadwal            tampilkan catatan jadwal

Contoh:  python simulasi.py portscan --port-akhir 500 --laju 50
Jangan menjalankan simulasi saat baseline sedang direkam (lihat 05_Data_Eksperimen/Server-Uji/CATATAN.md).
"""
import argparse
import csv
import json
import os
import random
import socket
import string
import subprocess
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

TARGET_BAWAAN = os.environ.get("NIDS_TARGET_UJI", "127.0.0.1")
TARGET_DIIZINKAN = {TARGET_BAWAAN, "127.0.0.1"}     # VPS uji milik peneliti (via env NIDS_TARGET_UJI) + laptop sendiri
FOLDER = os.path.dirname(os.path.abspath(__file__))
JADWAL_BAWAAN = os.path.abspath(os.path.join(FOLDER, "..", "..", "05_Data_Eksperimen", "Server-Uji", "jadwal_serangan.csv"))
KUNCI_SSH = os.path.join(os.path.expanduser("~"), ".ssh", "vps_ta_ed25519")
KOLOM = ["id", "skenario", "label", "mulai_wita", "selesai_wita", "mulai_us", "selesai_us", "ip_sumber", "target",
         "jumlah", "berhasil", "parameter", "catatan"]
# batas atas agar simulasi tetap kecil dan tidak mengganggu jaringan penyedia VPS
BATAS = {"laju_scan": 200, "laju_dos": 300, "durasi_dos": 300, "percobaan_ssh": 300, "koneksi_dos": 50}


def us():
    return int(time.time() * 1_000_000)


def wita(t_us):
    return datetime.fromtimestamp(t_us / 1e6, timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")


def ip_sumber(target, manual=None):
    """IP publik laptop seperti yang dilihat server (ditanyakan lewat SSH ke VPS uji)."""
    if manual:
        return manual
    if target == "127.0.0.1":
        return "127.0.0.1"
    try:
        r = subprocess.run(["ssh", "-i", KUNCI_SSH, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                            "root@" + target, 'echo "${SSH_CLIENT%% *}"'], capture_output=True, text=True, timeout=30)
        ip = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
        socket.inet_pton(socket.AF_INET6 if ":" in ip else socket.AF_INET, ip)
        return ip
    except Exception:
        sys.exit("Gagal mengetahui IP publik laptop lewat SSH. Isi manual: --ip-sumber <ip>")


def catat(path, baris):
    baru = not os.path.exists(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    nomor = 1
    if not baru:
        with open(path, encoding="utf-8") as f:
            nomor = sum(1 for _ in csv.DictReader(f)) + 1
    baris = dict(baris, id=nomor)
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=KOLOM)
        if baru:
            w.writeheader()
        w.writerow(baris)
    return baris


def laju_tetap(laju, jumlah, kerja, pekerja=20):
    """Jalankan kerja(i) sebanyak `jumlah` kali dengan laju `laju` per detik. Kembalikan jumlah berhasil."""
    ok = [0]
    kunci = threading.Lock()

    def bungkus(i):
        if kerja(i):
            with kunci:
                ok[0] += 1
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=pekerja) as ex:
        for i in range(jumlah):
            tunggu = t0 + i / laju - time.time()
            if tunggu > 0:
                time.sleep(tunggu)
            ex.submit(bungkus, i)
    return ok[0]


# ------------------------------------------------------------------ skenario
def sk_normal(a):
    """Pengunjung web biasa: beberapa sesi, tiap sesi membuka halaman 1-3 kali dengan jeda baca."""
    n = 0
    for s in range(a.sesi):
        for _ in range(random.randint(1, 3)):
            try:
                urllib.request.urlopen("http://%s:%d/" % (a.target, a.port_web), timeout=10).read()
                n += 1
            except Exception:
                pass
            time.sleep(random.uniform(2, 8))
        if s < a.sesi - 1:
            time.sleep(a.jeda)
    return a.sesi, n, {"sesi": a.sesi, "jeda": a.jeda}


def sk_portscan(a):
    laju = min(a.laju, BATAS["laju_scan"])
    port = list(range(a.port_awal, a.port_akhir + 1))

    def coba(i):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        try:
            return s.connect_ex((a.target, port[i])) == 0           # True = port terbuka
        finally:
            s.close()
    terbuka = laju_tetap(laju, len(port), coba)
    return len(port), terbuka, {"port": [a.port_awal, a.port_akhir], "laju": laju}


def sk_portscan_lambat(a):
    port = random.sample(range(1, 65536), a.jumlah)
    terbuka = 0
    for i, p in enumerate(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            terbuka += s.connect_ex((a.target, p)) == 0
        finally:
            s.close()
        if i < len(port) - 1:
            time.sleep(a.jeda)
    return a.jumlah, terbuka, {"jumlah": a.jumlah, "jeda": a.jeda}


def sk_ssh(a):
    import paramiko
    n = min(a.percobaan, BATAS["percobaan_ssh"])
    gagal_login = 0
    for i in range(n):
        sandi = "".join(random.choices(string.ascii_letters + string.digits, k=12))   # selalu sandi salah
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            c.connect(a.target, port=a.port_ssh, username=a.user, password=sandi, timeout=10, banner_timeout=10,
                      auth_timeout=10, allow_agent=False, look_for_keys=False)
        except paramiko.AuthenticationException:
            gagal_login += 1                                          # yang diharapkan: ditolak
        except Exception:
            pass
        finally:
            c.close()
        if i < n - 1:
            time.sleep(a.jeda)
    return n, gagal_login, {"percobaan": n, "jeda": a.jeda, "user": a.user}


def sk_dos(a):
    laju, durasi = min(a.laju, BATAS["laju_dos"]), min(a.durasi, BATAS["durasi_dos"])
    jumlah = int(laju * durasi)
    minta = ("GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: simulasi-ta\r\n\r\n" % a.target).encode()

    def kirim(_):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        try:
            s.connect((a.target, a.port_web))
            s.sendall(minta)
            return bool(s.recv(64))
        except Exception:
            return False
        finally:
            s.close()
    ok = laju_tetap(laju, jumlah, kirim, pekerja=min(a.koneksi, BATAS["koneksi_dos"]))
    return jumlah, ok, {"laju": laju, "durasi": durasi, "koneksi": a.koneksi}


SKENARIO = {"normal": (sk_normal, "normal"), "portscan": (sk_portscan, "serangan"),
            "portscan-lambat": (sk_portscan_lambat, "serangan"), "ssh-bruteforce": (sk_ssh, "serangan"),
            "dos-http": (sk_dos, "serangan")}


def jalankan(a):
    if a.target not in TARGET_DIIZINKAN:
        sys.exit("Ditolak: target %s bukan server uji milik peneliti (TARGET_DIIZINKAN)." % a.target)
    fungsi, label = SKENARIO[a.skenario]
    ip = ip_sumber(a.target, a.ip_sumber)
    print("Skenario %s (%s) -> %s, IP sumber %s ..." % (a.skenario, label, a.target, ip), flush=True)
    mulai = us()
    jumlah, berhasil, param = fungsi(a)
    selesai = us()
    b = catat(a.jadwal, {"skenario": a.skenario, "label": label, "mulai_wita": wita(mulai), "selesai_wita": wita(selesai),
                         "mulai_us": mulai, "selesai_us": selesai, "ip_sumber": ip, "target": a.target,
                         "jumlah": jumlah, "berhasil": berhasil, "parameter": json.dumps(param), "catatan": a.catatan})
    print("Selesai #%d: %s s.d. %s WITA (%.0f detik) | %d percobaan, %d berhasil | dicatat di %s" % (
        b["id"], b["mulai_wita"], b["selesai_wita"], (selesai - mulai) / 1e6, jumlah, berhasil, a.jadwal))
    return b


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("skenario", choices=list(SKENARIO) + ["jadwal"])
    ap.add_argument("--target", default=TARGET_BAWAAN)
    ap.add_argument("--jadwal", default=JADWAL_BAWAAN, help="berkas CSV catatan jadwal (kunci jawaban)")
    ap.add_argument("--ip-sumber", help="IP publik laptop (bawaan: ditanyakan ke server lewat SSH)")
    ap.add_argument("--catatan", default="")
    ap.add_argument("--port-web", type=int, default=80)
    ap.add_argument("--port-ssh", type=int, default=22)
    ap.add_argument("--sesi", type=int, default=10, help="normal: jumlah sesi pengunjung")
    ap.add_argument("--jeda", type=float, default=None, help="detik antarsesi / antarport / antarpercobaan")
    ap.add_argument("--port-awal", type=int, default=1)
    ap.add_argument("--port-akhir", type=int, default=1000)
    ap.add_argument("--laju", type=float, default=None, help="per detik (portscan bawaan 50, dos-http bawaan 50)")
    ap.add_argument("--jumlah", type=int, default=30, help="portscan-lambat: jumlah port")
    ap.add_argument("--percobaan", type=int, default=40, help="ssh-bruteforce: jumlah percobaan login")
    ap.add_argument("--user", default="uji", help="ssh-bruteforce: nama pengguna (sandi selalu acak & salah)")
    ap.add_argument("--durasi", type=float, default=60, help="dos-http: detik")
    ap.add_argument("--koneksi", type=int, default=20, help="dos-http: koneksi paralel")
    a = ap.parse_args()
    if a.skenario == "jadwal":
        if os.path.exists(a.jadwal):
            print(open(a.jadwal, encoding="utf-8").read())
        else:
            print("Belum ada catatan:", a.jadwal)
        return
    a.jeda = a.jeda if a.jeda is not None else {"normal": 20, "portscan-lambat": 30, "ssh-bruteforce": 1.5}.get(a.skenario, 0)
    a.laju = a.laju if a.laju is not None else 50
    jalankan(a)


if __name__ == "__main__":
    main()
