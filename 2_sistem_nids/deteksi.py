# -*- coding: utf-8 -*-
"""
Modul deteksi NIDS (Isolation Forest A+C).

  python deteksi.py langsung --model model.joblib --log /var/lib/nids-deteksi/deteksi.db --antarmuka eth0
      Deteksi real-time: membaca paket dari tcpdump (header saja), mencatat anomali ke log SQLite,
      dan mengirim notifikasi Telegram (bila TELEGRAM_TOKEN dan TELEGRAM_CHAT_ID diatur).

  python deteksi.py putar-ulang REKAMAN... [--model model.joblib] [--log hasil.db] [--fitur fitur.parquet]
      Memproses rekaman .pcap/.pcap.gz dengan pipa yang sama seperti deteksi langsung.
      --fitur  : simpan semua aliran berfitur lengkap (bahan latih_model.py)
      --model  : sekaligus jalankan deteksi dan laporkan ringkasannya

Konfigurasi rahasia (deteksi langsung) dibaca dari variabel lingkungan:
  TELEGRAM_TOKEN, TELEGRAM_CHAT_ID   (di server: /etc/nids-deteksi/rahasia.env, izin 600)
"""
import argparse
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nids.detektor import Detektor            # noqa: E402
from nids import katalog_model                # noqa: E402
from nids.katalog_model import DIR_BAWAAN as KATALOG_BAWAAN, PengawasModel   # noqa: E402
from nids.log_anomali import LogAnomali, sekarang_us   # noqa: E402
from nids.model import ModelDeteksi           # noqa: E402
from nids.pcap import baca_pcap               # noqa: E402
from nids.telegram import Notifikasi          # noqa: E402
from nids.tepercaya import PATH_BAWAAN as TEPERCAYA_BAWAAN, DaftarTepercaya   # noqa: E402


def kumpulkan(masukan):
    berkas = []
    for m in masukan:
        p = Path(m)
        berkas += sorted(q for q in p.iterdir() if q.name.endswith((".pcap", ".pcap.gz"))) if p.is_dir() else [p]
    return sorted(berkas, key=lambda q: q.name)


def cetak(*a):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), *a, flush=True)


# ============================================================================ deteksi langsung
def langsung(a):
    model = ModelDeteksi.muat(a.model)
    berkas_aktif = a.model
    pengawas = None
    if a.katalog_dir:
        induk = os.path.dirname(os.path.abspath(a.katalog_dir))
        if (os.path.isdir(a.katalog_dir) and os.access(a.katalog_dir, os.W_OK)) or (
            not os.path.exists(a.katalog_dir) and os.path.isdir(induk) and os.access(induk, os.W_OK)
        ):
            try:
                data_kat, entri_aktif = katalog_model.pastikan_awal(a.katalog_dir, a.model, model.ringkas())
                if entri_aktif is not None:
                    p_aktif = katalog_model.path_berkas_model(a.katalog_dir, entri_aktif)
                    mode_aktif = data_kat.get("mode", "A+C")
                    if os.path.exists(p_aktif):
                        if os.path.abspath(p_aktif) != os.path.abspath(a.model):
                            model = ModelDeteksi.muat(p_aktif, mode=mode_aktif)
                        model.terapkan_katalog(entri_aktif, mode=mode_aktif)
                        berkas_aktif = p_aktif
                pengawas = PengawasModel(a.katalog_dir, periksa_detik=5)
                pengawas.periksa(paksa=True)
            except Exception as e:
                cetak("peringatan katalog model: %s" % e)
    os.makedirs(os.path.dirname(os.path.abspath(a.log)), exist_ok=True)
    log = LogAnomali(a.log)
    token = (os.environ.get("TELEGRAM_TOKEN") or "").strip() or None
    chat = (os.environ.get("TELEGRAM_CHAT_ID") or "").strip() or None
    notif = Notifikasi(token, chat, path_log=a.log, jeda_detik=a.jeda_notifikasi, nama_server=a.nama_server,
                       jendela_detik=model.jendela_detik, min_aliran=a.min_aliran_notifikasi)
    tepercaya = DaftarTepercaya(a.tepercaya) if a.tepercaya else None
    det = Detektor(model, log, notif, jeda_batch_detik=a.jeda_batch, tepercaya=tepercaya,
                   katalog=pengawas, berkas_model=berkas_aktif)
    log.status(mulai_us=sekarang_us(), berhenti="tidak", nama_server=a.nama_server, antarmuka=a.antarmuka,
               telegram="aktif" if notif.aktif else "tidak aktif", jeda_notifikasi=a.jeda_notifikasi,
               min_aliran_notifikasi=a.min_aliran_notifikasi, server_ip=",".join(sorted(det.server_ip)),
               model_versi=det.model.versi, model_mode=det.model.mode)

    saring = a.saring or "tcp or udp"
    cmd = ["tcpdump", "-n", "-p", "-U", "-i", a.antarmuka, "-s", str(a.snaplen), "-w", "-", saring]
    cetak("mulai: model %s (%s, mode %s) | jendela %d s | Telegram %s | IP tepercaya %s | %s" % (
        berkas_aktif, det.model.versi, det.model.mode, model.jendela_detik,
        "aktif" if notif.aktif else "TIDAK aktif",
        len(tepercaya) if tepercaya is not None else "-", " ".join(cmd)))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=1 << 16)

    antrian, berhenti = queue.Queue(maxsize=200_000), threading.Event()

    def pembaca():
        try:
            for p in baca_pcap(proc.stdout):
                antrian.put(p)
        finally:
            antrian.put(None)                       # tcpdump berhenti

    threading.Thread(target=pembaca, name="pembaca", daemon=True).start()
    for s in (signal.SIGTERM, signal.SIGINT):
        signal.signal(s, lambda *_: berhenti.set())

    t_status = t_retensi = 0
    kode = 0
    while not berhenti.is_set():
        try:
            p = antrian.get(timeout=0.5)
        except queue.Empty:
            p = False
        if p is None:
            cetak("tcpdump berhenti (kode %s)" % proc.poll())
            kode = 1
            break
        kini = sekarang_us()
        if p:
            det.paket(p, kini)
        det.detak(kini)
        if kini - t_status >= 60_000_000:            # detak jantung untuk dashboard
            t_status = kini
            log.status(terakhir_us=kini, paket=det.pipa.jumlah_paket, aliran=det.jumlah_aliran,
                       anomali=det.jumlah_anomali, antrian=antrian.qsize(), aliran_aktif=len(det.pipa.penyusun.aktif),
                       aliran_keluar=det.jumlah_keluar, anomali_tidak_dikirim=notif.tidak_dikirim,
                       anomali_tepercaya=det.jumlah_tepercaya, model_versi=det.model.versi, model_mode=det.model.mode)
        if kini - t_retensi >= 86400_000_000:
            t_retensi = kini
            log.buang_lama(a.retensi_hari, a.retensi_aliran_hari)
    det.selesai()
    proc.terminate()
    notif.tutup()
    log.status(terakhir_us=sekarang_us(), berhenti="ya", berhenti_us=sekarang_us())
    cetak("berhenti: %d paket, %d aliran, %d anomali" % (det.pipa.jumlah_paket, det.jumlah_aliran, det.jumlah_anomali))
    return kode


# ============================================================================ putar ulang
def putar_ulang(a):
    import pandas as pd
    from nids.pipa import KOLOM

    berkas = kumpulkan(a.rekaman)
    if not berkas:
        sys.exit("Tidak ada berkas rekaman.")
    model = ModelDeteksi.muat(a.model) if a.model else None
    jendela = model.jendela_detik if model else a.jendela
    log = LogAnomali(a.log) if (a.log and model) else None
    semua = [] if a.fitur else None

    class Tanpa:                                     # bila hanya mengekstrak fitur
        jendela_detik = jendela

        def nilai(self, aliran):
            return [(0.0, 0.0, "")] * len(aliran)

    det = Detektor(model or Tanpa(), log, None, waktu_log="selesai")
    if semua is not None:
        asli = det.nilai

        def nilai_dan_simpan():
            semua.extend(det.tampung)
            return asli()
        det.nilai = nilai_dan_simpan

    t0 = time.time()
    for i, f in enumerate(berkas, 1):
        for p in baca_pcap(f):
            det.paket(p)
            det.detak(p.ts)
        print("\r  [%d/%d] %s  paket=%d aliran=%d anomali=%d" % (
            i, len(berkas), f.name, det.pipa.jumlah_paket, det.pipa.jumlah_aliran, det.jumlah_anomali),
            end="", flush=True)
    det.selesai()
    dt = time.time() - t0
    print()
    print("Selesai: %d berkas, %d paket, %d aliran dalam %.1f detik (%.0f paket/detik)" % (
        len(berkas), det.pipa.jumlah_paket, det.pipa.jumlah_aliran, dt, det.pipa.jumlah_paket / max(dt, 1e-9)))

    if semua is not None:
        df = pd.DataFrame(semua)
        df = df[[c for c in KOLOM + ["_mulai_us"] if c in df.columns]]
        df.to_parquet(a.fitur, index=False)
        print("Fitur %d aliran disimpan ke %s" % (len(df), a.fitur))
    if model:
        print("Anomali: %d aliran (%.2f%%)" % (det.jumlah_anomali, det.jumlah_anomali / max(det.jumlah_aliran, 1) * 100))
        if log:
            rows = log.db.execute("SELECT src_ip, oleh, COUNT(*) FROM anomali GROUP BY src_ip, oleh "
                                  "ORDER BY 3 DESC LIMIT 15").fetchall()
            print("IP sumber anomali terbanyak:")
            for ip, oleh, n in rows:
                print("  %-40s %-4s %6d" % (ip, oleh, n))
            print("Log anomali: %s" % a.log)
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="mode", required=True)

    s = sub.add_parser("langsung", help="deteksi real-time dari antarmuka jaringan")
    s.add_argument("--model", required=True)
    s.add_argument("--log", required=True, help="berkas SQLite log anomali")
    s.add_argument("--antarmuka", default="eth0")
    s.add_argument("--snaplen", type=int, default=160)
    s.add_argument("--saring", help="filter BPF tambahan (bawaan: 'tcp or udp')")
    s.add_argument("--nama-server", default="")
    s.add_argument("--jeda-notifikasi", type=int, default=600, help="detik antarnotifikasi per IP sumber")
    s.add_argument("--min-aliran-notifikasi", type=int, default=3,
                   help="notifikasi bila >= N aliran anomali dari satu IP dalam jendela (atau model A dan C sepakat)")
    s.add_argument("--jeda-batch", type=float, default=1.0, help="detik maksimum aliran menunggu dinilai")
    s.add_argument("--retensi-hari", type=int, default=90, help="lama menyimpan anomali & notifikasi")
    s.add_argument("--retensi-aliran-hari", type=int, default=30, help="lama menyimpan skor semua aliran")
    s.add_argument("--tepercaya", default=TEPERCAYA_BAWAAN,
                   help="berkas daftar IP tepercaya (ditulis dashboard); '' = tanpa daftar")
    s.add_argument("--katalog-dir", default=KATALOG_BAWAAN,
                   help="folder katalog model bersama (hot-reload dari dashboard); '' = nonaktif")
    s.set_defaults(f=langsung)

    s = sub.add_parser("putar-ulang", help="proses rekaman pcap dengan pipa yang sama")
    s.add_argument("rekaman", nargs="+")
    s.add_argument("--model")
    s.add_argument("--log", help="simpan anomali ke berkas SQLite ini (perlu --model)")
    s.add_argument("--fitur", help="simpan semua aliran berfitur ke berkas parquet")
    s.add_argument("--jendela", type=int, default=300, help="jendela agregasi bila tanpa --model")
    s.set_defaults(f=putar_ulang)

    a = ap.parse_args()
    sys.exit(a.f(a))


if __name__ == "__main__":
    main()
