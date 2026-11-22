# -*- coding: utf-8 -*-
"""Uji modul deteksi real-time.  Jalankan: python -m pytest -q tests"""
import gzip
import io
import os
import random
import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_fitur import SERVER, T0, paket, tulis_pcap               # noqa: E402
from nids.agregasi import FITUR_AGREGASI, AgregatorJendela, tambah_agregasi   # noqa: E402
from nids.detektor import Detektor                                  # noqa: E402
from nids.log_anomali import LogAnomali                             # noqa: E402
from nids.model import ModelDeteksi, latih                          # noqa: E402
from nids.pcap import ACK, FIN, PSH, RST, SYN, baca_pcap            # noqa: E402
from nids.pipa import putar_ulang                                   # noqa: E402
from nids.telegram import Notifikasi, susun_pesan                   # noqa: E402


# ------------------------------------------------------------------ agregator berjalan = versi tabel
def test_agregator_berjalan_sama_dengan_versi_tabel():
    rnd = random.Random(1)
    aliran, t = [], 1_761_000_000_000_000
    for i in range(3000):
        t += rnd.randint(1, 4_000_000)                                  # waktu unik & naik
        ip = "10.%d.%d.%d" % (rnd.randint(0, 2), rnd.randint(0, 3), rnd.randint(1, 6))
        aliran.append({"Source IP": ip, "Destination Port": rnd.choice([22, 80, 443, 3306, 8080, rnd.randint(1, 9999)]),
                       "Total Backward Packets": rnd.choice([0, 1, 5]), "Total Length of Bwd Packets": rnd.choice([0, 0, 500]),
                       "RST Flag Count": rnd.choice([0, 1]), "_t": t})
    ag = AgregatorJendela(60)
    jalan = pd.DataFrame([ag.tambah(dict(f), f["_t"]) for f in aliran])
    df = pd.DataFrame(aliran)
    df["Timestamp"] = pd.to_datetime(df["_t"], unit="us", utc=True)
    tabel = tambah_agregasi(df.drop(columns=["_t"]), 60)
    for c in FITUR_AGREGASI:
        assert (jalan[c].astype(float).round(9) == tabel[c].astype(float).round(9)).all(), c


# ------------------------------------------------------------------ rekaman buatan
def lalu_lintas_normal(t0, n_ip=120, per_ip=3):
    """Pengunjung web biasa: handshake, permintaan, balasan, FIN dua arah."""
    pk, t = [], t0
    for i in range(n_ip):
        c = "198.18.%d.%d" % (i // 200, i % 200 + 1)
        for j in range(per_ip):
            sp = 40000 + j
            t += 7.0
            pk += [(t, paket(c, SERVER, sp, 443, SYN)), (t + .01, paket(SERVER, c, 443, sp, SYN | ACK, win=65160)),
                   (t + .02, paket(c, SERVER, sp, 443, ACK)), (t + .03, paket(c, SERVER, sp, 443, PSH | ACK, payload=300)),
                   (t + .05, paket(SERVER, c, 443, sp, PSH | ACK, payload=1200 + 10 * j)),
                   (t + .06, paket(c, SERVER, sp, 443, FIN | ACK)), (t + .07, paket(SERVER, c, 443, sp, FIN | ACK)),
                   (t + .08, paket(c, SERVER, sp, 443, ACK))]
    return pk, t


def pemindaian(t0, penyerang="203.0.113.66", n=60):
    pk = []
    for i in range(n):
        t = t0 + i * 0.2
        pk += [(t, paket(penyerang, SERVER, 51000, 1000 + i, SYN)),
               (t + .001, paket(SERVER, penyerang, 1000 + i, 51000, RST | ACK))]
    return pk


@pytest.fixture
def berkas(tmp_path):
    normal, t_akhir = lalu_lintas_normal(T0)
    latih_f = tmp_path / "cap_latih.pcap.gz"
    tulis_pcap(latih_f, normal)
    uji_normal, t2 = lalu_lintas_normal(t_akhir + 600, n_ip=20, per_ip=1)
    uji = uji_normal + pemindaian(t_akhir + 700)
    uji.sort(key=lambda x: x[0])
    uji_f = tmp_path / "cap_uji.pcap.gz"
    tulis_pcap(uji_f, uji)
    return latih_f, uji_f


@pytest.fixture
def model(berkas, tmp_path):
    aliran, _ = putar_ulang([berkas[0]], 300)
    paket_model = latih(pd.DataFrame(aliran), 0.01, 0.01, 300)
    return ModelDeteksi(paket_model)


def test_putar_ulang_sama_dengan_fitur_tabel(berkas):
    aliran, pipa = putar_ulang([berkas[1]], 300)
    scan = [f for f in aliran if f["Source IP"] == "203.0.113.66"]
    assert len(scan) == 60 and pipa.jumlah_paket == 20 * 8 + 120
    assert max(f["agg_ip_port_unik"] for f in scan) == 60
    assert all(f["agg_ip_rasio_gagal"] == 1.0 for f in scan)


def test_detektor_menangkap_pemindaian_dan_mencatat(berkas, model, tmp_path):
    log = LogAnomali(str(tmp_path / "log.db"))
    terkirim = []
    notif = Notifikasi(kirim=lambda teks: (terkirim.append(teks), (True, 1761000000, None))[1],
                       path_log=str(tmp_path / "log.db"), jeda_detik=600, nama_server="uji", sinkron=True)
    det = Detektor(model, log, notif, waktu_log="selesai")
    for p in baca_pcap(berkas[1]):
        det.paket(p)
        det.detak(p.ts)
    det.selesai()
    scan = log.db.execute("SELECT COUNT(*), MIN(oleh), MAX(agg_ip_port_unik) FROM anomali "
                          "WHERE src_ip = '203.0.113.66'").fetchone()
    normal = log.db.execute("SELECT COUNT(*) FROM anomali WHERE src_ip != '203.0.113.66'").fetchone()[0]
    assert scan[0] >= 40 and "C" in scan[1] and scan[2] == 60           # sebagian besar aliran scan tertangkap
    # pengunjung biasa hampir tidak ditandai (maks. 3 aliran pertama periode uji: di data buatan semua pengunjung
    # berasal dari satu subnet, sehingga fitur agregasi subnet di awal periode masih kecil dan tampak berbeda)
    assert normal <= 3
    # jeda per IP: penyerang yang sama hanya memicu satu pesan dalam 10 menit
    pesan_penyerang = [t for t in terkirim if "203.0.113.66" in t]
    assert len(pesan_penyerang) == 1 and "WITA" in pesan_penyerang[0]
    n = log.db.execute("SELECT COUNT(*), SUM(berhasil) FROM notifikasi").fetchone()
    assert n[0] == len(terkirim) and n[1] == len(terkirim)
    menit = log.db.execute("SELECT SUM(aliran), SUM(anomali) FROM ringkasan").fetchone()
    assert menit[0] == det.jumlah_aliran and menit[1] == det.jumlah_anomali


def test_jeda_notifikasi_dan_ringkasan_tertahan():
    jam = [1000.0]
    terkirim = []
    n = Notifikasi(kirim=lambda teks: (terkirim.append(teks), (True, None, None))[1], jeda_detik=600,
                   jam=lambda: jam[0], sinkron=True, min_aliran=1)
    f = {"Source IP": "203.0.113.9", "Destination Port": 22, "agg_ip_aliran": 30, "agg_ip_port_unik": 1,
         "agg_ip_rasio_gagal": 0.1, "agg_ip_aliran_ssh": 30, "_mulai_us": 1_761_000_000_000_000}
    k = [(1, f, (0.5, 0.8, "C"))]
    assert n.anomali(k) == 1
    jam[0] += 60
    assert n.anomali(k * 5) == 0                                          # masih dalam jeda: ditahan
    jam[0] += 600
    assert n.anomali(k) == 1
    assert len(terkirim) == 2 and "+5 tertahan" in terkirim[1]
    assert "ke SSH" in terkirim[0] and "port berbeda" in terkirim[0] and "brute force" in terkirim[0]


def test_ambang_notifikasi():
    """Anomali tunggal tidak dikirim; dikirim setelah 3 anomali dari IP yang sama dalam jendela, atau bila A+C."""
    jam = [1000.0]
    terkirim = []
    n = Notifikasi(kirim=lambda teks: (terkirim.append(teks), (True, None, None))[1], jeda_detik=600,
                   jam=lambda: jam[0], sinkron=True, jendela_detik=300)
    f = {"Source IP": "203.0.113.9", "Destination Port": 22, "agg_ip_aliran": 2, "agg_ip_port_unik": 1,
         "agg_ip_rasio_gagal": 0.0, "agg_ip_aliran_ssh": 2, "_mulai_us": 1_761_000_000_000_000}
    satu = [(1, f, (0.8, 0.1, "A"))]
    assert n.anomali(satu) == 0
    jam[0] += 400                                                           # yang pertama sudah di luar jendela
    assert n.anomali(satu) == 0
    jam[0] += 60
    assert n.anomali(satu) == 0 and not terkirim                            # baru 2 dalam jendela
    jam[0] += 60
    assert n.anomali(satu) == 1 and len(terkirim) == 1                      # 3 dalam jendela -> dikirim
    assert "3 aliran anomali" in terkirim[0]
    g = dict(f, **{"Source IP": "198.51.100.1"})
    assert n.anomali([(2, g, (0.8, 0.9, "A+C"))]) == 1                     # kedua model sepakat: langsung
    assert "Anomali TINGGI" in terkirim[-1]


def test_pesan_telegram():
    f = {"Source IP": "2001:db8:1:2::9", "Destination Port": 443, "agg_ip_aliran": 3, "agg_ip_port_unik": 2,
         "agg_ip_rasio_gagal": 0.5, "agg_ip_aliran_ssh": 0, "_mulai_us": 1_761_000_000_000_000}
    t = susun_pesan("2001:db8:1:2::9", [(1, f, (0.7, 0.1, "A"))], 0, "srv <uji>", 300)
    assert "<code>2001:db8:1:2::/64</code>" in t and "IF-Flow" in t and "<b>srv &lt;uji&gt;</b>" in t
    assert "50% ditolak" in t and "Anomali SEDANG" in t and "Pola koneksi tidak biasa" in t


def test_koneksi_dari_server_tidak_dinilai(berkas, model):
    """Aliran yang dimulai server sendiri tidak dinilai (fokus pada lalu lintas masuk)."""
    from test_fitur import SERVER
    biasa = Detektor(model, None, None, waktu_log="selesai")
    masuk = Detektor(model, None, None, waktu_log="selesai", server_ip=[SERVER])
    for d in (biasa, masuk):
        for p in baca_pcap(berkas[1]):
            d.paket(p)
            d.detak(p.ts)
        d.selesai()
    assert masuk.jumlah_keluar == 0 and masuk.jumlah_aliran == biasa.jumlah_aliran     # semua uji dimulai dari luar
    keluar = Detektor(model, None, None, waktu_log="selesai", server_ip=["203.0.113.66"])
    for p in baca_pcap(berkas[1]):
        keluar.paket(p)
        keluar.detak(p.ts)
    keluar.selesai()
    assert keluar.jumlah_keluar == 60 and keluar.jumlah_aliran == biasa.jumlah_aliran - 60


def test_baca_pcap_dari_aliran_data(berkas):
    data = gzip.decompress(berkas[1].read_bytes())
    dari_berkas = list(baca_pcap(berkas[1]))
    dari_aliran = list(baca_pcap(io.BytesIO(data)))                     # seperti keluaran tcpdump -w -
    assert len(dari_aliran) == len(dari_berkas) and dari_aliran[5] == dari_berkas[5]


def test_galat_telegram_tidak_memuat_token():
    from nids.telegram import kirim_telegram
    tok = "123456789:" + "A" * 35
    ok, _, ket = kirim_telegram(tok + "\r", "1\r", "uji", batas_waktu=0.001)   # \r dibuang; galat jaringan disamarkan
    assert not ok and tok not in ket and "\r" not in ket
