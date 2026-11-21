# -*- coding: utf-8 -*-
"""Uji IP tepercaya, jawaban bot Telegram (nids.laporan), dan pemantau kesehatan (pantau.py)."""
import os
import sys
import time
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pantau                                                     # noqa: E402
from bot import urai                                              # noqa: E402
from nids import tepercaya as tp                                  # noqa: E402
from nids.detektor import Detektor                                # noqa: E402
from nids.laporan import buka_baca, jawab, teks_hampir, teks_ip   # noqa: E402
from nids.log_anomali import LogAnomali                           # noqa: E402

MENIT = 60_000_000
PENYERANG, NYARIS, KANTOR = "203.0.113.66", "198.51.100.9", "192.0.2.50"


def kuantil(ambang, p_ambang, maks):
    k = [[i / 1000, ambang * (i / 1000) / p_ambang] for i in range(0, int(p_ambang * 1000) + 1)]
    return k + [[1.0, maks]]


def aliran(ip, t, port=443, agg=1, port_unik=1):
    return {"Waktu Selesai": t, "_mulai_us": t - 1000, "Flow Duration": 1000, "Source IP": ip, "Source Port": 40000,
            "Destination IP": "192.0.2.10", "Destination Port": port, "Protocol": 6, "Total Fwd Packets": 3,
            "Total Backward Packets": 2, "agg_ip_aliran": agg, "agg_ip_port_unik": port_unik, "agg_ip_rasio_gagal": 1.0,
            "agg_ip_aliran_ssh": 0, "agg_s24_ip_unik": 1, "agg_s24_aliran": 1, "agg_s24_port_unik": 1}


@pytest.fixture
def log_db(tmp_path):
    """Log deteksi buatan dengan waktu 'sekarang': pengunjung normal, pemindai, satu IP nyaris ditandai."""
    path = str(tmp_path / "deteksi.db")
    log = LogAnomali(path)
    t0 = int(time.time() * 1e6) - 120 * MENIT
    log.catat_model({"versi": "m-uji", "hutan": "m-uji", "jendela_detik": 300,
                     "A": {"contamination": 0.001, "ambang": 0.70, "kuantil": kuantil(0.70, 0.999, 0.9)},
                     "C": {"contamination": 0.01, "ambang": 0.60, "kuantil": kuantil(0.60, 0.99, 0.9)}}, kini_us=t0)
    model = SimpleNamespace(A=SimpleNamespace(ambang=0.70), C=SimpleNamespace(ambang=0.60))
    fs, hs = [], []
    for i in range(100):
        fs.append(aliran("198.18.0.%d" % (i % 20 + 1), t0 + i * MENIT // 2)); hs.append((0.40, 0.30, ""))
    for i in range(30):
        fs.append(aliran(PENYERANG, t0 + 60 * MENIT + i * 1_000_000, port=1000 + i, agg=30, port_unik=30))
        hs.append((0.45, 0.85, "C"))
    for i in range(4):
        fs.append(aliran(NYARIS, t0 + 90 * MENIT + i * MENIT, port=22)); hs.append((0.40, 0.59, ""))
    log.catat(fs, hs, model, waktu_log_us="selesai")
    log.status(terakhir_us=int(time.time() * 1e6) - 30_000_000, berhenti="tidak", nama_server="Uji",
               mulai_us=t0)
    log.tutup()
    return path


# ------------------------------------------------------------------ IP tepercaya
def test_validasi_dan_berkas_tepercaya(tmp_path):
    p = str(tmp_path / "ip_tepercaya.json")
    assert tp.baca(p) == []
    assert tp.tambah(p, " 192.0.2.50 ", "laptop admin", "satria") == "192.0.2.50/32"
    assert tp.tambah(p, "198.51.100.77/24") == "198.51.100.0/24"           # dinormalkan
    for salah in ("bukan-ip", "10.0.0.0/8", "2001:db8::/32"):
        with pytest.raises(ValueError):
            tp.tambah(p, salah)
    with pytest.raises(ValueError):
        tp.tambah(p, "192.0.2.50")                                          # duplikat
    e = tp.baca(p)
    assert [x["cidr"] for x in e] == ["192.0.2.50/32", "198.51.100.0/24"] and e[0]["oleh"] == "satria"
    assert tp.cocok_dengan(e, "198.51.100.200")["cidr"] == "198.51.100.0/24"
    assert tp.cocok_dengan(e, "203.0.113.1") is None
    assert tp.hapus(p, "192.0.2.50/32") and not tp.hapus(p, "192.0.2.50/32")


def test_daftar_dimuat_ulang_saat_berkas_berubah(tmp_path):
    p = str(tmp_path / "t.json")
    jam = [0.0]
    d = tp.DaftarTepercaya(p, periksa_detik=30, jam=lambda: jam[0])
    assert len(d) == 0 and d.cocok(KANTOR) is None
    tp.tambah(p, KANTOR)
    jam[0] = 10
    d.muat_ulang(paksa=False)
    assert d.cocok(KANTOR) is None                     # belum 30 detik: belum diperiksa
    jam[0] = 31
    d.muat_ulang(paksa=False)
    assert d.cocok(KANTOR)["cidr"] == KANTOR + "/32"
    with open(p, "w") as f:
        f.write("{rusak")
    jam[0] = 70
    os.utime(p, ns=(time.time_ns(), time.time_ns() + 10**9))
    d.muat_ulang(paksa=False)
    assert d.cocok(KANTOR) is not None                 # berkas rusak: daftar lama dipertahankan


def test_detektor_tidak_menandai_ip_tepercaya(tmp_path):
    p = str(tmp_path / "t.json")
    tp.tambah(p, KANTOR)

    class Model:
        jendela_detik = 300

        def nilai(self, aliran):
            return [(0.9, 0.9, "A+C")] * len(aliran)

    terkirim = []
    notif = SimpleNamespace(anomali=lambda k: terkirim.extend(k))
    det = Detektor(Model(), None, notif, tepercaya=tp.DaftarTepercaya(p))
    det.tampung = [aliran(KANTOR, 1), aliran(PENYERANG, 2)]
    anomali = det.nilai()
    assert [a[1]["Source IP"] for a in anomali] == [PENYERANG] and len(terkirim) == 1
    assert det.jumlah_tepercaya == 1 and det.jumlah_aliran == 2


# ------------------------------------------------------------------ bot
def test_urai_perintah():
    assert urai("/ip@NidsBot 1.2.3.4") == ("ip", "1.2.3.4")
    assert urai("/STATUS") == ("status", "")
    assert urai("halo") is None and urai("/") is None and urai(None) is None


def test_jawaban_bot(log_db, tmp_path):
    h = jawab(log_db, "status", "", kondisi={"cpu_persen": 0.12, "ram_persen": 0.2, "disk_persen": 0.05})
    assert "deteksi berjalan" in h and "m-uji" in h and "134 aliran diperiksa" in h and "30 anomali dari 1 IP" in h
    assert "CPU 12%" in h
    h = jawab(log_db, "ringkasan", "")
    assert PENYERANG in h and "Pemindaian port" in h and "30 anomali" in h
    assert "<b>%s</b>" % PENYERANG in jawab(log_db, "ip", PENYERANG)
    assert "Model C" in jawab(log_db, "ip", NYARIS)
    assert "belum pernah tercatat" in jawab(log_db, "ip", "192.0.2.99")
    assert "bukan alamat IP" in jawab(log_db, "ip", "<b>x</b>") and "<b>x</b>" not in jawab(log_db, "ip", "<b>x</b>")
    assert "Tulis alamatnya" in jawab(log_db, "ip", "")
    assert "/status" in jawab(log_db, "bantuan", "") and "tidak dikenal" in jawab(log_db, "hapus", "")
    assert "belum tersedia" in jawab(str(tmp_path / "tidak-ada.db"), "status", "")

    # /hampir: NYARIS (skor C 0,59, ambang 0,60) masuk; setelah dijadikan tepercaya tidak lagi
    db = buka_baca(log_db)
    assert NYARIS in teks_hampir(db) and PENYERANG not in teks_hampir(db)
    p = str(tmp_path / "t.json")
    tp.tambah(p, NYARIS, "uji")
    d = tp.DaftarTepercaya(p)
    assert NYARIS not in teks_hampir(db, tepercaya=d)
    assert "IP tepercaya" in teks_ip(db, NYARIS, tepercaya=d)
    db.close()


# ------------------------------------------------------------------ pemantau
def argumen(log, tmp_path, **kw):
    a = dict(log=log, keadaan=str(tmp_path / "pantau.json"), nama_server="Uji", layanan="nids-deteksi,nids-bot",
             sepi_menit=30, disk_maks=0.9, ram_maks=0.95, ingatkan_jam=6)
    a.update(kw)
    return SimpleNamespace(**a)


def test_pemeriksaan_pantau(log_db, tmp_path):
    sehat = {"disk_persen": 0.05, "ram_persen": 0.2}
    a = argumen(log_db, tmp_path)
    assert pantau.periksa(a, layanan=lambda n: "active", kondisi_server=lambda: sehat) == {}
    m = pantau.periksa(a, layanan=lambda n: "failed" if n == "nids-bot" else "active",
                       kondisi_server=lambda: {"disk_persen": 0.95, "ram_persen": 0.2})
    assert set(m) == {"layanan:nids-bot", "disk"}
    # detak lama (> 3 menit) -> macet; tidak ada lalu lintas -> sepi tidak dicek karena modul tidak aktif
    kini = int(time.time() * 1e6) + 10 * MENIT
    m = pantau.periksa(a, layanan=lambda n: "active", kondisi_server=lambda: sehat, kini=kini)
    assert set(m) == {"detak"}
    # modul aktif tetapi aliran terakhir > 30 menit lalu -> sepi
    m = pantau.periksa(argumen(log_db, tmp_path, sepi_menit=5), layanan=lambda n: "active",
                       kondisi_server=lambda: sehat)
    assert set(m) == {"sepi"}
    # layanan tidak terpasang (None) tidak dianggap masalah
    assert pantau.periksa(a, layanan=lambda n: None, kondisi_server=lambda: sehat) == {}
    assert "log" in pantau.periksa(argumen(str(tmp_path / "x.db"), tmp_path), layanan=lambda n: None,
                                   kondisi_server=lambda: None)


def test_putaran_pantau_tidak_spam_dan_kirim_pulih(tmp_path):
    a = argumen("-", tmp_path)
    pesan, gagal = [], [False]

    def kirim(t):
        if gagal[0]:
            return False, None, "jaringan putus"
        pesan.append(t)
        return True, 0, None

    k = {"aktif": {}, "dikirim": 0}
    k = pantau.putaran(a, kirim, {"disk": "Disk hampir penuh"}, k, 1000)
    assert len(pesan) == 1 and "masalah sistem" in pesan[0] and "disk" in k["aktif"]
    k = pantau.putaran(a, kirim, {"disk": "Disk hampir penuh"}, k, 1120)        # 2 menit kemudian: diam
    assert len(pesan) == 1
    k = pantau.putaran(a, kirim, {"disk": "Disk hampir penuh"}, k, 1000 + 6 * 3600)   # pengingat 6 jam
    assert len(pesan) == 2
    gagal[0] = True                                                              # masalah baru, Telegram gagal
    k = pantau.putaran(a, kirim, {"disk": "x", "ram": "RAM hampir habis"}, k, 30000)
    assert "ram" not in k["aktif"]
    gagal[0] = False                                                             # dicoba lagi putaran berikutnya
    k = pantau.putaran(a, kirim, {"disk": "x", "ram": "RAM hampir habis"}, k, 30120)
    assert "ram" in k["aktif"] and "RAM hampir habis" in pesan[-1]
    k = pantau.putaran(a, kirim, {}, k, 30240)                                   # semua pulih
    assert "pulih" in pesan[-1] and "Disk hampir penuh" in pesan[-1] and k["aktif"] == {}
