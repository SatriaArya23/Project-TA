# -*- coding: utf-8 -*-
"""Uji halaman Deteksi & loop umpan balik di dashboard:  python -m pytest -q tests"""
import json
import os
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_penerima import app as app_dasar, csrf, masuk          # noqa: E402,F401  (fixture)
from penerima import statistik                                   # noqa: E402,F401  (menyiapkan path paket nids)
from nids.log_anomali import LogAnomali                          # noqa: E402

T0 = 1_761_800_000_000_000          # akhir Okt 2025 (UTC), mikrodetik
MENIT = 60_000_000
PENYERANG, LAMBAT, NYARIS = "203.0.113.66", "198.51.100.7", "198.51.100.9"


def kuantil(ambang, p_ambang, maks):
    """Sebaran skor latih buatan: naik linear sampai `ambang` di p = p_ambang, lalu sampai `maks` di p = 1."""
    k = [[i / 1000, ambang * (i / 1000) / p_ambang] for i in range(0, int(p_ambang * 1000) + 1)]
    return k + [[1.0, maks]]


def aliran(ip, t, port=443, sa=0.40, sc=0.30):
    return {"Waktu Selesai": t, "_mulai_us": t - 1000, "Flow Duration": 1000, "Source IP": ip, "Source Port": 40000,
            "Destination IP": "192.0.2.10", "Destination Port": port, "Protocol": 6, "Total Fwd Packets": 3,
            "Total Backward Packets": 2, "agg_ip_aliran": 1, "agg_ip_port_unik": 1, "agg_ip_rasio_gagal": 0.0,
            "agg_ip_aliran_ssh": 0, "agg_s24_ip_unik": 1, "agg_s24_aliran": 1, "agg_s24_port_unik": 1}


@pytest.fixture
def db_deteksi(tmp_path):
    path = str(tmp_path / "deteksi.db")
    log = LogAnomali(path)
    info = {"versi": "m20251030-000000", "hutan": "m20251030-000000", "jendela_detik": 300,
            "dilatih_utc": "2025-10-30T00:00:00Z", "jumlah_aliran_latih": 1000,
            "A": {"contamination": 0.001, "ambang": 0.70, "jumlah_fitur": 68, "kuantil": kuantil(0.70, 0.999, 0.9)},
            "C": {"contamination": 0.01, "ambang": 0.60, "jumlah_fitur": 7, "kuantil": kuantil(0.60, 0.99, 0.9)},
            "evaluasi": {"bagian": [{"judul": "Rancangan pada CIC-IDS2017", "metrik": {"F1-score": "0,874"}}]}}
    log.catat_model(info, kini_us=T0)
    model = SimpleNamespace(A=SimpleNamespace(ambang=0.70), C=SimpleNamespace(ambang=0.60))
    fs, hs = [], []
    for i in range(300):                                            # pengunjung normal
        fs.append(aliran("198.18.0.%d" % (i % 50 + 1), T0 + i * MENIT)); hs.append((0.40, 0.30, ""))
    for i in range(40):                                             # pemindaian: ditandai Model C
        fs.append(aliran(PENYERANG, T0 + 100 * MENIT + i * 1_000_000, port=1000 + i)); hs.append((0.45, 0.85, "C"))
    for i in range(5):                                              # serangan lambat: jauh di bawah ambang
        fs.append(aliran(LAMBAT, T0 + 200 * MENIT + i * MENIT, port=22)); hs.append((0.40, 0.50, ""))
    for i in range(5):                                              # nyaris: sedikit di bawah ambang C
        fs.append(aliran(NYARIS, T0 + 210 * MENIT + i * MENIT, port=22)); hs.append((0.40, 0.59, ""))
    log.catat(fs, hs, model, waktu_log_us="selesai")
    log.status(terakhir_us=T0 + 299 * MENIT, berhenti="tidak", nama_server="uji", telegram="aktif")
    log.tutup()
    return path


@pytest.fixture
def c(app_dasar, db_deteksi):
    app_dasar.config["DETEKSI_DB"] = db_deteksi
    k = app_dasar.test_client()
    masuk(k, "satria", "sandi-admin-123")
    return k


def wita(us):
    from datetime import datetime, timedelta, timezone
    return (datetime.fromtimestamp(us / 1e6, timezone.utc) + timedelta(hours=8)).strftime("%Y-%m-%dT%H:%M")


def lapor(c, jenis, ip, mulai, akhir, token=None):
    return c.post("/deteksi/umpan-balik", data={"csrf": token or csrf(c, "/deteksi/umpan-balik"), "jenis": jenis,
                                                 "ip": ip, "mulai": wita(mulai), "akhir": wita(akhir), "ket": "uji"})


def test_halaman_deteksi(c):
    h = c.get("/deteksi").get_data(as_text=True)
    assert "Jenis anomali" in h and "<svg" in h and PENYERANG in h and "m20251030-000000" in h
    assert "Aliran diperiksa" in h and "350" in h                  # 300 + 40 + 5 + 5 aliran
    assert "Model penanda" in h and "Kondisi server" in h and "data-grafik" in h and 'style="' not in h
    h7 = c.get("/deteksi?rentang=7h").get_data(as_text=True)
    assert "7 hari" in h7 and h7.count("g-sasaran") >= 2 * 168      # dua grafik garis, satu titik per jam
    h = c.get("/deteksi/anomali?ip=" + PENYERANG).get_data(as_text=True)
    assert "40 aliran" in h and "198.18.0.1<" not in h
    h = c.get("/deteksi/ip/" + PENYERANG).get_data(as_text=True)
    assert "Ditandai anomali" in h and "Laporkan serangan lolos" in h
    h = c.get("/deteksi/model").get_data(as_text=True)
    assert "F1-score" in h and "0,874" in h and "Riwayat versi model" in h
    assert c.get("/deteksi/ip/bukan-ip").status_code == 404
    assert c.get("/deteksi/ip/192.0.2.99").status_code == 404


def test_hampir_anomali_dan_cari_ip(c):
    h = c.get("/deteksi/hampir").get_data(as_text=True)
    # hanya NYARIS (skor C 0,59, ambang 0,60) di atas batas aman; LAMBAT terlalu jauh, PENYERANG sudah ditandai
    assert NYARIS in h and LAMBAT not in h and PENYERANG + "<" not in h and "1 IP sumber" in h
    assert "Periksa ulang" in h and "jenis=lolos" in h and 'style="' not in h
    assert 'aria-current="page">' in h and '<h1 class="judul-hal">Anomali</h1>' in h   # menu Anomali tetap aktif
    # cari IP: IP normal tetap bisa dibuka rinciannya, lengkap dengan skor tertinggi vs ambang
    r = c.get("/deteksi/anomali?cari=" + LAMBAT)
    assert r.status_code == 302 and r.headers["Location"].endswith("/deteksi/ip/" + LAMBAT)
    h = c.get("/deteksi/ip/" + LAMBAT).get_data(as_text=True)
    assert "Skor tertinggi Model C" in h and "0.500" in h and "Laporkan serangan lolos" in h
    assert "belum pernah tercatat" in c.get("/deteksi/anomali?cari=192.0.2.99").get_data(as_text=True)
    assert "bukan alamat IP" in c.get("/deteksi/anomali?cari=halo").get_data(as_text=True)


def test_tanpa_log_deteksi(app_dasar, tmp_path):
    app_dasar.config["DETEKSI_DB"] = str(tmp_path / "tidak-ada.db")
    k = app_dasar.test_client()
    masuk(k, "satria", "sandi-admin-123")
    assert "belum terhubung" in k.get("/deteksi").get_data(as_text=True)


def test_loop_umpan_balik_di_dashboard(c, db_deteksi):
    # 1) nyaris di bawah ambang -> terdeteksi setelah penyesuaian ambang (contamination ~2,6% <= 5%)
    r = lapor(c, "lolos", NYARIS, T0 + 209 * MENIT, T0 + 216 * MENIT)
    assert r.status_code == 302
    h = c.get(r.headers["Location"]).get_data(as_text=True)
    assert "Terdeteksi setelah penyesuaian ambang" in h and "--ambang-c 0.58999999" in h
    # 2) serangan lambat jauh di bawah ambang -> pelatihan ulang
    r = lapor(c, "lolos", LAMBAT, T0 + 199 * MENIT, T0 + 206 * MENIT)
    assert "Masuk antrean pelatihan ulang" in c.get(r.headers["Location"]).get_data(as_text=True)
    # 3) penyerang yang sudah tertangkap
    r = lapor(c, "lolos", PENYERANG, T0 + 99 * MENIT, T0 + 102 * MENIT)
    assert "Sudah terdeteksi" in c.get(r.headers["Location"]).get_data(as_text=True)
    # 4) alarm palsu -> pelatihan ulang sebagai data normal
    r = lapor(c, "palsu", PENYERANG, T0 + 99 * MENIT, T0 + 102 * MENIT)
    assert "dipelajari sebagai lalu lintas" in c.get(r.headers["Location"]).get_data(as_text=True)
    # ekspor kasus untuk latih_model.py --umpan-balik
    kasus = json.loads(c.get("/deteksi/umpan-balik/kasus.json").get_data(as_text=True))["kasus"]
    assert sorted((k["jenis"], k["src_ip"]) for k in kasus) == [("lolos", LAMBAT), ("palsu", PENYERANG)]
    # tandai selesai
    tok = csrf(c, "/deteksi/umpan-balik/2")
    c.post("/deteksi/umpan-balik/2/selesai", data={"csrf": tok, "catatan": "model m2"})
    assert "model m2" in c.get("/deteksi/umpan-balik/2").get_data(as_text=True)
    assert len(json.loads(c.get("/deteksi/umpan-balik/kasus.json").get_data(as_text=True))["kasus"]) == 1
    # log deteksi tidak disentuh dashboard (dibuka baca-saja)
    import sqlite3
    con = sqlite3.connect(db_deteksi)
    assert con.execute("SELECT name FROM sqlite_master WHERE name = 'umpan_balik'").fetchone() is None
    con.close()


def test_validasi_dan_hak_akses(c, app_dasar, db_deteksi):
    assert lapor(c, "lolos", "bukan-ip", T0, T0 + MENIT).status_code == 400
    assert lapor(c, "lolos", NYARIS, T0 + MENIT, T0).status_code == 400              # akhir < mulai
    assert lapor(c, "lolos", NYARIS, T0, T0 + 8 * 24 * 60 * MENIT).status_code == 400  # > 7 hari
    assert lapor(c, "lolos", NYARIS, T0, T0 + MENIT, token="salah").status_code == 400
    v = app_dasar.test_client()
    masuk(v, "paktut", "sandi-paktut-123")
    assert v.get("/deteksi").status_code == 200
    assert "Laporan baru" not in v.get("/deteksi/umpan-balik").get_data(as_text=True)
    assert lapor(v, "lolos", NYARIS, T0, T0 + MENIT).status_code == 403
    assert v.get("/deteksi/umpan-balik/kasus.json").status_code == 403


def test_ip_tepercaya(c, app_dasar, tmp_path):
    folder = tmp_path / "bersama"
    folder.mkdir()
    app_dasar.config["TEPERCAYA_PATH"] = str(folder / "ip_tepercaya.json")
    h = c.get("/deteksi/tepercaya").get_data(as_text=True)
    assert "Belum ada IP tepercaya" in h and 'name="ip"' in h and 'style="' not in h
    assert NYARIS in c.get("/deteksi/hampir").get_data(as_text=True)

    tambah = lambda ip, ket="": c.post("/deteksi/tepercaya", data={"csrf": csrf(c, "/deteksi/tepercaya"),
                                                                     "aksi": "tambah", "ip": ip, "ket": ket})
    assert tambah("10.0.0.0/8").status_code == 400                     # terlalu luas
    assert tambah("bukan-ip").status_code == 400
    r = tambah(NYARIS, "laptop admin")
    assert r.status_code == 200 and "ditambahkan" in r.get_data(as_text=True)
    assert tambah(NYARIS).status_code == 400                            # duplikat
    # IP tepercaya tidak muncul di daftar hampir anomali; halaman IP menandainya
    assert NYARIS not in c.get("/deteksi/hampir").get_data(as_text=True)
    assert "tepercaya</span>" in c.get("/deteksi/ip/" + NYARIS).get_data(as_text=True)
    assert "TEPERCAYA_TAMBAH" in c.get("/audit").get_data(as_text=True)

    # pemantau (viewer) hanya bisa melihat
    v = app_dasar.test_client()
    masuk(v, "paktut", "sandi-paktut-123")
    h = v.get("/deteksi/tepercaya").get_data(as_text=True)
    assert NYARIS in h and 'name="ip"' not in h and "Hapus" not in h
    tok = csrf(v, "/deteksi/umpan-balik")
    assert v.post("/deteksi/tepercaya", data={"csrf": tok, "aksi": "hapus", "cidr": NYARIS + "/32"}).status_code == 403

    r = c.post("/deteksi/tepercaya", data={"csrf": csrf(c, "/deteksi/tepercaya"), "aksi": "hapus", "cidr": NYARIS + "/32"})
    assert "dihapus" in r.get_data(as_text=True) and NYARIS in c.get("/deteksi/hampir").get_data(as_text=True)


def test_ip_tepercaya_tanpa_folder_bersama(c, app_dasar, tmp_path):
    app_dasar.config["TEPERCAYA_PATH"] = str(tmp_path / "tidak-ada" / "ip_tepercaya.json")
    h = c.get("/deteksi/tepercaya").get_data(as_text=True)
    assert "belum ada di server ini" in h and 'name="ip"' not in h
