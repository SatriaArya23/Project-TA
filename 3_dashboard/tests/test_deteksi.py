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
    assert "Skor tertinggi IF-Agg" in h and "0.500" in h and "Laporkan serangan lolos" in h
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


def test_ip_diblokir(c, app_dasar, tmp_path):
    folder = tmp_path / "bersama"
    folder.mkdir(exist_ok=True)
    app_dasar.config["TEPERCAYA_PATH"] = str(folder / "ip_tepercaya.json")
    app_dasar.config["BLOKIR_PATH"] = str(folder / "ip_diblokir.json")
    app_dasar.config["BLOKIR_STATUS_PATH"] = str(folder / "ip_diblokir_status.json")

    from nids import tepercaya as tp
    tp.tambah(app_dasar.config["TEPERCAYA_PATH"], NYARIS, "admin")

    h = c.get("/deteksi/blokir").get_data(as_text=True)
    assert "Belum" not in h and "Tidak ada IP yang sedang diblokir" in h and 'style="' not in h

    blokir = lambda ip, dur="1j", ket="", lanjut="": c.post("/deteksi/blokir", data={
        "csrf": csrf(c, "/deteksi/blokir"), "aksi": "tambah", "ip": ip, "durasi": dur, "ket": ket, "lanjut": lanjut})
    assert blokir("127.0.0.1").status_code == 400
    assert blokir("10.0.0.0/8").status_code == 400
    assert blokir(NYARIS).status_code == 400                         # beririsan dengan IP tepercaya

    r = blokir(PENYERANG, "1j", "port scan")
    assert r.status_code == 200 and "diblokir" in r.get_data(as_text=True)
    assert blokir(PENYERANG).status_code == 400                      # duplikat

    # indikator diblokir tampil di rincian IP dan daftar anomali
    hi = c.get("/deteksi/ip/" + PENYERANG).get_data(as_text=True)
    assert "diblokir</span>" in hi and "Buka blokir IP" in hi and 'style="' not in hi
    ha = c.get("/deteksi/anomali").get_data(as_text=True)
    assert "diblokir</span>" in ha and ">Buka</button>" in ha and 'style="' not in ha
    assert "BLOKIR_TAMBAH" in c.get("/audit").get_data(as_text=True)

    # blokir/buka dengan redirect cepat dari halaman rincian IP
    r_buka = c.post("/deteksi/blokir", data={"csrf": csrf(c, "/deteksi/ip/" + PENYERANG), "aksi": "hapus",
                                             "cidr": PENYERANG + "/32", "lanjut": "/deteksi/ip/" + PENYERANG})
    assert r_buka.status_code == 302 and r_buka.headers["Location"].endswith("/deteksi/ip/" + PENYERANG)
    hi2 = c.get("/deteksi/ip/" + PENYERANG).get_data(as_text=True)
    assert "dibuka" in hi2 and "Blokir IP</button>" in hi2
    assert "BLOKIR_HAPUS" in c.get("/audit").get_data(as_text=True)

    # pemantau (viewer) tidak dapat memblokir
    v = app_dasar.test_client()
    masuk(v, "paktut", "sandi-paktut-123")
    hv = v.get("/deteksi/blokir").get_data(as_text=True)
    assert "Hanya administrator" in hv and 'name="ip"' not in hv
    assert v.post("/deteksi/blokir", data={"csrf": csrf(v, "/deteksi/blokir"), "aksi": "tambah",
                                           "ip": PENYERANG, "durasi": "1j"}).status_code == 403


def test_login_tengah_tanpa_foto_latar(app_dasar):
    k = app_dasar.test_client()
    h = k.get("/login").get_data(as_text=True)
    assert "ASUNA · Anomaly Detection" in h and "Masuk ke ASUNA" in h and "logo-hotdog.png" in h
    assert "foto-anemon" not in h and "foto-karang" not in h and "wz-login-media" not in h
    assert 'style="' not in h


def test_kelola_model_katalog_dan_terapkan_umpan_balik(c, app_dasar, tmp_path):
    from nids import katalog_model

    mdir = str(tmp_path / "katalog-model")
    os.makedirs(mdir, exist_ok=True)
    app_dasar.config["MODEL_DIR"] = mdir

    # Buat dua berkas .joblib tiruan dan daftarkan ke katalog (dashboard tidak memuat isi joblib)
    f1, f2 = tmp_path / "m1.joblib", tmp_path / "m2.joblib"
    f1.write_bytes(b"joblib-1")
    f2.write_bytes(b"joblib-2")
    info1 = {
        "versi": "m20251030-000000", "hutan": "m20251030-000000", "jendela_detik": 300,
        "dilatih_utc": "2025-10-30T00:00:00Z", "jumlah_aliran_latih": 1000,
        "A": {"contamination": 0.001, "ambang": 0.70, "jumlah_fitur": 68, "transformasi": "log",
              "kuantil": kuantil(0.70, 0.999, 0.9)},
        "C": {"contamination": 0.01, "ambang": 0.60, "jumlah_fitur": 7, "transformasi": "log",
              "kuantil": kuantil(0.60, 0.99, 0.9)},
    }
    info2 = dict(info1, versi="m20251105-000000", hutan="m20251105-000000", jumlah_aliran_latih=5000)
    katalog_model.daftar_dari_file(mdir, str(f1), info1, nama="Baseline Normal", oleh="sistem", aktifkan=True)
    katalog_model.daftar_dari_file(mdir, str(f2), info2, nama="Profil Hari Ramai", oleh="satria", aktifkan=False)

    # Halaman model tampil rapi tanpa inline style, tanpa teks panjang, 1 tabel terpadu
    h = c.get("/deteksi/model").get_data(as_text=True)
    assert "Baseline Normal" in h and "Profil Hari Ramai" in h
    assert "Mode deteksi aktif" in h and "Tambah / unggah model baru" in h and "Riwayat versi model" in h
    assert "Penyesuaian sensitivitas (ambang)" not in h and "Katalog model tersimpan" not in h
    assert "worker terisolasi" not in h and "Skor kedua model tetap dicatat" not in h
    assert 'style="' not in h

    # 1) Ubah mode ke IF-Agg saja
    r = c.post("/deteksi/model", data={"csrf": csrf(c, "/deteksi/model"), "aksi": "mode", "mode": "C"})
    assert r.status_code == 302
    assert katalog_model.baca(mdir)["mode"] == "C"
    assert "IF-Agg saja" in c.get("/deteksi/model").get_data(as_text=True)

    # 1b) Unggah berkas .joblib masuk ke antrean validasi worker nids-model
    import io
    r_up = c.post("/deteksi/model/unggah", data={
        "csrf": csrf(c, "/deteksi/model"),
        "berkas": (io.BytesIO(b"isi-model-dummy-joblib"), "eksperimen_v3.joblib"),
        "nama": "Model Baru V3",
        "alasan": "hasil latih laptop",
    }, content_type="multipart/form-data")
    assert r_up.status_code == 302
    antre = katalog_model.baca_antrean_impor(mdir)
    assert antre is not None and antre["nama"] == "Model Baru V3"
    assert "MODEL_UNGGAH" in c.get("/audit").get_data(as_text=True)

    # Tolak ekstensi bukan .joblib
    r_up_bad = c.post("/deteksi/model/unggah", data={
        "csrf": csrf(c, "/deteksi/model"),
        "berkas": (io.BytesIO(b"halo"), "bukan_model.txt"),
    }, content_type="multipart/form-data")
    assert r_up_bad.status_code == 302
    assert "harus berekstensi .joblib" in c.get("/deteksi/model").get_data(as_text=True)

    # 2) Ubah ambang di luar batas aman -> 400
    r_bad = c.post("/deteksi/model", data={
        "csrf": csrf(c, "/deteksi/model"), "aksi": "ambang", "cont_a": "25", "cont_c": "1.0"
    })
    assert r_bad.status_code == 400 and "harus antara" in r_bad.get_data(as_text=True)

    # 3) Ubah ambang valid -> versi turunan baru dibuat dan langsung aktif
    r_ok = c.post("/deteksi/model", data={
        "csrf": csrf(c, "/deteksi/model"), "aksi": "ambang",
        "cont_a": "0,25", "cont_c": "1,50", "nama": "Sensitif Uji", "alasan": "uji dashboard"
    })
    assert r_ok.status_code == 302
    kat = katalog_model.baca(mdir)
    versi_turunan = kat["aktif"]
    assert versi_turunan not in ("m20251030-000000", "m20251105-000000")

    # 4) Ubah nama profil & rollback ke Profil Hari Ramai & hapus versi turunan
    assert c.post("/deteksi/model", data={
        "csrf": csrf(c, "/deteksi/model"), "aksi": "nama", "versi": versi_turunan, "nama": "Label Baru"
    }).status_code == 302
    assert katalog_model.cari(katalog_model.baca(mdir), versi_turunan)["nama"] == "Label Baru"

    assert c.post("/deteksi/model", data={
        "csrf": csrf(c, "/deteksi/model"), "aksi": "aktifkan", "versi": "m20251105-000000"
    }).status_code == 302
    assert katalog_model.baca(mdir)["aktif"] == "m20251105-000000"

    assert c.post("/deteksi/model", data={
        "csrf": csrf(c, "/deteksi/model"), "aksi": "hapus", "versi": versi_turunan
    }).status_code == 302
    assert katalog_model.cari(katalog_model.baca(mdir), versi_turunan) is None
    assert os.path.exists(os.path.join(mdir, "m20251030-000000.joblib"))    # berkas induk tetap aman!

    # Tidak boleh hapus model yang aktif
    assert c.post("/deteksi/model", data={
        "csrf": csrf(c, "/deteksi/model"), "aksi": "hapus", "versi": "m20251105-000000"
    }).status_code == 400

    # 5) Tombol 1-klik "Terapkan ambang usulan sekarang" dari Umpan Balik
    katalog_model.aktifkan(mdir, "m20251030-000000", oleh="satria")
    r_ub = lapor(c, "lolos", NYARIS, T0 + 209 * MENIT, T0 + 216 * MENIT)
    url_ub = r_ub.headers["Location"]
    h_ub = c.get(url_ub).get_data(as_text=True)
    assert "Terapkan ambang usulan sekarang" in h_ub and 'style="' not in h_ub
    r_terap = c.post(url_ub + "/terapkan", data={"csrf": csrf(c, url_ub)})
    assert r_terap.status_code == 302
    h_ub2 = c.get(url_ub).get_data(as_text=True)
    assert "diterapkan otomatis pada model" in h_ub2 and "selesai</span>" in h_ub2
    assert "Riwayat penyesuaian ambang" in h_ub2 and "IF-Agg" in h_ub2
    assert ">Detail</a>" in c.get("/deteksi/umpan-balik").get_data(as_text=True)

    # 6) Audit log mencatat aksi & pemantau (viewer) tidak bisa mengubah model
    audit = c.get("/audit").get_data(as_text=True)
    for ev in ("MODEL_MODE", "MODEL_AMBANG", "MODEL_NAMA", "MODEL_AKTIFKAN", "MODEL_HAPUS"):
        assert ev in audit

    v = app_dasar.test_client()
    masuk(v, "paktut", "sandi-paktut-123")
    hv = v.get("/deteksi/model").get_data(as_text=True)
    assert "hanya dapat dilakukan oleh administrator" in hv and 'name="mode"' not in hv
    assert v.post("/deteksi/model", data={
        "csrf": csrf(v, "/deteksi/model"), "aksi": "mode", "mode": "A"
    }).status_code == 403


def test_kontrol_rekam_tab_rekaman(c, app_dasar, tmp_path):
    from nids import rekam_kendali

    folder = tmp_path / "bersama-rekam"
    folder.mkdir()
    app_dasar.config["REKAM_CMD_PATH"] = str(folder / "rekam_perintah.json")
    app_dasar.config["REKAM_STATUS_PATH"] = str(folder / "rekam_status.json")

    h = c.get("/rekaman").get_data(as_text=True)
    assert "Kontrol perekaman lalu lintas" in h and "Mulai rekam lalu lintas" in h and 'style="' not in h

    r = c.post("/rekaman/kendali", data={
        "csrf": csrf(c, "/rekaman"), "aksi": "mulai", "durasi": "6j", "catatan": "uji rekam"
    })
    assert r.status_code == 302
    cmd = rekam_kendali.baca_perintah(app_dasar.config["REKAM_CMD_PATH"])
    assert cmd["aksi"] == "mulai" and cmd["durasi"] == "6j"

    # Simulasikan worker sudah menyalakan perekam -> tombol Hentikan tampil
    rekam_kendali.simpan_status(app_dasar.config["REKAM_STATUS_PATH"], {
        "terpasang": True, "aktif": True, "durasi_label": "6 jam", "pesan": "Sedang merekam"
    })
    h2 = c.get("/rekaman").get_data(as_text=True)
    assert "Sedang merekam" in h2 and "Hentikan &amp; simpan rekaman sekarang" in h2

    r_stop = c.post("/rekaman/kendali", data={"csrf": csrf(c, "/rekaman"), "aksi": "berhenti"})
    assert r_stop.status_code == 302
    assert rekam_kendali.baca_perintah(app_dasar.config["REKAM_CMD_PATH"])["aksi"] == "berhenti"
    audit = c.get("/audit").get_data(as_text=True)
    assert "REKAM_MULAI" in audit and "REKAM_BERHENTI" in audit

    # Viewer tidak boleh mengendalikan perekam
    v = app_dasar.test_client()
    masuk(v, "paktut", "sandi-paktut-123")
    assert v.post("/rekaman/kendali", data={"csrf": csrf(v, "/rekaman"), "aksi": "mulai", "durasi": "1j"}).status_code == 403


def test_multi_ai_dashboard_ringkasan_dan_ip(c, app_dasar, tmp_path):
    from nids import asisten_ai

    asisten_ai._CACHE.clear()
    folder = tmp_path / "bersama-ai"
    folder.mkdir()
    app_dasar.config["AI_CONFIG_PATH"] = str(folder / "ai_konfig.json")

    def fake_ai(url, payload, headers):
        if "generativelanguage" in url:
            return {"candidates": [{"content": {"parts": [{"text": "Analisis Gemini: risiko tinggi port scan."}]}}]}
        return {"choices": [{"message": {"content": "Analisis OpenAI: indikasi port scan, sarankan blokir 24 jam."}}]}

    app_dasar.config["AI_TRANSPORT"] = fake_ai

    # Tambah 2 profil AI (OpenAI + Gemini)
    r1 = c.post("/deteksi/ai", data={
        "csrf": csrf(c, "/deteksi/ai"), "aksi": "tambah",
        "nama": "OpenAI Utama", "provider": "openai", "model": "gpt-4o-mini",
        "api_key": "sk-rahasia-asli-99887766", "aktifkan": "1",
    })
    assert r1.status_code == 302
    r2 = c.post("/deteksi/ai", data={
        "csrf": csrf(c, "/deteksi/ai"), "aksi": "tambah",
        "nama": "Gemini Kedua", "provider": "gemini", "model": "gemini-2.5-flash",
        "api_key": "AIzaSecretKey554433",
    })
    assert r2.status_code == 302

    hai = c.get("/deteksi/ai").get_data(as_text=True)
    assert "OpenAI Utama" in hai and "Gemini Kedua" in hai and "2 profil" in hai
    assert "Deteksi anomali tetap 100%" not in hai
    assert "sk-rahasia-asli-99887766" not in hai and "AIzaSecretKey554433" not in hai   # kunci tak pernah bocor!
    assert 'style="' not in hai

    # Uji koneksi & Ringkas Ringkasan + Analisis IP (bisa memilih profil ke-2)
    profil = asisten_ai.daftar_aman(app_dasar.config["AI_CONFIG_PATH"])["profil"]
    id_openai = next(p["id"] for p in profil if p["nama"] == "OpenAI Utama")
    id_gemini = next(p["id"] for p in profil if p["nama"] == "Gemini Kedua")

    r_uji = c.post("/deteksi/ai", data={"csrf": csrf(c, "/deteksi/ai"), "aksi": "uji", "id": id_openai})
    assert r_uji.status_code == 302
    assert "berhasil dalam" in c.get("/deteksi/ai").get_data(as_text=True)

    r_ringkas = c.post("/deteksi/ringkas-ai", data={
        "csrf": csrf(c, "/deteksi"), "rentang": "24j", "profil_id": id_openai
    })
    assert r_ringkas.status_code == 200 and "Analisis OpenAI" in r_ringkas.get_data(as_text=True)

    r_ip = c.post("/deteksi/ip/" + PENYERANG + "/analisis-ai", data={
        "csrf": csrf(c, "/deteksi/ip/" + PENYERANG), "profil_id": id_gemini
    })
    assert r_ip.status_code == 200 and "Analisis Gemini" in r_ip.get_data(as_text=True)

    r_tanya = c.post("/deteksi/ai", data={
        "csrf": csrf(c, "/deteksi/ai"), "aksi": "tanya", "pertanyaan": "Apa ancaman terbesar hari ini?"
    })
    assert r_tanya.status_code == 200 and "Analisis OpenAI" in r_tanya.get_data(as_text=True)

    # Switch default & hapus profil
    assert c.post("/deteksi/ai", data={"csrf": csrf(c, "/deteksi/ai"), "aksi": "aktifkan", "id": id_gemini}).status_code == 302
    assert asisten_ai.baca(app_dasar.config["AI_CONFIG_PATH"])["aktif"] == id_gemini
    assert c.post("/deteksi/ai", data={"csrf": csrf(c, "/deteksi/ai"), "aksi": "hapus", "id": id_openai}).status_code == 302
    assert len(asisten_ai.baca(app_dasar.config["AI_CONFIG_PATH"])["profil"]) == 1

    # Audit log & RBAC viewer
    audit = c.get("/audit").get_data(as_text=True)
    for ev in ("AI_TAMBAH", "AI_UJI", "AI_RINGKAS", "AI_ANALISIS_IP", "AI_TANYA", "AI_AKTIFKAN", "AI_HAPUS"):
        assert ev in audit

    v = app_dasar.test_client()
    masuk(v, "paktut", "sandi-paktut-123")
    assert v.post("/deteksi/ai", data={"csrf": csrf(v, "/deteksi/ai"), "aksi": "tambah", "nama": "X"}).status_code == 403
    assert v.post("/deteksi/ringkas-ai", data={"csrf": csrf(v, "/deteksi"), "rentang": "24j"}).status_code == 403
