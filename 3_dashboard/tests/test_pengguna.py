# -*- coding: utf-8 -*-
"""Uji peran (admin / analis / pemantau), halaman Pengguna & Akun, dan migrasi tabel pengguna lama."""
import os
import re
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_penerima import app, csrf, masuk                  # noqa: E402,F401  (fixture)
from test_deteksi import NYARIS, T0, MENIT, db_deteksi, lapor  # noqa: E402,F401  (fixture)
from penerima.db import inisialisasi                         # noqa: E402


def buat(c, username, peran, nama=""):
    r = c.post("/pengguna", data={"csrf": csrf(c, "/pengguna"), "username": username, "nama": nama, "peran": peran})
    m = re.search(r'class="sandi mono">([^<]+)<', r.get_data(as_text=True))
    return r, (m.group(1) if m else None)


def ganti_sandi(c, lama, baru):
    return c.post("/akun", data={"csrf": csrf(c, "/akun"), "sandi_lama": lama, "sandi_baru": baru, "ulang": baru})


def id_pengguna(app, username):
    con = sqlite3.connect(app.config["DB_PATH"])
    i = con.execute("SELECT id FROM pengguna WHERE username = ?", (username,)).fetchone()[0]
    con.close()
    return i


def test_admin_menambah_bawahan_dan_hak_akses(app, db_deteksi):
    app.config["DETEKSI_DB"] = db_deteksi
    adm = app.test_client()
    masuk(adm, "satria", "sandi-admin-123")
    h = adm.get("/pengguna").get_data(as_text=True)
    assert "Tambah pengguna" in h and "Hak akses tiap peran" in h and 'style="' not in h
    assert ">Pengguna</span>" in adm.get("/deteksi").get_data(as_text=True)      # menu khusus admin

    r, sandi = buat(adm, "budi.s", "analis", "Budi Santoso")
    assert r.status_code == 200 and sandi and len(sandi) >= 12
    assert buat(adm, "budi.s", "viewer")[0].status_code == 400                    # username sudah dipakai
    assert buat(adm, "A B", "viewer")[0].status_code == 400                      # format username
    assert buat(adm, "orang", "superadmin")[0].status_code == 400                # peran tidak dikenal

    # analis baru: password sementara -> wajib ganti dulu
    an = app.test_client()
    masuk(an, "budi.s", sandi)
    r = an.get("/deteksi")
    assert r.status_code == 302 and r.headers["Location"].endswith("/akun")
    assert ganti_sandi(an, sandi, "pendek").status_code == 400
    assert ganti_sandi(an, sandi, "budi.s").status_code == 400
    r = ganti_sandi(an, sandi, "sandi-budi-baru-1")
    assert r.status_code == 302 and an.get("/deteksi").status_code == 200

    # analis: boleh melapor & periksa ulang, tidak boleh memutuskan atau mengelola pengguna
    h = an.get("/deteksi/umpan-balik").get_data(as_text=True)
    assert "Laporan baru" in h and ">Pengguna</span>" not in h
    r = lapor(an, "lolos", NYARIS, T0 + 209 * MENIT, T0 + 216 * MENIT)
    assert r.status_code == 302
    ub = r.headers["Location"].rsplit("/", 1)[1]
    h = an.get("/deteksi/umpan-balik/" + ub).get_data(as_text=True)
    assert "Periksa ulang lagi" in h and "Tandai selesai" not in h
    tok = csrf(an, "/deteksi/umpan-balik/" + ub)
    assert an.post("/deteksi/umpan-balik/%s/periksa" % ub, data={"csrf": tok}).status_code == 302
    assert an.post("/deteksi/umpan-balik/%s/selesai" % ub, data={"csrf": tok}).status_code == 403
    assert an.get("/deteksi/umpan-balik/kasus.json").status_code == 403
    assert an.get("/pengguna").status_code == 403

    # pemantau (viewer) tidak boleh melapor
    _, s2 = buat(adm, "pemantau1", "viewer")
    vw = app.test_client()
    masuk(vw, "pemantau1", s2)
    ganti_sandi(vw, s2, "sandi-pemantau-1")
    assert "Laporan baru" not in vw.get("/deteksi/umpan-balik").get_data(as_text=True)
    assert lapor(vw, "lolos", NYARIS, T0, T0 + MENIT).status_code == 403

    # admin menonaktifkan analis -> sesinya langsung tidak berlaku
    uid = id_pengguna(app, "budi.s")
    assert adm.post("/pengguna/%d" % uid, data={"csrf": csrf(adm, "/pengguna"), "aksi": "nonaktif"}).status_code == 302
    assert an.get("/deteksi").status_code == 302
    adm.post("/pengguna/%d" % uid, data={"csrf": csrf(adm, "/pengguna"), "aksi": "aktif"})

    # reset password -> password sementara baru, sesi lama keluar, wajib ganti lagi
    an2 = app.test_client()
    masuk(an2, "budi.s", "sandi-budi-baru-1")
    assert an2.get("/deteksi").status_code == 200
    r = adm.post("/pengguna/%d" % uid, data={"csrf": csrf(adm, "/pengguna"), "aksi": "reset"})
    s3 = re.search(r'class="sandi mono">([^<]+)<', r.get_data(as_text=True)).group(1)
    assert an2.get("/deteksi").status_code == 302
    masuk(an2, "budi.s", s3)
    assert an2.get("/deteksi").headers["Location"].endswith("/akun")

    # ubah peran analis -> admin, dan admin tidak bisa mengubah akunnya sendiri
    adm.post("/pengguna/%d" % uid, data={"csrf": csrf(adm, "/pengguna"), "aksi": "peran", "peran": "admin"})
    sendiri = id_pengguna(app, "satria")
    r = adm.post("/pengguna/%d" % sendiri, data={"csrf": csrf(adm, "/pengguna"), "aksi": "nonaktif"})
    assert r.status_code == 400 and adm.get("/deteksi").status_code == 200

    audit = adm.get("/audit").get_data(as_text=True)
    assert "PENGGUNA_TAMBAH" in audit and "PENGGUNA_UBAH" in audit and "GANTI_SANDI" in audit


def test_ganti_password_sendiri_mengeluarkan_sesi_lain(app):
    a, b = app.test_client(), app.test_client()
    masuk(a, "satria", "sandi-admin-123")
    masuk(b, "satria", "sandi-admin-123")
    assert ganti_sandi(a, "salah-sandi-123", "sandi-admin-baru-1").status_code == 400
    r = ganti_sandi(a, "sandi-admin-123", "sandi-admin-baru-1")
    assert r.status_code == 200 and "berhasil diganti" in r.get_data(as_text=True)
    assert a.get("/audit").status_code == 200            # sesi yang mengganti tetap masuk
    assert b.get("/audit").status_code == 302            # sesi lain keluar


def test_migrasi_tabel_pengguna_lama(tmp_path):
    path = str(tmp_path / "lama.db")
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE instalasi (id INTEGER PRIMARY KEY, nama TEXT UNIQUE NOT NULL, keterangan TEXT,
            dibuat_utc TEXT NOT NULL, aktif INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE pengguna (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, hash_sandi TEXT NOT NULL,
            peran TEXT NOT NULL CHECK (peran IN ('admin', 'viewer')), instalasi_id INTEGER REFERENCES instalasi(id),
            dibuat_utc TEXT NOT NULL, aktif INTEGER NOT NULL DEFAULT 1);
        INSERT INTO pengguna VALUES (1, 'admin', 'h1', 'admin', NULL, '2026-11-01T00:00:00Z', 1),
                                    (2, 'lama', 'h2', 'viewer', NULL, '2026-11-01T00:00:00Z', 0);
    """)
    con.commit()
    con.close()
    inisialisasi(path)
    inisialisasi(path)                                   # dijalankan dua kali tetap aman
    con = sqlite3.connect(path)
    assert con.execute("SELECT id, username, hash_sandi, peran, aktif, wajib_ganti_sandi FROM pengguna "
                       "ORDER BY id").fetchall() == [(1, "admin", "h1", "admin", 1, 0), (2, "lama", "h2", "viewer", 0, 0)]
    con.execute("INSERT INTO pengguna (username, hash_sandi, peran, dibuat_utc) VALUES ('an', 'h', 'analis', 'x')")
    con.close()


def test_sesi_berakhir_setelah_diam_dan_batas_maksimal(app, monkeypatch):
    from penerima import keamanan
    jam = [1_800_000_000]
    monkeypatch.setattr(keamanan, "kini_detik", lambda: jam[0])
    c = app.test_client()
    masuk(c, "satria", "sandi-admin-123")
    assert c.get("/audit").status_code == 200
    jam[0] += 25 * 60                                   # 25 menit diam: masih masuk, cap aktivitas diperbarui
    assert c.get("/audit").status_code == 200
    jam[0] += 25 * 60                                   # 25 menit lagi (50 sejak login, 25 sejak aktivitas)
    assert c.get("/audit").status_code == 200
    jam[0] += 31 * 60                                   # diam 31 menit -> keluar
    r = c.get("/audit")
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    assert masuk(c, "satria", "sandi-admin-123").status_code == 302   # token CSRF tetap sah, bisa masuk lagi

    for _ in range(35):                                 # aktif terus tiap 20 menit selama 11 jam 40 menit
        jam[0] += 20 * 60
        assert c.get("/audit").status_code == 200
    jam[0] += 25 * 60                                   # 12 jam 5 menit sejak login, baru diam 25 menit
    assert c.get("/audit").status_code == 302           # keluar karena batas 12 jam, bukan karena diam
    # cookie sesi tidak menyimpan tanggal kedaluwarsa (hilang saat browser ditutup)
    c2 = app.test_client()
    r = masuk(c2, "satria", "sandi-admin-123")
    kuki = [h for h in r.headers.getlist("Set-Cookie") if h.startswith("tanids_sesi=")]
    assert kuki and "Expires" not in kuki[0] and "Max-Age" not in kuki[0]
