# -*- coding: utf-8 -*-
"""Uji server penerima:  python -m pytest -q tests"""
import gzip
import hashlib
import os
import re
import sys

import pytest
from werkzeug.security import generate_password_hash

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from penerima import create_app                      # noqa: E402
from penerima.db import buka, sekarang               # noqa: E402
from penerima.keamanan import hash_token             # noqa: E402

TOK_A, TOK_B, TOK_BACA_A, TOK_BACA_SEMUA = "a" * 43, "b" * 43, "r" * 43, "s" * 43


@pytest.fixture
def app(tmp_path):
    app = create_app({"DATA_DIR": str(tmp_path), "SECRET_KEY": "uji", "SESSION_COOKIE_SECURE": False,
                      "BEHIND_PROXY": False, "MAX_UPLOAD_MB": 1, "MIN_FREE_MB": 0, "TESTING": True})
    con = buka(app.config["DB_PATH"])
    t = sekarang()
    con.execute("INSERT INTO instalasi (id, nama, dibuat_utc) VALUES (1, 'bali-hai', ?), (2, 'vps-satria', ?)", (t, t))
    for tok, peran, inst in [(TOK_A, "upload", 1), (TOK_B, "upload", 2), (TOK_BACA_A, "read", 1),
                             (TOK_BACA_SEMUA, "read", None)]:
        con.execute("INSERT INTO token (hash, peran, instalasi_id, label, dibuat_utc) VALUES (?,?,?,?,?)",
                    (hash_token(tok), peran, inst, "uji-" + tok[0], t))
    con.execute("INSERT INTO pengguna (username, hash_sandi, peran, instalasi_id, dibuat_utc) VALUES "
                "('paktut', ?, 'viewer', 1, ?), ('satria', ?, 'admin', NULL, ?)",
                (generate_password_hash("sandi-paktut-123"), t, generate_password_hash("sandi-admin-123"), t))
    con.commit()
    con.close()
    return app


@pytest.fixture
def c(app):
    return app.test_client()


def isi(n=0):
    return gzip.compress(("paket %d " % n).encode() * 200)


def kirim(c, nama, data, token=TOK_A, sha=None):
    return c.put("/api/v1/upload/" + nama, data=data, headers={
        "Authorization": "Bearer " + token, "Content-Type": "application/gzip",
        "X-Content-SHA256": sha or hashlib.sha256(data).hexdigest()})


N1 = "cap_20261024_100000.hdr.pcap.gz"


# ------------------------------------------------------------------ unggah
def test_unggah_normal_dan_tersimpan(c, app):
    d = isi()
    r = kirim(c, N1, d)
    assert r.status_code == 201
    j = r.get_json()
    assert j["file"] == N1 and j["size"] == len(d) and j["sha256"] == hashlib.sha256(d).hexdigest()
    assert re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$", j["received_at"])
    p = os.path.join(app.config["BERKAS_DIR"], "bali-hai", N1)
    assert open(p, "rb").read() == d
    assert not [f for f in os.listdir(os.path.dirname(p)) if f.startswith(".unggah-")]


def test_duplikat_409_dengan_sha_tersimpan(c):
    d = isi()
    kirim(c, N1, d)
    r = kirim(c, N1, d)
    assert r.status_code == 409 and r.get_json()["sha256"] == hashlib.sha256(d).hexdigest()
    lain = isi(9)                                      # isi berbeda, nama sama -> sha tersimpan (berbeda) dikembalikan
    r = kirim(c, N1, lain)
    assert r.status_code == 409 and r.get_json()["sha256"] != hashlib.sha256(lain).hexdigest()


def test_nama_sama_beda_instalasi_boleh(c):
    assert kirim(c, N1, isi(), TOK_A).status_code == 201
    assert kirim(c, N1, isi(), TOK_B).status_code == 201


@pytest.mark.parametrize("token", ["", "salah" * 10, TOK_BACA_A])
def test_token_tidak_valid_401(c, token):
    assert kirim(c, N1, isi(), token).status_code == 401


def test_tanpa_header_auth_401(c):
    assert c.put("/api/v1/upload/" + N1, data=isi()).status_code == 401


@pytest.mark.parametrize("nama", ["x.gz", "cap_20261024_100000.pcap.gz", "cap_2026102_100000.hdr.pcap.gz",
                                  "..%2Fetc%2Fpasswd", "cap_20261024_100000.hdr.pcap.gz.sh"])
def test_nama_tidak_valid_400(c, nama):
    assert kirim(c, nama, isi()).status_code in (400, 404)


def test_checksum_salah_422_dan_tidak_tersimpan(c, app):
    r = kirim(c, N1, isi(), sha="0" * 64)
    assert r.status_code == 422
    assert not os.path.exists(os.path.join(app.config["BERKAS_DIR"], "bali-hai", N1))
    assert kirim(c, N1, isi()).status_code == 201       # boleh dikirim ulang dengan benar


def test_sha_tidak_ada_400(c):
    r = c.put("/api/v1/upload/" + N1, data=isi(), headers={"Authorization": "Bearer " + TOK_A})
    assert r.status_code == 400


def test_bukan_gzip_415(c):
    assert kirim(c, N1, b"bukan gzip" * 10).status_code == 415


def test_terlalu_besar_413(c):
    d = b"\x1f\x8b" + os.urandom(1024 * 1024 + 10)
    assert kirim(c, N1, d).status_code == 413


def test_instalasi_nonaktif_401(c, app):
    con = buka(app.config["DB_PATH"]); con.execute("UPDATE instalasi SET aktif = 0 WHERE id = 1"); con.commit()
    assert kirim(c, N1, isi()).status_code == 401


def test_token_dicabut_401(c, app):
    con = buka(app.config["DB_PATH"])
    con.execute("UPDATE token SET dicabut_utc = ? WHERE hash = ?", (sekarang(), hash_token(TOK_A))); con.commit()
    assert kirim(c, N1, isi()).status_code == 401


def test_audit_mencatat_semua(c):
    kirim(c, N1, isi()); kirim(c, N1, isi()); kirim(c, N1, isi(), "x" * 43); kirim(c, "cap_x.gz", isi())
    j = c.get("/api/v1/audit", headers={"Authorization": "Bearer " + TOK_BACA_SEMUA}).get_json()
    jenis = [a["event"] for a in j["items"]]
    assert jenis.count("UPLOAD_DITERIMA") == 1 and jenis.count("UPLOAD_DUPLIKAT") == 1
    assert jenis.count("UPLOAD_DITOLAK") == 2


# ------------------------------------------------------------------ API baca
def test_api_baca_terbatas_instalasi(c):
    kirim(c, N1, isi(), TOK_A); kirim(c, N1, isi(), TOK_B)
    h = {"Authorization": "Bearer " + TOK_BACA_A}
    j = c.get("/api/v1/files", headers=h).get_json()
    assert j["total"] == 1 and j["items"][0]["installation"] == "bali-hai"
    j = c.get("/api/v1/files?installation=vps-satria", headers=h).get_json()   # tidak bisa keluar lingkup
    assert j["total"] == 1 and j["items"][0]["installation"] == "bali-hai"
    assert all(a["installation"] == "bali-hai" for a in c.get("/api/v1/audit", headers=h).get_json()["items"])
    s = c.get("/api/v1/summary", headers=h).get_json()["installations"]
    assert [x["installation"] for x in s] == ["bali-hai"] and s[0]["files"] == 1
    j = c.get("/api/v1/files", headers={"Authorization": "Bearer " + TOK_BACA_SEMUA}).get_json()
    assert j["total"] == 2


def test_api_baca_unduh_dan_lingkup(c):
    d = isi(); kirim(c, N1, d, TOK_A); kirim(c, N1, isi(5), TOK_B)
    h = {"Authorization": "Bearer " + TOK_BACA_A}
    ids = {x["installation"]: x["id"] for x in c.get("/api/v1/files",
           headers={"Authorization": "Bearer " + TOK_BACA_SEMUA}).get_json()["items"]}
    r = c.get("/api/v1/files/%d/download" % ids["bali-hai"], headers=h)
    assert r.status_code == 200 and r.data == d
    assert c.get("/api/v1/files/%d/download" % ids["vps-satria"], headers=h).status_code == 404


def test_api_baca_tanpa_token_atau_token_upload(c):
    assert c.get("/api/v1/files").status_code == 401
    assert c.get("/api/v1/files", headers={"Authorization": "Bearer " + TOK_A}).status_code == 401
    assert c.get("/api/v1/files?since=bukan-tanggal",
                 headers={"Authorization": "Bearer " + TOK_BACA_A}).status_code == 400


def test_health(c):
    assert c.get("/api/v1/health").get_json()["status"] == "ok"


# ------------------------------------------------------------------ dashboard
def csrf(c, url="/login"):
    return re.search(r'name="csrf" value="([^"]+)"', c.get(url).get_data(as_text=True)).group(1)


def masuk(c, u, p):
    return c.post("/login", data={"csrf": csrf(c), "username": u, "password": p})


def test_dashboard_wajib_login(c):
    for url in ("/", "/rekaman", "/berkas", "/audit", "/deteksi"):
        r = c.get(url)
        assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_login_salah_dan_csrf(c):
    assert masuk(c, "paktut", "salah").status_code == 401
    assert c.post("/login", data={"username": "paktut", "password": "sandi-paktut-123"}).status_code == 400


def test_viewer_hanya_lihat_instalasinya(c):
    kirim(c, N1, isi(), TOK_A); kirim(c, "cap_20261024_110000.hdr.pcap.gz", isi(), TOK_B)
    assert masuk(c, "paktut", "sandi-paktut-123").status_code == 302
    html = c.get("/berkas?instalasi=vps-satria").get_data(as_text=True)
    assert "bali-hai" in html and "vps-satria" not in html
    assert "vps-satria" not in c.get("/rekaman").get_data(as_text=True)


def test_admin_lihat_semua(c):
    kirim(c, N1, isi(), TOK_A); kirim(c, "cap_20261024_110000.hdr.pcap.gz", isi(), TOK_B)
    masuk(c, "satria", "sandi-admin-123")
    html = c.get("/berkas").get_data(as_text=True)
    assert "bali-hai" in html and "vps-satria" in html


def test_batas_percobaan_login(c):
    for _ in range(5):
        masuk(c, "paktut", "salah")
    r = masuk(c, "paktut", "sandi-paktut-123")          # benar, tapi IP sudah diblokir
    assert r.status_code == 401 and "Terlalu banyak" in r.get_data(as_text=True)


def test_redirect_lanjut_tidak_ke_luar(c):
    r = c.post("/login?lanjut=//jahat.example/", data={"csrf": csrf(c), "username": "satria",
                                                         "password": "sandi-admin-123"})
    assert r.headers["Location"] in ("/deteksi", "http://localhost/deteksi")


def test_header_keamanan(c):
    r = c.get("/login")
    assert r.headers["X-Frame-Options"] == "DENY" and "default-src 'self'" in r.headers["Content-Security-Policy"]


# ------------------------------------------------------------------ waktu WITA
def test_konversi_waktu_wita():
    from datetime import datetime, timedelta, timezone
    from penerima import waktu
    assert waktu.teks_wita(waktu.mulai_rekam("cap_20261023_200451.hdr.pcap.gz")) == "24 Okt 2026, 04.04"
    assert waktu.teks_wita(waktu.dari_iso("2026-10-24T06:40:15Z")) == "24 Okt 2026, 14.40"
    assert waktu.rentang_nama_untuk_tanggal_wita("2026-10-24") == ("cap_20261023_160000", "cap_20261024_160000")
    assert waktu.rentang_nama_untuk_tanggal_wita("bukan") is None
    kini = datetime(2026, 10, 24, 12, tzinfo=timezone.utc)
    assert waktu.macet(kini - timedelta(hours=3), kini) and not waktu.macet(kini - timedelta(minutes=70), kini)


def test_saring_tanggal_wita_dan_urutan(c):
    # 23 Okt 15:30 UTC = 23 Okt 23.30 WITA ; 23 Okt 16:30 UTC = 24 Okt 00.30 WITA
    kirim(c, "cap_20261023_163000.hdr.pcap.gz", isi(1)); kirim(c, "cap_20261023_153000.hdr.pcap.gz", isi(2))
    masuk(c, "satria", "sandi-admin-123")
    html = c.get("/berkas?tanggal=2026-10-24").get_data(as_text=True)
    assert "cap_20261023_163000" in html and "cap_20261023_153000" not in html
    assert "24 Okt 2026, 00.30" in html
    html = c.get("/berkas").get_data(as_text=True)                                   # tampilan per hari
    assert html.index("24 Okt 2026") < html.index("23 Okt 2026")                     # hari terbaru dulu
    assert "cap_20261023_163000" not in html
    j = c.get("/api/v1/files", headers={"Authorization": "Bearer " + TOK_BACA_SEMUA}).get_json()
    assert j["items"][0]["recording_start"] == "2026-10-23T16:30:00Z"


# ------------------------------------------------------------------ statistik, per hari, gabung
import ipaddress  # noqa: E402
import struct     # noqa: E402

SERVER = "10.0.0.1"


def pcap_gz(paket):
    """paket = [(detik, src, dst, sport, dport, flags)] -> isi .pcap.gz (Ethernet/IPv4/TCP, header saja)."""
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
    for t, src, dst, sp, dp, fl in paket:
        l4 = struct.pack("!HHIIBBHHH", sp, dp, 1, 0, 5 << 4, fl, 64240, 0, 0)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, 6, 0,
                         ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
        d = b"\x00" * 12 + b"\x08\x00" + ip + l4
        out += struct.pack("<IIII", int(t), 0, len(d), len(d)) + d
    return gzip.compress(out)


def rekaman_scan(t0, penyerang="198.51.100.9", n=10):
    pk = []
    for i in range(n):
        pk.append((t0 + i, penyerang, SERVER, 50000, 1000 + i, 0x02))                  # SYN
        pk.append((t0 + i, SERVER, penyerang, 1000 + i, 50000, 0x14))                  # RST+ACK
    pk.append((t0 + 20, "203.0.113.7", SERVER, 40000, 22, 0x02))                        # 1 SYN ke SSH
    return pcap_gz(pk)


def test_statistik_dihitung_saat_unggah(c, app):
    N = "cap_20261024_020000.hdr.pcap.gz"           # 24 Okt 10.00 WITA
    assert kirim(c, N, rekaman_scan(1761271200), token=TOK_B).status_code == 201
    con = buka(app.config["DB_PATH"])
    s = con.execute("SELECT * FROM statistik").fetchone()
    assert s["galat"] is None and s["paket"] == 21
    assert (s["syn_masuk"], s["syn_ssh"], s["rst_keluar"], s["ip_luar"]) == (11, 1, 10, 2)
    # berkas bukan pcap tetap diterima; statistiknya mencatat galat
    assert kirim(c, N1, isi(), token=TOK_A).status_code == 201
    assert con.execute("SELECT galat FROM statistik WHERE paket IS NULL").fetchone()["galat"]


def test_beranda_per_hari_dan_grafik(c):
    kirim(c, "cap_20261024_020000.hdr.pcap.gz", rekaman_scan(1761271200), token=TOK_B)
    kirim(c, "cap_20261024_030000.hdr.pcap.gz", rekaman_scan(1761274800, "198.51.100.10"), token=TOK_B)
    masuk(c, "satria", "sandi-admin-123")
    assert c.get("/").headers["Location"].endswith("/deteksi")
    html = c.get("/rekaman").get_data(as_text=True)
    assert "Lalu lintas yang terekam" in html and "<svg" in html and "<title>" in html
    assert "24 Okt 2026" in html and "unduh 1 hari" in html
    html = c.get("/berkas").get_data(as_text=True)
    assert "2<span" in html                          # 2 jam terekam pada 24 Okt
    assert ">22<" in html                            # 11 + 11 percobaan koneksi


def test_unduh_harian_menggabung_pcap(c):
    from penerima.statistik import hitung
    kirim(c, "cap_20261024_020000.hdr.pcap.gz", rekaman_scan(1761271200), token=TOK_B)
    kirim(c, "cap_20261024_030000.hdr.pcap.gz", rekaman_scan(1761274800), token=TOK_B)
    kirim(c, "cap_20261025_030000.hdr.pcap.gz", rekaman_scan(1761361200), token=TOK_B)   # hari lain
    masuk(c, "satria", "sandi-admin-123")
    r = c.get("/hari/vps-satria/2026-10-24/unduh")
    assert r.status_code == 200 and "harian_vps-satria_2026-10-24" in r.headers["Content-Disposition"]
    data = gzip.decompress(r.get_data())
    assert data[:4] == b"\xd4\xc3\xb2\xa1" and data.count(b"\xd4\xc3\xb2\xa1") == 1      # satu header global
    p = os.path.join(os.path.dirname(c.application.config["DB_PATH"]), "gabung.pcap")
    open(p, "wb").write(data)
    assert hitung(p)["paket"] == 42                                                      # 2 x 21 paket
    assert c.get("/hari/vps-satria/2026-10-26/unduh").status_code == 404
    assert c.get("/hari/../2026-10-24/unduh").status_code == 404
    log = c.get("/audit").get_data(as_text=True)
    assert "UNDUH_HARIAN" in log


def test_viewer_tidak_bisa_unduh_hari_instalasi_lain(c):
    kirim(c, "cap_20261024_020000.hdr.pcap.gz", rekaman_scan(1761271200), token=TOK_B)  # vps-satria
    masuk(c, "paktut", "sandi-paktut-123")                                              # viewer bali-hai
    assert c.get("/hari/vps-satria/2026-10-24/unduh").status_code == 404


def test_kelola_ubah_instalasi(app, monkeypatch):
    import kelola
    c = app.test_client()
    kirim(c, "cap_20261024_020000.hdr.pcap.gz", rekaman_scan(1761271200), token=TOK_B)
    monkeypatch.setenv("PENERIMA_DATA_DIR", app.config["DATA_DIR"])
    monkeypatch.setattr(sys, "argv", ["kelola", "instalasi-ubah", "vps-satria", "--nama-baru", "hotdog-watersport",
                                      "--keterangan", "Server VPS PT Hotdog Water Sport"])
    kelola.main()
    berkas = app.config["BERKAS_DIR"]
    assert os.path.exists(os.path.join(berkas, "hotdog-watersport", "cap_20261024_020000.hdr.pcap.gz"))
    assert not os.path.exists(os.path.join(berkas, "vps-satria"))
    con = buka(app.config["DB_PATH"])
    assert con.execute("SELECT keterangan FROM instalasi WHERE nama = 'hotdog-watersport'").fetchone()[0] \
        == "Server VPS PT Hotdog Water Sport"
    # unggahan berikutnya dengan token lama tetap masuk ke instalasi yang sama (token terikat id, bukan nama)
    assert kirim(c, "cap_20261024_030000.hdr.pcap.gz", rekaman_scan(1761274800), token=TOK_B).status_code == 201
    assert os.path.exists(os.path.join(berkas, "hotdog-watersport", "cap_20261024_030000.hdr.pcap.gz"))
