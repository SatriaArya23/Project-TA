# -*- coding: utf-8 -*-
"""Token API, sesi login, CSRF, dan pembatasan percobaan login."""
import functools
import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta, timezone

from flask import abort, g, redirect, request, session, url_for

from .db import koneksi, sekarang

BATAS_GAGAL_LOGIN = 5          # per IP
JENDELA_GAGAL_MENIT = 15


def buat_token():
    return secrets.token_urlsafe(32)


def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def ip_klien():
    return request.remote_addr or "-"


def token_bearer(peran):
    """Kembalikan baris token yang valid untuk peran tertentu, atau None."""
    h = request.headers.get("Authorization", "")
    if not h.startswith("Bearer "):
        return None
    token = h[7:].strip()
    if not token or len(token) > 200:
        return None
    db = koneksi()
    baris = db.execute(
        "SELECT t.*, i.nama AS instalasi_nama, i.aktif AS instalasi_aktif "
        "FROM token t LEFT JOIN instalasi i ON i.id = t.instalasi_id "
        "WHERE t.hash = ? AND t.dicabut_utc IS NULL", (hash_token(token),)).fetchone()
    if baris is None or baris["peran"] != peran:
        return None
    if peran == "upload" and not baris["instalasi_aktif"]:
        return None
    db.execute("UPDATE token SET terakhir_dipakai_utc = ? WHERE id = ?", (sekarang(), baris["id"]))
    db.commit()
    return baris


# ------------------------------------------------------------------ sesi web
def sidik_sandi(hash_sandi):
    """Sidik pendek hash password yang disimpan di sesi: bila password diganti/di-reset, sesi lama
    (di perangkat lain) otomatis tidak berlaku lagi."""
    return hashlib.sha256(hash_sandi.encode("utf-8")).hexdigest()[:16]


BATAS_DIAM_DETIK = 30 * 60          # keluar otomatis setelah 30 menit tanpa aktivitas
BATAS_SESI_DETIK = 12 * 3600        # dan paling lama 12 jam sejak login, walau aktif terus


def kini_detik():
    return int(time.time())


def mulai_sesi(p):
    """Dipanggil saat login berhasil (setelah session.clear())."""
    t = kini_detik()
    session["uid"], session["sv"] = p["id"], sidik_sandi(p["hash_sandi"])
    session["masuk"] = session["aktif"] = t


def akhiri_sesi():
    """Keluarkan pengguna tanpa membuang token CSRF (formulir login yang sedang terbuka tetap sah)."""
    for k in ("uid", "sv", "masuk", "aktif"):
        session.pop(k, None)


def pengguna_aktif():
    uid = session.get("uid")
    if uid is None:
        return None
    if "pengguna" not in g:
        t = kini_detik()
        masuk, aktif = session.get("masuk"), session.get("aktif")
        if masuk is None or aktif is None or t - aktif > BATAS_DIAM_DETIK or t - masuk > BATAS_SESI_DETIK:
            akhiri_sesi()                          # sesi kedaluwarsa (atau sesi lama tanpa cap waktu)
            g.pengguna = None
            return None
        p = koneksi().execute("SELECT * FROM pengguna WHERE id = ? AND aktif = 1", (uid,)).fetchone()
        if p is not None and not hmac.compare_digest(session.get("sv", ""), sidik_sandi(p["hash_sandi"])):
            p = None
        if p is not None and t - aktif >= 60:
            session["aktif"] = t                   # perbarui cap aktivitas (paling sering tiap menit)
        g.pengguna = p
    return g.pengguna


def wajib_login(f):
    @functools.wraps(f)
    def bungkus(*a, **kw):
        p = pengguna_aktif()
        if p is None:
            return redirect(url_for("web.login", lanjut=request.path))
        if p["wajib_ganti_sandi"] and request.endpoint != "web.akun":
            return redirect(url_for("web.akun"))          # password sementara: ganti dulu
        return f(*a, **kw)
    return bungkus


# ------------------------------------------------------------------ peran & hak akses
PERAN = {"admin": "Administrator", "analis": "Analis", "viewer": "Pemantau"}
KET_PERAN = {
    "admin": "atasan: semua akses, termasuk kelola pengguna dan keputusan umpan balik",
    "analis": "bawahan: melihat semua data, melaporkan serangan lolos / alarm palsu dan periksa ulang",
    "viewer": "baca-saja: hanya melihat",
}
HAK = {
    "lapor": ("admin", "analis"),           # kirim umpan balik, periksa ulang
    "putuskan": ("admin",),                 # tandai laporan selesai, unduh kasus pelatihan ulang
    "kelola_pengguna": ("admin",),
    "kelola_tepercaya": ("admin",),         # daftar IP tepercaya (memengaruhi deteksi)
    "kelola_blokir": ("admin",),            # blokir / buka blokir IP manual di firewall
}


def boleh(hak):
    p = pengguna_aktif()
    return p is not None and p["peran"] in HAK[hak]


def wajib_hak(hak, pesan="Akun Anda tidak memiliki izin untuk tindakan ini."):
    if not boleh(hak):
        abort(403, pesan)


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def cek_csrf():
    dikirim = request.form.get("csrf", "")
    if not dikirim or not hmac.compare_digest(dikirim, session.get("csrf", "")):
        abort(400, "Token formulir tidak valid. Muat ulang halaman lalu coba lagi.")


# ------------------------------------------------------------------ batas login
def login_diblokir(ip):
    batas = (datetime.now(timezone.utc) - timedelta(minutes=JENDELA_GAGAL_MENIT)).strftime("%Y-%m-%dT%H:%M:%SZ")
    db = koneksi()
    db.execute("DELETE FROM gagal_login WHERE waktu_utc < ?", (batas,))
    n = db.execute("SELECT COUNT(*) FROM gagal_login WHERE ip = ?", (ip,)).fetchone()[0]
    db.commit()
    return n >= BATAS_GAGAL_LOGIN


def catat_gagal_login(ip):
    db = koneksi()
    db.execute("INSERT INTO gagal_login (ip, waktu_utc) VALUES (?, ?)", (ip, sekarang()))
    db.commit()
