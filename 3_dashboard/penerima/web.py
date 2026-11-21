# -*- coding: utf-8 -*-
"""Dashboard web: login, rekaman lalu lintas (per hari / per jam), unduhan, catatan audit. Halaman utama = /deteksi."""
import os
import re
import secrets
from urllib.parse import urlsplit

from flask import (Blueprint, Response, abort, current_app, redirect, render_template, request, send_file,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from . import harian, statistik, waktu
from .api import ringkasan
from .db import catat_audit, koneksi, sekarang
from .keamanan import (KET_PERAN, PERAN, boleh, catat_gagal_login, cek_csrf, csrf_token, ip_klien, login_diblokir,
                       mulai_sesi, pengguna_aktif, sidik_sandi, wajib_hak, wajib_login)

bp = Blueprint("web", __name__)
PER_HALAMAN = 50
# Hash palsu agar waktu respons sama, baik username ada maupun tidak.
HASH_PALSU = "scrypt:32768:8:1$AAAAAAAAAAAAAAAA$" + "0" * 128


@bp.app_context_processor
def isi_template():
    return {"pengguna": pengguna_aktif(), "csrf_token": csrf_token, "nama_peran": PERAN,
            "boleh_kelola_pengguna": boleh("kelola_pengguna")}


@bp.app_template_filter("wita")
def filter_wita(iso_utc):
    return waktu.teks_wita(waktu.dari_iso(iso_utc))


@bp.app_template_filter("direkam")
def filter_direkam(nama):
    return waktu.teks_wita(waktu.mulai_rekam(nama))


@bp.app_template_filter("lalu")
def filter_lalu(iso_utc):
    return waktu.teks_lalu(waktu.dari_iso(iso_utc))


@bp.app_template_filter("macet")
def filter_macet(iso_utc):
    return waktu.macet(waktu.dari_iso(iso_utc))


@bp.app_template_filter("tanggal")
def filter_tanggal(t):
    return harian.teks_tanggal(t)


@bp.app_template_filter("angka")
def filter_angka(n):
    return "{:,}".format(int(n or 0)).replace(",", ".")


@bp.app_template_filter("ukuran")
def ukuran(n):
    n = float(n or 0)
    for s in ("B", "KB", "MB", "GB"):
        if n < 1024 or s == "GB":
            return ("%.0f %s" if s == "B" else "%.1f %s") % (n, s)
        n /= 1024


def lingkup():
    """instalasi_id yang boleh dilihat pengguna (None = semua)."""
    p = pengguna_aktif()
    return None if p["peran"] == "admin" else p["instalasi_id"]


def halaman():
    try:
        return max(1, int(request.args.get("hal", 1)))
    except ValueError:
        return 1


# ----------------------------------------------------------------------- login
@bp.route("/login", methods=["GET", "POST"])
def login():
    pesan = None
    if request.method == "POST":
        cek_csrf()
        ip = ip_klien()
        username = request.form.get("username", "").strip()[:64]
        if login_diblokir(ip):
            pesan = "Terlalu banyak percobaan gagal. Coba lagi 15 menit lagi."
            catat_audit("LOGIN_DIBLOKIR", aktor=username, ip=ip, kode=429)
        else:
            p = koneksi().execute("SELECT * FROM pengguna WHERE username = ? AND aktif = 1", (username,)).fetchone()
            ok = check_password_hash(p["hash_sandi"] if p else HASH_PALSU, request.form.get("password", ""))
            if p and ok:
                session.clear()
                session.permanent = False       # cookie sesi browser; batas 30 menit diam / 12 jam dicek di server
                mulai_sesi(p)
                koneksi().execute("UPDATE pengguna SET login_terakhir_utc = ? WHERE id = ?", (sekarang(), p["id"]))
                catat_audit("LOGIN_OK", aktor=username, ip=ip, kode=200)
                lanjut = request.args.get("lanjut", "")
                aman = lanjut.startswith("/") and not lanjut.startswith("//") and not urlsplit(lanjut).netloc
                return redirect(lanjut if aman else url_for("deteksi.ringkasan"))
            catat_gagal_login(ip)
            catat_audit("LOGIN_GAGAL", aktor=username, ip=ip, kode=401)
            pesan = "Username atau password salah."
    return render_template("login.html", pesan=pesan), (401 if pesan else 200)


@bp.post("/logout")
def logout():
    cek_csrf()
    session.clear()
    return redirect(url_for("web.login"))


# ----------------------------------------------------------------------- halaman
@bp.get("/")
@wajib_login
def akar():
    return redirect(url_for("deteksi.ringkasan"))


@bp.get("/rekaman")
@wajib_login
def beranda():
    lingk = lingkup()
    rows = harian.baris(koneksi(), lingk)
    hari = harian.per_hari(rows)
    return render_template("beranda.html", ringkasan=[r for r in ringkasan(lingk) if r["aktif"] or r["jumlah"]],
                           hari=hari[:7], total=harian.total(hari), g_hari=harian.grafik_harian(hari),
                           g_jam=harian.grafik_per_jam(rows))


@bp.get("/berkas")
@wajib_login
def berkas():
    """Tanpa ?tanggal: satu baris per hari. Dengan ?tanggal=YYYY-MM-DD: berkas per jam hari itu."""
    lingk, hal = lingkup(), halaman()
    db = koneksi()
    if not request.args.get("tanggal"):
        hari = harian.per_hari(harian.baris(db, lingk, request.args.get("instalasi") if lingk is None else None))
        semua_inst = db.execute("SELECT nama FROM instalasi ORDER BY nama").fetchall() if lingk is None else []
        return render_template("hari.html", hari=hari, total=harian.total(hari), semua_inst=semua_inst)
    syarat, nilai = [], []
    if lingk is not None:
        syarat.append("b.instalasi_id = ?"); nilai.append(lingk)
    elif request.args.get("instalasi"):
        syarat.append("i.nama = ?"); nilai.append(request.args["instalasi"])
    rentang = waktu.rentang_nama_untuk_tanggal_wita(request.args.get("tanggal"))
    if rentang:                                   # tanggal WITA -> rentang nama berkas (UTC)
        syarat.append("b.nama >= ? AND b.nama < ?"); nilai.extend(rentang)
    where = (" WHERE " + " AND ".join(syarat)) if syarat else ""
    dasar = (" FROM berkas b JOIN instalasi i ON i.id = b.instalasi_id"
             " LEFT JOIN statistik s ON s.berkas_id = b.id" + where)
    total = db.execute("SELECT COUNT(*)" + dasar, nilai).fetchone()[0]
    rows = db.execute("SELECT b.*, i.nama AS instalasi, s.paket, s.syn_masuk, s.ip_luar" + dasar +
                      " ORDER BY b.nama DESC, b.id DESC LIMIT ? OFFSET ?",
                      nilai + [PER_HALAMAN, (hal - 1) * PER_HALAMAN]).fetchall()
    semua_inst = db.execute("SELECT nama FROM instalasi ORDER BY nama").fetchall() if lingk is None else []
    pilih_inst = rows[0]["instalasi"] if rows else request.args.get("instalasi")
    return render_template("berkas.html", rows=rows, total=total, hal=hal, per=PER_HALAMAN, semua_inst=semua_inst,
                           tanggal=request.args.get("tanggal"), pilih_inst=pilih_inst)


@bp.get("/berkas/<int:berkas_id>/unduh")
@wajib_login
def unduh(berkas_id):
    lingk = lingkup()
    r = koneksi().execute("SELECT b.*, i.nama AS instalasi FROM berkas b JOIN instalasi i ON i.id = b.instalasi_id "
                          "WHERE b.id = ?", (berkas_id,)).fetchone()
    if r is None or (lingk is not None and r["instalasi_id"] != lingk):
        abort(404)
    catat_audit("UNDUH", instalasi=r["instalasi"], aktor=pengguna_aktif()["username"], ip=ip_klien(),
                nama=r["nama"], ukuran=r["ukuran"], sha=r["sha256"], kode=200, ket="lewat dashboard")
    return send_file(os.path.join(current_app.config["BERKAS_DIR"], r["instalasi"], r["nama"]),
                     mimetype="application/gzip", as_attachment=True, download_name=r["nama"])


@bp.get("/hari/<instalasi>/<tanggal>/unduh")
@wajib_login
def unduh_hari(instalasi, tanggal):
    """Semua rekaman per jam pada satu tanggal WITA, digabung menjadi satu berkas pcap.gz."""
    lingk = lingkup()
    db = koneksi()
    inst = db.execute("SELECT * FROM instalasi WHERE nama = ?", (instalasi,)).fetchone()
    rentang = waktu.rentang_nama_untuk_tanggal_wita(tanggal)
    if inst is None or rentang is None or (lingk is not None and inst["id"] != lingk):
        abort(404)
    rows = db.execute("SELECT nama, ukuran FROM berkas WHERE instalasi_id = ? AND nama >= ? AND nama < ? "
                      "ORDER BY nama", (inst["id"],) + tuple(rentang)).fetchall()
    if not rows:
        abort(404)
    nama = "harian_%s_%s.hdr.pcap.gz" % (instalasi, tanggal)
    folder = os.path.join(current_app.config["BERKAS_DIR"], instalasi)
    catat_audit("UNDUH_HARIAN", instalasi=instalasi, aktor=pengguna_aktif()["username"], ip=ip_klien(), nama=nama,
                ukuran=sum(r["ukuran"] for r in rows), kode=200,
                ket="%d berkas per jam digabung (%s s.d. %s)" % (len(rows), rows[0]["nama"], rows[-1]["nama"]))
    return Response(statistik.gabung_gzip([os.path.join(folder, r["nama"]) for r in rows]),
                    mimetype="application/gzip",
                    headers={"Content-Disposition": 'attachment; filename="%s"' % nama})


@bp.get("/audit")
@wajib_login
def audit():
    lingk, hal = lingkup(), halaman()
    db = koneksi()
    if lingk is not None:
        nama_inst = db.execute("SELECT nama FROM instalasi WHERE id = ?", (lingk,)).fetchone()["nama"]
        where, nilai = " WHERE instalasi = ?", [nama_inst]
    else:
        where, nilai = "", []
    total = db.execute("SELECT COUNT(*) FROM audit" + where, nilai).fetchone()[0]
    rows = db.execute("SELECT * FROM audit" + where + " ORDER BY id DESC LIMIT ? OFFSET ?",
                      nilai + [PER_HALAMAN, (hal - 1) * PER_HALAMAN]).fetchall()
    return render_template("audit.html", rows=rows, total=total, hal=hal, per=PER_HALAMAN)


# ----------------------------------------------------------------------- akun & pengguna
POLA_USERNAME = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")
MIN_SANDI = 10


def sandi_sementara():
    return secrets.token_urlsafe(9)          # 12 karakter acak; wajib diganti saat pertama masuk


def cek_sandi_baru(p, baru, ulang):
    if len(baru) < MIN_SANDI:
        return "Password baru minimal %d karakter." % MIN_SANDI
    if baru != ulang:
        return "Ulangi password tidak sama."
    if baru.lower() == p["username"].lower():
        return "Password tidak boleh sama dengan username."
    if check_password_hash(p["hash_sandi"], baru):
        return "Password baru harus berbeda dari password sekarang."
    return None


@bp.route("/akun", methods=["GET", "POST"])
@wajib_login
def akun():
    """Akun sendiri: ganti password (wajib bila masih memakai password sementara dari administrator)."""
    p = pengguna_aktif()
    pesan = ok = None
    if request.method == "POST":
        cek_csrf()
        f = request.form
        if not check_password_hash(p["hash_sandi"], f.get("sandi_lama", "")):
            pesan = "Password sekarang salah."
        else:
            pesan = cek_sandi_baru(p, f.get("sandi_baru", ""), f.get("ulang", ""))
        if pesan is None:
            h = generate_password_hash(f["sandi_baru"])
            db = koneksi()
            db.execute("UPDATE pengguna SET hash_sandi = ?, wajib_ganti_sandi = 0 WHERE id = ?", (h, p["id"]))
            db.commit()
            session["sv"] = sidik_sandi(h)                 # sesi ini tetap masuk, sesi lain keluar
            catat_audit("GANTI_SANDI", aktor=p["username"], ip=ip_klien(), kode=200)
            if p["wajib_ganti_sandi"]:
                return redirect(url_for("deteksi.ringkasan"))
            ok = "Password berhasil diganti. Sesi di perangkat lain otomatis keluar."
            p = db.execute("SELECT * FROM pengguna WHERE id = ?", (p["id"],)).fetchone()
    return (render_template("akun.html", p=p, pesan=pesan, ok=ok, min_sandi=MIN_SANDI, ket_peran=KET_PERAN),
            400 if pesan else 200)


def daftar_pengguna():
    return koneksi().execute("SELECT * FROM pengguna ORDER BY aktif DESC, CASE peran WHEN 'admin' THEN 0 "
                             "WHEN 'analis' THEN 1 ELSE 2 END, username").fetchall()


def tampil_pengguna(pesan=None, baru=None, kode=200, isi=None):
    return render_template("pengguna.html", rows=daftar_pengguna(), pesan=pesan, baru=baru, isi=isi or {},
                           ket_peran=KET_PERAN), kode


@bp.route("/pengguna", methods=["GET", "POST"])
@wajib_login
def pengguna():
    """Khusus administrator: tambah akun bawahan (analis / pemantau) atau administrator lain."""
    wajib_hak("kelola_pengguna", "Hanya administrator yang dapat mengelola pengguna.")
    if request.method == "GET":
        return tampil_pengguna()
    cek_csrf()
    f = request.form
    isi = {"username": f.get("username", "").strip().lower()[:32], "nama": f.get("nama", "").strip()[:80],
           "peran": f.get("peran", "")}
    if not POLA_USERNAME.match(isi["username"]):
        return tampil_pengguna("Username 3–32 karakter: huruf kecil, angka, titik, garis bawah, atau tanda hubung.",
                               kode=400, isi=isi)
    if isi["peran"] not in PERAN:
        return tampil_pengguna("Pilih peran.", kode=400, isi=isi)
    db = koneksi()
    if db.execute("SELECT 1 FROM pengguna WHERE username = ?", (isi["username"],)).fetchone():
        return tampil_pengguna("Username '%s' sudah dipakai." % isi["username"], kode=400, isi=isi)
    sandi = sandi_sementara()
    admin = pengguna_aktif()["username"]
    db.execute("INSERT INTO pengguna (username, hash_sandi, peran, dibuat_utc, nama, dibuat_oleh, wajib_ganti_sandi) "
               "VALUES (?, ?, ?, ?, ?, ?, 1)", (isi["username"], generate_password_hash(sandi), isi["peran"],
                                                 sekarang(), isi["nama"] or None, admin))
    db.commit()
    catat_audit("PENGGUNA_TAMBAH", aktor=admin, ip=ip_klien(), kode=200,
                ket="%s (peran: %s)" % (isi["username"], isi["peran"]))
    return tampil_pengguna(baru={"username": isi["username"], "sandi": sandi, "aksi": "dibuat"})


@bp.post("/pengguna/<int:uid>")
@wajib_login
def ubah_pengguna(uid):
    wajib_hak("kelola_pengguna", "Hanya administrator yang dapat mengelola pengguna.")
    cek_csrf()
    saya = pengguna_aktif()
    db = koneksi()
    r = db.execute("SELECT * FROM pengguna WHERE id = ?", (uid,)).fetchone()
    if r is None:
        abort(404)
    if r["id"] == saya["id"]:
        # mencegah administrator mengunci dirinya sendiri (dan menghilangkan admin terakhir)
        return tampil_pengguna("Akun Anda sendiri tidak dapat diubah dari sini; ganti password lewat halaman Akun.",
                               kode=400)
    aksi = request.form.get("aksi")
    baru = None
    if aksi == "peran" and request.form.get("peran") in PERAN:
        db.execute("UPDATE pengguna SET peran = ? WHERE id = ?", (request.form["peran"], uid))
        ket = "%s -> peran %s" % (r["username"], request.form["peran"])
    elif aksi in ("nonaktif", "aktif"):
        db.execute("UPDATE pengguna SET aktif = ? WHERE id = ?", (1 if aksi == "aktif" else 0, uid))
        ket = "%s -> %s" % (r["username"], "diaktifkan" if aksi == "aktif" else "dinonaktifkan")
    elif aksi == "reset":
        sandi = sandi_sementara()
        db.execute("UPDATE pengguna SET hash_sandi = ?, wajib_ganti_sandi = 1 WHERE id = ?",
                   (generate_password_hash(sandi), uid))
        ket = "%s -> password di-reset" % r["username"]
        baru = {"username": r["username"], "sandi": sandi, "aksi": "di-reset"}
    else:
        abort(400, "Tindakan tidak dikenal.")
    db.commit()
    catat_audit("PENGGUNA_UBAH", aktor=saya["username"], ip=ip_klien(), kode=200, ket=ket)
    if baru:
        return tampil_pengguna(baru=baru)
    return redirect(url_for("web.pengguna"))
