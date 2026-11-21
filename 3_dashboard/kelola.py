# -*- coding: utf-8 -*-
"""Alat kelola server penerima: instalasi, token, pengguna dashboard.

Di server dijalankan lewat pembungkus:  sudo tanids-kelola <perintah> ...
"""
import argparse
import getpass
import os
import re
import secrets
import sys

from werkzeug.security import generate_password_hash

from penerima.db import buka, inisialisasi, sekarang
from penerima.keamanan import buat_token, hash_token

POLA_INSTALASI = re.compile(r"^[a-z0-9][a-z0-9-]{1,40}$")


def db():
    data = os.environ.get("PENERIMA_DATA_DIR", "/var/lib/ta-nids-server")
    path = os.path.join(data, "penerima.db")
    inisialisasi(path)
    return buka(path)


def cari_instalasi(con, nama):
    r = con.execute("SELECT * FROM instalasi WHERE nama = ?", (nama,)).fetchone()
    if r is None:
        sys.exit("Instalasi '%s' tidak ada. Lihat: instalasi-daftar" % nama)
    return r


def info(a, *teks):
    """Pesan informasi; ke stderr bila rahasia dikirim ke stdout (--keluar -)."""
    print(*teks, file=sys.stderr if getattr(a, "keluar", None) == "-" else sys.stdout)


def tulis_rahasia(path, isi):
    if path == "-":
        sys.stdout.write(isi + "\n")
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(isi + "\n")


# ------------------------------------------------------------------ instalasi
def instalasi_tambah(a):
    if not POLA_INSTALASI.match(a.nama):
        sys.exit("Nama instalasi hanya huruf kecil, angka, dan '-' (2-41 karakter).")
    con = db()
    con.execute("INSERT INTO instalasi (nama, keterangan, dibuat_utc) VALUES (?, ?, ?)",
                (a.nama, a.keterangan, sekarang()))
    con.commit()
    print("Instalasi '%s' ditambahkan." % a.nama)


def instalasi_daftar(_):
    for r in db().execute("SELECT i.*, (SELECT COUNT(*) FROM berkas b WHERE b.instalasi_id = i.id) AS n "
                          "FROM instalasi i ORDER BY i.id"):
        print("%-3d %-24s %-9s %5d berkas  %s" % (r["id"], r["nama"], "aktif" if r["aktif"] else "NONAKTIF",
                                                 r["n"], r["keterangan"] or ""))


def instalasi_ubah(a):
    """Ganti nama dan/atau keterangan instalasi. Folder berkasnya ikut dipindah."""
    con = db()
    r = cari_instalasi(con, a.nama)
    baru = a.nama_baru or a.nama
    if not POLA_INSTALASI.match(baru):
        sys.exit("Nama instalasi hanya huruf kecil, angka, dan '-' (2-41 karakter).")
    if baru != a.nama and con.execute("SELECT 1 FROM instalasi WHERE nama = ?", (baru,)).fetchone():
        sys.exit("Nama '%s' sudah dipakai." % baru)
    folder = os.path.join(os.environ.get("PENERIMA_DATA_DIR", "/var/lib/ta-nids-server"), "berkas")
    lama_dir, baru_dir = os.path.join(folder, a.nama), os.path.join(folder, baru)
    if baru != a.nama and os.path.exists(baru_dir):
        sys.exit("Folder %s sudah ada." % baru_dir)
    ket = a.keterangan if a.keterangan is not None else r["keterangan"]
    con.execute("UPDATE instalasi SET nama = ?, keterangan = ? WHERE id = ?", (baru, ket, r["id"]))
    if baru != a.nama and os.path.isdir(lama_dir):      # catatan audit lama sengaja tidak diubah
        os.rename(lama_dir, baru_dir)
    con.execute("INSERT INTO audit (waktu_utc, jenis, instalasi, aktor, keterangan) VALUES (?, ?, ?, ?, ?)",
                (sekarang(), "INSTALASI_DIUBAH", baru, "tanids-kelola",
                 "nama: %s -> %s; keterangan: %s" % (a.nama, baru, ket)))
    con.commit()
    print("Instalasi '%s' -> '%s' (keterangan: %s)." % (a.nama, baru, ket))


def statistik_hitung(a):
    """Hitung statistik isi rekaman untuk berkas yang belum punya (atau semua dengan --ulang)."""
    from penerima import statistik
    con = db()
    folder = os.path.join(os.environ.get("PENERIMA_DATA_DIR", "/var/lib/ta-nids-server"), "berkas")
    syarat = "" if a.ulang else " WHERE s.berkas_id IS NULL OR s.galat IS NOT NULL"
    rows = con.execute("SELECT b.id, b.nama, i.nama AS inst FROM berkas b JOIN instalasi i ON i.id = b.instalasi_id "
                       "LEFT JOIN statistik s ON s.berkas_id = b.id" + syarat + " ORDER BY b.nama").fetchall()
    galat = 0
    for k, r in enumerate(rows, 1):
        if statistik.simpan(con, r["id"], os.path.join(folder, r["inst"], r["nama"])):
            galat += 1
        if k % 25 == 0 or k == len(rows):
            print("  %d/%d berkas" % (k, len(rows)))
    print("Statistik dihitung untuk %d berkas (%d gagal)." % (len(rows), galat))


def instalasi_status(a, aktif):
    con = db()
    cari_instalasi(con, a.nama)
    con.execute("UPDATE instalasi SET aktif = ? WHERE nama = ?", (aktif, a.nama))
    con.commit()
    print("Instalasi '%s' %s." % (a.nama, "diaktifkan" if aktif else "dinonaktifkan (unggahan ditolak)"))


# ------------------------------------------------------------------ token
def token_buat(a):
    con = db()
    inst_id = cari_instalasi(con, a.instalasi)["id"] if a.instalasi else None
    if a.peran == "upload" and inst_id is None:
        sys.exit("Token upload wajib terikat ke satu instalasi (--instalasi).")
    token = buat_token()
    if a.keluar:
        tulis_rahasia(a.keluar, token)
    con.execute("INSERT INTO token (hash, peran, instalasi_id, label, dibuat_utc) VALUES (?, ?, ?, ?, ?)",
                (hash_token(token), a.peran, inst_id, a.label, sekarang()))
    con.commit()
    info(a, "Token %s dibuat (label: %s, instalasi: %s)." % (a.peran, a.label, a.instalasi or "SEMUA"))
    if not a.keluar:
        info(a, "\n  %s\n\nSimpan sekarang: token ini tidak dapat ditampilkan lagi." % token)
    elif a.keluar != "-":
        info(a, "Token disimpan di %s (izin 600). Server hanya menyimpan hash-nya." % a.keluar)


def token_daftar(_):
    print("%-3s %-7s %-20s %-22s %-21s %-21s %s" % ("id", "peran", "instalasi", "label", "dibuat", "terakhir dipakai",
                                                   "status"))
    for r in db().execute("SELECT t.*, i.nama AS inst FROM token t LEFT JOIN instalasi i ON i.id = t.instalasi_id "
                          "ORDER BY t.id"):
        print("%-3d %-7s %-20s %-22s %-21s %-21s %s" % (
            r["id"], r["peran"], r["inst"] or "SEMUA", r["label"][:22], r["dibuat_utc"],
            r["terakhir_dipakai_utc"] or "-", "DICABUT " + r["dicabut_utc"] if r["dicabut_utc"] else "aktif"))


def token_cabut(a):
    con = db()
    n = con.execute("UPDATE token SET dicabut_utc = ? WHERE id = ? AND dicabut_utc IS NULL",
                    (sekarang(), a.id)).rowcount
    con.commit()
    print("Token %d dicabut." % a.id if n else "Token %d tidak ada atau sudah dicabut." % a.id)


# ------------------------------------------------------------------ pengguna
def pengguna_tambah(a):
    con = db()
    inst_id = cari_instalasi(con, a.instalasi)["id"] if a.instalasi else None
    if a.sandi_acak:
        sandi = secrets.token_urlsafe(12)
    else:
        sandi = getpass.getpass("Password baru: ")
        if len(sandi) < 10:
            sys.exit("Password minimal 10 karakter.")
        if sandi != getpass.getpass("Ulangi password: "):
            sys.exit("Password tidak sama.")
    ada = con.execute("SELECT id FROM pengguna WHERE username = ?", (a.username,)).fetchone()
    if ada:
        con.execute("UPDATE pengguna SET hash_sandi = ?, peran = ?, instalasi_id = ?, aktif = 1 WHERE id = ?",
                    (generate_password_hash(sandi), a.peran, inst_id, ada["id"]))
        aksi = "diperbarui"
    else:
        con.execute("INSERT INTO pengguna (username, hash_sandi, peran, instalasi_id, dibuat_utc) VALUES (?,?,?,?,?)",
                    (a.username, generate_password_hash(sandi), a.peran, inst_id, sekarang()))
        aksi = "ditambahkan"
    con.commit()
    info(a, "Pengguna '%s' %s (peran: %s, instalasi: %s)." % (a.username, aksi, a.peran, a.instalasi or "SEMUA"))
    if a.sandi_acak:
        if a.keluar:
            tulis_rahasia(a.keluar, "username: %s\npassword: %s" % (a.username, sandi))
            if a.keluar != "-":
                info(a, "Kredensial disimpan di %s (izin 600)." % a.keluar)
        else:
            info(a, "\n  password: %s\n" % sandi)


def pengguna_daftar(_):
    for r in db().execute("SELECT p.*, i.nama AS inst FROM pengguna p LEFT JOIN instalasi i ON i.id = p.instalasi_id "
                          "ORDER BY p.id"):
        print("%-3d %-20s %-7s %-20s %s" % (r["id"], r["username"], r["peran"], r["inst"] or "SEMUA",
                                           "aktif" if r["aktif"] else "NONAKTIF"))


def pengguna_nonaktif(a):
    con = db()
    n = con.execute("UPDATE pengguna SET aktif = 0 WHERE username = ?", (a.username,)).rowcount
    con.commit()
    print("Pengguna '%s' dinonaktifkan." % a.username if n else "Pengguna tidak ada.")


def main():
    p = argparse.ArgumentParser(prog="tanids-kelola", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="perintah", required=True)

    s = sub.add_parser("instalasi-tambah", help="daftarkan server pengirim baru")
    s.add_argument("nama"); s.add_argument("--keterangan", default="")
    s.set_defaults(f=instalasi_tambah)
    sub.add_parser("instalasi-daftar").set_defaults(f=instalasi_daftar)
    s = sub.add_parser("instalasi-nonaktif"); s.add_argument("nama")
    s.set_defaults(f=lambda a: instalasi_status(a, 0))
    s = sub.add_parser("instalasi-aktif"); s.add_argument("nama")
    s.set_defaults(f=lambda a: instalasi_status(a, 1))
    s = sub.add_parser("instalasi-ubah", help="ganti nama dan/atau keterangan instalasi")
    s.add_argument("nama"); s.add_argument("--nama-baru"); s.add_argument("--keterangan")
    s.set_defaults(f=instalasi_ubah)
    s = sub.add_parser("statistik-hitung", help="hitung statistik isi rekaman (untuk dashboard)")
    s.add_argument("--ulang", action="store_true", help="hitung ulang semua berkas")
    s.set_defaults(f=statistik_hitung)

    s = sub.add_parser("token-buat", help="buat token upload (pengirim) atau read (akses baca API)")
    s.add_argument("--peran", choices=["upload", "read"], required=True)
    s.add_argument("--instalasi", help="wajib untuk upload; untuk read membatasi ke satu instalasi")
    s.add_argument("--label", required=True)
    s.add_argument("--keluar", help="tulis token ke berkas ini (izin 600); '-' = hanya token ke stdout")
    s.set_defaults(f=token_buat)
    sub.add_parser("token-daftar").set_defaults(f=token_daftar)
    s = sub.add_parser("token-cabut"); s.add_argument("id", type=int); s.set_defaults(f=token_cabut)

    s = sub.add_parser("pengguna-tambah", help="tambah/ubah akun dashboard")
    s.add_argument("username"); s.add_argument("--peran", choices=["admin", "analis", "viewer"], default="viewer")
    s.add_argument("--instalasi", help="batasi viewer ke satu instalasi")
    s.add_argument("--sandi-acak", action="store_true", help="buat password acak")
    s.add_argument("--keluar", help="dengan --sandi-acak: tulis kredensial ke berkas (izin 600)")
    s.set_defaults(f=pengguna_tambah)
    sub.add_parser("pengguna-daftar").set_defaults(f=pengguna_daftar)
    s = sub.add_parser("pengguna-nonaktif"); s.add_argument("username"); s.set_defaults(f=pengguna_nonaktif)

    a = p.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
