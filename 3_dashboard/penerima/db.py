# -*- coding: utf-8 -*-
"""Basis data SQLite: instalasi, token, pengguna, berkas diterima, catatan audit, dan umpan balik deteksi."""
import sqlite3
from datetime import datetime, timezone

from flask import current_app, g

SKEMA = """
CREATE TABLE IF NOT EXISTS instalasi (
    id          INTEGER PRIMARY KEY,
    nama        TEXT UNIQUE NOT NULL,
    keterangan  TEXT,
    dibuat_utc  TEXT NOT NULL,
    aktif       INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS token (
    id                   INTEGER PRIMARY KEY,
    hash                 TEXT UNIQUE NOT NULL,
    peran                TEXT NOT NULL CHECK (peran IN ('upload', 'read')),
    instalasi_id         INTEGER REFERENCES instalasi(id),
    label                TEXT NOT NULL,
    dibuat_utc           TEXT NOT NULL,
    dicabut_utc          TEXT,
    terakhir_dipakai_utc TEXT
);
CREATE TABLE IF NOT EXISTS pengguna (
    id          INTEGER PRIMARY KEY,
    username    TEXT UNIQUE NOT NULL,
    hash_sandi  TEXT NOT NULL,
    -- admin = atasan: kelola pengguna dan keputusan umpan balik
    -- analis = bawahan yang boleh melapor umpan balik, viewer = pemantau baca-saja
    peran       TEXT NOT NULL CHECK (peran IN ('admin', 'analis', 'viewer')),
    instalasi_id INTEGER REFERENCES instalasi(id),
    dibuat_utc  TEXT NOT NULL,
    aktif       INTEGER NOT NULL DEFAULT 1,
    nama        TEXT,                         -- nama lengkap (opsional)
    dibuat_oleh TEXT,                         -- username admin pembuat; NULL = lewat tanids-kelola
    wajib_ganti_sandi INTEGER NOT NULL DEFAULT 0,   -- 1 = password sementara, harus diganti saat masuk
    login_terakhir_utc TEXT
);
CREATE TABLE IF NOT EXISTS berkas (
    id            INTEGER PRIMARY KEY,
    instalasi_id  INTEGER NOT NULL REFERENCES instalasi(id),
    nama          TEXT NOT NULL,
    ukuran        INTEGER NOT NULL,
    sha256        TEXT NOT NULL,
    diterima_utc  TEXT NOT NULL,
    ip_pengirim   TEXT,
    UNIQUE (instalasi_id, nama)
);
CREATE TABLE IF NOT EXISTS audit (
    id           INTEGER PRIMARY KEY,
    waktu_utc    TEXT NOT NULL,
    jenis        TEXT NOT NULL,
    instalasi    TEXT,
    aktor        TEXT,
    ip           TEXT,
    nama_berkas  TEXT,
    ukuran       INTEGER,
    sha256       TEXT,
    kode_http    INTEGER,
    keterangan   TEXT
);
CREATE TABLE IF NOT EXISTS gagal_login (
    ip         TEXT NOT NULL,
    waktu_utc  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS statistik (
    berkas_id     INTEGER PRIMARY KEY REFERENCES berkas(id) ON DELETE CASCADE,
    paket         INTEGER,
    syn_masuk     INTEGER,      -- percobaan koneksi TCP baru dari luar ke server
    syn_ssh       INTEGER,      -- ... yang menuju port 22
    rst_keluar    INTEGER,      -- paket RST dari server (koneksi ditolak / port tertutup)
    ip_luar       INTEGER,      -- jumlah IP luar berbeda yang mengirim ke server
    ip_luar_json  TEXT,
    port_json     TEXT,         -- [[port, jumlah], ...] port tujuan koneksi baru terbanyak
    dihitung_utc  TEXT NOT NULL,
    galat         TEXT
);
CREATE TABLE IF NOT EXISTS umpan_balik (
    id              INTEGER PRIMARY KEY,
    dibuat_utc      TEXT NOT NULL,
    pelapor         TEXT NOT NULL,
    jenis           TEXT NOT NULL CHECK (jenis IN ('lolos', 'palsu')),   -- serangan lolos / alarm palsu
    src_ip          TEXT NOT NULL,
    mulai_us        INTEGER NOT NULL,     -- rentang waktu kejadian (mikrodetik UTC)
    akhir_us        INTEGER NOT NULL,
    keterangan      TEXT,
    status          TEXT NOT NULL,        -- baru / sudah_terdeteksi / terdeteksi_penyesuaian / pelatihan_ulang / selesai ...
    hasil_json      TEXT,                 -- hasil periksa ulang di modul deteksi (nids.umpan_balik)
    diperiksa_utc   TEXT,
    selesai_utc     TEXT,
    catatan_selesai TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_waktu  ON audit (waktu_utc);
CREATE INDEX IF NOT EXISTS idx_berkas_waktu ON berkas (diterima_utc);
"""


def sekarang():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def buka(path):
    con = sqlite3.connect(path, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    con.execute("PRAGMA busy_timeout = 10000")
    return con


def inisialisasi(path):
    con = buka(path)
    con.execute("PRAGMA journal_mode = WAL")
    con.executescript(SKEMA)
    con.commit()
    migrasi_pengguna(con)
    con.close()


def migrasi_pengguna(con):
    """Basis data lama: tabel pengguna hanya mengenal peran admin/viewer dan belum punya kolom baru.
    SQLite tidak bisa mengubah CHECK, jadi tabel dibuat ulang lalu isinya disalin (akun lama tetap
    sama). Di dalam BEGIN IMMEDIATE dan diperiksa ulang, agar aman bila beberapa worker gunicorn
    menjalankannya bersamaan."""
    def lama():
        return "wajib_ganti_sandi" not in con.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'pengguna'").fetchone()[0]
    if not lama():
        return
    awal = con.isolation_level
    con.isolation_level = None
    try:
        con.execute("BEGIN IMMEDIATE")
        if lama():
            buat = SKEMA[SKEMA.index("CREATE TABLE IF NOT EXISTS pengguna"):]
            buat = buat[:buat.index(");") + 2].replace("IF NOT EXISTS pengguna", "pengguna_baru")
            con.execute(buat)
            con.execute("INSERT INTO pengguna_baru (id, username, hash_sandi, peran, instalasi_id, dibuat_utc, aktif) "
                        "SELECT id, username, hash_sandi, peran, instalasi_id, dibuat_utc, aktif FROM pengguna")
            con.execute("DROP TABLE pengguna")
            con.execute("ALTER TABLE pengguna_baru RENAME TO pengguna")
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise
    finally:
        con.isolation_level = awal


def koneksi():
    if "db" not in g:
        g.db = buka(current_app.config["DB_PATH"])
    return g.db


def tutup(_=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def catat_audit(jenis, instalasi=None, aktor=None, ip=None, nama=None, ukuran=None, sha=None,
                kode=None, ket=None, db=None):
    db = db or koneksi()
    db.execute(
        "INSERT INTO audit (waktu_utc, jenis, instalasi, aktor, ip, nama_berkas, ukuran, sha256, kode_http, keterangan) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (sekarang(), jenis, instalasi, aktor, ip, nama, ukuran, sha, kode, ket))
    db.commit()
