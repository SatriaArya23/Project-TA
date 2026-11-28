# -*- coding: utf-8 -*-
"""API: unggah berkas (token 'upload') dan baca daftar/audit (token 'read')."""
import hashlib
import os
import re
import shutil
import sqlite3
import tempfile

from flask import Blueprint, abort, current_app, jsonify, request, send_file

from . import statistik
from .db import catat_audit, koneksi, sekarang, tarik_audit_eksternal
from .keamanan import ip_klien, token_bearer
from .waktu import mulai_rekam

bp = Blueprint("api", __name__, url_prefix="/api/v1")

POLA_NAMA = re.compile(r"^cap_\d{8}_\d{6}\.hdr\.pcap\.gz$")
POLA_SHA = re.compile(r"^[0-9a-f]{64}$")
POLA_TANGGAL = re.compile(r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2})?Z?)?$")
MiB = 1024 * 1024


def info_berkas(b):
    return {"file": b["nama"], "size": b["ukuran"], "sha256": b["sha256"], "received_at": b["diterima_utc"]}


@bp.get("/health")
def health():
    return jsonify(status="ok", time=sekarang())


# ======================================================================= UNGGAH
@bp.put("/upload/<nama>")
def upload(nama):
    ip = ip_klien()
    nama_log = nama[:80]
    tok = token_bearer("upload")
    if tok is None:
        catat_audit("UPLOAD_DITOLAK", ip=ip, nama=nama_log, kode=401, ket="token tidak valid")
        return jsonify(error="token tidak valid"), 401

    inst, inst_id = tok["instalasi_nama"], tok["instalasi_id"]

    def tolak(kode, pesan, **lain):
        catat_audit("UPLOAD_DITOLAK", instalasi=inst, aktor=inst, ip=ip, nama=nama_log, kode=kode, ket=pesan, **lain)
        return jsonify(error=pesan), kode

    if not POLA_NAMA.match(nama):
        return tolak(400, "nama berkas tidak valid")
    sha_klaim = (request.headers.get("X-Content-SHA256") or "").strip().lower()
    if not POLA_SHA.match(sha_klaim):
        return tolak(400, "header X-Content-SHA256 wajib berisi sha256 heksadesimal")
    panjang = request.content_length
    if panjang is None:
        return tolak(411, "header Content-Length wajib")
    if panjang == 0:
        return tolak(400, "berkas kosong")
    if panjang > current_app.config["MAX_UPLOAD_MB"] * MiB:
        return tolak(413, "berkas melebihi %d MB" % current_app.config["MAX_UPLOAD_MB"], ukuran=panjang)

    db = koneksi()
    lama = db.execute("SELECT * FROM berkas WHERE instalasi_id = ? AND nama = ?", (inst_id, nama)).fetchone()
    if lama is not None:
        catat_audit("UPLOAD_DUPLIKAT", instalasi=inst, aktor=inst, ip=ip, nama=nama, ukuran=lama["ukuran"],
                    sha=lama["sha256"], kode=409,
                    ket="sha sama" if lama["sha256"] == sha_klaim else "sha BERBEDA dari klaim " + sha_klaim[:16])
        return jsonify(keterangan="sudah ada", **info_berkas(lama)), 409

    folder = os.path.join(current_app.config["BERKAS_DIR"], inst)
    os.makedirs(folder, mode=0o750, exist_ok=True)
    if shutil.disk_usage(folder).free - panjang < current_app.config["MIN_FREE_MB"] * MiB:
        return tolak(507, "ruang disk server penerima hampir penuh", ukuran=panjang)

    fd, tmp = tempfile.mkstemp(prefix=".unggah-", dir=folder)
    try:
        h, diterima, awal = hashlib.sha256(), 0, b""
        with os.fdopen(fd, "wb") as f:
            while True:
                blok = request.stream.read(MiB)
                if not blok:
                    break
                diterima += len(blok)
                if diterima > panjang:
                    break
                if len(awal) < 2:
                    awal += blok[:2 - len(awal)]
                h.update(blok)
                f.write(blok)
            f.flush()
            os.fsync(f.fileno())
        if diterima != panjang:
            return tolak(400, "data tidak lengkap (%d dari %d byte)" % (diterima, panjang), ukuran=diterima)
        if awal != b"\x1f\x8b":
            return tolak(415, "isi bukan berkas gzip", ukuran=diterima)
        sha = h.hexdigest()
        if sha != sha_klaim:
            return tolak(422, "checksum tidak cocok", ukuran=diterima, sha=sha)

        waktu = sekarang()
        try:
            db.execute("INSERT INTO berkas (instalasi_id, nama, ukuran, sha256, diterima_utc, ip_pengirim) "
                       "VALUES (?, ?, ?, ?, ?, ?)", (inst_id, nama, diterima, sha, waktu, ip))
        except sqlite3.IntegrityError:          # unggahan bersamaan dengan nama sama
            db.rollback()
            lama = db.execute("SELECT * FROM berkas WHERE instalasi_id = ? AND nama = ?", (inst_id, nama)).fetchone()
            return jsonify(keterangan="sudah ada", **info_berkas(lama)), 409
        os.chmod(tmp, 0o640)
        os.replace(tmp, os.path.join(folder, nama))
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

    catat_audit("UPLOAD_DITERIMA", instalasi=inst, aktor=inst, ip=ip, nama=nama, ukuran=diterima, sha=sha, kode=201)
    berkas_id = db.execute("SELECT id FROM berkas WHERE instalasi_id = ? AND nama = ?", (inst_id, nama)).fetchone()[0]
    statistik.simpan(db, berkas_id, os.path.join(folder, nama))      # isi rekaman untuk dashboard
    return jsonify(file=nama, size=diterima, sha256=sha, received_at=waktu), 201


# ======================================================================= BACA
def token_baca():
    tok = token_bearer("read")
    if tok is None:
        abort(401, "token tidak valid")
    return tok


def angka(nama, bawaan, maks):
    try:
        return max(0, min(int(request.args.get(nama, bawaan)), maks))
    except ValueError:
        abort(400, "parameter %s harus angka" % nama)


def tanggal(nama):
    v = request.args.get(nama)
    if v is not None and not POLA_TANGGAL.match(v):
        abort(400, "parameter %s harus berformat YYYY-MM-DD atau YYYY-MM-DDTHH:MM:SSZ" % nama)
    return v


def saring_berkas(instalasi_id):
    """Klausa WHERE untuk tabel berkas (alias b) dan instalasi (alias i)."""
    syarat, nilai = [], []
    if instalasi_id is not None:                     # token/pengguna terikat satu instalasi
        syarat.append("b.instalasi_id = ?"); nilai.append(instalasi_id)
    elif request.args.get("installation"):
        syarat.append("i.nama = ?"); nilai.append(request.args["installation"])
    if tanggal("since"):
        syarat.append("b.diterima_utc >= ?"); nilai.append(request.args["since"])
    if tanggal("until"):
        syarat.append("b.diterima_utc < ?"); nilai.append(request.args["until"])
    return (" WHERE " + " AND ".join(syarat)) if syarat else "", nilai


def baris_berkas(r):
    return {"id": r["id"], "installation": r["instalasi"], "file": r["nama"], "size": r["ukuran"],
            "sha256": r["sha256"], "recording_start": iso(mulai_rekam(r["nama"])),
            "received_at": r["diterima_utc"], "sender_ip": r["ip_pengirim"]}


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


@bp.get("/files")
def daftar_berkas():
    tok = token_baca()
    where, nilai = saring_berkas(tok["instalasi_id"])
    limit, offset = angka("limit", 100, 1000), angka("offset", 0, 10 ** 9)
    db = koneksi()
    total = db.execute("SELECT COUNT(*) FROM berkas b JOIN instalasi i ON i.id = b.instalasi_id" + where,
                       nilai).fetchone()[0]
    rows = db.execute("SELECT b.*, i.nama AS instalasi FROM berkas b JOIN instalasi i ON i.id = b.instalasi_id"
                      + where + " ORDER BY b.nama DESC, b.id DESC LIMIT ? OFFSET ?",
                      nilai + [limit, offset]).fetchall()
    return jsonify(total=total, limit=limit, offset=offset, items=[baris_berkas(r) for r in rows])


@bp.get("/files/<int:berkas_id>/download")
def unduh_berkas(berkas_id):
    tok = token_baca()
    r = koneksi().execute("SELECT b.*, i.nama AS instalasi FROM berkas b JOIN instalasi i ON i.id = b.instalasi_id "
                          "WHERE b.id = ?", (berkas_id,)).fetchone()
    if r is None or (tok["instalasi_id"] is not None and r["instalasi_id"] != tok["instalasi_id"]):
        abort(404, "berkas tidak ditemukan")
    catat_audit("UNDUH", instalasi=r["instalasi"], aktor="token:" + tok["label"], ip=ip_klien(),
                nama=r["nama"], ukuran=r["ukuran"], sha=r["sha256"], kode=200, ket="lewat API")
    return send_file(os.path.join(current_app.config["BERKAS_DIR"], r["instalasi"], r["nama"]),
                     mimetype="application/gzip", as_attachment=True, download_name=r["nama"])


@bp.get("/audit")
def daftar_audit():
    tok = token_baca()
    tarik_audit_eksternal(current_app.config.get("AUDIT_EKSTERNAL_PATH"))
    syarat, nilai = [], []
    if tok["instalasi_id"] is not None:
        syarat.append("instalasi = ?"); nilai.append(tok["instalasi_nama"])
    elif request.args.get("installation"):
        syarat.append("instalasi = ?"); nilai.append(request.args["installation"])
    if tanggal("since"):
        syarat.append("waktu_utc >= ?"); nilai.append(request.args["since"])
    if tanggal("until"):
        syarat.append("waktu_utc < ?"); nilai.append(request.args["until"])
    where = (" WHERE " + " AND ".join(syarat)) if syarat else ""
    limit, offset = angka("limit", 100, 1000), angka("offset", 0, 10 ** 9)
    rows = koneksi().execute("SELECT * FROM audit" + where + " ORDER BY id DESC LIMIT ? OFFSET ?",
                             nilai + [limit, offset]).fetchall()
    return jsonify(limit=limit, offset=offset, items=[{
        "time": r["waktu_utc"], "event": r["jenis"], "installation": r["instalasi"], "actor": r["aktor"],
        "ip": r["ip"], "file": r["nama_berkas"], "size": r["ukuran"], "sha256": r["sha256"],
        "http_status": r["kode_http"], "note": r["keterangan"]} for r in rows])


def ringkasan(instalasi_id=None):
    where, nilai = ("WHERE i.id = ?", [instalasi_id]) if instalasi_id is not None else ("", [])
    return koneksi().execute(
        "SELECT i.nama, i.keterangan, i.aktif, COUNT(b.id) AS jumlah, COALESCE(SUM(b.ukuran), 0) AS total, "
        "MIN(b.diterima_utc) AS pertama, MAX(b.diterima_utc) AS terakhir, MAX(b.nama) AS nama_terbaru, "
        "SUM(CASE WHEN b.diterima_utc >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 day') THEN 1 ELSE 0 END) AS sehari "
        "FROM instalasi i LEFT JOIN berkas b ON b.instalasi_id = i.id " + where +
        " GROUP BY i.id ORDER BY i.nama", nilai).fetchall()


@bp.get("/summary")
def api_ringkasan():
    tok = token_baca()
    return jsonify(generated_at=sekarang(), installations=[{
        "installation": r["nama"], "active": bool(r["aktif"]), "files": r["jumlah"], "total_bytes": r["total"],
        "first_received": r["pertama"], "last_received": r["terakhir"], "files_last_24h": r["sehari"] or 0,
        "latest_recording_start": iso(mulai_rekam(r["nama_terbaru"]))}
        for r in ringkasan(tok["instalasi_id"])])
