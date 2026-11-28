# -*- coding: utf-8 -*-
"""
Jembatan catatan audit lintas layanan ke dashboard (`/audit`).

Layanan terisolasi (`nids-bot`, `nids-model`) tidak menulis langsung ke `penerima.db` milik web.
Sebagai gantinya, kejadian penting (blokir/buka dari Telegram, penggunaan AI Telegram, impor/penolakan
model .joblib) ditulis sebagai baris JSON ke berkas bersama `/var/lib/nids-bersama/audit_eksternal.jsonl`,
lalu disinkronkan secara atomik ke tabel `audit` oleh dashboard.

Hanya memakai pustaka standar.
"""
import contextlib
import json
import os
from datetime import datetime, timezone

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None

PATH_BAWAAN = "/var/lib/nids-bersama/audit_eksternal.jsonl"


def sekarang_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@contextlib.contextmanager
def _kunci(path):
    if fcntl is None:
        yield
        return
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    lock_path = os.path.join(folder, ".audit_eksternal.lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o660)
    try:
        if hasattr(os, "fchmod"):
            try:
                os.fchmod(fd, 0o660)
            except OSError:
                pass
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def tulis(path, jenis, instalasi=None, aktor=None, ip=None, nama=None, ukuran=None, sha=None,
          kode=None, ket=None, waktu_utc=None):
    """Tambahkan satu baris peristiwa audit eksternal (aman dipanggil lintas proses)."""
    if not path:
        return
    if path == PATH_BAWAAN and not os.path.isdir(os.path.dirname(path)):
        return
    entri = {
        "waktu_utc": waktu_utc or sekarang_utc(),
        "jenis": str(jenis)[:64],
        "instalasi": instalasi,
        "aktor": aktor,
        "ip": ip,
        "nama_berkas": nama,
        "ukuran": ukuran,
        "sha256": sha,
        "kode_http": kode,
        "keterangan": (str(ket)[:500] if ket is not None else None),
    }
    try:
        with _kunci(path):
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o660)
            try:
                if hasattr(os, "fchmod"):
                    try:
                        os.fchmod(fd, 0o660)
                    except OSError:
                        pass
                with os.fdopen(fd, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entri, ensure_ascii=False) + "\n")
            except BaseException:
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise
    except OSError:
        pass


def kuras(path=PATH_BAWAAN):
    """Ambil seluruh entri yang belum ditarik lalu kosongkan berkas secara atomik."""
    if not path or not os.path.exists(path):
        return []
    hasil = []
    try:
        with _kunci(path):
            if not os.path.exists(path):
                return []
            with open(path, encoding="utf-8") as f:
                for baris in f:
                    baris = baris.strip()
                    if not baris:
                        continue
                    try:
                        obj = json.loads(baris)
                        if isinstance(obj, dict) and obj.get("jenis"):
                            hasil.append(obj)
                    except ValueError:
                        continue
            # Kosongkan isi berkas di bawah kunci yang sama agar tidak hilang atau terduplikasi
            with open(path, "w", encoding="utf-8") as f:
                f.write("")
    except OSError:
        return []
    return hasil
