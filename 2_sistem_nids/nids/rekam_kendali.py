# -*- coding: utf-8 -*-
"""
Antrean perintah & status kendali perekam lalu lintas (traffic-recorder) bersama dashboard.

* Dashboard (user `tanids`, non-root) menulis permintaan mulai/berhenti ke:
    /var/lib/nids-bersama/rekam_perintah.json
* Layanan systemd terpisah (`nids-rekam-kendali.path` + `.timer` -> `rekam_kendali.py`)
  menyalakan / mematikan `traffic-recorder.service`, memicu `traffic-uploader.service`
  saat dihentikan agar berkas langsung masuk ke Tab Rekaman, menghentikan perekam otomatis
  saat durasi berakhir, serta menulis status aktual ke:
    /var/lib/nids-bersama/rekam_status.json

Hanya memakai pustaka standar.
"""
import contextlib
import json
import os
import tempfile
import time
from datetime import datetime, timedelta, timezone

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None

PATH_PERINTAH = "/var/lib/nids-bersama/rekam_perintah.json"
PATH_STATUS = "/var/lib/nids-bersama/rekam_status.json"

DURASI_OPSI = [
    ("1j", "1 jam", 3600),
    ("6j", "6 jam", 6 * 3600),
    ("24j", "24 jam", 24 * 3600),
    ("3h", "3 hari", 3 * 86400),
    ("7h", "7 hari", 7 * 86400),
    ("terus", "Terus-menerus", None),
]
DURASI_PETA = {k: (label, detik) for k, label, detik in DURASI_OPSI}


def sekarang_utc(kini=None):
    t = datetime.now(timezone.utc) if kini is None else datetime.fromtimestamp(float(kini), timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc(teks):
    if not teks:
        return None
    try:
        return datetime.strptime(teks, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


@contextlib.contextmanager
def _kunci(path):
    if fcntl is None:
        yield
        return
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    lock_path = os.path.join(folder, ".rekam_kendali.lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o660)
    try:
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


def _simpan(path, data, prefix):
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    fd, sementara = tempfile.mkstemp(prefix=prefix, dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1, ensure_ascii=False)
        try:
            os.chmod(sementara, 0o660)
        except OSError:
            pass
        os.replace(sementara, path)
    except BaseException:
        if os.path.exists(sementara):
            os.unlink(sementara)
        raise


def baca_perintah(path=PATH_PERINTAH):
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else None
    except (FileNotFoundError, ValueError, OSError):
        return None


def baca_status(path=PATH_STATUS):
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else None
    except (FileNotFoundError, ValueError, OSError):
        return None


def simpan_status(path, status):
    with _kunci(path):
        _simpan(path, status, ".rekstat-")


def minta_mulai(path=PATH_PERINTAH, durasi="24j", oleh="", catatan="", kini=None):
    k = (durasi or "24j").strip().lower()
    if k not in DURASI_PETA:
        raise ValueError("Pilihan durasi perekaman tidak dikenal.")
    label, detik = DURASI_PETA[k]
    t0 = time.time() if kini is None else float(kini)
    batas = (datetime.fromtimestamp(t0, timezone.utc) + timedelta(seconds=detik)).strftime("%Y-%m-%dT%H:%M:%SZ") if detik else None
    cmd = {
        "id": "rk-%d" % int(t0 * 1000),
        "aksi": "mulai",
        "durasi": k,
        "durasi_label": label,
        "batas_utc": batas,
        "catatan": (catatan or "").strip()[:120],
        "oleh": oleh,
        "diminta_utc": sekarang_utc(t0),
    }
    with _kunci(path):
        _simpan(path, cmd, ".rekcmd-")
    return cmd


def minta_berhenti(path=PATH_PERINTAH, oleh="", kini=None):
    t0 = time.time() if kini is None else float(kini)
    cmd = {
        "id": "rk-%d" % int(t0 * 1000),
        "aksi": "berhenti",
        "oleh": oleh,
        "diminta_utc": sekarang_utc(t0),
    }
    with _kunci(path):
        _simpan(path, cmd, ".rekcmd-")
    return cmd
