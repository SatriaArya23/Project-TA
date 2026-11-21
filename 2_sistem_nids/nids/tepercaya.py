# -*- coding: utf-8 -*-
"""
Daftar IP tepercaya (whitelist): alamat atau subnet milik sendiri (kantor, administrator, layanan
pemantau) yang lalu lintasnya TIDAK dianggap anomali dan tidak memicu notifikasi.

* Disimpan sebagai berkas JSON di folder bersama (bawaan /var/lib/nids-bersama/ip_tepercaya.json):
  ditulis dashboard (halaman IP tepercaya, khusus administrator), dibaca modul deteksi dan bot.
* Modul deteksi memeriksa perubahan berkas paling lambat tiap 30 detik, tanpa perlu restart.
* Aliran dari IP tepercaya tetap dinilai dan dicatat (skornya tetap terlihat di dashboard),
  hanya tidak ditandai anomali. Berlaku untuk aliran baru; catatan lama tidak diubah.
* Subnet yang terlalu luas ditolak (IPv4 minimal /16, IPv6 minimal /48), supaya daftar ini tidak
  bisa dipakai untuk mematikan deteksi secara tidak sengaja.

Hanya memakai pustaka standar.
"""
import ipaddress
import json
import os
import tempfile
import time
from datetime import datetime, timezone

PATH_BAWAAN = "/var/lib/nids-bersama/ip_tepercaya.json"
PREFIKS_MIN = {4: 16, 6: 48}


def jaringan(teks):
    """'203.0.113.7' / '203.0.113.0/24' -> ip_network. ValueError berisi pesan untuk pengguna."""
    teks = (teks or "").strip()
    try:
        n = ipaddress.ip_network(teks, strict=False)
    except ValueError:
        raise ValueError("“%s” bukan alamat IP atau subnet yang valid." % teks[:64])
    if n.prefixlen < PREFIKS_MIN[n.version]:
        raise ValueError("Subnet %s terlalu luas (minimal /%d untuk IPv%d)." % (n, PREFIKS_MIN[n.version], n.version))
    return n


def baca(path):
    """Isi berkas -> list entri {cidr, keterangan, oleh, waktu_utc}. Berkas tidak ada = daftar kosong."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return []
    return [e for e in data.get("entri", []) if isinstance(e, dict) and e.get("cidr")]


def simpan(path, entri):
    """Tulis atomik (berkas sementara di folder yang sama lalu rename), izin 640."""
    folder = os.path.dirname(os.path.abspath(path))
    fd, sementara = tempfile.mkstemp(prefix=".tepercaya-", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"entri": entri}, f, indent=1, ensure_ascii=False)
        os.chmod(sementara, 0o640)
        os.replace(sementara, path)
    except BaseException:
        if os.path.exists(sementara):
            os.unlink(sementara)
        raise


def tambah(path, teks, keterangan="", oleh=""):
    n = jaringan(teks)
    entri = baca(path)
    if any(e["cidr"] == str(n) for e in entri):
        raise ValueError("%s sudah ada di daftar." % n)
    entri.append({"cidr": str(n), "keterangan": (keterangan or "").strip()[:120], "oleh": oleh,
                  "waktu_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")})
    simpan(path, entri)
    return str(n)


def hapus(path, cidr):
    entri = baca(path)
    sisa = [e for e in entri if e["cidr"] != cidr]
    if len(sisa) == len(entri):
        return False
    simpan(path, sisa)
    return True


def cocok_dengan(entri, ip):
    """Entri pertama yang mencakup `ip`, atau None."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for e in entri:
        try:
            if a in ipaddress.ip_network(e["cidr"], strict=False):
                return e
        except ValueError:
            continue
    return None


class DaftarTepercaya:
    """Daftar yang dimuat ulang otomatis bila berkasnya berubah (diperiksa paling sering tiap `periksa_detik`)."""

    def __init__(self, path=PATH_BAWAAN, periksa_detik=30, jam=time.monotonic):
        self.path, self.periksa, self.jam = path, periksa_detik, jam
        self._mtime, self._t_periksa = None, None
        self.entri, self._net = [], []
        self.muat_ulang()

    def muat_ulang(self, paksa=True):
        kini = self.jam()
        if not paksa and self._t_periksa is not None and kini - self._t_periksa < self.periksa:
            return False
        self._t_periksa = kini
        try:
            mtime = os.stat(self.path).st_mtime_ns
        except OSError:
            mtime = None
        if mtime == self._mtime and not paksa:
            return False
        self._mtime = mtime
        try:
            entri = baca(self.path) if mtime is not None else []
        except (OSError, ValueError):
            return False                      # berkas rusak / sedang ditulis: pakai daftar lama
        net = []
        for e in entri:
            try:
                net.append((ipaddress.ip_network(e["cidr"], strict=False), e))
            except ValueError:
                continue
        self.entri, self._net = entri, net
        return True

    def cocok(self, ip):
        if not self._net:
            return None
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for n, e in self._net:
            if a.version == n.version and a in n:
                return e
        return None

    def __len__(self):
        return len(self._net)
