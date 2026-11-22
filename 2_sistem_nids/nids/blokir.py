# -*- coding: utf-8 -*-
"""
Daftar IP diblokir (firewall manual oleh administrator): alamat atau subnet sumber yang diblokir
atas persetujuan administrator melalui dashboard web maupun Telegram Bot.

* Disimpan sebagai berkas JSON di folder bersama (/var/lib/nids-bersama/ip_diblokir.json),
  ditulis oleh dashboard (tanids) dan bot Telegram (nids) dengan izin berkas 0660 grup nids.
* Layanan systemd terpisah (nids-blokir.path + nids-blokir.service) memantau perubahan berkas ini
  dan menyinkronkannya secara atomik ke tabel nftables `inet nids_blokir`.
* Pengaman bawaan menolak pemblokiran loopback, jaringan privat internal, IP tepercaya,
  IP server sendiri, serta IP klien administrator yang sedang aktif.

Hanya memakai pustaka standar.
"""
import contextlib
import ipaddress
import json
import os
import tempfile
import time
from datetime import datetime, timedelta, timezone

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows (untuk unit test lokal)
    fcntl = None

from . import tepercaya as daftar_tepercaya

PATH_BAWAAN = "/var/lib/nids-bersama/ip_diblokir.json"
STATUS_BAWAAN = "/var/lib/nids-bersama/ip_diblokir_status.json"
PREFIKS_MIN = {4: 24, 6: 64}

DURASI_OPSI = [
    ("1j", "1 jam", 3600),
    ("24j", "24 jam", 86400),
    ("7h", "7 hari", 7 * 86400),
    ("permanen", "Permanen", None),
]
DURASI_PETA = {k: (label, detik) for k, label, detik in DURASI_OPSI}

# Jaringan terlarang yang tidak boleh diblokir agar server dan komunikasi internal tidak lumpuh.
# Catatan: blok TEST-NET (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) sengaja tidak masuk daftar ini
# agar dapat digunakan secara aman dalam pengujian otomatis maupun dokumentasi.
_JARINGAN_TERLARANG = tuple(ipaddress.ip_network(x) for x in (
    "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
    "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
))


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
    lock_path = os.path.join(folder, ".ip_diblokir.lock")
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


def parse_durasi(teks):
    """'1j'/'24j'/'7h'/'permanen' -> (kode, label, detik_atau_None). ValueError bila tidak valid."""
    t = (teks or "permanen").strip().lower()
    if t in ("perm", "tetap", "selamanya"):
        t = "permanen"
    if t not in DURASI_PETA:
        raise ValueError("Durasi blokir tidak dikenal: pilih 1j, 24j, 7h, atau permanen.")
    label, detik = DURASI_PETA[t]
    return t, label, detik


def jaringan(teks):
    """Validasi alamat IP atau subnet untuk diblokir -> ip_network."""
    teks = (teks or "").strip()
    try:
        n = ipaddress.ip_network(teks, strict=False)
    except ValueError:
        raise ValueError("“%s” bukan alamat IP atau subnet yang valid." % teks[:64])
    if n.prefixlen < PREFIKS_MIN[n.version]:
        raise ValueError("Subnet %s terlalu luas untuk diblokir (maksimal /%d untuk IPv%d)."
                         % (n, PREFIKS_MIN[n.version], n.version))
    for terlarang in _JARINGAN_TERLARANG:
        if n.version == terlarang.version and n.overlaps(terlarang):
            raise ValueError("Alamat %s termasuk jaringan lokal, loopback, atau khusus sehingga tidak boleh diblokir." % n)
    return n


def masih_aktif(entri, kini=None):
    ked = parse_utc(entri.get("kedaluwarsa_utc"))
    if ked is None:
        return True
    t = time.time() if kini is None else float(kini)
    return ked > t


def _baca_mentah(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return []
    return [e for e in data.get("entri", []) if isinstance(e, dict) and e.get("cidr")]


def baca(path=PATH_BAWAAN, sertakan_kedaluwarsa=False, kini=None):
    """Daftar entri {cidr, durasi, keterangan, oleh, waktu_utc, kedaluwarsa_utc}."""
    entri = _baca_mentah(path)
    if sertakan_kedaluwarsa:
        return entri
    return [e for e in entri if masih_aktif(e, kini)]


def simpan(path, entri):
    """Tulis atomik dengan izin 660 agar dashboard (tanids) dan bot (nids) sama-sama dapat menulis."""
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    fd, sementara = tempfile.mkstemp(prefix=".diblokir-", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"entri": entri}, f, indent=1, ensure_ascii=False)
        os.chmod(sementara, 0o660)
        os.replace(sementara, path)
    except BaseException:
        if os.path.exists(sementara):
            os.unlink(sementara)
        raise


def periksa_dilindungi(net, path_tepercaya=None, ip_dilindungi=()):
    """Tolak pemblokiran jika beririsan dengan IP tepercaya, IP server, atau IP admin aktif."""
    if path_tepercaya and os.path.exists(path_tepercaya):
        for e in daftar_tepercaya.baca(path_tepercaya):
            try:
                tp_net = ipaddress.ip_network(e["cidr"], strict=False)
            except ValueError:
                continue
            if net.version == tp_net.version and net.overlaps(tp_net):
                raise ValueError("Alamat %s beririsan dengan IP tepercaya (%s). Hapus dari IP tepercaya dulu jika ingin memblokir."
                                 % (net, e["cidr"]))
    for ip_str in (ip_dilindungi or ()):
        ip_str = (ip_str or "").strip()
        if not ip_str or ip_str == "-":
            continue
        try:
            prot = ipaddress.ip_network(ip_str, strict=False)
        except ValueError:
            continue
        if net.version == prot.version and net.overlaps(prot):
            raise ValueError("Alamat %s tidak dapat diblokir karena merupakan alamat server atau IP Anda saat ini." % net)


def tambah(path, teks, durasi="permanen", keterangan="", oleh="", path_tepercaya=None, ip_dilindungi=(), kini=None):
    """Tambahkan IP/subnet ke daftar blokir dan kembalikan entri baru."""
    net = jaringan(teks)
    kode_durasi, label_durasi, detik = parse_durasi(durasi)
    periksa_dilindungi(net, path_tepercaya=path_tepercaya, ip_dilindungi=ip_dilindungi)
    t_now = time.time() if kini is None else float(kini)
    ked_utc = None if detik is None else datetime.fromtimestamp(t_now + detik, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    baru = {
        "cidr": str(net),
        "durasi": kode_durasi,
        "durasi_label": label_durasi,
        "keterangan": (keterangan or "").strip()[:120],
        "oleh": (oleh or "").strip()[:64],
        "waktu_utc": sekarang_utc(t_now),
        "kedaluwarsa_utc": ked_utc,
    }
    with _kunci(path):
        entri = [e for e in _baca_mentah(path) if masih_aktif(e, t_now)]
        if any(e["cidr"] == str(net) for e in entri):
            raise ValueError("%s sudah sedang diblokir." % net)
        entri.append(baru)
        simpan(path, entri)
    return baru


def hapus(path, teks, kini=None):
    """Hapus IP/subnet dari daftar blokir. Kembalikan entri yang dihapus atau None."""
    mentah = (teks or "").strip()
    if not mentah:
        return None
    target_set = {mentah}
    try:
        target_set.add(str(ipaddress.ip_network(mentah, strict=False)))
    except ValueError:
        pass
    t_now = time.time() if kini is None else float(kini)
    with _kunci(path):
        lama = _baca_mentah(path)
        dihapus = None
        sisa = []
        for e in lama:
            if e["cidr"] in target_set:
                dihapus = e
                continue
            if masih_aktif(e, t_now):
                sisa.append(e)
        if dihapus is not None or len(sisa) != len(lama):
            simpan(path, sisa)
    return dihapus


def bersihkan_kedaluwarsa(path, kini=None):
    """Buang entri kedaluwarsa dari JSON. Kembalikan (daftar_aktif, apakah_berubah)."""
    t_now = time.time() if kini is None else float(kini)
    with _kunci(path):
        lama = _baca_mentah(path)
        aktif = [e for e in lama if masih_aktif(e, t_now)]
        berubah = len(aktif) != len(lama)
        if berubah:
            simpan(path, aktif)
    return aktif, berubah


def cocok_dengan(entri, ip):
    """Entri blokir aktif pertama yang mencakup `ip`, atau None."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for e in entri:
        if not masih_aktif(e):
            continue
        try:
            n = ipaddress.ip_network(e["cidr"], strict=False)
            if a.version == n.version and a in n:
                return e
        except ValueError:
            continue
    return None


def skrip_nft(entri):
    """Hasilkan perintah atomik nftables untuk tabel terisolasi `inet nids_blokir`."""
    v4, v6 = [], []
    for e in entri:
        try:
            n = ipaddress.ip_network(e["cidr"], strict=False)
        except ValueError:
            continue
        (v4 if n.version == 4 else v6).append(str(n))
    v4 = sorted(set(v4))
    v6 = sorted(set(v6))
    if not v4 and not v6:
        return "add table inet nids_blokir\ndelete table inet nids_blokir\n"
    baris = [
        "add table inet nids_blokir",
        "delete table inet nids_blokir",
        "table inet nids_blokir {",
    ]
    if v4:
        baris += [
            "    set v4 {",
            "        type ipv4_addr",
            "        flags interval",
            "        auto-merge",
            "        elements = { %s }" % ", ".join(v4),
            "    }",
        ]
    if v6:
        baris += [
            "    set v6 {",
            "        type ipv6_addr",
            "        flags interval",
            "        auto-merge",
            "        elements = { %s }" % ", ".join(v6),
            "    }",
        ]
    baris += [
        "    chain input {",
        "        type filter hook input priority filter - 10; policy accept;",
    ]
    if v4:
        baris.append("        ip saddr @v4 drop")
    if v6:
        baris.append("        ip6 saddr @v6 drop")
    baris += ["    }", "}"]
    return "\n".join(baris) + "\n"


def tulis_status(path_status, data):
    """Simpan status sinkronisasi firewall terakhir (izin 644 agar dapat dibaca dashboard)."""
    folder = os.path.dirname(os.path.abspath(path_status))
    os.makedirs(folder, exist_ok=True)
    fd, sementara = tempfile.mkstemp(prefix=".diblokir-status-", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1, ensure_ascii=False)
        os.chmod(sementara, 0o644)
        os.replace(sementara, path_status)
    except BaseException:
        if os.path.exists(sementara):
            os.unlink(sementara)
        raise


def baca_status(path_status=STATUS_BAWAAN):
    try:
        with open(path_status, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, ValueError, OSError):
        return None
