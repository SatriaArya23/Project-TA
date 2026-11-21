# -*- coding: utf-8 -*-
"""Statistik lalu lintas per berkas rekaman, dihitung dari header paket.

Dipakai dashboard untuk menunjukkan isi rekaman (jumlah paket, percobaan koneksi
dari luar, sumber, port tujuan) dan untuk menggabungkan rekaman per jam menjadi
satu berkas per hari saat diunduh.

Pembaca pcap diambil dari paket `nids` (folder nids-deteksi), sama dengan pipeline
deteksi. Di server, pasang.sh menyalin paket itu ke folder aplikasi.
"""
import gzip
import json
import os
import struct
import sys
import zlib
from collections import Counter

from .db import sekarang

_lokasi = os.environ.get("PENERIMA_NIDS_PATH")
_induk = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))      # folder 04_Kode
for _p in ([_lokasi] if _lokasi else []) + [
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),                       # /opt/ta-nids-server
        os.path.join(_induk, "2_sistem_nids"),                                              # laptop: 04_Kode/2_sistem_nids
        os.path.join(_induk, "nids-deteksi")]:                                              # nama folder lama
    if _p and os.path.isdir(os.path.join(_p, "nids")) and _p not in sys.path:
        sys.path.append(_p)
from nids.pcap import ACK, RST, SYN, TCP, baca_pcap  # noqa: E402

def alamat_server(paket):
    """Setiap paket yang terekam melibatkan server (sebagai pengirim atau penerima), sehingga
    alamat IPv4 dan IPv6 yang paling sering muncul pasti alamat server itu sendiri, bahkan
    ketika satu penyerang mendominasi lalu lintas."""
    v4, v6 = Counter(), Counter()
    for p in paket:
        for ip in (p.src, p.dst):
            (v6 if ":" in ip else v4)[ip] += 1
    return {c.most_common(1)[0][0] for c in (v4, v6) if c}


def hitung(path):
    """Kembalikan dict statistik satu berkas pcap(.gz)."""
    paket = list(baca_pcap(path))
    n = len(paket)
    server = alamat_server(paket)
    syn_masuk = syn_ssh = rst_keluar = 0
    ip_luar, port = set(), Counter()
    for p in paket:
        masuk = p.dst in server and p.src not in server
        if masuk:
            ip_luar.add(p.src)
            baru = (p.proto == TCP and p.flags & SYN and not p.flags & ACK) or p.proto != TCP
            if baru:
                port[p.dport] += 1
            if p.proto == TCP and p.flags & SYN and not p.flags & ACK:
                syn_masuk += 1
                if p.dport == 22:
                    syn_ssh += 1
        elif p.src in server and p.proto == TCP and p.flags & RST:
            rst_keluar += 1
    return {"paket": n, "syn_masuk": syn_masuk, "syn_ssh": syn_ssh, "rst_keluar": rst_keluar,
            "ip_luar": len(ip_luar), "ip_luar_json": json.dumps(sorted(ip_luar)),
            "port_json": json.dumps(port.most_common(15))}


def simpan(db, berkas_id, path):
    """Hitung & simpan statistik satu berkas. Galat dicatat, tidak dilempar."""
    try:
        s, galat = hitung(path), None
    except Exception as e:                       # berkas rusak tidak boleh menggagalkan unggahan
        s, galat = {}, "%s: %s" % (type(e).__name__, e)
    db.execute("INSERT OR REPLACE INTO statistik (berkas_id, paket, syn_masuk, syn_ssh, rst_keluar, ip_luar, "
               "ip_luar_json, port_json, dihitung_utc, galat) VALUES (?,?,?,?,?,?,?,?,?,?)",
               (berkas_id, s.get("paket"), s.get("syn_masuk"), s.get("syn_ssh"), s.get("rst_keluar"),
                s.get("ip_luar"), s.get("ip_luar_json"), s.get("port_json"), sekarang(), galat))
    db.commit()
    return galat


# ------------------------------------------------------------------ gabung per hari
def _buka(path):
    with open(path, "rb") as f:
        gz = f.read(2) == b"\x1f\x8b"
    return gzip.open(path, "rb") if gz else open(path, "rb")


def gabung_gzip(paths, blok=1 << 20):
    """Generator: isi beberapa berkas pcap(.gz) berurutan, digabung jadi SATU pcap
    terkompresi gzip. Header global hanya dari berkas pertama; berkas lain harus
    ber-link-type sama."""
    z = zlib.compressobj(6, zlib.DEFLATED, 31)            # wbits 31 = format gzip
    kepala = None
    for i, path in enumerate(paths):
        with _buka(path) as f:
            h = f.read(24)
            if len(h) < 24:
                continue
            if kepala is None:
                kepala = h
                yield z.compress(h)
            elif h[:4] != kepala[:4] or h[20:24] != kepala[20:24]:
                raise ValueError("format pcap %s berbeda dari berkas pertama" % os.path.basename(path))
            while True:
                b = f.read(blok)
                if not b:
                    break
                c = z.compress(b)
                if c:
                    yield c
    if kepala is None:                                      # tidak ada berkas: pcap kosong yang valid
        yield z.compress(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
    yield z.flush()
