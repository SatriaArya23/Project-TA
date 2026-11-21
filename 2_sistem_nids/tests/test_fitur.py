# -*- coding: utf-8 -*-
"""Uji ekstraksi fitur dengan pcap buatan yang nilainya diketahui.
Jalankan: python -m pytest -q tests"""
import gzip
import ipaddress
import struct
import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from nids.agregasi import tambah_agregasi, subnet       # noqa: E402
from nids.aliran import FITUR, METADATA, PenyusunAliran  # noqa: E402
from nids.pcap import baca_pcap, SYN, ACK, FIN, RST, PSH  # noqa: E402


def ekstrak(berkas, tampil=False):
    """Rekaman -> tabel 68 fitur aliran (tanpa agregasi), untuk menguji penyusun aliran."""
    penyusun, aliran = PenyusunAliran(), []
    for f in berkas:
        for p in baca_pcap(f):
            aliran += penyusun.masuk(p)
    aliran += penyusun.selesaikan()
    df = pd.DataFrame(aliran, columns=METADATA + FITUR)
    return df.sort_values("Timestamp", kind="stable").reset_index(drop=True), None

SERVER = "10.0.0.1"


def paket(src, dst, sport, dport, flags=0, payload=0, win=64240, udp=False, simpan_payload=False):
    """Ethernet + IPv4 + TCP/UDP. Bila simpan_payload=False, payload tidak
    ikut disimpan (seperti rekaman header saja) tetapi panjangnya tetap
    tercatat di header IP."""
    if udp:
        l4 = struct.pack("!HHHH", sport, dport, 8 + payload, 0)
    else:
        l4 = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 5 << 4, flags, win, 0, 0)
    total = 20 + len(l4) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 17 if udp else 6, 0,
                     ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    eth = b"\x00" * 12 + b"\x08\x00"
    data = eth + ip + l4 + (b"\x00" * payload if simpan_payload else b"")
    return data, len(eth) + total


def tulis_pcap(path, daftar):
    """daftar = [(detik_float, (data, panjang_asli)), ...]"""
    with gzip.open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for t, (d, orig) in daftar:
            s, us = int(t), round((t - int(t)) * 1e6)
            f.write(struct.pack("<IIII", s, us, len(d), orig) + d)


T0 = 1_761_000_000.0


@pytest.fixture
def rekaman(tmp_path):
    c = "203.0.113.7"
    pk = [
        # 1) koneksi HTTP normal: handshake, 1 permintaan 100 B, 1 balasan 1000 B, FIN dua arah
        (T0 + 0.000, paket(c, SERVER, 40000, 80, SYN)),
        (T0 + 0.010, paket(SERVER, c, 80, 40000, SYN | ACK, win=65160)),
        (T0 + 0.020, paket(c, SERVER, 40000, 80, ACK)),
        (T0 + 0.030, paket(c, SERVER, 40000, 80, PSH | ACK, payload=100)),
        (T0 + 0.050, paket(SERVER, c, 80, 40000, PSH | ACK, payload=1000)),
        (T0 + 0.060, paket(c, SERVER, 40000, 80, FIN | ACK)),
        (T0 + 0.070, paket(SERVER, c, 80, 40000, FIN | ACK)),
        (T0 + 0.080, paket(c, SERVER, 40000, 80, ACK)),     # ACK terakhir, tetap aliran yang sama
    ]
    # 2) pemindaian port: 20 SYN dari 198.51.100.9 ke port berbeda, server membalas RST
    for i in range(20):
        t = T0 + 1 + i * 0.1
        pk.append((t, paket("198.51.100.9", SERVER, 50000, 1000 + i, SYN)))
        pk.append((t + 0.001, paket(SERVER, "198.51.100.9", 1000 + i, 50000, RST | ACK)))
    # 3) DNS UDP
    pk.append((T0 + 5, paket(SERVER, "1.1.1.1", 53000, 53, udp=True, payload=40)))
    pk.append((T0 + 5.02, paket("1.1.1.1", SERVER, 53, 53000, udp=True, payload=120)))
    pk.sort(key=lambda x: x[0])
    f = tmp_path / "cap_uji.hdr.pcap.gz"
    tulis_pcap(f, pk)
    return f


def test_payload_dari_header_ip(rekaman):
    ps = list(baca_pcap(rekaman))
    assert len(ps) == 50
    assert ps[3].payload == 100 and ps[4].payload == 1000    # walau byte payload tidak disimpan


def test_aliran_http(rekaman):
    df, _ = ekstrak([rekaman], tampil=False)
    assert len(df) == 1 + 20 + 1
    r = df[df["Destination Port"] == 80].iloc[0]
    assert r["Source IP"] == "203.0.113.7"
    assert r["Flow Duration"] == 80_000
    assert (r["Total Fwd Packets"], r["Total Backward Packets"]) == (5, 3)
    assert (r["Total Length of Fwd Packets"], r["Total Length of Bwd Packets"]) == (100, 1000)
    assert r["Fwd Packet Length Max"] == 100 and r["Bwd Packet Length Max"] == 1000
    assert r["Flow IAT Max"] == 20_000 and r["Flow IAT Min"] == 10_000
    assert r["SYN Flag Count"] == 2 and r["FIN Flag Count"] == 2
    assert r["Init_Win_bytes_forward"] == 64240 and r["Init_Win_bytes_backward"] == 65160
    assert r["act_data_pkt_fwd"] == 1
    assert r["Fwd Header Length"] == 5 * 20 and r["min_seg_size_forward"] == 20
    assert r["Flow Bytes/s"] == pytest.approx(1100 / 0.08)


def test_udp_dan_scan(rekaman):
    df, _ = ekstrak([rekaman], tampil=False)
    dns = df[df["Destination Port"] == 53].iloc[0]
    assert dns["Init_Win_bytes_forward"] == -1 and dns["Fwd Header Length"] == 8
    assert (dns["Total Length of Fwd Packets"], dns["Total Length of Bwd Packets"]) == (40, 120)
    scan = df[df["Source IP"] == "198.51.100.9"]
    assert len(scan) == 20
    assert (scan["RST Flag Count"] == 1).all() and (scan["Total Length of Bwd Packets"] == 0).all()


def test_agregasi(rekaman):
    df, _ = ekstrak([rekaman], tampil=False)
    df = tambah_agregasi(df, jendela_detik=60)
    scan = df[df["Source IP"] == "198.51.100.9"].sort_values("Timestamp")
    akhir = scan.iloc[-1]
    assert akhir["agg_ip_aliran"] == 20 and akhir["agg_ip_port_unik"] == 20
    assert akhir["agg_ip_rasio_gagal"] == 1.0
    assert scan.iloc[0]["agg_ip_aliran"] == 1                # jendela hanya melihat ke belakang
    http = df[df["Destination Port"] == 80].iloc[0]
    assert http["agg_ip_aliran"] == 1 and http["agg_ip_rasio_gagal"] == 0
    # jendela 1 detik: hanya ~10 aliran scan terakhir yang terhitung
    df1 = tambah_agregasi(df[df.columns[:75]], jendela_detik=1)
    assert df1[df1["Source IP"] == "198.51.100.9"]["agg_ip_aliran"].max() == 10


def test_subnet():
    assert subnet("198.51.100.9") == "198.51.100.0/24"
    assert subnet("2a02:4780:5e:4c51::1") == "2a02:4780:5e:4c51::/64"
