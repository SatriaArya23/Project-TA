# -*- coding: utf-8 -*-
"""
Pembaca berkas pcap (juga .pcap.gz) tanpa pustaka tambahan.

Setiap paket diringkas menjadi objek Paket berisi informasi header saja:
waktu, alamat IP, port, protokol, flag TCP, ukuran jendela TCP,
panjang header transport, dan panjang payload.

Panjang payload dihitung dari kolom panjang di header IP, bukan dari jumlah
byte yang tersimpan. Jadi hasilnya tetap benar untuk rekaman yang payload-nya
sudah dikosongkan oleh strip_payload.py.

Hanya paket TCP dan UDP yang dikembalikan (sama seperti CICFlowMeter).
"""
import gzip
import ipaddress
import struct
from dataclasses import dataclass

# link-type pcap
LT_ETHERNET, LT_RAW, LT_RAW_ALT, LT_IPV4, LT_IPV6, LT_SLL, LT_SLL2 = 1, 101, 12, 228, 229, 113, 276
ETH_IPV4, ETH_IPV6 = 0x0800, 0x86DD
ETH_VLAN = (0x8100, 0x88A8, 0x9100)
EXT_IPV6 = (0, 43, 60)          # hop-by-hop, routing, destination options
TCP, UDP = 6, 17

# flag TCP
FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80


@dataclass(slots=True)
class Paket:
    ts: int            # waktu dalam mikrodetik sejak epoch (UTC)
    src: str
    dst: str
    sport: int
    dport: int
    proto: int         # 6 = TCP, 17 = UDP
    flags: int         # flag TCP (0 untuk UDP)
    win: int           # ukuran jendela TCP (0 untuk UDP)
    hdr: int           # panjang header transport (byte)
    payload: int       # panjang payload (byte)


def _buka(path):
    with open(path, "rb") as f:
        gz = f.read(2) == b"\x1f\x8b"
    return gzip.open(path, "rb") if gz else open(path, "rb")


def _awal_ip(linktype, d):
    """Kembalikan (offset header IP, versi IP) atau (None, None)."""
    if linktype == LT_ETHERNET:
        if len(d) < 14:
            return None, None
        off, et = 14, struct.unpack_from("!H", d, 12)[0]
        while et in ETH_VLAN and len(d) >= off + 4:
            et = struct.unpack_from("!H", d, off + 2)[0]
            off += 4
        return off, {ETH_IPV4: 4, ETH_IPV6: 6}.get(et)
    if linktype == LT_SLL:
        if len(d) < 16:
            return None, None
        return 16, {ETH_IPV4: 4, ETH_IPV6: 6}.get(struct.unpack_from("!H", d, 14)[0])
    if linktype == LT_SLL2:
        if len(d) < 20:
            return None, None
        return 20, {ETH_IPV4: 4, ETH_IPV6: 6}.get(struct.unpack_from("!H", d, 0)[0])
    if linktype in (LT_RAW, LT_RAW_ALT, LT_IPV4, LT_IPV6):
        if not d:
            return None, None
        v = d[0] >> 4
        return 0, (v if v in (4, 6) else None)
    raise ValueError("link-type %d tidak didukung" % linktype)


def _urai(linktype, d, ts):
    off, ver = _awal_ip(linktype, d)
    if ver is None:
        return None
    if ver == 4:
        if len(d) < off + 20:
            return None
        ihl = (d[off] & 0x0F) * 4
        total = struct.unpack_from("!H", d, off + 2)[0]
        if struct.unpack_from("!H", d, off + 6)[0] & 0x1FFF:      # fragmen lanjutan
            return None
        proto = d[off + 9]
        src = ipaddress.IPv4Address(d[off + 12:off + 16]).compressed
        dst = ipaddress.IPv4Address(d[off + 16:off + 20]).compressed
        l4, sisa = off + ihl, total - ihl
    else:
        if len(d) < off + 40:
            return None
        sisa = struct.unpack_from("!H", d, off + 4)[0]
        proto = d[off + 6]
        src = ipaddress.IPv6Address(d[off + 8:off + 24]).compressed
        dst = ipaddress.IPv6Address(d[off + 24:off + 40]).compressed
        l4 = off + 40
        while proto in EXT_IPV6 and len(d) >= l4 + 2:
            n = (d[l4 + 1] + 1) * 8
            proto, l4, sisa = d[l4], l4 + n, sisa - n
        if proto == 44:                                            # header fragmen
            if len(d) < l4 + 8 or struct.unpack_from("!H", d, l4 + 2)[0] & 0xFFF8:
                return None
            proto, l4, sisa = d[l4], l4 + 8, sisa - 8
    if proto == TCP:
        if len(d) < l4 + 16:
            return None
        sport, dport = struct.unpack_from("!HH", d, l4)
        hdr = (d[l4 + 12] >> 4) * 4
        flags = d[l4 + 13]
        win = struct.unpack_from("!H", d, l4 + 14)[0]
    elif proto == UDP:
        if len(d) < l4 + 4:
            return None
        sport, dport = struct.unpack_from("!HH", d, l4)
        hdr, flags, win = 8, 0, 0
    else:
        return None
    return Paket(ts, src, dst, sport, dport, proto, flags, win, hdr, max(0, sisa - hdr))


def baca_pcap(sumber):
    """Hasilkan Paket satu per satu dari berkas pcap / pcap.gz (path), atau dari objek berkas
    biner yang sedang mengalir, misalnya keluaran `tcpdump -U -w -` (deteksi langsung)."""
    if hasattr(sumber, "read"):
        yield from _baca_dari(sumber, "aliran masukan")
    else:
        with _buka(sumber) as f:
            yield from _baca_dari(f, sumber)


def _baca_dari(f, nama):
    gh = f.read(24)
    if len(gh) < 24:
        return
    magic = gh[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        e = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        e = ">"
    else:
        raise ValueError("%s bukan berkas pcap (pcapng tidak didukung)" % nama)
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack(e + "I", gh[20:24])[0] & 0x0FFFFFFF
    rec = struct.Struct(e + "IIII")
    while True:
        h = f.read(16)
        if len(h) < 16:
            return
        sec, frac, incl, _orig = rec.unpack(h)
        d = f.read(incl)
        if len(d) < incl:
            return
        ts = sec * 1_000_000 + (frac // 1000 if nano else frac)
        p = _urai(linktype, d, ts)
        if p is not None:
            yield p
