# -*- coding: utf-8 -*-
"""
Fitur agregasi jendela waktu (Tabel 3.5 BAB III).

Untuk setiap aliran dihitung perilaku sumbernya dalam W detik terakhir
(termasuk aliran itu sendiri):

  Per IP sumber
    agg_ip_aliran       jumlah aliran
    agg_ip_port_unik    jumlah port tujuan yang berbeda
    agg_ip_rasio_gagal  proporsi aliran yang ditolak / tidak dibalas
    agg_ip_aliran_ssh   jumlah aliran menuju port 22
  Per subnet sumber (/24 untuk IPv4, /64 untuk IPv6)
    agg_s24_ip_unik     jumlah alamat IP sumber yang berbeda
    agg_s24_aliran      jumlah aliran
    agg_s24_port_unik   jumlah port tujuan yang berbeda

Aliran "gagal" = tidak ada paket balasan sama sekali, atau ditutup RST
tanpa ada data balasan. Ini pola khas port tertutup / koneksi ditolak.

Masukan cukup kolom: Source IP, Destination Port, Timestamp,
Total Backward Packets, Total Length of Bwd Packets, RST Flag Count.
Jadi fungsi yang sama bisa dipakai untuk rekaman server maupun CIC-IDS2017
versi yang memuat IP sumber dan waktu.
"""
from collections import Counter, deque

import numpy as np
import pandas as pd

FITUR_AGREGASI = ["agg_ip_aliran", "agg_ip_port_unik", "agg_ip_rasio_gagal", "agg_ip_aliran_ssh",
                  "agg_s24_ip_unik", "agg_s24_aliran", "agg_s24_port_unik"]


def subnet(ip):
    ip = str(ip)
    if ":" in ip:                                   # IPv6 -> /64 (4 blok pertama)
        blok = (ip.split("::")[0].split(":") + ["0"] * 4)[:4]
        return ":".join(blok) + "::/64"
    return ip.rsplit(".", 1)[0] + ".0/24"


def _jendela(t, W):
    """Untuk tiap indeks i (t sudah urut): rentang [lo, hi) aliran dengan
    waktu dalam (t[i]-W, t[i]], termasuk aliran lain yang waktunya sama."""
    n = len(t)
    lo = np.searchsorted(t, t - W, side="right")
    hi = np.searchsorted(t, t, side="right")
    return lo, hi, n


def _hitung_grup(t, port, gagal, ssh, ipsrc, W, per_ip):
    lo, hi, n = _jendela(t, W)
    # jumlah & proporsi: pakai jumlah kumulatif
    cg = np.concatenate([[0], np.cumsum(gagal)])
    cs = np.concatenate([[0], np.cumsum(ssh)])
    jml = hi - lo
    hasil = {"aliran": jml}
    if per_ip:
        hasil["rasio_gagal"] = (cg[hi] - cg[lo]) / jml
        hasil["aliran_ssh"] = cs[hi] - cs[lo]
    # jumlah nilai unik: jendela geser dengan penghitung
    port_unik = np.empty(n, dtype=np.int64)
    ip_unik = np.empty(n, dtype=np.int64)
    cp, ci = Counter(), Counter()
    a = b = 0
    for i in range(n):
        while b < hi[i]:
            cp[port[b]] += 1; ci[ipsrc[b]] += 1; b += 1
        while a < lo[i]:
            for c, v in ((cp, port[a]), (ci, ipsrc[a])):
                c[v] -= 1
                if c[v] == 0:
                    del c[v]
            a += 1
        port_unik[i] = len(cp)
        ip_unik[i] = len(ci)
    hasil["port_unik"] = port_unik
    if not per_ip:
        hasil["ip_unik"] = ip_unik
    return hasil


def tambah_agregasi(df, jendela_detik=60):
    """Kembalikan salinan df dengan 7 kolom FITUR_AGREGASI."""
    W = int(jendela_detik * 1_000_000)
    d = df.reset_index(drop=True)
    ts = pd.to_datetime(d["Timestamp"], utc=True, format="mixed")
    t = ((ts - pd.Timestamp("1970-01-01", tz="UTC")) // pd.Timedelta(microseconds=1)).to_numpy()
    gagal = ((d["Total Backward Packets"] == 0) |
             ((d["RST Flag Count"] > 0) & (d["Total Length of Bwd Packets"] == 0))).to_numpy(np.int64)
    port = d["Destination Port"].to_numpy()
    ssh = (port == 22).astype(np.int64)
    ip = d["Source IP"].astype(str).to_numpy()
    s24 = pd.Series(ip).map(subnet).to_numpy()
    keluar = {c: np.zeros(len(d)) for c in FITUR_AGREGASI}

    for kunci, per_ip, awalan in ((ip, True, "agg_ip_"), (s24, False, "agg_s24_")):
        for idx in pd.Series(np.arange(len(d))).groupby(kunci, sort=False).indices.values():
            idx = idx[np.argsort(t[idx], kind="stable")]
            h = _hitung_grup(t[idx], port[idx], gagal[idx], ssh[idx], ip[idx], W, per_ip)
            for nama, nilai in h.items():
                if awalan + nama in keluar:
                    keluar[awalan + nama][idx] = nilai
    for c in FITUR_AGREGASI:
        d[c] = keluar[c]
    return d


# ============================================================================ versi berjalan (real-time)
def gagal(f):
    """Aliran tidak dibalas sama sekali, atau ditolak RST tanpa data balasan."""
    return f["Total Backward Packets"] == 0 or (f["RST Flag Count"] > 0 and f["Total Length of Bwd Packets"] == 0)


class _Jendela:
    """Isi jendela geser untuk satu kunci (satu IP atau satu subnet)."""
    __slots__ = ("isi", "gagal", "ssh", "port", "ip")

    def __init__(self):
        self.isi = deque()            # (waktu, port, gagal, ssh, ip)
        self.gagal = self.ssh = 0
        self.port, self.ip = Counter(), Counter()

    def tambah(self, e):
        self.isi.append(e)
        self.gagal += e[2]; self.ssh += e[3]
        self.port[e[1]] += 1; self.ip[e[4]] += 1

    def buang_sebelum(self, batas):
        while self.isi and self.isi[0][0] <= batas:
            _, port, g, s, ip = self.isi.popleft()
            self.gagal -= g; self.ssh -= s
            for c, k in ((self.port, port), (self.ip, ip)):
                c[k] -= 1
                if not c[k]:
                    del c[k]


class AgregatorJendela:
    """Fitur agregasi yang diperbarui satu aliran demi satu aliran (untuk deteksi langsung).

    Waktu acuan = saat aliran SELESAI disusun (waktu paket terakhir / waktu sapuan),
    karena saat itulah aliran baru dapat dinilai. Untuk setiap aliran yang masuk,
    fitur dihitung dari aliran-aliran yang selesai dalam W detik terakhir dari IP /
    subnet yang sama, termasuk aliran itu sendiri.

    Mode putar-ulang (rekaman) memakai kelas yang sama, sehingga fitur untuk melatih
    model dan fitur saat deteksi langsung dihitung dengan cara yang identik.
    """

    def __init__(self, jendela_detik=300):
        self.W = int(jendela_detik * 1_000_000)
        self.per_ip, self.per_subnet = {}, {}
        self._hitung = 0

    def tambah(self, aliran, waktu_us):
        """Lengkapi dict `aliran` dengan 7 fitur agregasi (diubah di tempat) dan kembalikan."""
        ip = aliran["Source IP"]
        e = (waktu_us, aliran["Destination Port"], int(gagal(aliran)), int(aliran["Destination Port"] == 22), ip)
        batas = waktu_us - self.W
        a = self.per_ip.setdefault(ip, _Jendela())
        b = self.per_subnet.setdefault(subnet(ip), _Jendela())
        for j in (a, b):
            j.buang_sebelum(batas)
            j.tambah(e)
        n = len(a.isi)
        aliran.update({
            "agg_ip_aliran": n, "agg_ip_port_unik": len(a.port), "agg_ip_rasio_gagal": a.gagal / n,
            "agg_ip_aliran_ssh": a.ssh,
            "agg_s24_ip_unik": len(b.ip), "agg_s24_aliran": len(b.isi), "agg_s24_port_unik": len(b.port),
        })
        self._hitung += 1
        if self._hitung % 10_000 == 0:
            self.bersihkan(waktu_us)
        return aliran

    def bersihkan(self, waktu_us):
        """Buang kunci yang jendelanya sudah kosong (hemat memori saat berjalan lama)."""
        batas = waktu_us - self.W
        for d in (self.per_ip, self.per_subnet):
            for k in list(d):
                d[k].buang_sebelum(batas)
                if not d[k].isi:
                    del d[k]
