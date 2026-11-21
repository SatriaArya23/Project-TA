# -*- coding: utf-8 -*-
"""
Penyusun aliran (flow) dan penghitung 68 fitur aliran.

Definisi fitur mengikuti CICFlowMeter (alat yang dipakai untuk membuat
dataset CIC-IDS2017), sehingga nama kolomnya sama dengan model CIC-IDS2017:

* Aliran = kumpulan paket dengan 5 unsur yang sama (IP sumber, IP tujuan,
  port sumber, port tujuan, protokol), dua arah. Pengirim paket pertama
  dianggap arah maju (forward / Fwd), lawannya arah balik (backward / Bwd).
* "Panjang paket" = panjang payload (tanpa header), seperti CICFlowMeter.
* Satuan waktu = mikrodetik.
* Aliran ditutup bila: sudah 120 detik sejak paket pertama (flow timeout),
  ada flag RST, atau kedua pihak sudah mengirim FIN.
* Periode aktif/diam dipisah oleh jeda lebih dari 5 detik (activity timeout).

Perbedaan kecil yang disengaja dengan CICFlowMeter versi 2017:
* Bila durasi aliran 0 (aliran 1 paket), laju per detik dihitung dengan
  durasi 1 mikrodetik, bukan menghasilkan inf/NaN. Dengan begitu aliran
  pemindaian satu paket tetap bisa dinilai model, tidak dibuang.
* Subflow dipisah oleh jeda lebih dari 1 detik; nilai subflow = total / jumlah subflow.
"""
import math
from datetime import datetime, timezone

from .pcap import FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, TCP

FLOW_TIMEOUT = 120_000_000      # 120 detik
ACTIVITY_TIMEOUT = 5_000_000    # 5 detik
SUBFLOW_GAP = 1_000_000         # 1 detik
SISA_SETELAH_TUTUP = 5_000_000  # paket ACK terakhir setelah FIN masih digabung ke aliran lama

FITUR = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Fwd URG Flags", "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]
METADATA = ["Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port",
            "Protocol", "Timestamp"]


def _stat(xs):
    """(maks, min, rata-rata, simpangan baku sampel) - 0 bila kosong."""
    n = len(xs)
    if n == 0:
        return 0, 0, 0.0, 0.0
    m = sum(xs) / n
    sd = math.sqrt(sum((x - m) ** 2 for x in xs) / (n - 1)) if n > 1 else 0.0
    return max(xs), min(xs), m, sd


def _selisih(ts):
    return [b - a for a, b in zip(ts, ts[1:])]


class Aliran:
    __slots__ = ("src", "dst", "sport", "dport", "proto", "mulai", "akhir",
                 "fwd_len", "bwd_len", "fwd_ts", "bwd_ts", "semua_ts", "semua_len",
                 "fwd_hdr", "bwd_hdr", "flag", "fwd_psh", "fwd_urg",
                 "win_fwd", "win_bwd", "act_fwd", "aktif", "diam", "a_mulai", "a_akhir",
                 "subflow", "fin_fwd", "fin_bwd", "tutup")

    def __init__(self, p):
        self.src, self.dst, self.sport, self.dport, self.proto = p.src, p.dst, p.sport, p.dport, p.proto
        self.mulai = self.akhir = p.ts
        self.fwd_len, self.bwd_len, self.fwd_ts, self.bwd_ts = [], [], [], []
        self.semua_ts, self.semua_len = [], []
        self.fwd_hdr, self.bwd_hdr = [], []
        self.flag = dict.fromkeys(("FIN", "SYN", "RST", "PSH", "ACK", "URG", "CWE", "ECE"), 0)
        self.fwd_psh = self.fwd_urg = self.act_fwd = 0
        self.win_fwd = self.win_bwd = -1
        self.aktif, self.diam = [], []
        self.a_mulai = self.a_akhir = p.ts
        self.subflow = 1
        self.fin_fwd = self.fin_bwd = False
        self.tutup = False
        self.tambah(p)

    def maju(self, p):
        return p.src == self.src and p.sport == self.sport

    def tambah(self, p):
        if self.semua_ts:
            if p.ts - self.akhir > SUBFLOW_GAP:
                self.subflow += 1
            if p.ts - self.a_akhir > ACTIVITY_TIMEOUT:      # periode aktif selesai
                if self.a_akhir - self.a_mulai > 0:
                    self.aktif.append(self.a_akhir - self.a_mulai)
                self.diam.append(p.ts - self.a_akhir)
                self.a_mulai = self.a_akhir = p.ts
            else:
                self.a_akhir = p.ts
        self.akhir = p.ts
        self.semua_ts.append(p.ts)
        self.semua_len.append(p.payload)
        f = p.flags
        if self.proto == TCP:
            for nama, bit in (("FIN", FIN), ("SYN", SYN), ("RST", RST), ("PSH", PSH),
                              ("ACK", ACK), ("URG", URG), ("CWE", CWR), ("ECE", ECE)):
                if f & bit:
                    self.flag[nama] += 1
        if self.maju(p):
            self.fwd_len.append(p.payload); self.fwd_ts.append(p.ts); self.fwd_hdr.append(p.hdr)
            if f & PSH: self.fwd_psh += 1
            if f & URG: self.fwd_urg += 1
            if p.payload >= 1: self.act_fwd += 1
            if self.win_fwd < 0 and self.proto == TCP: self.win_fwd = p.win
            if f & FIN: self.fin_fwd = True
        else:
            self.bwd_len.append(p.payload); self.bwd_ts.append(p.ts); self.bwd_hdr.append(p.hdr)
            if self.win_bwd < 0 and self.proto == TCP: self.win_bwd = p.win
            if f & FIN: self.fin_bwd = True
        if f & RST or (self.fin_fwd and self.fin_bwd):
            self.tutup = True

    def fitur(self):
        dur = self.akhir - self.mulai
        dets = max(dur, 1) / 1_000_000
        nf, nb = len(self.fwd_len), len(self.bwd_len)
        bf, bb = sum(self.fwd_len), sum(self.bwd_len)
        fmax, fmin, fmean, fstd = _stat(self.fwd_len)
        bmax, bmin, bmean, bstd = _stat(self.bwd_len)
        amax, amin, amean, astd = _stat(self.semua_len)
        imax, imin, imean, istd = _stat(_selisih(self.semua_ts))
        fi = _selisih(self.fwd_ts); bi = _selisih(self.bwd_ts)
        fimax, fimin, fimean, fistd = _stat(fi)
        bimax, bimin, bimean, bistd = _stat(bi)
        aktif = self.aktif + ([self.a_akhir - self.a_mulai] if self.a_akhir - self.a_mulai > 0 else [])
        acmax, acmin, acmean, acstd = _stat(aktif)
        idmax, idmin, idmean, idstd = _stat(self.diam)
        n = nf + nb
        nilai = [
            dur, nf, nb, bf, bb,
            fmax, fmin, fmean, fstd, bmax, bmin, bmean, bstd,
            (bf + bb) / dets, n / dets,
            imean, istd, imax, imin,
            sum(fi), fimean, fistd, fimax, fimin,
            sum(bi), bimean, bistd, bimax, bimin,
            self.fwd_psh, self.fwd_urg, sum(self.fwd_hdr), sum(self.bwd_hdr),
            nf / dets, nb / dets,
            amin, amax, amean, astd, astd ** 2,
            self.flag["FIN"], self.flag["SYN"], self.flag["RST"], self.flag["PSH"], self.flag["ACK"],
            self.flag["URG"], self.flag["CWE"], self.flag["ECE"],
            nb / nf if nf else 0, (bf + bb) / n, fmean, bmean,
            nf / self.subflow, bf / self.subflow, nb / self.subflow, bb / self.subflow,
            self.win_fwd, self.win_bwd, self.act_fwd, min(self.fwd_hdr) if self.fwd_hdr else 0,
            acmean, acstd, acmax, acmin,
            idmean, idstd, idmax, idmin,
        ]
        meta = {
            "Flow ID": "%s-%s-%d-%d-%d" % (self.src, self.dst, self.sport, self.dport, self.proto),
            "Source IP": self.src, "Source Port": self.sport,
            "Destination IP": self.dst, "Destination Port": self.dport,
            "Protocol": self.proto,
            "Timestamp": datetime.fromtimestamp(self.mulai / 1e6, timezone.utc)
                                 .strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "_mulai_us": self.mulai,                 # waktu paket pertama (untuk log & latensi)
        }
        meta.update(zip(FITUR, nilai))
        return meta


def _kunci(p):
    a, b = (p.src, p.sport), (p.dst, p.dport)
    return (p.proto,) + ((a, b) if a <= b else (b, a))


class PenyusunAliran:
    """Masukkan paket berurutan waktu dengan .masuk(p); aliran selesai
    dikembalikan sebagai daftar dict (metadata + 68 fitur)."""

    def __init__(self):
        self.aktif = {}
        self._hitung = 0

    def masuk(self, p):
        selesai = []
        k = _kunci(p)
        a = self.aktif.get(k)
        if a is not None:
            habis = p.ts - a.mulai > FLOW_TIMEOUT
            syn_baru = p.proto == TCP and (p.flags & SYN) and not (p.flags & ACK)
            if habis or (a.tutup and (syn_baru or p.ts - a.akhir > SISA_SETELAH_TUTUP)):
                selesai.append(a.fitur())
                a = None
        if a is None:
            self.aktif[k] = Aliran(p)
        else:
            a.tambah(p)
        self._hitung += 1
        if self._hitung % 5000 == 0:
            selesai += self.sapu(p.ts)
        return selesai

    def sapu(self, sekarang):
        """Tutup aliran yang sudah kedaluwarsa pada waktu `sekarang`."""
        keluar = []
        for k, a in list(self.aktif.items()):
            if (sekarang - a.mulai > FLOW_TIMEOUT or sekarang - a.akhir > FLOW_TIMEOUT
                    or (a.tutup and sekarang - a.akhir > SISA_SETELAH_TUTUP)):
                keluar.append(a.fitur())
                del self.aktif[k]
        return keluar

    def selesaikan(self):
        """Tutup semua aliran yang tersisa (akhir rekaman)."""
        keluar = [a.fitur() for a in self.aktif.values()]
        self.aktif.clear()
        return keluar
