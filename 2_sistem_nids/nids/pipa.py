# -*- coding: utf-8 -*-
"""
Pipa pemrosesan: paket -> aliran (68 fitur) -> fitur agregasi berjalan (7 fitur).

Dipakai dengan cara yang sama untuk:
  * deteksi langsung  : paket datang dari tcpdump, waktu = jam dinding
  * putar ulang       : paket dibaca dari rekaman .pcap.gz, waktu = waktu paket
Karena kodenya sama, fitur yang dipakai untuk melatih model (hasil putar ulang
rekaman) identik dengan fitur yang dilihat model saat deteksi langsung.
"""
from .agregasi import FITUR_AGREGASI, AgregatorJendela
from .aliran import FITUR, METADATA, PenyusunAliran
from .pcap import baca_pcap

KOLOM = METADATA + ["Waktu Selesai"] + FITUR + FITUR_AGREGASI


class Pipa:
    def __init__(self, jendela_detik=300):
        self.jendela_detik = jendela_detik
        self.penyusun = PenyusunAliran()
        self.agregator = AgregatorJendela(jendela_detik)
        self.jumlah_paket = 0
        self.jumlah_aliran = 0
        self.waktu_terakhir = None

    def _lengkapi(self, daftar, waktu_us):
        for f in daftar:
            f["Waktu Selesai"] = waktu_us
            self.agregator.tambah(f, waktu_us)
        self.jumlah_aliran += len(daftar)
        return daftar

    def paket(self, p):
        """Masukkan satu paket; kembalikan aliran yang selesai (sudah berfitur lengkap)."""
        self.jumlah_paket += 1
        self.waktu_terakhir = p.ts
        return self._lengkapi(self.penyusun.masuk(p), p.ts)

    def sapu(self, waktu_us):
        """Tutup aliran yang sudah kedaluwarsa pada waktu ini (dipanggil berkala)."""
        return self._lengkapi(self.penyusun.sapu(waktu_us), waktu_us)

    def selesai(self):
        """Akhir rekaman: tutup semua aliran yang tersisa."""
        t = self.waktu_terakhir or 0
        return self._lengkapi(self.penyusun.selesaikan(), t)


def putar_ulang(berkas, jendela_detik=300, setiap_aliran=None):
    """Proses rekaman berurutan dan hasilkan semua aliran berfitur lengkap (list of dict).
    `setiap_aliran(daftar)` opsional dipanggil setiap ada aliran selesai."""
    pipa = Pipa(jendela_detik)
    semua = []

    def kumpul(daftar):
        if daftar:
            semua.extend(daftar)
            if setiap_aliran:
                setiap_aliran(daftar)

    sapu_terakhir = None
    for f in berkas:
        for p in baca_pcap(f):
            kumpul(pipa.paket(p))
            if sapu_terakhir is None or p.ts - sapu_terakhir >= 1_000_000:    # sama seperti detak deteksi langsung
                sapu_terakhir = p.ts
                kumpul(pipa.sapu(p.ts))
    kumpul(pipa.selesai())
    return semua, pipa
