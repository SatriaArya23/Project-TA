# -*- coding: utf-8 -*-
"""
Detektor: pipa (paket -> aliran berfitur) + model A+C + log anomali + notifikasi Telegram.

Aliran yang selesai ditampung lalu dinilai berkelompok (micro-batch): saat tampungan mencapai
`ukuran_batch` aliran, atau paling lambat `jeda_batch_detik` setelah aliran pertama masuk tampungan.
Menilai berkelompok jauh lebih cepat daripada satu per satu, sehingga sistem tetap mampu mengikuti
lalu lintas saat terjadi banjir paket, dengan tambahan latensi paling lama `jeda_batch_detik`.

Yang dinilai hanya aliran yang DIMULAI DARI LUAR (lalu lintas masuk ke server). Aliran yang dimulai server
sendiri (DNS, sinkronisasi waktu, unduhan pembaruan) tidak dinilai, karena fokus sistem adalah serangan
terhadap server. Alamat server diambil dari model (server_ip saat pelatihan) atau parameter `server_ip`.

Aliran dari IP tepercaya (nids.tepercaya, diatur administrator di dashboard) tetap dinilai dan dicatat,
tetapi tidak ditandai anomali sehingga juga tidak memicu notifikasi.
"""
from .pipa import Pipa


class Detektor:
    def __init__(self, model, log=None, notifikasi=None, ukuran_batch=256, jeda_batch_detik=1.0,
                 waktu_log="sekarang", server_ip=None, tepercaya=None):
        """waktu_log='sekarang' (deteksi langsung: t_log = jam dinding) atau 'selesai'
        (putar ulang: t_log = waktu aliran selesai disusun menurut rekaman)."""
        self.model, self.log, self.notifikasi = model, log, notifikasi
        self.pipa = Pipa(model.jendela_detik)
        self.ukuran_batch, self.jeda_batch = ukuran_batch, int(jeda_batch_detik * 1_000_000)
        self.waktu_log = waktu_log
        info = getattr(model, "info", None) or {}
        self.server_ip = set(server_ip if server_ip is not None else info.get("server_ip") or [])
        self.tampung, self.t_tampung = [], None
        self.tepercaya = tepercaya                   # DaftarTepercaya atau None
        self.jumlah_aliran = self.jumlah_anomali = self.jumlah_keluar = self.jumlah_tepercaya = 0
        self._sapu_terakhir = None
        if log is not None and hasattr(model, "ringkas"):
            log.catat_model(model.ringkas())

    def paket(self, p, kini_us=None):
        self._terima(self.pipa.paket(p), kini_us if kini_us is not None else p.ts)

    def detak(self, kini_us):
        """Dipanggil berkala (±1 detik): tutup aliran kedaluwarsa dan nilai tampungan yang menunggu."""
        if self._sapu_terakhir is None or kini_us - self._sapu_terakhir >= 1_000_000:
            self._sapu_terakhir = kini_us
            self._terima(self.pipa.sapu(kini_us), kini_us)
        if self.tampung and kini_us - self.t_tampung >= self.jeda_batch:
            self.nilai()

    def selesai(self):
        self._terima(self.pipa.selesai(), self.pipa.waktu_terakhir or 0)
        self.nilai()

    def _terima(self, aliran, kini_us):
        if aliran and self.server_ip:                       # koneksi yang dimulai server sendiri tidak dinilai
            masuk = [f for f in aliran if f["Source IP"] not in self.server_ip]
            self.jumlah_keluar += len(aliran) - len(masuk)
            aliran = masuk
        if not aliran:
            return
        if not self.tampung:
            self.t_tampung = kini_us
        self.tampung.extend(aliran)
        if len(self.tampung) >= self.ukuran_batch:
            self.nilai()

    def nilai(self):
        """Nilai seluruh tampungan; kembalikan list anomali (id, aliran, hasil)."""
        if not self.tampung:
            return []
        aliran, self.tampung = self.tampung, []
        hasil = list(self.model.nilai(aliran))
        self.jumlah_aliran += len(aliran)
        if self.tepercaya is not None:
            self.tepercaya.muat_ulang(paksa=False)
            for i, (f, h) in enumerate(zip(aliran, hasil)):
                if h[2] and self.tepercaya.cocok(f["Source IP"]):
                    hasil[i] = (h[0], h[1], "")          # skor tetap dicatat, tidak ditandai anomali
                    self.jumlah_tepercaya += 1
        anomali = []
        if self.log is not None:
            anomali = self.log.catat(aliran, hasil, self.model,
                                     waktu_log_us="selesai" if self.waktu_log == "selesai" else None)
        else:
            anomali = [(None, f, h) for f, h in zip(aliran, hasil) if h[2]]
        self.jumlah_anomali += len(anomali)
        if self.notifikasi is not None:
            self.notifikasi.anomali(anomali)
        return anomali
