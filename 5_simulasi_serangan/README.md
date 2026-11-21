# 5_simulasi_serangan — Simulasi serangan terkendali & evaluasi

Alat untuk **menguji sistem NIDS di VPS uji milik peneliti**. Serangan dijalankan dari laptop ke VPS uji, dan setiap
skenario dicatat otomatis (waktu mulai/selesai + IP sumber) di `05_Data_Eksperimen\Server-Uji\jadwal_serangan.csv`.
Catatan itu menjadi **kunci jawaban** untuk menghitung precision, recall, F1-score, FPR, dan latensi.

> ⚠️ Target dibatasi di kode (`TARGET_DIIZINKAN`): hanya VPS uji milik peneliti (dan 127.0.0.1 untuk uji).
> **Jangan** diarahkan ke server perusahaan atau server orang lain. **Jangan** dijalankan saat baseline sedang direkam
> (sampai 8 Nov 2026 15.29 WITA).

| Berkas | Isinya apa |
|---|---|
| `simulasi.py` | Menjalankan satu skenario dan mencatatnya ke jadwal |
| `ambil_log.py` | Menyalin log deteksi dari VPS uji ke laptop (`Server-Uji\hasil\deteksi_vps_uji.db`) |
| `evaluasi.py` | Pelabelan aliran berdasarkan jadwal + perhitungan metrik (dipakai notebook 06) |
| `tests\` | Uji otomatis (berjalan di laptop sendiri, tidak ke server) |

## Skenario

| Skenario | Yang dilakukan | Bawaan | Batas atas |
|---|---|---|---|
| `normal` | Pengunjung web biasa: membuka halaman 1–3 kali per sesi, jeda baca 2–8 detik | 10 sesi, jeda 20 s | – |
| `portscan` | Pemindaian port TCP cepat | port 1–1000, 50 port/s | 200/s |
| `portscan-lambat` | Pemindaian port acak, pelan | 30 port, jeda 30 s | – |
| `ssh-bruteforce` | Percobaan login SSH dengan sandi acak (selalu salah) | 40 kali, jeda 1,5 s, user `uji` | 300 kali |
| `dos-http` | Banjir permintaan HTTP skala kecil ke halaman web | 50 permintaan/s selama 60 s | 300/s, 300 s |

## Urutan pengujian (setelah 8 Nov)

1. Latih ulang model VPS uji dari baseline baru, lalu pasang di server (saya bantu).
2. Jalankan skenario satu per satu dari PowerShell, **beri jeda ≥ 15 menit** antarskenario supaya jendela waktunya
   tidak bercampur dan jeda notifikasi Telegram (10 menit per IP) sudah habis. Jangan membuka SSH ke VPS uji selama
   skenario berjalan (supaya aliran SSH Anda tidak tercampur dengan serangan).
   ```powershell
   cd D:\KULIAH\TA\04_Kode\5_simulasi_serangan
   python simulasi.py normal
   python simulasi.py portscan
   python simulasi.py ssh-bruteforce
   python simulasi.py dos-http
   python simulasi.py portscan-lambat
   python simulasi.py normal
   python simulasi.py jadwal            # lihat catatan
   ```
   Disarankan mengulang setiap skenario 3 kali (hari/jam berbeda) supaya hasilnya tidak kebetulan.
3. `python ambil_log.py`
4. Buka `04_Kode\4_notebook\06_Evaluasi_VPS_Uji.ipynb` → Run All.

Pustaka: `pip install paramiko pandas matplotlib`. Uji: `python -m pytest -q tests`.
