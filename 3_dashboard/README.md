# 3_dashboard — Server Penerima Rekaman + Dashboard Web ASUNA (ta-nids-server)

Bagian server dari Tugas Akhir *NIDS Berbasis Machine Learning (studi kasus PT Hotdog Water Sport)* dengan antarmuka pemantauan **ASUNA**.
Server ini menerima berkas rekaman header paket dari perekam
[`vps-traffic-recorder`](https://github.com/Desa012/vps-traffic-recorder), mencatat setiap pengiriman, menyajikan *dashboard* NIDS (`Dual-IF`: `IF-Flow` dan `IF-Agg`), umpan balik model, serta halaman kelola blokir IP (`nftables`).

Alamat contoh pemasangan: **https://penerima.example.com**

| Fitur | Keterangan |
|---|---|
| Unggah | `PUT /api/v1/upload/<nama>`, HTTPS + token per instalasi, verifikasi SHA-256, tolak duplikat (409) |
| Token | Disimpan sebagai hash SHA-256; bisa dicabut kapan saja; token unggah tidak bisa membaca dan sebaliknya |
| Audit | Setiap unggahan (diterima/duplikat/ditolak), unduhan, aksi blokir IP, dan login dicatat: waktu, IP, pelaku, rincian |
| Akses baca | Dashboard login dan API token `read`; hak akses berbasis peran (**Admin / Analis / Pemantau**) |
| Statistik rekaman | Setiap berkas dihitung isinya saat diterima memakai pembaca pcap dari `2_sistem_nids` |
| Tampilan per hari | Rekaman per jam ditampilkan per hari (WITA) + grafik; **"unduh 1 hari"** menggabungkan rekaman menjadi satu `.pcap.gz` |
| Deteksi (`Dual-IF`) | Halaman **Deteksi**: status modul, aliran diperiksa & anomali per jam, IP teratas, saring model (`IF-Flow`, `IF-Agg`, `Dual-IF`), rincian IP, notifikasi Telegram ASUNA & latensinya, serta riwayat versi model |
| Blokir IP (`nftables`) | Halaman **Blokir IP** (khusus Admin): tambah atau buka blokir IP/CIDR (maksimal `/24` IPv4 dan `/64` IPv6) lewat antrean `ip_diblokir.json` yang dieksekusi layanan `nids-blokir` dengan proteksi *anti-lockout* |
| Umpan balik | Laporan **serangan lolos** / **alarm palsu** → pemeriksaan kuantil skor di modul deteksi → usulan ambang baru atau antrean `kasus_pelatihan_ulang.json` |
| Keamanan | `gunicorn` sebagai user `tanids` tanpa *root* (`127.0.0.1`), Nginx + HTTPS Let's Encrypt, CSP ketat, CSRF, batas percobaan login |

## Struktur

```
penerima/        aplikasi Flask (api.py = API, web.py = dashboard rekaman, deteksi.py = halaman Deteksi &
                 Umpan balik, db.py = SQLite, keamanan.py)
kelola.py        alat kelola instalasi, token, pengguna  (di server: sudo tanids-kelola ...)
wsgi.py          titik masuk gunicorn
deploy/          pasang.sh, unit systemd, templat nginx, pembungkus tanids-kelola
tests/           uji otomatis (python -m pytest -q tests)
```

Lokasi di server: kode `/opt/ta-nids-server`, konfigurasi `/etc/ta-nids-server/config.env`,
data `/var/lib/ta-nids-server/` (`penerima.db` + `berkas/<instalasi>/<nama>`).

## Pemasangan / pembaruan

```bash
# dari laptop: salin folder 3_dashboard DAN 2_sistem_nids (berdampingan) ke server, lalu di server (root):
sudo bash deploy/pasang.sh --domain penerima.example.com
```

Skrip aman dijalankan ulang (kunci rahasia, basis data, dan berkas dipertahankan). Skrip memasang
`python3-venv`, membuat user `tanids`, venv + Flask/gunicorn, layanan `ta-nids-server`, situs nginx
tersendiri, dan sertifikat Let's Encrypt (`certbot certonly --nginx`, diperpanjang otomatis). Konfigurasi
nginx diuji (`nginx -t`) sebelum dimuat dan dikembalikan bila gagal; situs lain di server tidak diubah.

## Mengelola

```bash
sudo tanids-kelola instalasi-tambah bali-hai --keterangan "PT Bali Cruises Nusantara"
sudo tanids-kelola instalasi-daftar
sudo tanids-kelola instalasi-nonaktif bali-hai
sudo tanids-kelola instalasi-ubah vps-satria --nama-baru hotdog-watersport --keterangan "Server VPS PT Hotdog Water Sport"
sudo tanids-kelola statistik-hitung            # hitung statistik berkas lama (sekali setelah pembaruan)

# token (tampil SEKALI; '--keluar -' = hanya token ke stdout, cocok untuk diarahkan ke berkas)
sudo tanids-kelola token-buat --peran upload --instalasi bali-hai --label bali-hai-server --keluar - > token.txt
sudo tanids-kelola token-buat --peran read   --instalasi bali-hai --label bali-hai-api-baca
sudo tanids-kelola token-daftar
sudo tanids-kelola token-cabut 6

# akun dashboard
sudo tanids-kelola pengguna-tambah paktut --peran viewer --instalasi bali-hai --sandi-acak
sudo tanids-kelola pengguna-tambah satria --peran admin            
sudo tanids-kelola pengguna-nonaktif paktut
```

## API

Semua respons JSON. Waktu dalam UTC (`YYYY-MM-DDTHH:MM:SSZ`).

### Unggah (token `upload`)

```
PUT /api/v1/upload/cap_YYYYMMDD_HHMMSS.hdr.pcap.gz
Authorization: Bearer <token>
Content-Type: application/gzip
X-Content-SHA256: <sha256 heksadesimal isi berkas>
```

| Kode | Arti |
|---|---|
| 201 | Diterima: `{"file","size","sha256","received_at"}` |
| 409 | Nama sudah ada untuk instalasi ini: data yang tersimpan dikembalikan (pengirim membandingkan sha256) |
| 400 / 411 / 413 / 415 | Nama tidak valid, header kurang, terlalu besar (> 512 MB), bukan gzip |
| 401 | Token salah, dicabut, atau instalasi nonaktif |
| 422 | Checksum tidak cocok (berkas tidak disimpan) |
| 507 | Disk penerima hampir penuh (pengirim mencoba lagi nanti) |

### Baca (token `read`)

| Endpoint | Isi |
|---|---|
| `GET /api/v1/summary` | per instalasi: jumlah berkas, total byte, pertama/terakhir diterima, jumlah 24 jam |
| `GET /api/v1/files?since=&until=&installation=&limit=&offset=` | daftar berkas diterima (terbaru dulu, maks 1000 per halaman) |
| `GET /api/v1/files/<id>/download` | unduh berkas (tercatat di audit) |
| `GET /api/v1/audit?since=&until=&limit=&offset=` | catatan audit |
| `GET /api/v1/health` | tanpa token, untuk pemantauan |

Token `read` yang terikat ke satu instalasi hanya melihat data instalasi itu (parameter `installation`
diabaikan). Contoh:

```bash
curl -H "Authorization: Bearer $(cat token-api-baca.txt)" "https://penerima.example.com/api/v1/files?since=2026-10-24"
```

## Uji

```bash
pip install flask pytest
python -m pytest -q tests        # 49 uji: kontrak unggah, token, lingkup baca, dashboard ASUNA, CSRF,
                                 # batas login, statistik rekaman, tampilan per hari, unduh gabungan,
                                 # halaman Deteksi Dual-IF, Blokir IP (nftables) & anti-lockout,
                                 # loop umpan balik, serta hak akses RBAC
```

## Rencana lanjutan

- B2: halaman pencocokan audit pengirim vs penerima, grafik volume per jam.
- Halaman Deteksi aktif setelah `2_sistem_nids/deploy/pasang-deteksi.sh` dijalankan di server yang sama
  (skrip itu menambahkan user `tanids` ke grup `nids` agar log deteksi bisa dibaca).

Data disimpan selama masa Tugas Akhir, lalu dihapus sesuai kesepakatan dengan perusahaan.
