# 2_sistem_nids — Sistem NIDS (deteksi real-time Isolation Forest A+C)

Program yang memantau lalu lintas server secara *real-time*:

```
tcpdump (header) ─► pcap.py ─► aliran.py ─► agregasi.py ─► Model A + C ─► log SQLite ─► Telegram
 (penangkap paket)   (baca)     (68 fitur)   (7 fitur,       (model.py,     (log_anomali)  (telegram.py)
                                              300 detik)      detektor.py)        │
                                                                                   └──► dashboard (folder 3_dashboard)
rekaman .pcap.gz ─┘  (putar ulang: pipa yang SAMA, untuk membuat data latih dan pengujian)
```

Penjelasan setiap berkas dengan bahasa sederhana: lihat `..\README.md` (peta kode).
Di server nama folder dan layanannya `nids-deteksi` (`/opt/nids-deteksi`, `systemctl status nids-deteksi`).

## Program yang dijalankan

| Program | Kegunaan |
|---|---|
| `deteksi.py langsung` | Deteksi real-time di server (dijalankan otomatis oleh layanan `nids-deteksi`) |
| `deteksi.py putar-ulang` | Memproses rekaman dengan pipa yang sama: membuat tabel fitur (`--fitur`) atau menguji model (`--model --log`) |
| `latih_model.py` | Melatih Model A + C dari tabel fitur, dengan pembersihan sumber serangan intens |
| `latih_model.py --umpan-balik kasus.json` | **Modul pelatihan ulang** dari kasus umpan balik dashboard |
| `ubah_ambang.py` | Menerapkan usulan ambang dari halaman Umpan balik sebagai versi model baru (tanpa latih ulang) |

```powershell
cd D:\KULIAH\TA\04_Kode\2_sistem_nids
python -m pytest -q tests                                                    # 16 uji otomatis
$R = "..\..\05_Data_Eksperimen\Server-Uji"
python deteksi.py putar-ulang "$R\rekaman" --fitur "$R\hasil\fitur.parquet"   # rekaman -> tabel fitur
python latih_model.py "$R\hasil\fitur.parquet" --keluar "$R\hasil\model.joblib"
python deteksi.py putar-ulang "$R\rekaman" --model "$R\hasil\model.joblib" --log "$R\hasil\uji.db"
```

Cara yang sama (dengan penjelasan dan tabel) ada di notebook `..\4_notebook\03_*`, `04_*`, dan `05_Cara_Kerja_NIDS.ipynb`.

## Pemasangan di server

```bash
# salin folder 2_sistem_nids (dan 3_dashboard bila dashboard ikut dipasang) ke server, lalu sebagai root:
sudo bash deploy/pasang-deteksi.sh --nama-server "VPS Uji" --latih fitur.parquet
# Telegram: isi /etc/nids-deteksi/rahasia.env (izin 600) lalu: systemctl restart nids-deteksi
#   TELEGRAM_TOKEN=...
#   TELEGRAM_CHAT_ID=...
```

`--latih` melatih model di server itu sendiri (versi scikit-learn sama dengan modul deteksi). Skrip juga memberi
dashboard izin baca ke log deteksi (`/var/lib/nids-deteksi/deteksi.db`). Layanan berjalan tanpa root, hanya dengan
izin menangkap paket (CAP_NET_RAW/CAP_NET_ADMIN).

## Rancangan model (hasil penalaan 11 Nov 2026, notebook 07)

* Dua Isolation Forest: **Model A** (68 fitur aliran) dan **Model C** (7 fitur agregasi), anomali bila A **atau** C.
* **Transformasi log** sign(x)·log(1+|x|) pada setiap fitur sebelum distandarkan: sesi besar yang sah (unduhan
  panjang) tidak lagi mudah terisolasi.
* **Pembersihan data latih**: sumber intens (≥ 20 port / ≥ 20 SSH per 5 menit) **dan** subnet pemindaian terdistribusi
  (≥ 20 port / ≥ 20 IP per subnet per 5 menit) dikeluarkan.
* *Contamination* A = 0,001, C = 0,0075 (dipilih pada data validasi VPS perusahaan).
* Hasil uji (data perusahaan 8–11 Nov, belum pernah dipakai memilih), dibanding rancangan awal: IP penyerang
  terdeteksi 264 → 933, aliran serangan intens tertangkap 84% → 92%, alarm palsu pengunjung 0,07% → 0,95% (≤ 1%).
  Di CIC-IDS2017: F1 0,874 → 0,872, FPR 7,5% → 7,1%, brute force SSH 91,6% → 100%, DoS 97,2% → 92,5%.
* Model lama (tanpa kunci `transformasi`) tetap dapat dimuat dan dinilai seperti semula.

## Yang dinilai & kapan notifikasi dikirim

* **Hanya koneksi yang dimulai dari luar** (lalu lintas masuk) yang dinilai. Koneksi yang dimulai server sendiri
  (DNS, sinkronisasi waktu, pembaruan) tidak dinilai. Model tetap dilatih dari seluruh lalu lintas normal, karena
  melatih hanya dengan koneksi masuk justru menaikkan alarm palsu pada pengunjung (notebook 03/04).
* **Notifikasi Telegram** dikirim bila satu IP sumber menghasilkan **≥ 3 aliran anomali dalam 5 menit**
  (`MIN_ALIRAN_NOTIF` di `/etc/nids-deteksi/config.env`), **atau** kedua model (A dan C) sepakat. Anomali tunggal
  tetap tercatat di log & dashboard. Jeda 10 menit per IP tetap berlaku. Pada data VPS uji 5–11 Nov 2026 aturan ini
  menurunkan notifikasi dari 83 menjadi 21 (13,6 → 3,4 per hari).
* Pesan memuat tingkat (SEDANG/TINGGI), dugaan jenis kejadian (pemindaian port, brute force SSH, banjir koneksi),
  sumber, port, pola 5 menit terakhir, dan model penanda.
* Koneksi ke Telegram mengutamakan IPv4 (tiap alamat paling lama 5 detik): di VPS uji rute IPv6 ke Telegram macet,
  sehingga sebelumnya setiap pesan tertahan ±15 detik.

## Loop umpan balik

```
 dashboard: admin melaporkan "serangan lolos" / "alarm palsu"
      │
 1. periksa ulang di modul deteksi (nids/umpan_balik.py): skor aliran IP itu dinilai ulang dengan ambang
    yang diturunkan (batas aman: contamination A ≤ 1%, C ≤ 5%)
      │ terdeteksi                               │ tidak terdeteksi / alarm palsu
      ▼                                          ▼
 ubah_ambang.py → model versi baru        2. antrean pelatihan ulang → latih_model.py --umpan-balik
 (hutan sama, hanya ambang)                  (lolos: dikeluarkan dari data latih & jadi data validasi;
                                              palsu: tetap dipelajari sebagai normal; contamination dari kisi)
```

Temuan uji coba (data Hotdog, 2 Nov 2026): pemindai lambat 212.23.222.131 (687 port dalam ±2 hari) lolos karena skor C
tertingginya persis sama dengan ambang → terdeteksi setelah penyesuaian ambang (±6 aliran / 1,7 IP tambahan per hari).
Pemindai 91.230.168.174 (42 port dalam 7 hari) tetap lolos bahkan dengan jendela 1 jam / 24 jam dan contamination 5%:
pola sepelan itu tidak dapat dibedakan dari kebisingan latar internet pada server publik (batasan sistem).

## Aturan pembentukan aliran (mengikuti CICFlowMeter)

* Satu aliran = paket dengan IP dan port yang sama, dua arah. Pengirim paket pertama = arah *forward*.
* "Panjang paket" = panjang **payload**, dihitung dari header IP, sehingga tetap benar walau payload sudah dikosongkan.
* Aliran ditutup bila: 120 detik sejak paket pertama, ada RST, atau kedua pihak sudah mengirim FIN.
* Periode aktif/diam dipisah jeda > 5 detik; *subflow* dipisah jeda > 1 detik.
* Hanya TCP dan UDP (sama seperti CICFlowMeter).
* Perbedaan disengaja: aliran berdurasi 0 dihitung lajunya dengan durasi 1 µs (bukan inf), supaya aliran pemindaian
  satu paket tetap bisa dinilai.

## Fitur agregasi (jendela 300 detik ke belakang)

| Kolom | Arti |
|---|---|
| `agg_ip_aliran` | Jumlah aliran dari IP sumber yang sama dalam jendela |
| `agg_ip_port_unik` | Jumlah port tujuan berbeda yang dihubungi IP itu |
| `agg_ip_rasio_gagal` | Proporsi aliran yang tidak dibalas atau ditolak (RST) |
| `agg_ip_aliran_ssh` | Jumlah aliran ke port 22 |
| `agg_s24_ip_unik` | Jumlah IP berbeda dari subnet /24 yang sama |
| `agg_s24_aliran` | Jumlah aliran dari subnet /24 itu |
| `agg_s24_port_unik` | Jumlah port tujuan berbeda dari subnet /24 itu |

Jendela hanya melihat **ke belakang** (aliran yang sudah terjadi), sehingga cara yang sama dipakai saat deteksi langsung.
