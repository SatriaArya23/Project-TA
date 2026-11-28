# 2_sistem_nids — Sistem NIDS (Deteksi Real-Time `Dual-IF`: `IF-Flow` + `IF-Agg`)

Program yang memantau lalu lintas server secara *real-time*, mendukung lapisan adaptasi *online* & *hot-reload* katalog model, mengirim notifikasi/bot **ASUNA** ke Telegram (termasuk Asisten Multi-AI dinamis), mengendalikan perekam lalu lintas, dan mengeksekusi pemblokiran IP manual melalui `nftables`:

```text
tcpdump (header) ─► pcap.py ─► aliran.py ─► agregasi.py ─► Dual-IF + Adaptasi ─► log SQLite (+ aliran_fitur) ─► Telegram (ASUNA)
 (penangkap paket)   (baca)     (68 fitur)   (7 fitur,      (model.py,             (log_anomali)                    & blokir.py (nftables)
                                              300 detik)     adaptasi.py)                 │
                                                                 ▲                        └──► dashboard ASUNA (3_dashboard)
rekaman .pcap.gz ─┘  (putar ulang: pipa yang SAMA)               └──── katalog_model.py (hot-reload / impor_model.py)
```

Penjelasan struktur kode secara menyeluruh tersedia pada `..\README.md`.
Di server, layanan terpasang sebagai `nids-deteksi`, `nids-bot`, `nids-pantau.timer`, `nids-blokir.path`/`.timer`, `nids-model.path`, dan `nids-rekam-kendali.path`/`.timer` (`/opt/nids-deteksi`).

## Program yang dijalankan

| Program | Kegunaan |
|---|---|
| `deteksi.py langsung` | Deteksi *real-time* di server (dijalankan otomatis oleh layanan `nids-deteksi`) |
| `deteksi.py putar-ulang` | Memproses rekaman dengan pipa yang sama: membuat tabel fitur (`--fitur`) atau menguji model (`--model --log`) |
| `latih_model.py` | Melatih `IF-Flow` dan `IF-Agg` (arsitektur `Dual-IF`) dari tabel fitur, dengan pembersihan sumber serangan intens |
| `ubah_ambang.py` | Menerapkan usulan ambang dari halaman Umpan balik sebagai versi model baru (tanpa latih ulang) |
| `impor_model.py` | Worker terisolasi (`nids-model`) untuk memvalidasi & menguji asap unggahan `.joblib` sebelum didaftarkan ke katalog |
| `rekam_kendali.py` | Worker terisolasi (`nids-rekam-kendali`) untuk memulai/menghentikan `traffic-recorder` & auto-stop sesuai durasi |
| `blokir.py` | Menyinkronkan daftar antrean `ip_diblokir.json` ke tabel firewall kernel `nftables` (`inet nids_blokir`) |
| `bot.py` / `pantau.py` | Bot Telegram ASUNA (`/status`, `/ringkasan`, `/ip`, `/hampir`, `/blokir`, `/buka`, `/diblokir`, `/ai`, `/models`, `/modelai`, `/analisis`, `/ringkasai`, `/tanya`) dan pemantau layanan |

```powershell
cd 2_sistem_nids
python -m pytest -q tests                                                    # 37 uji otomatis
$R = "..\..\05_Data_Eksperimen\Server-Uji"
python deteksi.py putar-ulang "$R\rekaman" --fitur "$R\hasil\fitur.parquet"   # rekaman -> tabel fitur
python latih_model.py "$R\hasil\fitur.parquet" --keluar "$R\hasil\model.joblib"
python deteksi.py putar-ulang "$R\rekaman" --model "$R\hasil\model.joblib" --log "$R\hasil\uji.db"
```

## Pemasangan di server

```bash
# salin folder 2_sistem_nids (dan 3_dashboard bila dashboard ikut dipasang) ke server, lalu sebagai root:
sudo bash deploy/pasang-deteksi.sh --nama-server "VPS Uji" --latih fitur.parquet
# Telegram: isi /etc/nids-deteksi/rahasia.env (izin 600) lalu: systemctl restart nids-deteksi nids-bot
#   TELEGRAM_TOKEN=...
#   TELEGRAM_CHAT_ID=...
```

`--latih` melatih model di server itu sendiri agar versi `scikit-learn` sama persis dengan modul deteksi. Skrip juga memberi dashboard izin baca ke log deteksi (`/var/lib/nids-deteksi/deteksi.db`). Layanan deteksi berjalan tanpa *root* (`CAP_NET_RAW`/`CAP_NET_ADMIN`), sedangkan sinkronisasi `nftables` diisolasi pada layanan `nids-blokir` dengan validasi *anti-lockout* di `nids/blokir.py`.

## Rancangan model (`Dual-IF`)

* Dua Isolation Forest paralel: **`IF-Flow`** (68 fitur aliran, kunci internal `'A'`) dan **`IF-Agg`** (7 fitur agregasi jendela 300 detik, kunci internal `'C'`), anomali bila salah satu menandai (`Dual-IF`, kunci `'A+C'`).
* **Transformasi log** `sgn(x) · ln(1 + |x|)` pada setiap fitur sebelum standardisasi agar sesi sah bervolume besar tidak mudah terisolasi.
* **Pembersihan data latih**: sumber intens (≥ 20 port / ≥ 20 SSH per 5 menit) serta subnet pemindaian terdistribusi (≥ 20 port / ≥ 20 IP per subnet per 5 menit) dikeluarkan.
* Parameter *contamination* acuan: `IF-Flow` = 0,001 dan `IF-Agg` = 0,0075.
* Hasil uji desain di CIC-IDS2017: F1-score **0,872**, Recall **94,6%**, Precision **81,0%**, FPR **7,1%**, ROC-AUC **0,951**, SSH *brute force* **100,0%**, *port scan* **99,97%**, DoS **92,5%**.
* Model versi terdahulu tetap dapat dimuat karena kunci internal berkas `.joblib` dan skema `deteksi.db` menjaga kompatibilitas mundur.

## Yang dinilai & kapan notifikasi dikirim

* **Hanya koneksi yang dimulai dari luar** (lalu lintas masuk) yang dinilai; koneksi keluar dari server sendiri (DNS, sinkronisasi waktu, pembaruan paket) tidak ditandai anomali.
* **Notifikasi Telegram ASUNA** dikirim bila satu IP sumber menghasilkan **≥ 3 aliran anomali dalam 5 menit** (`MIN_ALIRAN_NOTIF`), atau kedua model (`IF-Flow` dan `IF-Agg` sebagai **`Dual-IF`**) sepakat, dengan jeda 10 menit per IP.
* Pemblokiran IP tidak dijalankan otomatis untuk mencegah *self-lockout* maupun pemblokiran pengunjung sah; pemblokiran aktif atas perintah eksplisit admin via dashboard maupun perintah `/blokir` pada bot Telegram.

## Loop umpan balik

```text
 dashboard ASUNA: admin melaporkan "serangan lolos" / "alarm palsu"
      │
 1. periksa ulang di modul deteksi (nids/umpan_balik.py): skor aliran IP itu dinilai ulang
    dengan ambang yang diturunkan (batas aman: contamination IF-Flow ≤ 1%, IF-Agg ≤ 5%)
      │ terdeteksi                               │ tidak terdeteksi / alarm palsu
      ▼                                          ▼
 ubah_ambang.py → model versi baru        2. antrean pelatihan ulang → latih_model.py --umpan-balik
 (hutan sama, hanya ambang)                  (lolos: dikeluarkan dari data latih & jadi validasi;
                                              palsu: dipertahankan sebagai normal)
```

## Aturan pembentukan aliran (mengikuti CICFlowMeter)

* Satu aliran = paket dengan tuple lima atribut yang sama, dua arah. Pengirim paket pertama = arah *forward*.
* Panjang paket mengacu pada panjang **payload** yang dihitung dari header IP sehingga tetap akurat walau payload sudah dinolkan.
* Aliran ditutup bila durasi melampaui 120 detik sejak paket pertama, terdapat flag `RST`, atau kedua pihak mengirim `FIN`.
* Periode aktif/diam dipisah jeda > 5 detik; *subflow* dipisah jeda > 1 detik. Hanya memproses protokol TCP dan UDP.

## Fitur agregasi (`IF-Agg`, jendela 300 detik ke belakang)

| Kolom | Arti |
|---|---|
| `agg_ip_aliran` | Jumlah aliran dari IP sumber yang sama dalam jendela 300 detik |
| `agg_ip_port_unik` | Jumlah port tujuan berbeda yang dihubungi IP sumber |
| `agg_ip_rasio_gagal` | Proporsi aliran yang tidak dibalas atau ditolak (`RST`) |
| `agg_ip_aliran_ssh` | Jumlah aliran menuju port 22 |
| `agg_s24_ip_unik` | Jumlah IP berbeda dari subnet `/24` (IPv4) atau `/64` (IPv6) |
| `agg_s24_aliran` | Jumlah aliran dari subnet tersebut |
| `agg_s24_port_unik` | Jumlah port tujuan berbeda yang dihubungi subnet tersebut |
