<div align="center">

# ASUNA — Network Intrusion Detection System (`Dual-IF`)

**Rancang Bangun Network Intrusion Detection System (NIDS) Berbasis Machine Learning (*Unsupervised Anomaly Detection*) untuk Deteksi Anomali, Monitoring, Notifikasi Real-Time, dan Pemblokiran IP pada Server VPS**

[![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white)](https://www.python.org)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-Isolation_Forest-F7931E?logo=scikitlearn&logoColor=white)](https://scikit-learn.org)
[![Flask](https://img.shields.io/badge/Dashboard-Flask_3.1-000000?logo=flask&logoColor=white)](3_dashboard/)
[![SQLite](https://img.shields.io/badge/Storage-SQLite_WAL-003B57?logo=sqlite&logoColor=white)](https://www.sqlite.org)
[![Telegram](https://img.shields.io/badge/Alerting-Telegram_Bot_API-26A5E4?logo=telegram&logoColor=white)](2_sistem_nids/)
[![Ubuntu](https://img.shields.io/badge/Target-Ubuntu_systemd_%2B_nftables-E95420?logo=ubuntu&logoColor=white)](2_sistem_nids/deploy/)

*Sistem deteksi intrusi jaringan mandiri tanpa ketergantungan aturan signature maupun layanan pihak ketiga wajib — mencakup perekaman header privasi-aman terkendali dari dashboard, deteksi Dual Isolation Forest (`IF-Flow` dan `IF-Agg`) dengan lapisan adaptasi online, katalog & impor model `.joblib` hot-reload, asisten Multi-AI dinamis (on-demand, bebas pilih provider & model), audit lintas layanan, bot Telegram & dashboard **ASUNA**, hingga pemblokiran IP via `nftables`.*

</div>

---

## Ringkasan Proyek

Server VPS ber-IP publik terus-menerus menjadi sasaran pemindaian port (*port scan*), *brute force* SSH, hingga banjir permintaan (*flood*). IDS berbasis *signature* hanya mengenali pola yang sudah terdaftar pada basis aturan, sedangkan layanan keamanan awan komersial bergantung pada biaya langganan dan ekosistem tertutup.

Proyek Tugas Akhir ini membangun **sistem NIDS *end-to-end* berbasis Isolation Forest** yang mempelajari perilaku lalu lintas normal server target secara *unsupervised*, menjalankan deteksi *real-time* yang dapat **beradaptasi secara *online*** atas keputusan verifikasi admin, mencatat log terstruktur & audit lintas layanan, menyajikan dashboard web & bot Telegram **ASUNA** beserta **Asisten Multi-AI dinamis**, serta mendukung pemblokiran alamat IP penyerang secara manual lewat firewall kernel (`nftables`).

### Arsitektur `Dual-IF` (`IF-Flow` + `IF-Agg`) + Adaptasi Online

Eksperimen awal menggunakan fitur per aliran (*per-flow*) tunggal gagal menangkap serangan bertipe **anomali kolektif** (*port scan* 0,23% dan *brute force* SSH 0,08% pada CIC-IDS2017) karena tiap koneksi individual terlihat normal. Di sisi lain, menyatukan semua fitur ke dalam satu model (`IF-Joint`) membuat fitur agregasi jarang terpilih oleh pohon acak.

Solusi yang diterapkan adalah **arsitektur paralel `Dual-IF` dengan gerbang logika `OR` serta lapisan adaptasi online**:
- **`IF-Flow` (68 fitur aliran gaya CICFlowMeter):** mendeteksi anomali karakteristik paket dan laju pada satu sesi komunikasi dua arah (misalnya *DoS / HTTP flood*).
- **`IF-Agg` (7 fitur agregasi jendela 300 detik):** mendeteksi anomali kolektif berdasarkan perilaku IP sumber dan subnet `/24` maupun `/64` (jumlah aliran, port unik, rasio koneksi gagal, aliran ke SSH, serta aktivitas terdistribusi per subnet).
- **Transformasi & Pembersihan Baseline:** seluruh fitur dinormalisasi dengan transformasi *signed* log (`sgn(x) * ln(1 + |x|)`) sebelum standardisasi, serta data latih lokal dibersihkan dari IP/subnet pemindai intens agar batas normal tidak melebar.
- **Lapisan Adaptasi Berbasis Vektor Fitur (`adaptasi.py`):** vektor standar aliran anomali & mendekati ambang disimpan ke tabel `aliran_fitur`. Saat admin menetapkan kejadian *Hampir anomali* / *Umpan balik* sebagai **Anomali** atau **Bukan anomali**, sistem mengekstrak prototipe *centroid* + radius jarak RMS dan memuatnya ulang ke `nids-deteksi` secara *hot-reload* tanpa *restart*, sehingga pola serupa di masa depan (termasuk dari IP berbeda) langsung dikenali secara tepat dan tidak lagi jatuh ke daftar *hampir anomali*.

---

## Diagram Alur Sistem

Diagram alur ringkas di bawah merangkum alur kerja sistem secara keseluruhan, mulai dari penangkapan lalu lintas, deteksi **Dual-IF + Adaptasi Online**, kendali model/rekaman, **Asisten Multi-AI Dinamis**, audit lintas layanan, pemblokiran IP, hingga pelatihan ulang *offline*:

```mermaid
flowchart TB
    subgraph Z1["Zona 1: Server VPS Target (Real-Time)"]
        NET["Lalu Lintas Jaringan Masuk"] --> CAP["1. Penangkap Paket tcpdump (Header maks 160 byte, tanpa root)"]
        CAP --> REC["Perekam Arsip Per Jam (Payload dinolkan, gzip, HTTPS + SHA-256)"]
        CAP --> FEAT["2. Ekstraksi Fitur Identik (68 fitur aliran + 7 fitur agregasi 300 dtk)"]
        FEAT --> INF["3. Inferensi Dual-IF + Lapisan Adaptasi (IF-Flow OR IF-Agg + Prototipe RMS)"]
        INF --> DEC{"Skor melewati ambang?"}
        DEC -- "Tidak" --> LOGN["Catat Ringkasan, Skor & Vektor Batas (deteksi.db + aliran_fitur)"]
        DEC -- "Ya" --> WL{"IP di Daftar Tepercaya?"}
        WL -- "Ya (Whitelist)" --> LOGN
        WL -- "Tidak" --> LOGA["4. Catat Log Anomali + Vektor SQLite WAL (deteksi.db)"]
        LOGA --> TG["5. Bot Telegram ASUNA (>=3 anomali/5 mnt atau kesepakatan Dual-IF)"]
        LOGA --> DASH["6. Dashboard Web ASUNA (Flask + Gunicorn + HTTPS + RBAC)"]
    end

    subgraph Z3["Kendali Admin, Adaptasi Online, Multi-AI & Audit"]
        DASH -- "Putuskan Hampir Anomali / Umpan Balik" --> ADP["7. Adaptasi Prototipe & Evaluasi Kuantil (adaptasi.py + umpan_balik.py)"]
        ADP -- "Hot-reload aturan/ambang/mode" --> KAT["Katalog Model Bersama (katalog_model.py)"]
        KAT -. "Muat ulang <=5 detik (tanpa restart)" .-> INF
        DASH -- "Mulai / Berhenti Rekam" --> RKM["Kendali Perekam (nids-rekam-kendali)"]
        RKM -. "Kontrol layanan rekam" .-> REC
        DASH -- "Chat Multi-Turn / Ringkas" --> AI["Asisten Multi-AI Dinamis (/models otomatis: OpenAI, Gemini, Claude, Compat)"]
        TG -- "Perintah /ai /models /modelai /analisis" --> AI
        AI -. "Kirim ringkasan statistik saja (tanpa payload)" .-> LOGA
        DASH -- "Blokir / Buka IP" --> QBLK["Antrean ip_diblokir.json (validasi anti-lockout)"]
        TG -- "Perintah /blokir /buka /diblokir" --> QBLK
        QBLK --> NFT["Layanan nids-blokir -> Firewall nftables (inet nids_blokir)"]
        TG -. "Audit eksternal" .-> AUD["Audit Terpusat (/audit + Filter & Ekspor CSV)"]
        DASH --> AUD
    end

    subgraph Z2["Zona 2: Laptop Peneliti (Offline)"]
        REC -. "Unduh arsip header + CIC-IDS2017" .-> TRN["Putar Ulang Pipa Identik, Pembersihan Baseline & Latih IF-Flow / IF-Agg"]
        ADP -. "Ekspor kasus umpan balik JSON" .-> TRN
        TRN --> VAL["Validasi Metrik (CIC-IDS2017 & Simulasi VPS Uji)"]
        VAL --> PKG["Paket model.joblib Versi Baru"]
        PKG -- "Unggah via Dashboard -> Validasi nids-model" --> KAT
    end
```

### 1. Arsitektur Umum Sistem (3 Zona)

![Arsitektur Umum Sistem NIDS](docs/diagrams/gambar_3_2_arsitektur_nids.png)

### 2. Diagram Alur Sistem Real-Time pada Server VPS

![Alur Real-Time Server VPS](docs/diagrams/gambar_3_3_alur_server_nids.png)

### 3. Diagram Alur Pelatihan & Pemutakhiran Model Offline

![Alur Pelatihan dan Evaluasi Offline](docs/diagrams/gambar_3_4_alur_laptop_nids.png)

> Sumber diagram yang dapat disunting tersedia pada [`docs/diagrams/Arsitektur_Sistem_NIDS_Revisi.drawio`](docs/diagrams/Arsitektur_Sistem_NIDS_Revisi.drawio).

---

## Ringkasan Hasil Uji Rancangan

### 1. Evaluasi Rancangan pada Dataset Benchmark CIC-IDS2017

| Metrik / Kategori | `IF-Flow` Awal | `Dual-IF` (`IF-Flow + IF-Agg`) + Transformasi Log |
|---|---:|---:|
| **F1-Score** | 0,610 | **0,872** |
| **Recall (Detection Rate)** | — | **94,6%** |
| **Precision** | — | **81,0%** |
| **False Positive Rate (FPR)** | 9,26% | **7,1%** |
| **ROC-AUC** | — | **0,951** |
| Deteksi **Port Scan** | 0,23% | **99,97%** |
| Deteksi **SSH Brute Force** | 0,08% | **100,0%** |
| Deteksi **DoS** | 78,0% | **92,5%** |

### 2. Penalaan pada Data Lalu Lintas Server Nyata (20 Hari, 79.616 Aliran)
- Varian terpilih (**transformasi *signed* `log1p` + pembersihan sumber/subnet pemindai pada data latih**) meningkatkan deteksi IP penyerang dari **264 → 933 IP** dan cakupan aliran serangan intens dari **84% → 92%**, dengan *false positive* pengunjung web terjaga pada **0,95%** (< 1%).
- Waktu inferensi ringan (**~3,85 µs/aliran**), memungkinkan pemantauan kontinu pada VPS berkapasitas 1 vCPU dan 4 GB RAM.

---

## Fitur Utama

- **Mesin Deteksi Real-Time & Adaptasi Online (`nids-deteksi`):** penangkapan header paket `tcpdump` tanpa hak *root* (`CAP_NET_RAW`), *micro-batching* (≤ 1 detik), filter lalu lintas keluar server, pengecualian IP tepercaya (`ip_tepercaya.json`), penyimpanan vektor fitur ternormalisasi (`aliran_fitur`), serta **lapisan adaptasi jarak vektor RMS (`adaptasi.py`)** dengan pemuatan ulang otomatis ≤ 5 detik tanpa *restart*.
- **Dashboard Web ASUNA (`ta-nids-server`):** aplikasi Flask + Gunicorn + Nginx HTTPS dengan mode terang/gelap, grafik SVG sisi server, ringkasan 24 jam / 7 hari, daftar anomali & **Hampir Anomali** (lengkap dengan tombol keputusan langsung **Anomali** / **Bukan anomali**), pencarian riwayat per IP, IP tepercaya, serta manajemen pengguna berbasis peran (**Admin / Analis / Pemantau**).
- **Manajemen Katalog Model & Kendali Perekaman:** admin dapat beralih mode deteksi (`Dual-IF`, `IF-Flow saja`, `IF-Agg saja`), mengubah/melakukan *rollback* versi model secara *hot-reload*, mengunggah berkas `.joblib` baru yang divalidasi otomatis oleh layanan terisolasi `nids-model`, mengelola aturan adaptasi aktif, serta mengendalikan perekaman *traffic* (`nids-rekam-kendali`) dari tab Rekaman.
- **Asisten Multi-AI Dinamis & Obrolan Multi-Turn:** mendukung banyak koneksi AI sekaligus (**OpenAI**, **Google Gemini**, **Anthropic Claude**, dan **OpenAI-Compatible** seperti Groq/OpenRouter/DeepSeek/Ollama), penemuan daftar model otomatis via `/models`, pemilihan koneksi + model secara bebas (termasuk model *reasoning* dan ID model kustom) pada obrolan *multi-turn* (`ai_chat`), ringkasan, IP, dan Telegram, dengan prinsip *on-demand* hanya mengirim statistik agregat tanpa *payload* paket.
- **Pemblokiran IP Manual Terproteksi (`nids-blokir`):** administrator dapat memblokir maupun membuka blokir IP atau rentang jaringan (maksimal `/24` IPv4 dan `/64` IPv6) lewat dashboard maupun bot Telegram (`/blokir`, `/buka`, `/diblokir`) melalui firewall kernel `nftables` (`inet nids_blokir`), lengkap dengan validasi **anti-lockout**.
- **Audit Lintas Layanan & Ekspor CSV:** pencatatan peristiwa terpusat di `/audit` yang mengagregasikan aksi web, bot Telegram, serta worker `nids-model` melalui antrean atomik `audit_eksternal.jsonl`, mencatat penolakan akses (`403`) & kegagalan operasi, isolasi ruang lingkup `viewer`, filter kategori/tanggal/pencarian, serta ekspor CSV.
- **Notifikasi & Bot Telegram ASUNA (`nids-bot` + `nids-pantau`):** peringatan anomali anti-spam, perintah `/status`, `/ringkasan`, `/ip`, `/hampir`, `/blokir`, `/buka`, `/diblokir`, `/ai`, `/models`, `/modelai`, `/analisis`, `/ringkasai`, `/tanya`, serta pemantau kesehatan layanan tiap 2 menit.

---

## Struktur Repositori

```text
Project-TA/
├── 1_perekam_traffic/        # Perekam header paket per jam (payload dinolkan, gzip, unggah HTTPS + SHA-256)
├── 2_sistem_nids/            # Mesin deteksi Dual-IF + adaptasi, bot Telegram, pemantau, blokir nftables (37 uji)
│   ├── nids/                 # pcap, aliran (68), agregasi (7), model, adaptasi, katalog_model, asisten_ai,
│   │                         # audit_bersama, rekam_kendali, umpan_balik, log_anomali, blokir, laporan
│   ├── deteksi.py            # Program utama (mode langsung & putar-ulang identik)
│   ├── latih_model.py        # Pelatihan IF-Flow & IF-Agg (+ pembersihan data & umpan balik)
│   ├── ubah_ambang.py        # Penalaan ambang tanpa melatih ulang pohon
│   ├── impor_model.py        # Worker nids-model untuk validasi & impor unggahan .joblib
│   ├── rekam_kendali.py      # Worker kendali layanan perekaman dari dashboard
│   ├── blokir.py             # Layanan sinkronisasi antrean IP ke firewall nftables
│   ├── bot.py & pantau.py    # Bot Telegram ASUNA & pemantau kesehatan systemd
│   └── tests/                # Unit test deteksi, adaptasi, katalog, AI dinamis, blokir, & umpan balik
├── 3_dashboard/              # Dashboard web ASUNA (Flask, RBAC, adaptasi, Multi-AI chat, audit CSV, 56 uji)
├── 4_notebook/               # Notebook Jupyter 00–07 (dataset, preprocessing, training, evaluasi, penalaan)
├── 5_simulasi_serangan/      # Simulator serangan terkendali & evaluator metrik + 4 uji
└── docs/
    └── diagrams/             # Diagram arsitektur & alur kerja (.drawio & PNG resolusi tinggi)
```

> **Catatan Privasi & Keamanan Repositori:** Repositori publik ini hanya memuat kode sumber, skrip pengujian, notebook tanpa *output* mentah, dan diagram arsitektur. Data eksperimen mentah (CIC-IDS2017 dan rekaman lalu lintas server), berkas model terlatih (`.joblib`), basis data (`.db`), kredensial/token/API key, alamat IP server asli, serta aset visual milik perusahaan studi kasus tidak disertakan.

---

## Pengujian Otomatis

Seluruh **97 pengujian otomatis** berjalan secara lokal tanpa koneksi ke server maupun panggilan API AI nyata (*mock transport*):

```bash
# 1. Modul deteksi NIDS, adaptasi fitur, katalog model, AI dinamis, bot, & blokir IP (37 uji)
python -m pytest -q 2_sistem_nids/tests

# 2. Dashboard web ASUNA, adaptasi hampir anomali, Multi-AI chat, audit CSV, RBAC & keamanan (56 uji)
python -m pytest -q 3_dashboard/tests

# 3. Simulator serangan lokal & perhitungan metrik evaluasi (4 uji)
python -m pytest -q 5_simulasi_serangan/tests
```

---

## Keamanan & Privasi Desain

- **Privasi Lalu Lintas:** perekaman hanya menyalin 160 byte header paket dan menolkan *payload* sebelum meninggalkan server; isi komunikasi pengguna tidak pernah disimpan maupun dikirim ke API AI.
- **Pemisahan Hak Istimewa:** perekam dan mesin deteksi berjalan tanpa hak *root* (`CAP_NET_RAW`), *dashboard* berjalan baca-saja terhadap `deteksi.db`, impor model (`nids-model`) dan manipulasi `nftables` (`nids-blokir`) diisolasi pada unit `systemd` terpisah.
- **Keamanan Aplikasi Web & Kredensial:** *Content Security Policy* ketat (`default-src 'self'`, tanpa *inline style/script*), proteksi CSRF, pembatasan percobaan login per IP, *session timeout*, penyamaran API key AI di UI, validasi anti-SSRF endpoint AI, serta pencatatan audit lintas layanan.

---

<div align="center">

Dikembangkan sebagai proyek Tugas Akhir oleh **Putu Satria Arya Putra**  
Program Studi Teknologi Informasi, Fakultas Teknik, Universitas Udayana

</div>
