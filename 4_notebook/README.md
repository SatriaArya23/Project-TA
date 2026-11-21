# Notebook TA (preprocessing & training)

Jalankan berurutan. Notebook ada di folder ini; **data dan hasilnya** ada di `D:\KULIAH\TA\05_Data_Eksperimen\`.

| No | Notebook | Data yang dipakai | Hasil disimpan di | Waktu |
|---|---|---|---|---|
| 00 | `00_Unduh_Dataset.ipynb` | internet (mirror CIC-IDS2017) | `05_Data_Eksperimen\CIC-IDS2017\data\raw_labelled` | sekali saja |
| 01 | `01_Preprocessing_v2.ipynb` | `CIC-IDS2017\data\` | `CIC-IDS2017\data\processed_v2`, `laporan_preprocessing_v2.md` | ± 3 menit |
| 02 | `02_Training_v2.ipynb` | `CIC-IDS2017\data\processed_v2` | `CIC-IDS2017\hasil_v2\` | ± 6 menit |
| 03 | `03_Baseline_VPS_Perusahaan.ipynb` | `Server-HotDog\rekaman\` | `Server-HotDog\hasil\` (fitur, model, tabel) | ± 30 detik |
| 04 | `04_Baseline_VPS_Uji.ipynb` | `Server-Uji\rekaman\` | `Server-Uji\hasil\` (fitur, model, tabel) | ± 10 detik |
| 05 | `05_Cara_Kerja_NIDS.ipynb` | `Server-Uji\rekaman\` + model dari 04 | `Server-Uji\hasil\demo_deteksi.db` | ± 15 detik |
| 07 | `07_Penalaan_Model_VPS_Perusahaan.ipynb` | `Server-HotDog\rekaman\` (20 hari) + `CIC-IDS2017\data\processed_v2` | `Server-HotDog\hasil\penalaan_*.csv`, `model_vps_perusahaan_final.joblib` | ± 2 menit |
| 06 | `06_Evaluasi_VPS_Uji.ipynb` | `Server-Uji\jadwal_serangan.csv` + `hasil\deteksi_vps_uji.db` | `Server-Uji\hasil\` (metrik, per skenario, grafik) | ± 10 detik |

Notebook 01–05 memakai kode sistem NIDS di `..\2_sistem_nids`, sehingga preprocessing di notebook **sama persis**
dengan yang dilakukan sistem NIDS di server.

## Di laptop

Buka folder ini dengan VS Code atau Jupyter, buka notebook, lalu pilih **Run All**. Jalur data dan kode sudah diatur
otomatis (relatif terhadap folder ini).

Pustaka yang dibutuhkan: `pip install numpy pandas scikit-learn joblib pyarrow matplotlib requests`.

## Di Google Colab (notebook 00–02 saja)

1. Unggah ke Google Drive:
   - `00_Unduh_Dataset.ipynb`, `01_Preprocessing_v2.ipynb`, `02_Training_v2.ipynb`, dan
     `D:\KULIAH\TA\05_Data_Eksperimen\CIC-IDS2017\fitur_68.json` → ke `MyDrive/TA/CIC-IDS2017/`
   - folder `D:\KULIAH\TA\04_Kode\2_sistem_nids` → ke `MyDrive/TA/2_sistem_nids/`

   Folder `data\` **tidak perlu** diunggah, karena notebook 00 mengunduh datasetnya sendiri.
2. Jalankan berurutan: **00 → 01 → 02**.
3. Di Colab, pencocokan dengan data versi 1 dilewati otomatis (hasilnya di laptop: 100% identik).

Notebook 03–05 dijalankan di laptop, karena memakai rekaman server yang tersimpan di laptop.
