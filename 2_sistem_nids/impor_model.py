#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Worker validasi & impor berkas model `.joblib` yang diunggah administrator melalui dashboard.

Dijalankan oleh layanan `nids-model.path` -> `nids-model.service` sebagai pengguna non-root `nids`
(terisolasi di lingkungan /opt/nids-deteksi/venv yang memiliki scikit-learn & joblib).

Langkah verifikasi sebelum mendaftarkan model ke katalog bersama:
  1. Cek keamanan nama berkas & ukuran (maks 50 MB).
  2. Hitung SHA-256 berkas dan cocokkan dengan SHA-256 yang dimasukkan admin (bila diisi).
  3. Muat berkas melalui ModelDeteksi.muat() dan tangkap peringatan kompatibilitas scikit-learn.
  4. Validasi kelengkapan struktur Dual-IF: 68 fitur aliran (FITUR) + 7 fitur agregasi (FITUR_AGREGASI)
     serta ambang skor valid (finite float).
  5. Jalankan smoke-test inferensi pada 2 aliran uji untuk memastikan model dapat menilai tanpa galat.
  6. Daftarkan ke katalog.json (status tersimpan atau langsung aktif bila diminta) lalu hapus berkas sementara.
"""
import argparse
import hashlib
import hmac
import math
import os
import sys
import warnings

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nids import audit_bersama                           # noqa: E402
from nids import katalog_model                           # noqa: E402
from nids.agregasi import FITUR_AGREGASI                 # noqa: E402
from nids.aliran import FITUR                            # noqa: E402
from nids.model import ModelDeteksi                      # noqa: E402


def _sha256_berkas(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            pot = f.read(1 << 20)
            if not pot:
                break
            h.update(pot)
    return h.hexdigest()


def _aliran_smoke(nilai):
    d = {
        "Waktu Selesai": 1_761_800_000_000_000,
        "_mulai_us": 1_761_799_999_000_000,
        "Flow Duration": 1_000_000,
        "Source IP": "203.0.113.10",
        "Source Port": 40000,
        "Destination IP": "192.0.2.10",
        "Destination Port": 443,
        "Protocol": 6,
        "Total Fwd Packets": 3,
        "Total Backward Packets": 2,
    }
    for k in FITUR:
        d[k] = float(nilai)
    for k in FITUR_AGREGASI:
        d[k] = float(nilai)
    return d


def validasi_dan_impor(folder=katalog_model.DIR_BAWAAN, path_audit=audit_bersama.PATH_BAWAAN):
    """Proses satu tugas pada `impor_antrean.json` (bila ada). Kembalikan status dict atau None."""
    tugas = katalog_model.baca_antrean_impor(folder)
    if not tugas:
        return None

    t_id = tugas.get("id") or katalog_model.versi_baru()
    berkas_nama = tugas.get("berkas_masuk") or ""
    path_masuk = None

    def gagal(pesan):
        st = {
            "id": t_id,
            "status": "gagal",
            "nama": tugas.get("nama") or berkas_nama,
            "oleh": tugas.get("oleh") or "",
            "waktu_utc": katalog_model.sekarang_utc(),
            "pesan": pesan,
        }
        katalog_model.tulis_status_impor(folder, st)
        katalog_model.hapus_antrean_impor(folder)
        audit_bersama.tulis(path_audit, "MODEL_IMPOR_GAGAL", aktor=tugas.get("oleh") or "worker",
                            nama=berkas_nama[:80], kode=400, ket=pesan)
        if path_masuk and os.path.exists(path_masuk):
            try:
                os.unlink(path_masuk)
            except OSError:
                pass
        return st

    try:
        nama_aman = katalog_model.nama_berkas_aman(berkas_nama)
        path_masuk = os.path.join(katalog_model.dir_masuk(folder), nama_aman)
    except ValueError as e:
        return gagal(str(e))

    katalog_model.tulis_status_impor(folder, {
        "id": t_id,
        "status": "memproses",
        "nama": tugas.get("nama") or nama_aman,
        "oleh": tugas.get("oleh") or "",
        "waktu_utc": katalog_model.sekarang_utc(),
        "pesan": "Memvalidasi struktur model & menjalankan smoke-test inferensi...",
    })

    if not os.path.isfile(path_masuk):
        return gagal("Berkas unggahan tidak ditemukan di antrean masuk.")
    if not nama_aman.lower().endswith(".joblib"):
        return gagal("Format berkas harus .joblib.")
    ukuran = os.path.getsize(path_masuk)
    if ukuran <= 0 or ukuran > katalog_model.MAKS_UKURAN_MODEL:
        return gagal("Ukuran berkas tidak valid (maksimal %d MB)." % (katalog_model.MAKS_UKURAN_MODEL // (1024 * 1024)))

    sha_aktual = _sha256_berkas(path_masuk)
    sha_harap = (tugas.get("sha_diharapkan") or "").strip().lower()
    if sha_harap and not hmac.compare_digest(sha_aktual, sha_harap):
        return gagal("Checksum SHA-256 tidak cocok (diharapkan %s…, berkas %s…)." % (sha_harap[:12], sha_aktual[:12]))

    peringatan = []
    try:
        with warnings.catch_warnings(record=True) as wlog:
            warnings.simplefilter("always")
            model = ModelDeteksi.muat(path_masuk)
            for w in wlog:
                peringatan.append(str(w.message))
    except Exception as e:
        return gagal("Gagal memuat berkas .joblib: %s: %s" % (type(e).__name__, e))

    # Validasi struktur fitur & ambang
    if list(model.A.fitur) != list(FITUR):
        return gagal("Daftar fitur IF-Flow tidak cocok (%d fitur, harus 68 fitur standar)." % len(model.A.fitur))
    if list(model.C.fitur) != list(FITUR_AGREGASI):
        return gagal("Daftar fitur IF-Agg tidak cocok (%d fitur, harus 7 fitur agregasi)." % len(model.C.fitur))
    if not (math.isfinite(model.A.ambang) and math.isfinite(model.C.ambang)):
        return gagal("Nilai ambang skor model tidak valid (NaN/Inf).")

    # Smoke-test inferensi nyata
    try:
        hasil = model.nilai([_aliran_smoke(1.0), _aliran_smoke(500.0)])
        if len(hasil) != 2:
            return gagal("Smoke-test inferensi mengembalikan jumlah hasil tidak sesuai.")
        for sa, sc, oleh in hasil:
            if not (math.isfinite(sa) and math.isfinite(sc)) or oleh not in ("", "A", "C", "A+C"):
                return gagal("Smoke-test inferensi menghasilkan skor/penanda tidak valid.")
    except Exception as e:
        return gagal("Smoke-test inferensi gagal pada versi scikit-learn server: %s: %s" % (type(e).__name__, e))

    # Pastikan versi unik di katalog bila sama dengan versi lama
    ringkas = model.ringkas()
    kat_lama = katalog_model.baca(folder)
    if katalog_model.cari(kat_lama, ringkas.get("versi")) is not None:
        ringkas["versi"] = katalog_model.versi_baru()
    ringkas["sha256"] = sha_aktual
    ringkas["alasan"] = tugas.get("alasan") or "diunggah lewat dashboard"
    if peringatan:
        ringkas["peringatan_impor"] = peringatan[:3]

    nama_profil = tugas.get("nama") or ringkas.get("nama") or ("Model Unggahan %s" % ringkas["versi"])
    entri = katalog_model.daftar_dari_file(
        folder, path_masuk, ringkas, nama=nama_profil,
        oleh=tugas.get("oleh") or "admin", aktifkan=bool(tugas.get("aktifkan")),
    )

    try:
        os.unlink(path_masuk)
    except OSError:
        pass
    katalog_model.hapus_antrean_impor(folder)

    pesan_ok = "Model %s (%s) lolos validasi dan ditambahkan ke katalog%s." % (
        entri["nama"], entri["versi"], " serta langsung diaktifkan" if tugas.get("aktifkan") else ""
    )
    st = {
        "id": t_id,
        "status": "berhasil",
        "versi": entri["versi"],
        "nama": entri["nama"],
        "sha256": sha_aktual,
        "peringatan": peringatan[:3],
        "oleh": tugas.get("oleh") or "",
        "waktu_utc": katalog_model.sekarang_utc(),
        "pesan": pesan_ok,
    }
    katalog_model.tulis_status_impor(folder, st)
    audit_bersama.tulis(path_audit, "MODEL_IMPOR_OK", aktor=tugas.get("oleh") or "worker",
                        nama=entri.get("berkas"), sha=sha_aktual, kode=200, ket=pesan_ok)
    return st


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--folder", default=katalog_model.DIR_BAWAAN)
    ap.add_argument("--audit-eksternal", default=audit_bersama.PATH_BAWAAN)
    a = ap.parse_args()
    st = validasi_dan_impor(a.folder, path_audit=a.audit_eksternal)
    if st:
        print("[%s] %s" % (st["status"], st["pesan"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
