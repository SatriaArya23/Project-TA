# -*- coding: utf-8 -*-
"""Uji katalog model, mode deteksi (Dual-IF / IF-Flow / IF-Agg), dan hot-reload tanpa restart."""
import os
import sys

import joblib
import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from nids import katalog_model                           # noqa: E402
from nids.agregasi import FITUR_AGREGASI                 # noqa: E402
from nids.aliran import FITUR                            # noqa: E402
from nids.detektor import Detektor                       # noqa: E402
from nids.log_anomali import LogAnomali                  # noqa: E402
from nids.model import ModelDeteksi, latih               # noqa: E402


def _df_latih(seed=42, n=260):
    rng = np.random.default_rng(seed)
    data = {k: rng.normal(10.0, 2.0, size=n) for k in FITUR}
    for k in FITUR_AGREGASI:
        data[k] = rng.normal(2.0, 0.5, size=n)
    return pd.DataFrame(data)


def _aliran_uji(val_flow=10.0, val_agg=2.0):
    d = {
        "Waktu Selesai": 1_761_800_000_000_000,
        "_mulai_us": 1_761_799_999_000_000,
        "Flow Duration": 1_000_000,
        "Source IP": "203.0.113.55",
        "Source Port": 51234,
        "Destination IP": "192.0.2.10",
        "Destination Port": 22,
        "Protocol": 6,
        "Total Fwd Packets": 4,
        "Total Backward Packets": 2,
    }
    for k in FITUR:
        d[k] = float(val_flow)
    for k in FITUR_AGREGASI:
        d[k] = float(val_agg)
    return d


def test_mode_deteksi_dual_if_flow_dan_agg():
    paket = latih(_df_latih(), contamination_A=0.01, contamination_C=0.01)
    # Buat aliran ekstrem hanya pada fitur aliran (A), hanya pada agregasi (C), dan pada keduanya
    f_flow = _aliran_uji(val_flow=9999.0, val_agg=2.0)
    f_agg = _aliran_uji(val_flow=10.0, val_agg=9999.0)
    f_dua = _aliran_uji(val_flow=9999.0, val_agg=9999.0)

    m_dual = ModelDeteksi(paket, mode="A+C")
    h_dual = m_dual.nilai([f_flow, f_agg, f_dua])
    assert h_dual[0][2] == "A"
    assert h_dual[1][2] == "C"
    assert h_dual[2][2] == "A+C"

    m_flow = ModelDeteksi(paket, mode="A")
    h_flow = m_flow.nilai([f_flow, f_agg, f_dua])
    assert h_flow[0][2] == "A"
    assert h_flow[1][2] == ""                  # IF-Agg tidak menandai saat mode IF-Flow saja
    assert h_flow[1][1] == pytest.approx(h_dual[1][1])   # skor_c tetap dihitung!
    assert h_flow[2][2] == "A"

    m_agg = ModelDeteksi(paket, mode="C")
    h_agg = m_agg.nilai([f_flow, f_agg, f_dua])
    assert h_agg[0][2] == ""                   # IF-Flow tidak menandai saat mode IF-Agg saja
    assert h_agg[0][0] == pytest.approx(h_dual[0][0])    # skor_a tetap dihitung!
    assert h_agg[1][2] == "C"
    assert h_agg[2][2] == "C"


def test_katalog_lifecycle_validasi_dan_hapus_aman(tmp_path):
    kat = str(tmp_path / "katalog")
    p1 = str(tmp_path / "m1.joblib")
    p2 = str(tmp_path / "m2.joblib")
    paket1 = latih(_df_latih(seed=1), contamination_A=0.001, contamination_C=0.0075, info={"versi": "m-awal-1"})
    paket2 = latih(_df_latih(seed=2), contamination_A=0.002, contamination_C=0.01, info={"versi": "m-ramai-2"})
    joblib.dump(paket1, p1)
    joblib.dump(paket2, p2)

    data, aktif = katalog_model.pastikan_awal(kat, p1, ModelDeteksi(paket1).ringkas())
    assert data["aktif"] == "m-awal-1" and aktif["versi"] == "m-awal-1"
    assert os.path.exists(os.path.join(kat, "m-awal-1.joblib"))

    # Ubah mode & validasi mode salah
    katalog_model.atur_mode(kat, "C", oleh="satria")
    assert katalog_model.baca(kat)["mode"] == "C"
    with pytest.raises(ValueError):
        katalog_model.atur_mode(kat, "X")

    # Ubah nama profil
    katalog_model.ubah_nama(kat, "m-awal-1", "Baseline Normal", oleh="satria")
    assert katalog_model.cari(katalog_model.baca(kat), "m-awal-1")["nama"] == "Baseline Normal"

    # Buat turunan ambang (tanpa melatih ulang pohon, berbagi berkas joblib yang sama)
    with pytest.raises(ValueError):
        katalog_model.buat_turunan_ambang(kat, contamination_a=0.50)   # melebihi batas aman 1%
    with pytest.raises(ValueError):
        katalog_model.buat_turunan_ambang(kat, contamination_c=0.00001)  # di bawah batas min

    turunan = katalog_model.buat_turunan_ambang(
        kat, contamination_a=0.005, contamination_c=0.02,
        nama="Lebih Sensitif", alasan="uji sensitivitas", oleh="satria",
    )
    assert turunan["induk"] == "m-awal-1"
    assert turunan["berkas"] == "m-awal-1.joblib"
    assert katalog_model.baca(kat)["aktif"] == turunan["versi"]

    # Tidak boleh menghapus model yang sedang aktif
    with pytest.raises(ValueError):
        katalog_model.hapus(kat, turunan["versi"])

    # Rollback ke m-awal-1 lalu hapus turunan -> berkas m-awal-1.joblib HARUS tetap ada!
    katalog_model.aktifkan(kat, "m-awal-1", oleh="satria")
    assert katalog_model.baca(kat)["aktif"] == "m-awal-1"
    katalog_model.hapus(kat, turunan["versi"], oleh="satria")
    assert os.path.exists(os.path.join(kat, "m-awal-1.joblib"))

    # Daftarkan model terpisah kedua, lalu hapus -> berkas m-ramai-2.joblib ikut dibersihkan
    katalog_model.daftar_dari_file(kat, p2, ModelDeteksi(paket2).ringkas(), nama="Profil Ramai", oleh="satria")
    assert os.path.exists(os.path.join(kat, "m-ramai-2.joblib"))
    katalog_model.hapus(kat, "m-ramai-2", oleh="satria")
    assert not os.path.exists(os.path.join(kat, "m-ramai-2.joblib"))


def test_detektor_hot_reload_tanpa_restart(tmp_path):
    kat = str(tmp_path / "katalog")
    p1 = str(tmp_path / "m1.joblib")
    p2 = str(tmp_path / "m2.joblib")
    paket1 = latih(_df_latih(seed=10), contamination_A=0.001, contamination_C=0.0075, info={"versi": "v1-awal"})
    paket2 = latih(_df_latih(seed=20), contamination_A=0.002, contamination_C=0.01, info={"versi": "v2-baru"})
    joblib.dump(paket1, p1)
    joblib.dump(paket2, p2)

    m1 = ModelDeteksi(paket1)
    katalog_model.pastikan_awal(kat, p1, m1.ringkas())
    katalog_model.daftar_dari_file(kat, p2, ModelDeteksi(paket2).ringkas(), nama="Model V2", oleh="admin")

    jam = [100.0]
    pengawas = katalog_model.PengawasModel(kat, periksa_detik=5, jam=lambda: jam[0])
    pengawas.periksa(paksa=True)

    log = LogAnomali(str(tmp_path / "deteksi.db"))
    det = Detektor(m1, log=log, katalog=pengawas, berkas_model=os.path.join(kat, "v1-awal.joblib"))
    assert det.model.versi == "v1-awal" and det.model.mode == "A+C"

    # 1) Ubah mode & ambang di katalog (berkas joblib sama -> reload di memori tanpa ganti objek hutan)
    hutan_awal = det.model.A.model
    katalog_model.atur_mode(kat, "A", oleh="admin")
    v_amb = katalog_model.buat_turunan_ambang(kat, contamination_a=0.008, nama="Sensitif A", oleh="admin")
    jam[0] += 6.0
    assert det.periksa_katalog() is True
    assert det.model.versi == v_amb["versi"]
    assert det.model.mode == "A"
    assert det.model.A.model is hutan_awal     # hutan sama, tidak memuat ulang dari disk!

    # 2) Pindah ke model berbeda (v2-baru.joblib) -> memuat hutan baru dan mencatat ke tabel model
    katalog_model.aktifkan(kat, "v2-baru", oleh="admin")
    jam[0] += 6.0
    assert det.periksa_katalog() is True
    assert det.model.versi == "v2-baru"
    assert det.model.A.model is not hutan_awal
    versi_log = [r[0] for r in log.db.execute("SELECT versi FROM model ORDER BY id").fetchall()]
    assert versi_log == ["v1-awal", v_amb["versi"], "v2-baru"]
    log.tutup()
