# -*- coding: utf-8 -*-
"""Uji loop umpan balik: periksa ulang di modul deteksi -> penyesuaian ambang -> versi model baru."""
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_realtime import berkas, model                             # noqa: E402,F401  (fixture)
from nids.detektor import Detektor                                  # noqa: E402
from nids.log_anomali import LogAnomali                             # noqa: E402
from nids.model import ModelDeteksi, kuantil_skor, ubah_ambang      # noqa: E402
from nids.pcap import baca_pcap                                     # noqa: E402
from nids.umpan_balik import ambang_dari_kontaminasi, ambang_model, kontaminasi_dari_skor, periksa_ulang  # noqa: E402

PENYERANG = "203.0.113.66"


def jalankan(model, f, log):
    det = Detektor(model, log, None, waktu_log="selesai")
    for p in baca_pcap(f):
        det.paket(p)
        det.detak(p.ts)
    det.selesai()
    return det


def test_kuantil_bolak_balik():
    s = np.random.default_rng(0).gamma(2.0, 0.1, 50_000)
    k = kuantil_skor(s)
    for c in (0.001, 0.01, 0.05):
        t = ambang_dari_kontaminasi(k, c)
        assert abs(t - np.quantile(s, 1 - c)) < 1e-3
        assert abs(kontaminasi_dari_skor(k, t) - c) < 1e-6
        assert abs((s > t).mean() - c) < 0.1 * c + 2e-5


def test_log_menyimpan_semua_aliran_dan_versi_model(berkas, model, tmp_path):
    log = LogAnomali(str(tmp_path / "d.db"))
    det = jalankan(model, berkas[1], log)
    n, ditandai = log.db.execute("SELECT COUNT(*), SUM(oleh != '') FROM aliran").fetchone()
    assert n == det.jumlah_aliran and ditandai == det.jumlah_anomali
    versi = log.db.execute("SELECT versi FROM model").fetchall()
    assert versi == [(model.versi,)]
    assert log.db.execute("SELECT COUNT(*) FROM anomali WHERE model_id IS NULL").fetchone()[0] == 0
    jalankan(model, berkas[1], log)                     # versi sama -> tidak dicatat dua kali
    assert log.db.execute("SELECT COUNT(*) FROM model").fetchone()[0] == 1


def test_loop_umpan_balik(berkas, model, tmp_path):
    log = LogAnomali(str(tmp_path / "d.db"))
    jalankan(model, berkas[1], log)
    db = log.db
    t0, t1 = db.execute("SELECT MIN(waktu_selesai_us), MAX(waktu_selesai_us) FROM aliran").fetchone()
    kini = t1 + 60_000_000

    # serangan yang sudah tertangkap
    h = periksa_ulang(db, "lolos", PENYERANG, t0, t1, kini_us=kini)
    assert h["status"] == "sudah_terdeteksi" and h["ditandai"] > 0
    # IP yang tidak ada
    assert periksa_ulang(db, "lolos", "192.0.2.1", t0, t1, kini_us=kini)["status"] == "tidak_ada_aliran"
    # alarm palsu -> pelatihan ulang (sebagai data normal)
    assert periksa_ulang(db, "palsu", PENYERANG, t0, t1, kini_us=kini)["status"] == "pelatihan_ulang"

    # ambang batas aman (untuk daftar "hampir anomali" di dashboard) <= ambang yang berlaku
    am = ambang_model(db)
    for m in am.values():
        for nama in ("A", "C"):
            assert m[nama]["batas"] <= m[nama]["ambang"]
    assert all(m["C"]["batas"] == m["C"]["ambang"] for m in ambang_model(db, batas={"C": 0.0}).values())

    # pengunjung biasa yang "dilaporkan lolos": ambang perlu diturunkan
    ip = db.execute("SELECT src_ip FROM aliran WHERE src_ip != ? AND src_ip LIKE '198.18.%' AND oleh = '' "
                    "ORDER BY skor_c DESC LIMIT 1", (PENYERANG,)).fetchone()[0]
    ketat = periksa_ulang(db, "lolos", ip, t0, t1, batas={"A": 0.0, "C": 0.0}, kini_us=kini)
    assert ketat["status"] == "pelatihan_ulang" and ketat["kandidat"]
    longgar = periksa_ulang(db, "lolos", ip, t0, t1, batas={"A": 1.0, "C": 1.0}, kini_us=kini)
    assert longgar["status"] == "terdeteksi_penyesuaian"
    u = longgar["usulan"]
    assert u["tertangkap"] >= 1 and u["contamination_baru"] > (u["contamination_sekarang"] or 0)

    # terapkan usulan -> versi model baru menandai IP tersebut, hutan tetap sama
    baru = ModelDeteksi(ubah_ambang(model.paket, ambang={u["model"]: float("%.8f" % u["ambang_baru"])},
                                    alasan="uji"))
    assert abs(baru.paket[u["model"]]["contamination"] - u["contamination_baru"]) < 1e-9
    assert baru.versi != model.versi and baru.paket["induk"] == model.versi
    assert baru.paket["A"]["model"] is model.paket["A"]["model"]
    log2 = LogAnomali(str(tmp_path / "d2.db"))
    jalankan(baru, berkas[1], log2)
    assert log2.db.execute("SELECT COUNT(*) FROM aliran WHERE src_ip = ? AND oleh != ''", (ip,)).fetchone()[0] >= 1
    # versi baru tercatat di log dengan ringkasan & sebaran skor
    info = baru.ringkas()
    assert info["induk"] == model.versi and len(info["C"]["kuantil"]) > 1000
    # "periksa ulang lagi" di log lama setelah versi baru aktif: hutan sama -> aliran lama dinilai dg ambang baru
    log.catat_model(info)
    lagi = periksa_ulang(db, "lolos", ip, t0, t1, kini_us=kini)
    assert lagi["status"] == "sudah_terdeteksi" and lagi["versi_acuan"] == [baru.versi]


def test_latih_ulang_dengan_kasus(berkas, model, tmp_path):
    """latih_model.pilih_contamination memilih kisi yang menangkap kasus lolos."""
    import latih_model
    from nids.pipa import putar_ulang
    aliran, _ = putar_ulang([berkas[1]], 300)
    df = pd.DataFrame(aliran)
    ip = "198.18.0.5"
    t0, t1 = int(df["Waktu Selesai"].min()), int(df["Waktu Selesai"].max())
    lolos = [{"id": 1, "jenis": "lolos", "src_ip": PENYERANG, "mulai_us": t0, "akhir_us": t1}]
    palsu = [{"id": 2, "jenis": "palsu", "src_ip": ip, "mulai_us": t0, "akhir_us": t1}]
    df_lolos = df[latih_model.cocok_kasus(df, lolos)]
    df_palsu = df[latih_model.cocok_kasus(df, palsu)]
    latih_df = df[~latih_model.cocok_kasus(df, lolos)]
    pilihan, tabel = latih_model.pilih_contamination(model.paket, latih_df, df_lolos, lolos, df_palsu)
    assert len(tabel) == len(latih_model.GRID_A) * len(latih_model.GRID_C)
    assert pilihan["kasus_lolos_terdeteksi"] == 1 and len(df_lolos) == 60
