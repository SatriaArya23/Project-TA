# -*- coding: utf-8 -*-
"""Uji Paket A (impor & validasi .joblib), Paket B (kendali rekam), dan Paket C (Multi-AI + Telegram)."""
import hashlib
import os
import sys
from types import SimpleNamespace

import joblib
import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import impor_model                                        # noqa: E402
import rekam_kendali as rk_worker                         # noqa: E402
from nids import asisten_ai, katalog_model                # noqa: E402
from nids import rekam_kendali as rk                      # noqa: E402
from nids.agregasi import FITUR_AGREGASI                  # noqa: E402
from nids.aliran import FITUR                             # noqa: E402
from nids.laporan import aksi_ai_telegram                 # noqa: E402
from nids.log_anomali import LogAnomali                   # noqa: E402
from nids.model import ModelDeteksi, latih                # noqa: E402


def _df_latih(seed=7, n=260):
    rng = np.random.default_rng(seed)
    data = {k: rng.normal(10.0, 2.0, size=n) for k in FITUR}
    for k in FITUR_AGREGASI:
        data[k] = rng.normal(2.0, 0.5, size=n)
    return pd.DataFrame(data)


def _sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


# ------------------------------------------------------------------ Paket A: impor & smoke-test .joblib
def test_impor_model_valid_dan_tolak_tidak_sah(tmp_path):
    kat = str(tmp_path / "model")
    masuk = katalog_model.dir_masuk(kat)
    os.makedirs(masuk, exist_ok=True)

    # Daftarkan model awal terlebih dahulu
    p0 = str(tmp_path / "awal.joblib")
    paket0 = latih(_df_latih(seed=1), info={"versi": "v-awal"})
    joblib.dump(paket0, p0)
    katalog_model.pastikan_awal(kat, p0, ModelDeteksi(paket0).ringkas())

    # 1) Unggah model baru yang valid dengan SHA-256 cocok
    p_baru = os.path.join(masuk, "upload_ok.joblib")
    paket1 = latih(_df_latih(seed=2), info={"versi": "v-eksp-2"})
    joblib.dump(paket1, p_baru)
    sha1 = _sha(p_baru)
    katalog_model.antre_impor(kat, "upload_ok.joblib", sha1, nama="Eksperimen Bagus",
                              alasan="uji valid", oleh="satria", sha_diharapkan=sha1, aktifkan=False)
    st = impor_model.validasi_dan_impor(kat)
    assert st["status"] == "berhasil" and st["versi"] == "v-eksp-2"
    assert not os.path.exists(p_baru)                                   # berkas masuk dibersihkan
    d = katalog_model.baca(kat)
    assert d["aktif"] == "v-awal"                                       # tidak langsung menimpa aktif
    assert katalog_model.cari(d, "v-eksp-2")["nama"] == "Eksperimen Bagus"

    # 2) Tolak SHA-256 tidak cocok
    p_sha = os.path.join(masuk, "upload_sha.joblib")
    joblib.dump(paket1, p_sha)
    katalog_model.antre_impor(kat, "upload_sha.joblib", _sha(p_sha), oleh="satria", sha_diharapkan="0" * 64)
    st_sha = impor_model.validasi_dan_impor(kat)
    assert st_sha["status"] == "gagal" and "SHA-256 tidak cocok" in st_sha["pesan"]
    assert not os.path.exists(p_sha)

    # 3) Tolak berkas rusak / bukan joblib
    p_rusak = os.path.join(masuk, "rusak.joblib")
    open(p_rusak, "wb").write(b"bukan berkas joblib")
    katalog_model.antre_impor(kat, "rusak.joblib", _sha(p_rusak), oleh="satria")
    st_rusak = impor_model.validasi_dan_impor(kat)
    assert st_rusak["status"] == "gagal" and "Gagal memuat" in st_rusak["pesan"]
    assert katalog_model.baca(kat)["aktif"] == "v-awal"                 # model aktif tetap aman


# ------------------------------------------------------------------ Paket B: kendali rekam
def test_rekam_kendali_mulai_berhenti_dan_autostop(tmp_path):
    p_cmd = str(tmp_path / "rekam_perintah.json")
    p_st = str(tmp_path / "rekam_status.json")
    state = {"aktif": False, "aksi_log": []}

    def fake_sys(*args):
        state["aksi_log"].append(args)
        if args == ("start", rk_worker.RECORDER_UNIT):
            state["aktif"] = True
        elif args == ("stop", rk_worker.RECORDER_UNIT):
            state["aktif"] = False
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    t0 = 1_761_800_000.0
    rk.minta_mulai(p_cmd, durasi="1j", oleh="satria", catatan="hari ramai", kini=t0)
    st = rk_worker.sinkron(p_cmd, p_st, kini=t0, cek_aktif=lambda: state["aktif"],
                           cek_terpasang=lambda: True, jalankan=fake_sys)
    assert st["aktif"] is True and st["durasi_label"] == "1 jam" and st["batas_utc"] is not None

    # Lewat 1 jam + 10 detik -> auto-stop dan memicu traffic-uploader
    st2 = rk_worker.sinkron(p_cmd, p_st, kini=t0 + 3610, cek_aktif=lambda: state["aktif"],
                            cek_terpasang=lambda: True, jalankan=fake_sys)
    assert st2["aktif"] is False and "otomatis" in st2["pesan"]
    assert ("start", "--no-block", rk_worker.UPLOADER_UNIT) in state["aksi_log"]

    # Mulai lagi lalu hentikan manual
    rk.minta_mulai(p_cmd, durasi="terus", oleh="satria", kini=t0 + 4000)
    rk_worker.sinkron(p_cmd, p_st, kini=t0 + 4000, cek_aktif=lambda: state["aktif"],
                      cek_terpasang=lambda: True, jalankan=fake_sys)
    assert state["aktif"] is True
    rk.minta_berhenti(p_cmd, oleh="satria", kini=t0 + 4050)
    st3 = rk_worker.sinkron(p_cmd, p_st, kini=t0 + 4050, cek_aktif=lambda: state["aktif"],
                            cek_terpasang=lambda: True, jalankan=fake_sys)
    assert st3["aktif"] is False and "dihentikan" in st3["pesan"]


# ------------------------------------------------------------------ Paket C: Multi-AI + Telegram
def test_multi_ai_provider_validasi_cache_dan_telegram(tmp_path):
    p_ai = str(tmp_path / "ai_konfig.json")
    asisten_ai._CACHE.clear()

    # Validasi SSRF & HTTPS
    with pytest.raises(ValueError):
        asisten_ai.tambah_profil(p_ai, "Buruk", "openai_compat", "m", api_key="k",
                                 base_url="http://169.254.169.254/latest/meta-data")
    with pytest.raises(ValueError):
        asisten_ai.tambah_profil(p_ai, "HTTP Luar", "openai_compat", "m", api_key="k",
                                 base_url="http://api.contoh.example/v1")

    # Tambah > 1 profil AI (OpenAI, Gemini, Anthropic, plus Ollama lokal tanpa key)
    p1 = asisten_ai.tambah_profil(p_ai, "OpenAI Utama", "openai", "gpt-4o-mini",
                                  api_key="sk-test-1234567890", oleh="satria", jadikan_aktif=True)
    p2 = asisten_ai.tambah_profil(p_ai, "Gemini Cadangan", "gemini", "gemini-2.5-flash",
                                  api_key="AIzaSyTestKey1234", oleh="satria")
    p3 = asisten_ai.tambah_profil(p_ai, "Claude Analis", "anthropic", "claude-3-5-haiku-latest",
                                  api_key="sk-ant-test9999", oleh="satria")
    asisten_ai.tambah_profil(p_ai, "Ollama Lokal", "openai_compat", "llama3.2",
                             base_url="http://127.0.0.1:11434/v1", oleh="satria")

    aman = asisten_ai.daftar_aman(p_ai)
    assert len(aman["profil"]) == 4 and aman["aktif"] == p1["id"]
    for item in aman["profil"]:
        assert "api_key" not in item
        assert "1234567890" not in item["kunci_samar"]

    panggilan = []

    def fake_http(url, payload, headers):
        panggilan.append((url, payload, headers))
        if "generativelanguage" in url:
            return {"candidates": [{"content": {"parts": [{"text": "Ringkasan Gemini OK"}]}}]}
        if "anthropic" in url:
            return {"content": [{"type": "text", "text": "Ringkasan Claude OK"}]}
        return {"choices": [{"message": {"content": "Ringkasan OpenAI OK"}}]}

    # Uji 3 format provider berbeda
    assert asisten_ai.uji_profil(p_ai, p1["id"], transport=fake_http)["balasan"] == "Ringkasan OpenAI OK"
    assert asisten_ai.uji_profil(p_ai, p2["id"], transport=fake_http)["balasan"] == "Ringkasan Gemini OK"
    assert asisten_ai.uji_profil(p_ai, p3["id"], transport=fake_http)["balasan"] == "Ringkasan Claude OK"

    # Buat deteksi.db kecil untuk uji analisis IP, ringkasan, cache, dan bot Telegram
    db_path = str(tmp_path / "deteksi.db")
    log = LogAnomali(db_path)
    log.catat_model({"versi": "v1", "jendela_detik": 300,
                     "A": {"ambang": 0.7, "contamination": 0.001, "kuantil": [[0.0, 0.1], [1.0, 0.9]]},
                     "C": {"ambang": 0.6, "contamination": 0.01, "kuantil": [[0.0, 0.1], [1.0, 0.9]]}})
    f = {"Waktu Selesai": 1_761_800_000_000_000, "_mulai_us": 1_761_799_999_000_000, "Flow Duration": 1000,
         "Source IP": "203.0.113.77", "Source Port": 40000, "Destination IP": "192.0.2.10", "Destination Port": 22,
         "Protocol": 6, "Total Fwd Packets": 4, "Total Backward Packets": 1, "agg_ip_aliran": 35,
         "agg_ip_port_unik": 1, "agg_ip_rasio_gagal": 0.9, "agg_ip_aliran_ssh": 35,
         "agg_s24_ip_unik": 1, "agg_s24_aliran": 35, "agg_s24_port_unik": 1}
    log.catat([f], [(0.45, 0.88, "C")], SimpleNamespace(A=SimpleNamespace(ambang=0.7), C=SimpleNamespace(ambang=0.6)),
              waktu_log_us="selesai")
    log.tutup()

    # Bot Telegram: /ai, /analisis (1st live, 2nd cached!), /ringkasai, /tanya, ganti AI aktif
    t_list = aksi_ai_telegram("ai", "", db_path, path_ai=p_ai, transport=fake_http)
    assert "OpenAI Utama" in t_list and "Gemini Cadangan" in t_list

    n_sebelum = len(panggilan)
    t_an1 = aksi_ai_telegram("analisis", "203.0.113.77", db_path, path_ai=p_ai, transport=fake_http)
    assert "Ringkasan OpenAI OK" in t_an1 and len(panggilan) == n_sebelum + 1
    t_an2 = aksi_ai_telegram("analisis", "203.0.113.77", db_path, path_ai=p_ai, transport=fake_http)
    assert "(cache)" in t_an2 and len(panggilan) == n_sebelum + 1       # hemat kuota: dari cache!

    t_sw = aksi_ai_telegram("ai", "Gemini Cadangan", db_path, path_ai=p_ai, transport=fake_http)
    assert "Gemini Cadangan" in t_sw
    t_rg = aksi_ai_telegram("ringkasai", "24j", db_path, path_ai=p_ai, transport=fake_http)
    assert "Ringkasan Gemini OK" in t_rg
    t_tn = aksi_ai_telegram("tanya", "Ada brute force SSH?", db_path, path_ai=p_ai, transport=fake_http)
    assert "Ringkasan Gemini OK" in t_tn


def test_dynamic_models_discovery_chat_dan_reasoning(tmp_path):
    p_ai = str(tmp_path / "ai_dyn.json")
    asisten_ai._CACHE.clear()
    req_log = []

    def fake_dyn(url, payload, headers, method="GET"):
        req_log.append((method, url, payload))
        if method == "GET" and url.endswith("/v1/models") and "openai" in url:
            return {"data": [{"id": "gpt-4o-mini"}, {"id": "o4-mini"}, {"id": "gpt-5"}, {"id": "whisper-1"}]}
        if method == "GET" and "generativelanguage" in url:
            return {"models": [
                {"name": "models/gemini-2.5-pro", "supportedGenerationMethods": ["generateContent"]},
                {"name": "models/embedding-001", "supportedGenerationMethods": ["embedContent"]},
            ]}
        if method == "GET" and "anthropic" in url:
            return {"data": [{"id": "claude-sonnet-4-20250514"}]}
        return {"choices": [{"message": {"content": "Siap, model reasoning aktif."}}]}

    # Tambah tanpa mengisi field model -> ambil daftar model otomatis
    po = asisten_ai.tambah_profil(p_ai, "OpenAI Dinamis", "openai", model="",
                                  api_key="sk-dyn-11112222", oleh="satria", jadikan_aktif=True, transport=fake_dyn)
    assert "o4-mini" in po["models"] and "gpt-5" in po["models"] and "whisper-1" not in po["models"]

    pg = asisten_ai.tambah_profil(p_ai, "Gemini Dinamis", "gemini", model="",
                                  api_key="AIzaDynKey1234", oleh="satria", transport=fake_dyn)
    assert pg["models"] == ["gemini-2.5-pro"] and pg["model"] == "gemini-2.5-pro"

    pa = asisten_ai.tambah_profil(p_ai, "Claude Dinamis", "anthropic", model="",
                                  api_key="sk-ant-dyn1234", oleh="satria", transport=fake_dyn)
    assert pa["models"] == ["claude-sonnet-4-20250514"]

    db_path = str(tmp_path / "deteksi.db")
    log = LogAnomali(db_path)
    log.catat_model({"versi": "v1", "jendela_detik": 300})

    # Chat multi-turn + model_override o4-mini (wajib max_completion_tokens, tanpa temperature non-default)
    res = asisten_ai.chat_keamanan(
        p_ai, log.db, "Apakah scan berbahaya?",
        riwayat_chat=[{"role": "user", "content": "Halo"}, {"role": "assistant", "content": "Halo SOC"}],
        profil_id=po["id"], model_override="o4-mini", transport=fake_dyn,
    )
    log.tutup()
    assert res["model"] == "o4-mini" and "Siap" in res["teks"]
    post_reqs = [(u, pl) for m, u, pl in req_log if m == "POST"]
    assert post_reqs[-1][1]["model"] == "o4-mini"
    assert "max_completion_tokens" in post_reqs[-1][1] and "temperature" not in post_reqs[-1][1]
    assert len(post_reqs[-1][1]["messages"]) >= 4

    # Telegram /models dan /modelai
    t_mods = aksi_ai_telegram("models", "", db_path, path_ai=p_ai, transport=fake_dyn)
    assert "o4-mini" in t_mods
    t_swm = aksi_ai_telegram("modelai", "o4-mini", db_path, path_ai=p_ai, transport=fake_dyn)
    assert "o4-mini" in t_swm
    assert asisten_ai.baca(p_ai)["profil"][0]["model"] == "o4-mini"


def test_adaptasi_model_anomali_dan_normal_serta_guard(tmp_path):
    from nids import adaptasi
    from nids.detektor import Detektor
    from nids.umpan_balik import BATAS_CONTAMINATION, hampir_anomali

    df = _df_latih(seed=11, n=260)
    paket = latih(df, info={"versi": "v-ad-0"})
    base_row = {k: float(df.iloc[0][k]) for k in list(FITUR) + list(FITUR_AGREGASI)}

    flow_atk = dict(base_row, **{
        "Waktu Selesai": 1_761_800_100_000_000, "_mulai_us": 1_761_800_090_000_000,
        "Source IP": "198.51.100.10", "Source Port": 51000, "Destination IP": "192.0.2.10",
        "Destination Port": 8080, "Protocol": 6, "Total Fwd Packets": 8, "Total Backward Packets": 1,
        "Flow Duration": 5000.0, "agg_ip_aliran": 15.0, "agg_ip_port_unik": 15.0,
    })
    flow_legit = dict(base_row, **{
        "Waktu Selesai": 1_761_800_110_000_000, "_mulai_us": 1_761_800_100_000_000,
        "Source IP": "203.0.113.50", "Source Port": 52000, "Destination IP": "192.0.2.10",
        "Destination Port": 9443, "Protocol": 6, "Total Fwd Packets": 40, "Total Backward Packets": 35,
        "Flow Duration": 90000.0, "Flow Bytes/s": 400.0, "agg_ip_aliran": 9.0, "agg_ip_port_unik": 1.0,
    })

    # Kalibrasi kuantil & ambang agar flow_atk & flow_legit berada tepat di zona "hampir anomali"
    m_awal = ModelDeteksi(paket)
    r0, _, _ = m_awal.nilai_detail([flow_atk, flow_legit])
    sa0, sc0 = max(r0[0][0], r0[1][0]), max(r0[0][1], r0[1][1])
    min_sa, min_sc = min(r0[0][0], r0[1][0]), min(r0[0][1], r0[1][1])
    paket["A"]["threshold"] = sa0 + 0.04
    paket["C"]["threshold"] = sc0 + 0.04
    paket["A"]["kuantil"] = [[0.0, 0.0], [0.995, min_sa - 0.02], [1.0, sa0 + 0.2]]
    paket["C"]["kuantil"] = [[0.0, 0.0], [0.96, min_sc - 0.02], [1.0, sc0 + 0.2]]

    kat = str(tmp_path / "model")
    p0 = str(tmp_path / "base.joblib")
    joblib.dump(paket, p0)
    katalog_model.pastikan_awal(kat, p0, ModelDeteksi(paket).ringkas())

    db_path = str(tmp_path / "deteksi.db")
    log = LogAnomali(db_path)
    pengawas = katalog_model.PengawasModel(kat, periksa_detik=0)
    det = Detektor(ModelDeteksi(paket), log=log, katalog=pengawas, berkas_model=p0, waktu_log="selesai")

    hasil_awal, xa_awal, xc_awal = det.model.nilai_detail([flow_atk, flow_legit])
    assert hasil_awal[0][2] == "" and hasil_awal[1][2] == ""
    log.catat([flow_atk, flow_legit], hasil_awal, det.model, waktu_log_us="selesai", vektor=(xa_awal, xc_awal))

    hampir0 = hampir_anomali(log.db, 0)
    assert {x["src_ip"] for x in hampir0} == {"198.51.100.10", "203.0.113.50"}

    # 1) Admin putuskan flow_atk = ANOMALI -> tambah aturan & hot-reload
    at_atk = adaptasi.ekstrak_prototipe(
        log.db, "198.51.100.10", 1_761_800_000_000_000, 1_761_800_200_000_000,
        label="anomali", model_info=det.model.ringkas(), oleh="satria", catatan="scan 8080",
    )
    assert at_atk["mode_cocok"] == "vektor"
    v_atk = katalog_model.tambah_adaptasi(kat, at_atk, oleh="satria")
    assert det.periksa_katalog(paksa=True) is True
    assert len(det.model.adaptasi) == 1

    # Kejadian serupa dari IP BERBEDA langsung terdeteksi sebagai ANOMALI (bukan hampir anomali)
    flow_atk_baru = dict(flow_atk, **{"Source IP": "198.51.100.99", "Total Fwd Packets": 9})
    det_atk_baru, _, _ = det.model.nilai_detail([flow_atk_baru])
    assert det_atk_baru[0][2] != ""
    hampir1 = hampir_anomali(log.db, 0, aturan_adaptasi=det.model.adaptasi)
    assert [x["src_ip"] for x in hampir1] == ["203.0.113.50"]

    # 2) Admin putuskan flow_legit = NORMAL -> tambah aturan & hot-reload
    at_norm = adaptasi.ekstrak_prototipe(
        log.db, "203.0.113.50", 1_761_800_000_000_000, 1_761_800_200_000_000,
        label="normal", model_info=det.model.ringkas(), oleh="satria", catatan="backup internal",
    )
    katalog_model.tambah_adaptasi(kat, at_norm, oleh="satria")
    assert det.periksa_katalog(paksa=True) is True
    assert hampir_anomali(log.db, 0, aturan_adaptasi=det.model.adaptasi) == []

    # IP BERBEDA dengan pola backup serupa pada port 9443 disupresi di bawah batas aman
    flow_legit_baru = dict(flow_legit, **{"Source IP": "203.0.113.99", "Total Fwd Packets": 39})
    det_norm_baru, xa_n, xc_n = det.model.nilai_detail([flow_legit_baru])
    ba, bc = det.model.batas_aman()
    assert det_norm_baru[0][2] == "" and det_norm_baru[0][0] <= ba and det_norm_baru[0][1] <= bc

    # Guard SSH port 22: aturan normal port 9443 TIDAK pernah menekan lalu lintas SSH port 22
    assert adaptasi.cocokkan(
        [at_norm], vec_a=xa_n[0].tolist(), vec_c=xc_n[0].tolist(), dst_port=22, protokol=6, paket=75
    ) is None
    # Uji rollback / hapus adaptasi
    v_del = katalog_model.hapus_adaptasi(kat, v_atk["adaptasi"][0]["id"], oleh="satria")
    assert v_del is not None and len(v_del["adaptasi"]) == 1
    log.tutup()
