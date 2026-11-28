# -*- coding: utf-8 -*-
"""Uji terpadu dashboard: model adaptif dari hampir anomali/umpan balik, chat multi-AI dinamis, & audit lintas layanan."""
import csv
import io
import json
import os
import re
import sys

import joblib
import numpy as np
import pandas as pd
from werkzeug.security import generate_password_hash

KODE_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(KODE_ROOT, "2_sistem_nids"))
sys.path.insert(0, os.path.join(KODE_ROOT, "3_dashboard"))

from nids import audit_bersama, katalog_model                 # noqa: E402
from nids.agregasi import FITUR_AGREGASI                    # noqa: E402
from nids.aliran import FITUR                               # noqa: E402
from nids.log_anomali import LogAnomali                     # noqa: E402
from nids.model import ModelDeteksi, latih                  # noqa: E402
from nids.umpan_balik import BATAS_CONTAMINATION            # noqa: E402
from penerima import create_app                             # noqa: E402
from penerima.db import koneksi, sekarang                   # noqa: E402


def _csrf(client, path="/login"):
    h = client.get(path).get_data(as_text=True)
    m = re.search(r'name="csrf" value="([^"]+)"', h)
    assert m, "Token CSRF tidak ditemukan di " + path
    return m.group(1)


def _masuk(client, username, password):
    r = client.post("/login", data={"csrf": _csrf(client, "/login"), "username": username, "password": password})
    assert r.status_code in (302, 200)


def _siapkan_env(tmp_path):
    data_dir = tmp_path / "data"
    bersama = tmp_path / "bersama"
    model_dir = bersama / "model"
    deteksi_dir = tmp_path / "deteksi"
    for d in (data_dir, bersama, model_dir, deteksi_dir):
        d.mkdir(parents=True, exist_ok=True)

    # Latih model sintetis kecil & buat dua aliran boundary ("hampir anomali") bervektor lengkap
    rng = np.random.default_rng(21)
    df = pd.DataFrame({
        **{k: rng.normal(10.0, 2.0, size=260) for k in FITUR},
        **{k: rng.normal(2.0, 0.5, size=260) for k in FITUR_AGREGASI},
    })
    paket = latih(df, info={"versi": "v-dash-0", "nama": "Baseline VPS"})
    base = {k: float(df.iloc[0][k]) for k in list(FITUR) + list(FITUR_AGREGASI)}
    kini_us = int(1_761_900_000_000_000)

    f1 = dict(base, **{
        "Waktu Selesai": kini_us - 120_000_000, "_mulai_us": kini_us - 125_000_000,
        "Source IP": "198.51.100.11", "Source Port": 44100, "Destination IP": "192.0.2.5",
        "Destination Port": 8080, "Protocol": 6, "Total Fwd Packets": 8, "Total Backward Packets": 1,
        "agg_ip_aliran": 14.0, "agg_ip_port_unik": 14.0,
    })
    f2 = dict(base, **{
        "Waktu Selesai": kini_us - 60_000_000, "_mulai_us": kini_us - 65_000_000,
        "Source IP": "203.0.113.51", "Source Port": 55200, "Destination IP": "192.0.2.5",
        "Destination Port": 9443, "Protocol": 6, "Total Fwd Packets": 32, "Total Backward Packets": 28,
        "Flow Duration": 85000.0, "agg_ip_aliran": 8.0, "agg_ip_port_unik": 1.0,
    })

    m_tmp = ModelDeteksi(paket)
    res0, _, _ = m_tmp.nilai_detail([f1, f2])
    sa0, sc0 = max(res0[0][0], res0[1][0]), max(res0[0][1], res0[1][1])
    min_sa, min_sc = min(res0[0][0], res0[1][0]), min(res0[0][1], res0[1][1])
    paket["A"]["threshold"] = sa0 + 0.04
    paket["C"]["threshold"] = sc0 + 0.04
    paket["A"]["kuantil"] = [[0.0, 0.0], [0.995, min_sa - 0.02], [1.0, sa0 + 0.2]]
    paket["C"]["kuantil"] = [[0.0, 0.0], [0.96, min_sc - 0.02], [1.0, sc0 + 0.2]]

    m = ModelDeteksi(paket)
    p0 = str(tmp_path / "m0.joblib")
    joblib.dump(paket, p0)
    katalog_model.pastikan_awal(str(model_dir), p0, m.ringkas())

    det_db = str(deteksi_dir / "deteksi.db")
    log = LogAnomali(det_db)
    log.catat_model(m.ringkas())
    det_res, xa, xc = m.nilai_detail([f1, f2])
    log.catat([f1, f2], det_res, m, waktu_log_us="selesai", vektor=(xa, xc))
    log.status(model_versi="v-dash-0", model_mode="A+C")
    log.tutup()

    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "kunci-pengujian-tetap",
        "SESSION_COOKIE_SECURE": False,
        "DATA_DIR": str(data_dir),
        "DETEKSI_DB": det_db,
        "MODEL_DIR": str(model_dir),
        "TEPERCAYA_PATH": str(bersama / "ip_tepercaya.json"),
        "BLOKIR_PATH": str(bersama / "ip_diblokir.json"),
        "BLOKIR_STATUS_PATH": str(bersama / "ip_diblokir_status.json"),
        "REKAM_CMD_PATH": str(bersama / "rekam_perintah.json"),
        "REKAM_STATUS_PATH": str(bersama / "rekam_status.json"),
        "AI_CONFIG_PATH": str(bersama / "ai_konfig.json"),
        "AUDIT_EKSTERNAL_PATH": str(bersama / "audit_eksternal.jsonl"),
    })
    with app.app_context():
        db = koneksi()
        db.execute("INSERT INTO instalasi (nama, keterangan, dibuat_utc) VALUES (?, ?, ?)", ("vps-uji", "Uji", sekarang()))
        db.execute(
            "INSERT INTO pengguna (username, hash_sandi, peran, instalasi_id, dibuat_utc) VALUES (?,?,?,?,?)",
            ("admin1", generate_password_hash("sandi-admin-123"), "admin", None, sekarang()),
        )
        db.execute(
            "INSERT INTO pengguna (username, hash_sandi, peran, instalasi_id, dibuat_utc) VALUES (?,?,?,?,?)",
            ("viewer_tanpa_inst", generate_password_hash("sandi-viewer-123"), "viewer", None, sekarang()),
        )
        db.commit()
    return app


def test_hampir_anomali_adaptasi_model_dan_hapus(tmp_path):
    app = _siapkan_env(tmp_path)
    adm = app.test_client()
    _masuk(adm, "admin1", "sandi-admin-123")

    # Awalnya kedua IP muncul di /deteksi/hampir
    h0 = adm.get("/deteksi/hampir").get_data(as_text=True)
    assert "198.51.100.11" in h0 and "203.0.113.51" in h0 and 'style="' not in h0

    # Keputusan langsung Anomali pada 198.51.100.11 -> hilang dari /deteksi/hampir & aturan aktif di katalog
    r_anom = adm.post("/deteksi/hampir/putuskan", data={
        "csrf": _csrf(adm, "/deteksi/hampir"),
        "ip": "198.51.100.11",
        "mulai_us": str(1_761_900_000_000_000 - 200_000_000),
        "akhir_us": str(1_761_900_000_000_000),
        "rentang": "24j",
        "keputusan": "anomali",
    })
    assert r_anom.status_code == 302
    h1 = adm.get("/deteksi/hampir").get_data(as_text=True)
    assert "Pola 198.51.100.11 ditetapkan sebagai ANOMALI" in h1
    assert ">198.51.100.11</a>" not in h1 and ">203.0.113.51</a>" in h1
    assert "198.51.100.11" not in adm.get("/deteksi/hampir").get_data(as_text=True)

    # Keputusan langsung Normal pada 203.0.113.51 -> /deteksi/hampir bersih
    r_norm = adm.post("/deteksi/hampir/putuskan", data={
        "csrf": _csrf(adm, "/deteksi/hampir"),
        "ip": "203.0.113.51",
        "mulai_us": str(1_761_900_000_000_000 - 200_000_000),
        "akhir_us": str(1_761_900_000_000_000),
        "rentang": "24j",
        "keputusan": "normal",
    })
    assert r_norm.status_code == 302
    h2 = adm.get("/deteksi/hampir").get_data(as_text=True)
    assert "Pola 203.0.113.51 ditetapkan sebagai BUKAN ANOMALI" in h2
    assert ">198.51.100.11</a>" not in h2 and ">203.0.113.51</a>" not in h2

    # Cek halaman model menampilkan 2 aturan adaptasi aktif, lalu hapus 1 aturan
    hm = adm.get("/deteksi/model").get_data(as_text=True)
    assert "Aturan adaptasi aktif" in hm and "2 aturan" in hm and 'style="' not in hm
    kat = katalog_model.baca(app.config["MODEL_DIR"])
    aturan = kat["model"][0]["adaptasi"]
    assert len(aturan) == 2

    r_del = adm.post("/deteksi/model", data={
        "csrf": _csrf(adm, "/deteksi/model"),
        "aksi": "hapus_adaptasi",
        "id_aturan": aturan[0]["id"],
    })
    assert r_del.status_code == 302
    hm2 = adm.get("/deteksi/model").get_data(as_text=True)
    assert "1 aturan" in hm2

    # Pastikan audit mencatat ADAPTASI_TAMBAH dan ADAPTASI_HAPUS
    aud = adm.get("/audit").get_data(as_text=True)
    assert "ADAPTASI_TAMBAH" in aud and "ADAPTASI_HAPUS" in aud


def test_ai_dinamis_chat_multiturn_dan_pilih_model(tmp_path):
    app = _siapkan_env(tmp_path)
    payloads = []

    def fake_transport(url, payload, headers, method="GET"):
        payloads.append((method, url, payload))
        if method == "GET" and url.endswith("/v1/models"):
            return {"data": [{"id": "gpt-4o-mini"}, {"id": "o4-mini"}, {"id": "gpt-4.1"}]}
        return {"choices": [{"message": {"content": "Balasan dari %s OK." % (payload or {}).get("model")}}]}

    app.config["AI_TRANSPORT"] = fake_transport
    adm = app.test_client()
    _masuk(adm, "admin1", "sandi-admin-123")

    # Tambah koneksi tanpa mengisi model -> deteksi model otomatis
    r_add = adm.post("/deteksi/ai", data={
        "csrf": _csrf(adm, "/deteksi/ai"),
        "aksi": "tambah",
        "nama": "OpenAI Dinamis",
        "provider": "openai",
        "api_key": "sk-test-dinamis-9999",
        "model": "",
        "aktifkan": "1",
    })
    assert r_add.status_code == 302
    page = adm.get("/deteksi/ai").get_data(as_text=True)
    assert "OpenAI Dinamis" in page and "gpt-4.1" in page and 'style="' not in page

    # Chat turn 1 pakai o4-mini dari dropdown model_pilih
    r_c1 = adm.post("/deteksi/ai", data={
        "csrf": _csrf(adm, "/deteksi/ai"),
        "aksi": "tanya",
        "model_pilih": "o4-mini",
        "pertanyaan": "Jelaskan status traffic saat ini",
    })
    assert r_c1.status_code == 200
    t1 = r_c1.get_data(as_text=True)
    assert "Balasan dari o4-mini OK." in t1 and "2 pesan" in t1

    # Chat turn 2 pakai model_kustom -> riwayat turn 1 ikut terkirim ke API
    r_c2 = adm.post("/deteksi/ai", data={
        "csrf": _csrf(adm, "/deteksi/ai"),
        "aksi": "tanya",
        "model_pilih": "__kustom__",
        "model_kustom": "gpt-5-mini",
        "pertanyaan": "Lalu langkah mitigasinya?",
    })
    assert r_c2.status_code == 200
    t2 = r_c2.get_data(as_text=True)
    assert "Balasan dari gpt-5-mini OK." in t2 and "4 pesan" in t2
    last_chat_req = [p for m, u, p in payloads if m == "POST"][-1]
    assert last_chat_req["model"] == "gpt-5-mini"
    assert any("Jelaskan status traffic saat ini" in str(m.get("content")) for m in last_chat_req["messages"])

    # Ringkas AI di halaman /deteksi memilih model gpt-4.1
    r_ring = adm.post("/deteksi/ringkas-ai", data={
        "csrf": _csrf(adm, "/deteksi"),
        "rentang": "24j",
        "model_pilih": "gpt-4.1",
    })
    assert r_ring.status_code == 200 and "Balasan dari gpt-4.1 OK." in r_ring.get_data(as_text=True)

    # Reset percakapan (Chat baru)
    r_rst = adm.post("/deteksi/ai", data={"csrf": _csrf(adm, "/deteksi/ai"), "aksi": "chat_baru"})
    assert r_rst.status_code == 302
    assert "0 pesan" in adm.get("/deteksi/ai").get_data(as_text=True)


def test_audit_lintas_layanan_isolasi_viewer_filter_csv(tmp_path):
    app = _siapkan_env(tmp_path)

    # Simulasikan event dari nids-bot (Telegram) & nids-model worker lewat antrean audit eksternal
    audit_path = app.config["AUDIT_EKSTERNAL_PATH"]
    audit_bersama.tulis(audit_path, "TELEGRAM_BLOKIR", aktor="tg:12345", ket="198.51.100.77 [24j]")
    audit_bersama.tulis(audit_path, "MODEL_IMPOR_OK", aktor="admin1", nama="exp.joblib", sha="abcd", kode=200)

    # Viewer tanpa instalasi: tidak boleh melihat audit global & mencoba aksi terlarang tercatat AKSES_DITOLAK
    vw = app.test_client()
    _masuk(vw, "viewer_tanpa_inst", "sandi-viewer-123")
    r_v_aud = vw.get("/audit").get_data(as_text=True)
    assert "TELEGRAM_BLOKIR" not in r_v_aud and "MODEL_IMPOR_OK" not in r_v_aud
    r_403 = vw.post("/deteksi/blokir", data={"csrf": _csrf(vw, "/deteksi/blokir"), "aksi": "tambah", "ip": "8.8.8.8"})
    assert r_403.status_code == 403

    # Admin: gagal blokir tercatat BLOKIR_GAGAL, dan audit menampilkan seluruh event + filter + CSV
    adm = app.test_client()
    _masuk(adm, "admin1", "sandi-admin-123")
    r_bad = adm.post("/deteksi/blokir", data={
        "csrf": _csrf(adm, "/deteksi/blokir"), "aksi": "tambah", "ip": "127.0.0.1", "durasi": "1j",
    })
    assert r_bad.status_code == 200 or r_bad.status_code == 400

    aud_full = adm.get("/audit").get_data(as_text=True)
    for jenis in ("TELEGRAM_BLOKIR", "MODEL_IMPOR_OK", "AKSES_DITOLAK", "BLOKIR_GAGAL"):
        assert jenis in aud_full

    # Filter kategori blokir + cari
    aud_fil = adm.get("/audit?kategori=blokir&cari=198.51.100.77").get_data(as_text=True)
    assert "TELEGRAM_BLOKIR" in aud_fil and "MODEL_IMPOR_OK" not in aud_fil

    # Ekspor CSV
    r_csv = adm.get("/audit?kategori=blokir&format=csv")
    assert r_csv.status_code == 200 and "text/csv" in r_csv.mimetype
    baris = list(csv.reader(io.StringIO(r_csv.get_data(as_text=True))))
    assert baris[0][0] == "waktu_utc" and any(b[1] == "TELEGRAM_BLOKIR" for b in baris[1:])
    assert "AUDIT_EKSPOR" in adm.get("/audit").get_data(as_text=True)
