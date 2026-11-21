# -*- coding: utf-8 -*-
"""Uji simulator & evaluasi. Semua berjalan di laptop sendiri (127.0.0.1), tidak ke server mana pun.
Jalankan: python -m pytest -q tests"""
import http.server
import os
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

AKAR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AKAR))
sys.path.insert(0, str(AKAR.parent / "2_sistem_nids"))
import evaluasi                                   # noqa: E402
import simulasi                                   # noqa: E402
from nids.log_anomali import LogAnomali           # noqa: E402


@pytest.fixture
def web():
    class Diam(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *a):
            pass
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Diam)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def argumen(tmp_path, skenario, **k):
    a = dict(skenario=skenario, target="127.0.0.1", jadwal=str(tmp_path / "jadwal.csv"), ip_sumber=None, catatan="uji",
             port_web=80, port_ssh=22, sesi=1, jeda=0, port_awal=1, port_akhir=10, laju=200, jumlah=3,
             percobaan=1, user="uji", durasi=1, koneksi=5)
    a.update(k)
    return SimpleNamespace(**a)


def test_target_selain_server_uji_ditolak(tmp_path):
    with pytest.raises(SystemExit):
        simulasi.jalankan(argumen(tmp_path, "portscan", target="8.8.8.8"))
    assert not (tmp_path / "jadwal.csv").exists()


def test_skenario_lokal_tercatat(tmp_path, web, monkeypatch):
    monkeypatch.setattr(simulasi.random, "uniform", lambda a, b: 0)            # tanpa jeda baca saat uji
    b1 = simulasi.jalankan(argumen(tmp_path, "normal", port_web=web))
    b2 = simulasi.jalankan(argumen(tmp_path, "portscan", port_awal=web - 5, port_akhir=web + 5))
    b3 = simulasi.jalankan(argumen(tmp_path, "dos-http", port_web=web, laju=20, durasi=1))
    assert b1["label"] == "normal" and b1["berhasil"] >= 1
    assert b2["label"] == "serangan" and b2["jumlah"] == 11 and b2["berhasil"] >= 1     # port web terbuka
    assert b3["jumlah"] == 20 and b3["berhasil"] == 20
    j = evaluasi.muat_jadwal(str(tmp_path / "jadwal.csv"))
    assert list(j.id) == [1, 2, 3] and set(j.ip_sumber) == {"127.0.0.1"}
    assert (j.selesai_us >= j.mulai_us).all()


def test_batas_laju_dan_durasi(tmp_path, web):
    b = simulasi.jalankan(argumen(tmp_path, "dos-http", port_web=web, laju=10_000, durasi=0.01))
    assert b["jumlah"] == int(simulasi.BATAS["laju_dos"] * 0.01)               # laju dipangkas ke batas


def test_evaluasi_metrik(tmp_path):
    T, S = 1_800_000_000_000_000, 1_000_000
    db = str(tmp_path / "d.db")
    log = LogAnomali(db)
    log.catat_model({"versi": "uji"})
    m = SimpleNamespace(A=SimpleNamespace(ambang=0.7), C=SimpleNamespace(ambang=0.7))

    def f(ip, t):
        return {"Waktu Selesai": t, "_mulai_us": t - 10, "Flow Duration": 10, "Source IP": ip, "Source Port": 1,
                "Destination IP": "192.0.2.1", "Destination Port": 22, "Protocol": 6, "Total Fwd Packets": 1,
                "Total Backward Packets": 1, **{k: 0 for k in ("agg_ip_aliran", "agg_ip_port_unik", "agg_ip_rasio_gagal",
                                                              "agg_ip_aliran_ssh", "agg_s24_ip_unik", "agg_s24_aliran",
                                                              "agg_s24_port_unik")}}
    fs, hs = [], []
    for i in range(10):                     # serangan: 8 dari 10 tertangkap
        fs.append(f("203.0.113.5", T + i * S)); hs.append((0.5, 0.9 if i < 8 else 0.1, "C" if i < 8 else ""))
    for i in range(5):                      # pengunjung normal dari laptop: 1 alarm palsu
        fs.append(f("203.0.113.5", T + 1000 * S + i * S)); hs.append((0.8 if i == 0 else 0.1, 0.1, "A" if i == 0 else ""))
    for i in range(85):                     # latar internet: 1 alarm palsu
        fs.append(f("198.51.100.%d" % (i % 50 + 1), T + i * S)); hs.append((0.1, 0.9 if i == 0 else 0.1, "C" if i == 0 else ""))
    log.catat(fs, hs, m, waktu_log_us="selesai")
    log.catat_notifikasi(src_ip="203.0.113.5", anomali_id=1, waktu_log_us=T, waktu_kirim_us=T + 100_000,
                         waktu_terima_us=T + 600_000, berhasil=1)
    log.tutup()
    jadwal = tmp_path / "j.csv"
    jadwal.write_text("id,skenario,label,mulai_wita,selesai_wita,mulai_us,selesai_us,ip_sumber,target,jumlah,berhasil,parameter,catatan\n"
                      "1,ssh-bruteforce,serangan,a,b,%d,%d,203.0.113.5,x,10,10,{},\n"
                      "2,normal,normal,a,b,%d,%d,203.0.113.5,x,5,5,{},\n" % (T, T + 9 * S, T + 1000 * S, T + 1004 * S),
                      encoding="utf-8")
    j = evaluasi.muat_jadwal(str(jadwal))
    aliran, anomali, notif, _ = evaluasi.muat_log(db)
    df = evaluasi.beri_label(aliran, j)
    assert (df.label == "serangan").sum() == 10 and (df.label == "normal").sum() == 5 and (df.label == "latar").sum() == 85
    r = evaluasi.metrik(df)
    assert (r["TP"], r["FN"], r["FP"], r["TN"]) == (8, 2, 2, 88)
    assert r["recall"] == pytest.approx(0.8) and r["precision"] == pytest.approx(0.8) and r["FPR"] == pytest.approx(2 / 90)
    ps = evaluasi.per_skenario(df, anomali, notif, j)
    s1 = ps.iloc[0]
    assert s1["terdeteksi"] and s1["tertangkap (%)"] == 80.0 and s1["deteksi pertama (s sejak mulai)"] == 0.0
    assert s1["latensi notifikasi (s)"] == pytest.approx(0.6)
