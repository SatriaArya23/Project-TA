# -*- coding: utf-8 -*-
"""Uji blokir IP manual (nids.blokir, blokir.py, perintah bot Telegram, dan tombol interaktif)."""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bot                                                          # noqa: E402
import blokir as blokir_fw                                          # noqa: E402
from nids import blokir as bk                                       # noqa: E402
from nids import tepercaya as tp                                    # noqa: E402
from nids.laporan import aksi_blokir_telegram, jawab, teks_diblokir   # noqa: E402
from nids.telegram import susun_tombol_blokir                       # noqa: E402
from test_pantau_bot import KANTOR, NYARIS, PENYERANG, log_db       # noqa: F401,E402


def test_validasi_guardrails_blokir(tmp_path):
    pb = str(tmp_path / "ip_diblokir.json")
    pt = str(tmp_path / "ip_tepercaya.json")
    tp.tambah(pt, KANTOR, "kantor", "satria")

    # valid: IP tunggal dan /24
    e1 = bk.tambah(pb, " " + PENYERANG + " ", durasi="1j", keterangan="scan", oleh="satria", path_tepercaya=pt)
    assert e1["cidr"] == PENYERANG + "/32" and e1["durasi"] == "1j" and e1["kedaluwarsa_utc"] is not None
    e2 = bk.tambah(pb, "198.51.100.77/24", durasi="permanen", oleh="satria", path_tepercaya=pt)
    assert e2["cidr"] == "198.51.100.0/24" and e2["kedaluwarsa_utc"] is None

    # invalid / terlarang / beririsan IP tepercaya / IP dilindungi
    for buruk in ("bukan-ip", "203.0.113.0/16", "127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1",
                  KANTOR, "192.0.2.0/24", PENYERANG):
        with pytest.raises(ValueError):
            bk.tambah(pb, buruk, path_tepercaya=pt)

    with pytest.raises(ValueError):
        bk.tambah(pb, "203.0.114.9", path_tepercaya=pt, ip_dilindungi=["203.0.114.9"])

    aktif = bk.baca(pb)
    assert [x["cidr"] for x in aktif] == [PENYERANG + "/32", "198.51.100.0/24"]
    assert bk.cocok_dengan(aktif, PENYERANG) is not None
    assert bk.cocok_dengan(aktif, "198.51.100.250") is not None
    assert bk.hapus(pb, PENYERANG)["cidr"] == PENYERANG + "/32"
    assert bk.hapus(pb, PENYERANG) is None


def test_kedaluwarsa_otomatis(tmp_path):
    pb = str(tmp_path / "ip_diblokir.json")
    t0 = 1_761_000_000
    bk.tambah(pb, PENYERANG, durasi="1j", oleh="admin", kini=t0)
    assert len(bk.baca(pb, kini=t0 + 1800)) == 1
    assert bk.baca(pb, kini=t0 + 3601) == []
    aktif, berubah = bk.bersihkan_kedaluwarsa(pb, kini=t0 + 3601)
    assert berubah and aktif == []


def test_skrip_nft_dan_sinkron(tmp_path):
    pb = str(tmp_path / "ip_diblokir.json")
    ps = str(tmp_path / "status.json")
    pt = str(tmp_path / "ip_tepercaya.json")
    bk.tambah(pb, PENYERANG, durasi="24j", oleh="admin")
    bk.tambah(pb, "2001:db8:1::5", durasi="permanen", oleh="admin")
    hasil_skrip = []
    st = blokir_fw.sinkron(pb, ps, pt, runner=lambda s: hasil_skrip.append(s), ip_server=[])
    assert st["ok"] and st["jumlah"] == 2
    assert "table inet nids_blokir" in hasil_skrip[0]
    assert PENYERANG + "/32" in hasil_skrip[0] and "2001:db8:1::5/128" in hasil_skrip[0]
    assert "ip saddr @v4 drop" in hasil_skrip[0] and "ip6 saddr @v6 drop" in hasil_skrip[0]
    assert bk.baca_status(ps)["jumlah"] == 2

    # setelah dibuka semua -> tabel dihapus bersih
    bk.hapus(pb, PENYERANG)
    bk.hapus(pb, "2001:db8:1::5")
    st2 = blokir_fw.sinkron(pb, ps, pt, runner=lambda s: hasil_skrip.append(s), ip_server=[])
    assert st2["jumlah"] == 0 and "delete table inet nids_blokir" in hasil_skrip[-1]


def test_telegram_tombol_dan_perintah_blokir(log_db, tmp_path, monkeypatch):
    pb = str(tmp_path / "ip_diblokir.json")
    pt = str(tmp_path / "ip_tepercaya.json")
    tp.tambah(pt, KANTOR, "kantor")

    kb = susun_tombol_blokir(PENYERANG)["inline_keyboard"][0]
    assert kb[0]["callback_data"] == "blk:1j:" + PENYERANG and len(kb[0]["callback_data"]) <= 64
    assert kb[1]["callback_data"] == "blk:perm:" + PENYERANG

    assert bot.urai_callback("blk:1j:" + PENYERANG) == ("blokir", PENYERANG + " 1j via tombol Telegram")
    assert bot.urai_callback("unblk:" + PENYERANG) == ("buka", PENYERANG)

    teks, markup, ringkas = aksi_blokir_telegram("blokir", PENYERANG + " 1j port scan", "telegram (@satria)",
                                                 pb, path_tepercaya=pt, ip_server=[], path_log=log_db)
    assert "IP Diblokir" in teks and "1 jam" in ringkas
    assert markup["inline_keyboard"][0][0]["callback_data"] == "unblk:" + PENYERANG

    # /ip dan /diblokir menampilkan status diblokir
    assert "SEDANG DIBLOKIR" in jawab(log_db, "ip", PENYERANG, diblokir=pb)
    assert PENYERANG in teks_diblokir(pb)

    # IP tepercaya tidak bisa diblokir lewat Telegram
    teks_tolak, m_tolak, _ = aksi_blokir_telegram("blokir", KANTOR, "telegram (@satria)",
                                                  pb, path_tepercaya=pt, ip_server=[])
    assert "Gagal memblokir" in teks_tolak and m_tolak is None

    # callback dari chat lain diabaikan tanpa mengubah ip_diblokir.json
    panggilan = []
    monkeypatch.setattr(bot, "panggil_api", lambda *a, **kw: panggilan.append(a))
    monkeypatch.setattr(bot, "kirim_telegram", lambda *a, **kw: (panggilan.append(a), (True, 0, None))[1])
    bot.tangani_callback({"id": "1", "data": "unblk:" + PENYERANG, "from": {"username": "asing"},
                          "message": {"chat": {"id": 99999}, "message_id": 1}},
                         "tok", "12345", log_db, pb, pt)
    assert panggilan == [] and len(bk.baca(pb)) == 1

    # callback dari chat admin sah membuka blokir dan memperbarui tombol
    bot.tangani_callback({"id": "2", "data": "unblk:" + PENYERANG, "from": {"username": "satria"},
                          "message": {"chat": {"id": 12345}, "message_id": 77}},
                         "tok", "12345", log_db, pb, pt)
    assert bk.baca(pb) == []
    assert any(c[1] == "answerCallbackQuery" for c in panggilan)
    assert any(c[1] == "editMessageReplyMarkup" for c in panggilan)
