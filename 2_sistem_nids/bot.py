# -*- coding: utf-8 -*-
"""
Bot Telegram NIDS: perintah BACA-SAJA untuk administrator (layanan nids-bot).

  /status      modul deteksi berjalan? ringkasan 24 jam, kondisi server
  /ringkasan   anomali 24 jam (atau /ringkasan 7h) per jenis + IP teratas
  /ip <ip>     rincian satu IP sumber
  /hampir      IP yang hampir ditandai anomali
  /bantuan     daftar perintah

Keamanan:
* Hanya menjawab chat yang sama dengan TELEGRAM_CHAT_ID (chat/grup administrator penerima notifikasi);
  pesan dari chat lain diabaikan tanpa balasan.
* Tidak ada perintah yang mengubah sistem; log deteksi dibuka baca-saja.
* Memakai long polling (getUpdates), jadi tidak perlu membuka port apa pun di server.

Token & chat ID dibaca dari lingkungan (TELEGRAM_TOKEN, TELEGRAM_CHAT_ID; di server /etc/nids-deteksi/rahasia.env).
"""
import argparse
import os
import signal
import sys
import time
import traceback
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nids.laporan import PERINTAH_MENU, jawab                     # noqa: E402
from nids.sistem import kondisi                                   # noqa: E402
from nids.telegram import kirim_telegram, panggil_api             # noqa: E402
from nids.tepercaya import PATH_BAWAAN, DaftarTepercaya           # noqa: E402

BATAS_PER_MENIT = 20


def cetak(*a):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), *a, flush=True)


def urai(teks):
    """'/ip@NamaBot 1.2.3.4' -> ('ip', '1.2.3.4'); bukan perintah -> None."""
    teks = (teks or "").strip()
    if not teks.startswith("/"):
        return None
    kepala, _, sisa = teks[1:].partition(" ")
    perintah = kepala.split("@", 1)[0].strip().lower()
    return (perintah, sisa.strip()) if perintah else None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log", default="/var/lib/nids-deteksi/deteksi.db")
    ap.add_argument("--tepercaya", default=PATH_BAWAAN)
    a = ap.parse_args()

    token = (os.environ.get("TELEGRAM_TOKEN") or "").strip()
    chat = (os.environ.get("TELEGRAM_CHAT_ID") or "").strip()
    if not token or not chat:
        cetak("TELEGRAM_TOKEN / TELEGRAM_CHAT_ID belum diatur; bot tidak dijalankan.")
        return 0
    tepercaya = DaftarTepercaya(a.tepercaya) if a.tepercaya else None
    berhenti = {"ya": False}
    for s in (signal.SIGTERM, signal.SIGINT):
        signal.signal(s, lambda *_: berhenti.update(ya=True))

    try:
        panggil_api(token, "setMyCommands", {"commands": [{"command": c, "description": d} for c, d in PERINTAH_MENU]},
                    batas_waktu=15)
    except RuntimeError as ex:
        cetak("setMyCommands gagal:", ex)
    mulai, offset, jejak = time.time(), None, deque()
    cetak("bot berjalan (long polling); hanya menjawab chat yang dikonfigurasi")

    while not berhenti["ya"]:
        try:
            r = panggil_api(token, "getUpdates", {"timeout": 50, "offset": offset, "allowed_updates": ["message"]},
                            batas_waktu=65)
        except RuntimeError as ex:
            cetak("getUpdates gagal:", ex)
            time.sleep(5)
            continue
        for u in r.get("result", []):
            offset = u["update_id"] + 1
            m = u.get("message") or {}
            dari_chat = str((m.get("chat") or {}).get("id", ""))
            if dari_chat != chat:
                cetak("pesan dari chat lain diabaikan (chat id %s)" % dari_chat)
                continue
            if m.get("date", 0) < mulai - 120:                 # tumpukan pesan lama saat bot mati
                continue
            p = urai(m.get("text"))
            if not p:
                continue
            kini = time.time()
            while jejak and kini - jejak[0] > 60:
                jejak.popleft()
            if len(jejak) >= BATAS_PER_MENIT:
                continue
            jejak.append(kini)
            if tepercaya is not None:
                tepercaya.muat_ulang(paksa=False)
            try:
                teks = jawab(a.log, p[0], p[1], tepercaya, kondisi() if p[0] == "status" else None)
            except Exception as ex:                           # jangan sampai bot mati karena satu perintah
                traceback.print_exc()
                teks = "Maaf, terjadi galat saat membaca log (%s)." % type(ex).__name__
            ok, _, ket = kirim_telegram(token, chat, teks)
            cetak("/%s oleh %s -> %s" % (p[0], (m.get("from") or {}).get("username") or "-",
                                         "terkirim" if ok else "GAGAL: %s" % ket))
    cetak("bot berhenti")
    return 0


if __name__ == "__main__":
    sys.exit(main())
