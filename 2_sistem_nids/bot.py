# -*- coding: utf-8 -*-
"""
Bot Telegram NIDS: pemantauan & kontrol blokir IP manual untuk administrator (layanan nids-bot).

  /status      modul deteksi berjalan? ringkasan 24 jam, kondisi server
  /ringkasan   anomali 24 jam (atau /ringkasan 7h) per jenis + IP teratas
  /ip <ip>     rincian satu IP sumber
  /hampir      IP yang hampir ditandai anomali
  /diblokir    daftar IP yang sedang diblokir di firewall
  /blokir      blokir IP manual: /blokir <ip> [1j|24j|7h|permanen] [alasan]
  /buka        buka blokir IP: /buka <ip>
  /bantuan     daftar perintah

Keamanan:
* Hanya menjawab pesan & tombol interaktif (callback_query) dari chat TELEGRAM_CHAT_ID;
  pesan atau klik dari chat lain diabaikan tanpa balasan.
* Memakai long polling (getUpdates), jadi tidak perlu membuka port apa pun di server.
* Pemblokiran firewall dijalankan oleh layanan terpisah (nids-blokir.path) setelah menulis daftar ke JSON bersama.

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
from nids import asisten_ai                                       # noqa: E402
from nids import audit_bersama                                    # noqa: E402
from nids import blokir as bk                                       # noqa: E402
from nids.laporan import (PERINTAH_MENU, aksi_ai_telegram,          # noqa: E402
                          aksi_blokir_telegram, jawab)
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


def urai_callback(data):
    """'blk:1j:1.2.3.4' / 'blk:perm:1.2.3.4' / 'unblk:1.2.3.4' -> (aksi, argumen) atau None."""
    bagian = (data or "").strip().split(":", 2)
    if len(bagian) == 3 and bagian[0] == "blk" and bagian[2]:
        durasi = "permanen" if bagian[1] == "perm" else bagian[1]
        return "blokir", "%s %s via tombol Telegram" % (bagian[2], durasi)
    if len(bagian) == 2 and bagian[0] == "unblk" and bagian[1]:
        return "buka", bagian[1]
    return None


def label_pengirim(obj):
    f = obj.get("from") or {}
    u = f.get("username")
    if u:
        return "telegram (@%s)" % u
    nama = " ".join(x for x in (f.get("first_name"), f.get("last_name")) if x).strip()
    return ("telegram (%s)" % nama) if nama else "telegram"


def tangani_callback(cb, token, chat, path_log, path_blokir, path_tepercaya, path_audit=None):
    msg = cb.get("message") or {}
    dari_chat = str((msg.get("chat") or {}).get("id", ""))
    if dari_chat != chat:
        cetak("callback dari chat lain diabaikan (chat id %s)" % dari_chat)
        return
    hasil_urai = urai_callback(cb.get("data"))
    if not hasil_urai:
        try:
            panggil_api(token, "answerCallbackQuery", {"callback_query_id": cb["id"], "text": "Tombol tidak dikenal"},
                        batas_waktu=10)
        except RuntimeError:
            pass
        return
    aksi, arg = hasil_urai
    oleh = label_pengirim(cb)
    teks, markup, ringkas = aksi_blokir_telegram(aksi, arg, oleh, path_blokir, path_tepercaya=path_tepercaya,
                                                 path_log=path_log)
    if path_audit:
        gagal = teks.startswith("❌")
        j = ("TELEGRAM_BLOKIR_GAGAL" if aksi == "blokir" else "TELEGRAM_BUKA") if gagal else (
            "TELEGRAM_BLOKIR" if aksi == "blokir" else "TELEGRAM_BUKA")
        audit_bersama.tulis(path_audit, j, aktor=oleh, kode=(400 if gagal else 200), ket=ringkas)
    try:
        panggil_api(token, "answerCallbackQuery", {"callback_query_id": cb["id"], "text": ringkas[:180]},
                    batas_waktu=10)
    except RuntimeError as ex:
        cetak("answerCallbackQuery gagal:", ex)
    if markup is not None and msg.get("message_id"):
        try:
            panggil_api(token, "editMessageReplyMarkup",
                        {"chat_id": chat, "message_id": msg["message_id"], "reply_markup": markup},
                        batas_waktu=10)
        except RuntimeError as ex:
            cetak("editMessageReplyMarkup gagal:", ex)
    ok, _, ket = kirim_telegram(token, chat, teks)
    cetak("tombol %s oleh %s -> %s" % (aksi, oleh, "terkirim" if ok else "GAGAL: %s" % ket))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log", default="/var/lib/nids-deteksi/deteksi.db")
    ap.add_argument("--tepercaya", default=PATH_BAWAAN)
    ap.add_argument("--diblokir", default=bk.PATH_BAWAAN)
    ap.add_argument("--ai-konfig", default=asisten_ai.PATH_BAWAAN)
    ap.add_argument("--audit-eksternal", default=audit_bersama.PATH_BAWAAN)
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
            r = panggil_api(token, "getUpdates",
                            {"timeout": 50, "offset": offset, "allowed_updates": ["message", "callback_query"]},
                            batas_waktu=65)
        except RuntimeError as ex:
            cetak("getUpdates gagal:", ex)
            time.sleep(5)
            continue
        for u in r.get("result", []):
            offset = u["update_id"] + 1
            if "callback_query" in u:
                try:
                    tangani_callback(u["callback_query"], token, chat, a.log, a.diblokir, a.tepercaya,
                                     path_audit=a.audit_eksternal)
                except Exception as ex:
                    traceback.print_exc()
                    cetak("galat callback:", ex)
                continue
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
            markup = None
            try:
                oleh_tg = label_pengirim(m)
                if p[0] in ("blokir", "buka"):
                    teks, markup, ringkas = aksi_blokir_telegram(p[0], p[1], oleh_tg, a.diblokir,
                                                                    path_tepercaya=a.tepercaya, path_log=a.log)
                    gagal = teks.startswith("❌")
                    j = ("TELEGRAM_BLOKIR_GAGAL" if gagal else "TELEGRAM_BLOKIR") if p[0] == "blokir" else "TELEGRAM_BUKA"
                    audit_bersama.tulis(a.audit_eksternal, j, aktor=oleh_tg, kode=(400 if gagal else 200), ket=ringkas)
                elif p[0] in ("ai", "modelai", "models", "analisis", "ringkasai", "tanya"):
                    teks = aksi_ai_telegram(p[0], p[1], a.log, path_ai=a.ai_konfig,
                                            path_blokir=a.diblokir, tepercaya=tepercaya)
                    gagal = teks.startswith("❌")
                    audit_bersama.tulis(a.audit_eksternal, "TELEGRAM_AI_GAGAL" if gagal else "TELEGRAM_AI",
                                        aktor=oleh_tg, kode=(400 if gagal else 200),
                                        ket="/%s %s" % (p[0], (p[1] or "")[:120]))
                else:
                    teks = jawab(a.log, p[0], p[1], tepercaya, kondisi() if p[0] == "status" else None,
                                 diblokir=a.diblokir)
            except Exception as ex:                           # jangan sampai bot mati karena satu perintah
                traceback.print_exc()
                teks = "Maaf, terjadi galat saat memproses perintah (%s)." % type(ex).__name__
            ok, _, ket = kirim_telegram(token, chat, teks, reply_markup=markup)
            cetak("/%s oleh %s -> %s" % (p[0], (m.get("from") or {}).get("username") or "-",
                                         "terkirim" if ok else "GAGAL: %s" % ket))
    cetak("bot berhenti")
    return 0


if __name__ == "__main__":
    sys.exit(main())
