# -*- coding: utf-8 -*-
"""
Teks jawaban perintah bot Telegram (/status, /ringkasan, /ip, /hampir), dibaca dari log deteksi.

Semua fungsi hanya MEMBACA log (koneksi baca-saja) dan mengembalikan teks berformat HTML Telegram.
Hanya memakai pustaka standar, sehingga juga bisa diuji tanpa numpy/scikit-learn.
"""
import html
import ipaddress
import sqlite3
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import asisten_ai
from . import blokir as daftar_blokir
from .dugaan import dugaan
from .umpan_balik import ambang_model, hampir_anomali, kedekatan

WITA = timezone(timedelta(hours=8))
BULAN = ["Jan", "Feb", "Mar", "Apr", "Mei", "Jun", "Jul", "Agu", "Sep", "Okt", "Nov", "Des"]
JAM_US = 3600 * 1_000_000
BATAS_DETAK_US = 180 * 1_000_000          # modul menulis detak tiap 60 detik
NAMA_MODEL = {"A": "IF-Flow", "C": "IF-Agg", "A+C": "Dual-IF"}
e = html.escape


def nama_model(kode):
    if not kode:
        return ""
    bagian = [NAMA_MODEL.get(x.strip(), x.strip()) for x in str(kode).split(",") if x.strip()]
    return ", ".join(dict.fromkeys(bagian))


def buka_baca(path):
    con = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
    con.row_factory = sqlite3.Row
    return con


def kini_us():
    return int(time.time() * 1_000_000)


def wita(us, detik=False):
    d = datetime.fromtimestamp(us / 1e6, WITA)
    return ("%d %s, %02d.%02d" + (".%02d" if detik else "")) % (
        (d.day, BULAN[d.month - 1], d.hour, d.minute) + ((d.second,) if detik else ()))


def wita_iso(iso_utc):
    t = daftar_blokir.parse_utc(iso_utc)
    return (wita(t * 1_000_000) + " WITA") if t else "permanen"


def _ambil_diblokir(diblokir, kini=None):
    if diblokir is None:
        return []
    if isinstance(diblokir, str):
        return daftar_blokir.baca(diblokir, kini=kini)
    return list(diblokir)


def _ip_ringkas(cidr):
    if cidr.endswith("/32"):
        return cidr[:-3]
    if cidr.endswith("/128"):
        return cidr[:-4]
    return cidr


def tombol_blokir_ip(ip_atau_cidr, diblokir=False):
    kunci = _ip_ringkas(str(ip_atau_cidr))
    if diblokir:
        return {"inline_keyboard": [[{"text": "🔓 Buka Blokir", "callback_data": "unblk:%s" % kunci}]]}
    return {"inline_keyboard": [[
        {"text": "🚫 Blokir 1 Jam", "callback_data": "blk:1j:%s" % kunci},
        {"text": "🔒 Blokir Permanen", "callback_data": "blk:perm:%s" % kunci},
    ]]}


def ip_dilindungi_lokal(path_log=None):
    hasil = []
    if path_log:
        try:
            db = buka_baca(path_log)
            try:
                r = db.execute("SELECT nilai FROM status WHERE kunci = 'server_ip'").fetchone()
                if r and r[0]:
                    hasil.extend(x.strip() for x in r[0].split(",") if x.strip())
            finally:
                db.close()
        except Exception:
            pass
    try:
        r = subprocess.run(["ip", "-o", "addr", "show"], capture_output=True, text=True, timeout=3)
        for baris in r.stdout.splitlines():
            bagian = baris.split()
            for i, tok in enumerate(bagian):
                if tok in ("inet", "inet6") and i + 1 < len(bagian):
                    hasil.append(bagian[i + 1].split("/")[0])
    except Exception:
        pass
    return hasil


def lalu(us, kini=None):
    dt = max(0, ((kini or kini_us()) - us) / 1e6)
    if dt < 90:
        return "%d detik lalu" % dt
    if dt < 5400:
        return "%d menit lalu" % round(dt / 60)
    if dt < 129600:
        return "%d jam lalu" % round(dt / 3600)
    return "%d hari lalu" % round(dt / 86400)


def angka(n):
    return "{:,}".format(int(n or 0)).replace(",", ".")


def persen(x, d=0):
    return (("%." + str(d) + "f%%") % ((x or 0) * 100)).replace(".", ",")


def status_modul(db, kini=None):
    s = {r["kunci"]: r["nilai"] for r in db.execute("SELECT kunci, nilai FROM status")}
    kini = kini or kini_us()
    terakhir = int(s.get("terakhir_us") or 0)
    s["terakhir_us"] = terakhir
    s["aktif"] = s.get("berhenti") != "ya" and bool(terakhir) and kini - terakhir < BATAS_DETAK_US
    return s


def _rentang(argumen):
    """'' / '24j' -> 1 hari, '7h' / '7' -> 7 hari."""
    a = (argumen or "").strip().lower()
    return (7, "7 hari") if a in ("7h", "7", "7hari", "minggu") else (1, "24 jam")


# ------------------------------------------------------------------ /status
def teks_status(db, kondisi=None, kini=None):
    kini = kini or kini_us()
    s = status_modul(db, kini)
    awal = kini - 24 * JAM_US
    n = db.execute("SELECT COALESCE(SUM(aliran), 0), COALESCE(SUM(anomali), 0) FROM ringkasan WHERE menit_utc >= ?",
                   (awal // 1_000_000,)).fetchone()
    ip = db.execute("SELECT COUNT(DISTINCT src_ip) FROM anomali WHERE waktu_selesai_us >= ?", (awal,)).fetchone()[0]
    notif = db.execute("SELECT COUNT(*), COALESCE(SUM(berhasil), 0) FROM notifikasi WHERE waktu_kirim_us >= ?",
                       (awal,)).fetchone()
    m = db.execute("SELECT versi FROM model ORDER BY id DESC LIMIT 1").fetchone()
    nama = s.get("nama_server") or "server"
    if s["aktif"]:
        baris = ["🟢 <b>%s · deteksi berjalan</b>" % e(nama)]
    elif s.get("berhenti") == "ya":
        baris = ["🔴 <b>%s · deteksi BERHENTI</b>" % e(nama)]
    else:
        baris = ["🔴 <b>%s · deteksi tidak berdetak</b>" % e(nama)]
    if s["terakhir_us"]:
        baris.append("Detak terakhir: %s" % lalu(s["terakhir_us"], kini))
    if s.get("mulai_us"):
        baris.append("Berjalan sejak: %s WITA" % wita(int(s["mulai_us"])))
    if m:
        baris.append("Model aktif: <code>%s</code>" % e(m["versi"]))
    baris += ["", "<b>24 jam terakhir</b>",
              "• %s aliran diperiksa" % angka(n[0]),
              "• %s anomali dari %s IP sumber" % (angka(n[1]), angka(ip)),
              "• %s notifikasi terkirim%s" % (angka(notif[1]),
                                              (", %d gagal" % (notif[0] - notif[1])) if notif[0] - notif[1] else "")]
    if kondisi:
        baris += ["", "<b>Server</b>",
                  "CPU %s · RAM %s · disk %s" % (persen(kondisi["cpu_persen"]), persen(kondisi["ram_persen"]),
                                                  persen(kondisi["disk_persen"]))]
    return "\n".join(baris)


# ------------------------------------------------------------------ /ringkasan
def teks_ringkasan(db, argumen="", kini=None):
    kini = kini or kini_us()
    hari, nama = _rentang(argumen)
    awal = kini - hari * 24 * JAM_US
    n = db.execute("SELECT COALESCE(SUM(aliran), 0), COALESCE(SUM(anomali), 0) FROM ringkasan WHERE menit_utc >= ?",
                   (awal // 1_000_000,)).fetchone()
    rows = db.execute("SELECT src_ip, oleh, agg_ip_aliran, agg_ip_port_unik, agg_ip_aliran_ssh FROM anomali "
                      "WHERE waktu_selesai_us >= ?", (awal,)).fetchall()
    jenis, per_ip = {}, {}
    for r in rows:
        d = dugaan({"agg_ip_aliran": r[2] or 0, "agg_ip_port_unik": r[3] or 0, "agg_ip_aliran_ssh": r[4] or 0})
        jenis[d] = jenis.get(d, 0) + 1
        p = per_ip.setdefault(r[0], {"n": 0, "oleh": set(), "dugaan": {}})
        p["n"] += 1
        p["oleh"].add(r[1])
        p["dugaan"][d] = p["dugaan"].get(d, 0) + 1
    notif = db.execute("SELECT COALESCE(SUM(berhasil), 0) FROM notifikasi WHERE waktu_kirim_us >= ?",
                       (awal,)).fetchone()[0]
    baris = ["📊 <b>Ringkasan %s terakhir</b>" % nama,
             "%s aliran diperiksa · %s anomali (%s) · %s IP sumber · %s notifikasi" % (
                 angka(n[0]), angka(n[1]), persen(n[1] / n[0] if n[0] else 0, 2), angka(len(per_ip)), angka(notif))]
    if not rows:
        return "\n".join(baris + ["", "Tidak ada anomali. ✅"])
    baris += ["", "<b>Dugaan jenis</b>"]
    baris += ["• %s: %s aliran" % (e(k), angka(v)) for k, v in sorted(jenis.items(), key=lambda x: -x[1])]
    baris += ["", "<b>IP sumber teratas</b>"]
    for ip, p in sorted(per_ip.items(), key=lambda x: -x[1]["n"])[:5]:
        utama = max(p["dugaan"].items(), key=lambda x: x[1])[0]
        baris.append("• <code>%s</code> — %s anomali, %s, %s" % (
            e(ip), angka(p["n"]), e(utama.lower()), nama_model(",".join(sorted(p["oleh"])))))
    baris += ["", "Rincian satu IP: /ip &lt;alamat&gt;"]
    return "\n".join(baris)


# ------------------------------------------------------------------ /ip
def teks_ip(db, argumen, tepercaya=None, diblokir=None, kini=None):
    kini = kini or kini_us()
    teks = (argumen or "").strip().split()
    if not teks:
        return "Tulis alamatnya, mis. <code>/ip 203.0.113.7</code>"
    try:
        ip = str(ipaddress.ip_address(teks[0]))
    except ValueError:
        return "“%s” bukan alamat IP yang valid." % e(teks[0][:64])
    r = db.execute("SELECT COUNT(*), SUM(oleh != ''), MIN(waktu_selesai_us), MAX(waktu_selesai_us), "
                   "COUNT(DISTINCT dst_port) FROM aliran WHERE src_ip = ?", (ip,)).fetchone()
    bk = daftar_blokir.cocok_dengan(_ambil_diblokir(diblokir, kini=kini / 1e6), ip)
    t = tepercaya.cocok(ip) if tepercaya is not None else None
    if not r[0]:
        baris = []
        if bk:
            baris.append("🚫 <b>%s sedang diblokir</b> (%s)" % (e(bk["cidr"]), wita_iso(bk.get("kedaluwarsa_utc"))))
        elif t:
            baris.append("✅ <b>%s</b> ada di daftar IP tepercaya (%s)" % (e(ip), e(t["cidr"])))
        baris.append("IP <code>%s</code> belum pernah tercatat oleh modul deteksi (belum pernah membuka koneksi ke server "
                     "dalam masa simpan log)." % e(ip))
        return "\n".join(baris)
    baris = ["🔎 <b>%s</b>" % e(ip)]
    if bk:
        baris.append("🚫 <b>SEDANG DIBLOKIR</b> (%s · %s%s)" % (
            e(bk["cidr"]), wita_iso(bk.get("kedaluwarsa_utc")),
            (" · " + e(bk["keterangan"])) if bk.get("keterangan") else ""))
    if t:
        baris.append("✅ IP tepercaya (%s%s)" % (e(t["cidr"]), (" · " + e(t["keterangan"])) if t.get("keterangan") else ""))
    baris += ["%s aliran · %s ditandai anomali (%s)" % (angka(r[0]), angka(r[1]), persen((r[1] or 0) / r[0], 1)),
              "Pertama %s · terakhir %s (%s)" % (wita(r[2]), wita(r[3]), lalu(r[3], kini))]
    port = db.execute("SELECT dst_port, COUNT(*) FROM aliran WHERE src_ip = ? GROUP BY dst_port ORDER BY 2 DESC LIMIT 5",
                      (ip,)).fetchall()
    baris.append("Port tujuan: %s%s" % (", ".join("%s (%s)" % (p, angka(n)) for p, n in port),
                                          " …" if r[4] > 5 else ""))
    am, skor = ambang_model(db), {}
    for mid, ma, mc in db.execute("SELECT model_id, MAX(skor_a), MAX(skor_c) FROM aliran WHERE src_ip = ? "
                                  "GROUP BY model_id", (ip,)):
        for k in kedekatan(am, mid, ma, mc):
            if k["model"] not in skor or k["persentil"] > skor[k["model"]]["persentil"]:
                skor[k["model"]] = k
    if skor:
        baris += ["", "<b>Skor tertinggi vs ambang</b>"]
        for nama in ("A", "C"):
            if nama in skor:
                k = skor[nama]
                baris.append("• %s: %.4f / %.4f (persentil %s, ditandai &gt; %s)" % (
                    nama_model(nama), k["skor"], k["ambang"], persen(k["persentil"], 2), persen(k["persentil_ambang"], 2)))
    a = db.execute("SELECT oleh, agg_ip_aliran, agg_ip_port_unik, agg_ip_aliran_ssh FROM anomali WHERE src_ip = ? "
                   "ORDER BY agg_ip_aliran DESC LIMIT 1", (ip,)).fetchone()
    if a:
        baris.append("Dugaan: %s" % e(dugaan({"agg_ip_aliran": a[1] or 0, "agg_ip_port_unik": a[2] or 0,
                                               "agg_ip_aliran_ssh": a[3] or 0})))
    nt = db.execute("SELECT COUNT(*), MAX(waktu_kirim_us) FROM notifikasi WHERE src_ip = ? AND berhasil = 1",
                    (ip,)).fetchone()
    if nt[0]:
        baris.append("Notifikasi: %s pesan, terakhir %s" % (angka(nt[0]), lalu(nt[1], kini)))
    return "\n".join(baris)


# ------------------------------------------------------------------ /hampir
def teks_hampir(db, argumen="", tepercaya=None, kini=None):
    kini = kini or kini_us()
    hari, nama = _rentang(argumen)
    daftar = hampir_anomali(db, kini - hari * 24 * JAM_US,
                            abaikan=(lambda ip: tepercaya.cocok(ip) is not None) if tepercaya is not None else None)
    if not daftar:
        return "Tidak ada IP yang hampir ditandai dalam %s terakhir. ✅" % nama
    baris = ["🟡 <b>Hampir anomali · %s terakhir</b>" % nama,
             "%d IP tidak ditandai, tetapi skornya di atas batas aman umpan balik. Teratas:" % len(daftar), ""]
    for p in daftar[:10]:
        t = p["terdekat"]
        port = [row[0] for row in db.execute(
            "SELECT dst_port FROM aliran WHERE src_ip = ? AND waktu_selesai_us >= ? GROUP BY dst_port "
            "ORDER BY COUNT(*) DESC LIMIT 3", (p["src_ip"], p["awal"]))]
        baris.append("• <code>%s</code> — %d/%d aliran dekat ambang, %s %s / %s, port %s" % (
            e(p["src_ip"]), p["dekat"], p["aliran"], nama_model(t["model"]), persen(t["persentil"], 2),
            persen(t["persentil_ambang"], 2), ",".join(map(str, port))))
    baris += ["", "Bukan berarti serangan; cek dengan /ip &lt;alamat&gt; lalu laporkan lewat dashboard bila mencurigakan."]
    return "\n".join(baris)


# ------------------------------------------------------------------ /diblokir, /blokir, /buka
def teks_diblokir(path_blokir, kini=None):
    entri = daftar_blokir.baca(path_blokir, kini=kini)
    if not entri:
        return ("🛡️ <b>Daftar IP diblokir</b>\nTidak ada IP yang sedang diblokir saat ini.\n\n"
                "Untuk memblokir: <code>/blokir &lt;ip&gt; [1j|24j|7h|permanen] [alasan]</code>")
    baris = ["🚫 <b>Daftar IP diblokir (%d aktif)</b>" % len(entri), ""]
    for x in entri[:20]:
        ket = (" · " + e(x["keterangan"])) if x.get("keterangan") else ""
        oleh = (" · oleh " + e(x["oleh"])) if x.get("oleh") else ""
        baris.append("• <code>%s</code> — %s%s%s" % (e(x["cidr"]), wita_iso(x.get("kedaluwarsa_utc")), ket, oleh))
    if len(entri) > 20:
        baris.append("… dan %d lainnya (lihat di dashboard)." % (len(entri) - 20))
    baris += ["", "Untuk membuka blokir: <code>/buka &lt;ip&gt;</code>"]
    return "\n".join(baris)


def aksi_blokir_telegram(aksi, argumen, oleh, path_blokir, path_tepercaya=None, ip_server=None, path_log=None, kini=None):
    """Jalankan /blokir, /buka, atau klik tombol inline. Kembalikan (teks_html, reply_markup, ringkas_popup)."""
    bagian = (argumen or "").strip().split()
    if aksi == "blokir":
        if not bagian:
            return ("Format: <code>/blokir &lt;ip&gt; [1j|24j|7h|permanen] [alasan]</code>\n"
                    "Contoh: <code>/blokir 203.0.113.66 1j port scan</code>"), None, "Masukkan alamat IP"
        ip_teks = bagian[0]
        durasi, idx_ket = "permanen", 1
        if len(bagian) > 1 and bagian[1].lower() in ("1j", "24j", "7h", "permanen", "perm", "tetap", "selamanya"):
            durasi, idx_ket = bagian[1], 2
        ket = " ".join(bagian[idx_ket:]).strip()[:120] or "Blokir manual lewat Telegram"
        prot = ip_dilindungi_lokal(path_log) if ip_server is None else list(ip_server)
        try:
            entri = daftar_blokir.tambah(path_blokir, ip_teks, durasi=durasi, keterangan=ket, oleh=oleh,
                                         path_tepercaya=path_tepercaya, ip_dilindungi=prot, kini=kini)
        except ValueError as ex:
            return "❌ Gagal memblokir: %s" % e(str(ex)), None, str(ex)[:150]
        batas = wita_iso(entri.get("kedaluwarsa_utc"))
        teks = ("🚫 <b>IP Diblokir:</b> <code>%s</code>\n"
                "Berlaku: %s\nOleh: %s\nAlasan: %s\n\n"
                "<i>Aturan firewall diterapkan dalam beberapa detik.</i>"
                % (e(entri["cidr"]), e(batas), e(oleh), e(entri["keterangan"])))
        return teks, tombol_blokir_ip(entri["cidr"], diblokir=True), "IP %s diblokir (%s)" % (
            _ip_ringkas(entri["cidr"]), entri["durasi_label"])

    if aksi == "buka":
        if not bagian:
            return "Format: <code>/buka &lt;ip&gt;</code>", None, "Masukkan alamat IP"
        ip_teks = bagian[0]
        dihapus = daftar_blokir.hapus(path_blokir, ip_teks, kini=kini)
        if not dihapus:
            return "ℹ️ <code>%s</code> tidak sedang ada di daftar blokir." % e(ip_teks[:64]), tombol_blokir_ip(
                ip_teks, diblokir=False), "IP tidak sedang diblokir"
        teks = ("🔓 <b>Blokir Dibuka:</b> <code>%s</code>\nOleh: %s\n\n"
                "<i>Aturan firewall dicabut dalam beberapa detik.</i>" % (e(dihapus["cidr"]), e(oleh)))
        return teks, tombol_blokir_ip(dihapus["cidr"], diblokir=False), "Blokir %s dibuka" % _ip_ringkas(dihapus["cidr"])

    return "Aksi tidak dikenal.", None, "Aksi tidak dikenal"


BANTUAN = "\n".join([
    "🤖 <b>Perintah bot ASUNA NIDS</b>",
    "",
    "/status — modul deteksi berjalan? ringkasan 24 jam, kondisi server",
    "/ringkasan — anomali 24 jam terakhir per jenis + IP teratas (<code>/ringkasan 7h</code> = 7 hari)",
    "/ip &lt;alamat&gt; — rincian satu IP sumber",
    "/hampir — IP yang hampir ditandai anomali (<code>/hampir 7h</code>)",
    "/diblokir — daftar IP yang sedang diblokir di firewall",
    "/blokir &lt;ip&gt; [1j|24j|7h|permanen] [alasan] — blokir IP secara manual",
    "/buka &lt;ip&gt; — buka blokir IP",
    "",
    "<b>Asisten Analisis AI (on-demand)</b>",
    "/analisis &lt;ip&gt; [koneksi] [model] — analisis AI untuk satu IP sumber",
    "/ringkasai [7h] [koneksi] [model] — ringkasan eksekutif keamanan 24 jam / 7 hari oleh AI",
    "/tanya &lt;pertanyaan&gt; — tanya AI berdasarkan log 24 jam terakhir",
    "/ai [koneksi] [model] — lihat daftar koneksi AI atau ganti provider &amp; model aktif",
    "/modelai &lt;nama_model&gt; — ganti model AI aktif pada koneksi sekarang",
    "/models [koneksi] — lihat daftar model dinamis dari API provider",
    "/bantuan — daftar perintah ini",
])

PERINTAH_MENU = [("status", "Status modul deteksi & server"), ("ringkasan", "Ringkasan anomali 24 jam"),
                 ("ip", "Rincian satu IP sumber, mis. /ip 1.2.3.4"), ("hampir", "IP yang hampir ditandai anomali"),
                 ("diblokir", "Daftar IP yang sedang diblokir"), ("blokir", "Blokir IP, mis. /blokir 1.2.3.4 1j"),
                 ("buka", "Buka blokir IP, mis. /buka 1.2.3.4"),
                 ("analisis", "Analisis AI satu IP, mis. /analisis 1.2.3.4"),
                 ("ringkasai", "Ringkasan keamanan 24 jam oleh AI"),
                 ("tanya", "Tanya AI tentang kondisi keamanan server"),
                 ("ai", "Lihat / ganti koneksi & model AI aktif"),
                 ("modelai", "Ganti model AI pada provider sekarang"),
                 ("models", "Lihat daftar model dinamis dari API AI"),
                 ("bantuan", "Daftar perintah")]


def _format_balasan_ai(judul, res):
    teks_bersih = e(res["teks"])
    kepala = "🧠 <b>%s</b>\n<i>%s · %s%s</i>\n\n" % (
        e(judul), e(res["profil_nama"]), e(res["model"]),
        " (cache)" if res.get("dari_cache") else "",
    )
    isi = kepala + teks_bersih
    if len(isi) > 3950:
        isi = isi[:3920] + "\n…"
    return isi


def _pisah_profil_model(path_ai, sisa_tokens):
    """Dukung `/perintah ... [koneksi] [model]` maupun `/perintah ... [model]`."""
    if not sisa_tokens:
        return None, None
    data = asisten_ai.baca(path_ai)
    toks = [t for t in sisa_tokens if t]
    if len(toks) >= 2:
        p = asisten_ai.cari_profil(data, toks[0])
        if p is not None:
            return p["id"], toks[1]
    if len(toks) == 1:
        p = asisten_ai.cari_profil(data, toks[0])
        if p is not None:
            return p["id"], None
        return None, toks[0]
    return None, toks[-1]


def aksi_ai_telegram(perintah, argumen, path_log, path_ai=asisten_ai.PATH_BAWAAN,
                     path_blokir=None, tepercaya=None, transport=None):
    """Tangani /ai, /modelai, /models, /analisis, /ringkasai, dan /tanya dari bot Telegram."""
    perintah = (perintah or "").lower()
    arg = (argumen or "").strip()
    kw_tr = {"transport": transport} if transport is not None else {}

    if perintah == "ai":
        if arg:
            toks = arg.split(None, 1)
            try:
                p = asisten_ai.aktifkan_profil(path_ai, toks[0], model_default=(toks[1].strip() if len(toks) > 1 else None))
            except ValueError as ex:
                return "❌ %s" % e(str(ex))
            return "✅ Koneksi AI aktif diubah ke <b>%s</b> (model: <code>%s</code>)." % (e(p["nama"]), e(p["model"]))
        d = asisten_ai.daftar_aman(path_ai)
        if not d["profil"]:
            return ("🧠 <b>Asisten AI belum dikonfigurasi.</b>\n"
                    "Tambahkan API Key OpenAI / Gemini / Claude di menu <i>Asisten AI</i> pada dashboard ASUNA.")
        baris = ["🧠 <b>Koneksi Asisten AI Terpasang</b>", ""]
        for p in d["profil"]:
            tanda = "✅ <b>aktif</b>" if p["aktif"] else "tersimpan"
            jml_m = len(p.get("models") or [])
            baris.append("• <b>%s</b> (%s) — <code>%s</code> (%d model) [%s]" % (
                e(p["nama"]), e(p["provider_label"]), e(p["model"]), jml_m, tanda))
        baris.append("\nGanti provider/model: <code>/ai &lt;nama&gt; [model]</code> · <code>/modelai &lt;model&gt;</code> · <code>/models</code>")
        return "\n".join(baris)

    if perintah == "modelai":
        if not arg:
            return "Format: <code>/modelai &lt;nama_model&gt;</code> (contoh: <code>/modelai gpt-4.1-mini</code>)"
        data = asisten_ai.baca(path_ai)
        aktif = asisten_ai.cari_profil(data, None)
        if aktif is None:
            return "❌ Belum ada koneksi AI yang dikonfigurasi."
        if aktif.get("dari_env"):
            return "ℹ️ Koneksi dari environment server tidak dapat diubah lewat bot; tambahkan koneksi di dashboard."
        try:
            p = asisten_ai.aktifkan_profil(path_ai, aktif["id"], model_default=arg.split()[0])
        except ValueError as ex:
            return "❌ %s" % e(str(ex))
        return "✅ Model AI aktif pada <b>%s</b> diganti ke <code>%s</code>." % (e(p["nama"]), e(p["model"]))

    if perintah == "models":
        data = asisten_ai.baca(path_ai)
        target = asisten_ai.cari_profil(data, arg or None)
        if target is None:
            return "❌ Koneksi AI tidak ditemukan."
        if not target.get("dari_env"):
            try:
                target = asisten_ai.segarkan_model(path_ai, target["id"], **kw_tr)
            except (ValueError, RuntimeError):
                pass
        daftar = target.get("models") or [target.get("model")]
        baris = ["📋 <b>Daftar Model · %s</b> (aktif: <code>%s</code>)" % (e(target["nama"]), e(target["model"])), ""]
        for m in daftar[:25]:
            tanda = " ✅" if m == target.get("model") else ""
            baris.append("• <code>%s</code>%s" % (e(m), tanda))
        if len(daftar) > 25:
            baris.append("<i>…dan %d model lainnya (lihat lengkap di dashboard Asisten AI).</i>" % (len(daftar) - 25))
        return "\n".join(baris)

    try:
        db = buka_baca(path_log)
    except sqlite3.Error:
        return "Log deteksi belum tersedia."
    try:
        if perintah == "analisis":
            bagian = arg.split()
            if not bagian:
                return "Format: <code>/analisis &lt;alamat_ip&gt; [koneksi] [model]</code>"
            try:
                ip = str(ipaddress.ip_address(bagian[0].strip()))
            except ValueError:
                return "❌ <code>%s</code> bukan alamat IP yang valid." % e(bagian[0][:64])
            profil_req, model_req = _pisah_profil_model(path_ai, bagian[1:])
            diblokir = bool(daftar_blokir.cocok_dengan(_ambil_diblokir(path_blokir), ip)) if path_blokir else False
            dipercaya = bool(tepercaya.cocok(ip)) if tepercaya is not None else False
            res = asisten_ai.analisis_ip(path_ai, db, ip, profil_id=profil_req, model_override=model_req,
                                         diblokir=diblokir, tepercaya=dipercaya, **kw_tr)
            return _format_balasan_ai("Analisis AI · %s" % ip, res)

        if perintah == "ringkasai":
            bagian = arg.split()
            hari = 7 if any(x.lower() in ("7h", "7", "minggu") for x in bagian) else 1
            sisa = [x for x in bagian if x.lower() not in ("7h", "7", "minggu", "24j", "1h")]
            profil_req, model_req = _pisah_profil_model(path_ai, sisa)
            res = asisten_ai.analisis_ringkasan(path_ai, db, hari=hari, profil_id=profil_req,
                                                model_override=model_req, **kw_tr)
            label = "7 hari" if hari == 7 else "24 jam"
            return _format_balasan_ai("Ringkasan AI (%s)" % label, res)

        if perintah == "tanya":
            if not arg:
                return "Format: <code>/tanya &lt;pertanyaan tentang keamanan server&gt;</code>"
            res = asisten_ai.tanya_keamanan(path_ai, db, arg, **kw_tr)
            return _format_balasan_ai("Jawaban Asisten AI", res)

        return "Perintah AI tidak dikenal."
    except (ValueError, RuntimeError) as ex:
        return "❌ Analisis AI gagal: %s" % e(str(ex))
    finally:
        db.close()


def jawab(path_log, perintah, argumen, tepercaya=None, kondisi=None, diblokir=None):
    """Satu perintah baca / lihat -> teks jawaban. Log dibuka baca-saja untuk setiap perintah."""
    perintah = perintah.lower()
    if perintah in ("start", "bantuan", "help"):
        return BANTUAN
    if perintah == "diblokir":
        return teks_diblokir(diblokir) if isinstance(diblokir, str) else "Daftar blokir belum dikonfigurasi."
    if perintah not in ("status", "ringkasan", "ip", "hampir"):
        return "Perintah tidak dikenal. Ketik /bantuan."
    try:
        db = buka_baca(path_log)
    except sqlite3.Error:
        return "Log deteksi belum tersedia."
    try:
        if perintah == "status":
            return teks_status(db, kondisi)
        if perintah == "ringkasan":
            return teks_ringkasan(db, argumen)
        if perintah == "ip":
            return teks_ip(db, argumen, tepercaya, diblokir=diblokir)
        return teks_hampir(db, argumen, tepercaya)
    finally:
        db.close()

