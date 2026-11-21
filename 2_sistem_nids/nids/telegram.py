# -*- coding: utf-8 -*-
"""
Notifikasi Telegram Bot: hanya untuk anomali yang meyakinkan, dengan jeda per IP sumber.

* Ambang notifikasi: pesan dikirim bila satu IP sumber menghasilkan minimal `min_aliran` (bawaan 3)
  aliran anomali dalam jendela waktu yang sama, ATAU kedua model (A dan C) sepakat menandai alirannya.
  Anomali tunggal tetap dicatat di log dan tampil di dashboard, tetapi tidak dikirim, supaya
  administrator tidak dibanjiri pesan (alert fatigue).
* Satu IP sumber paling banyak memicu satu pesan per `jeda_detik` (bawaan 600 detik), agar
  rentetan anomali dari satu serangan tidak menjadi ratusan pesan. Anomali selama jeda tetap
  dicatat di log dan jumlahnya disebut pada pesan berikutnya.
* Pengiriman berjalan di thread tersendiri, sehingga deteksi tidak tertahan oleh jaringan.
* Setiap pengiriman dicatat (waktu kirim, waktu konfirmasi Telegram) untuk mengukur latensi notifikasi.

Token bot dan chat ID dibaca dari konfigurasi (berkas rahasia), tidak pernah ditulis ke log.
"""
import html
import http.client
import json
import queue
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from .agregasi import subnet
from .dugaan import dugaan  # noqa: F401  (dipakai susun_pesan; diekspor ulang untuk kompatibilitas)
from .log_anomali import LogAnomali, sekarang_us

WITA = timezone(timedelta(hours=8))
BULAN = ["Jan", "Feb", "Mar", "Apr", "Mei", "Jun", "Jul", "Agu", "Sep", "Okt", "Nov", "Des"]
NAMA_MODEL = {"A": "Model A (pola satu koneksi)", "C": "Model C (perilaku sumber)", "A+C": "Model A dan C"}


def teks_wita(us):
    d = datetime.fromtimestamp(us / 1e6, WITA)
    return "%d %s %d, %02d.%02d.%02d WITA" % (d.day, BULAN[d.month - 1], d.year, d.hour, d.minute, d.second)


def tingkat(kejadian, f):
    """TINGGI bila kedua model sepakat atau pola sumbernya intens; selain itu SEDANG."""
    if any(k[2][2] == "A+C" for k in kejadian) or f["agg_ip_port_unik"] >= 20 or f["agg_ip_aliran_ssh"] >= 20 \
            or f["agg_ip_aliran"] >= 100:
        return "TINGGI"
    return "SEDANG"


def susun_pesan(ip, kejadian, ditahan, nama_server, jendela_detik):
    """kejadian = list (id, aliran, (skor_a, skor_c, oleh)) dari satu IP pada satu kiriman. Format HTML Telegram."""
    e = html.escape
    f = max(kejadian, key=lambda k: k[1]["agg_ip_aliran"])[1]          # aliran dengan konteks terlengkap
    port = sorted({k[1]["Destination Port"] for k in kejadian})
    oleh = {k[2][2] for k in kejadian}
    model = NAMA_MODEL["A+C"] if len(oleh) > 1 or "A+C" in oleh else NAMA_MODEL[oleh.pop()]
    t = tingkat(kejadian, f)
    baris = [
        "%s <b>NIDS · Anomali %s</b>" % ("🔴" if t == "TINGGI" else "🟠", t),
        "%s%s" % (("<b>%s</b> · " % e(nama_server)) if nama_server else "",
                  teks_wita(min(k[1]["_mulai_us"] for k in kejadian))),
        "",
        "<b>Dugaan:</b> %s" % dugaan(f),
        "<b>Sumber:</b> <code>%s</code>  (subnet <code>%s</code>)" % (e(ip), e(subnet(ip))),
        "<b>Port tujuan:</b> %s%s" % (", ".join(map(str, port[:10])), " …" if len(port) > 10 else ""),
        "",
        "<b>%d menit terakhir dari sumber ini</b>" % (jendela_detik // 60),
        "• %d koneksi ke %d port berbeda" % (f["agg_ip_aliran"], f["agg_ip_port_unik"]),
        "• %d%% ditolak / tidak dibalas" % round(f["agg_ip_rasio_gagal"] * 100),
        "• %d ke SSH (port 22)" % f["agg_ip_aliran_ssh"],
        "",
        "<b>Penanda:</b> %s" % model,
        "%d aliran anomali%s" % (len(kejadian), (" · +%d tertahan sejak pesan sebelumnya" % ditahan) if ditahan else ""),
    ]
    return "\n".join(baris)


class _HTTPSUtamakanIPv4(http.client.HTTPSConnection):
    """Sambungan HTTPS yang mencoba alamat IPv4 lebih dulu, tiap alamat paling lama 5 detik.

    Di sebagian VPS rute IPv6 ke api.telegram.org tidak tersambung; tanpa ini setiap pesan tertahan
    sampai batas waktu IPv6 habis (±15 detik) sebelum beralih ke IPv4."""
    def connect(self):
        alamat = sorted(socket.getaddrinfo(self.host, self.port, 0, socket.SOCK_STREAM),
                        key=lambda a: a[0] != socket.AF_INET)
        galat = OSError("tidak ada alamat untuk %s" % self.host)
        for fam, jenis, proto, _, sa in alamat:
            s = socket.socket(fam, jenis, proto)
            try:
                s.settimeout(5)
                s.connect(sa)
                s.settimeout(self.timeout)
                self.sock = self._context.wrap_socket(s, server_hostname=self.host)
                return
            except OSError as e:
                galat = e
                s.close()
        raise galat


class _PengendaliHTTPS(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_HTTPSUtamakanIPv4, req, context=ssl.create_default_context())


_pembuka = urllib.request.build_opener(_PengendaliHTTPS)


def _samarkan(teks, token):
    """Keterangan galat masuk ke log & dashboard: jangan pernah memuat token bot."""
    teks = str(teks)
    return teks.replace(token, "***") if token else teks


def kirim_telegram(token, chat_id, teks, batas_waktu=15):
    """Kirim satu pesan. Kembalikan (berhasil, telegram_date, keterangan)."""
    token, chat_id = str(token).strip(), str(chat_id).strip()       # buang spasi / \r dari berkas rahasia
    url = "https://api.telegram.org/bot%s/sendMessage" % token
    data = urllib.parse.urlencode({"chat_id": chat_id, "text": teks, "parse_mode": "HTML",
                                   "disable_web_page_preview": "true"}).encode()
    for percobaan in range(3):
        try:
            with _pembuka.open(urllib.request.Request(url, data=data), timeout=batas_waktu) as r:
                j = json.loads(r.read().decode())
            if j.get("ok"):
                return True, j["result"].get("date"), None
            return False, None, _samarkan(j.get("description"), token)[:200]
        except urllib.error.HTTPError as e:
            try:
                j = json.loads(e.read().decode())
            except Exception:
                j = {}
            tunggu = (j.get("parameters") or {}).get("retry_after")
            if e.code == 429 and tunggu and percobaan < 2:        # dibatasi Telegram: tunggu lalu ulangi
                time.sleep(min(int(tunggu), 30))
                continue
            return False, None, "HTTP %d %s" % (e.code, _samarkan(j.get("description", ""), token)[:150])
        except Exception as e:                                     # jaringan putus, DNS, dsb.
            if percobaan < 2:
                time.sleep(2 * (percobaan + 1))
                continue
            return False, None, "%s: %s" % (type(e).__name__, _samarkan(e, token)[:150])
    return False, None, "gagal setelah 3 percobaan"


def panggil_api(token, metode, params=None, batas_waktu=60):
    """Panggil satu metode Bot API (mis. getUpdates, setMyCommands). Galat tidak pernah memuat token."""
    token = str(token).strip()
    url = "https://api.telegram.org/bot%s/%s" % (token, metode)
    data = urllib.parse.urlencode({k: (json.dumps(v) if isinstance(v, (list, dict)) else v)
                                   for k, v in (params or {}).items() if v is not None}).encode()
    try:
        with _pembuka.open(urllib.request.Request(url, data=data), timeout=batas_waktu) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            j = json.loads(e.read().decode())
        except Exception:
            j = {}
        raise RuntimeError("HTTP %d %s" % (e.code, _samarkan(j.get("description", ""), token)[:150])) from None
    except Exception as e:
        raise RuntimeError("%s: %s" % (type(e).__name__, _samarkan(e, token)[:150])) from None


class Notifikasi:
    def __init__(self, token=None, chat_id=None, path_log=None, jeda_detik=600, nama_server="",
                 jendela_detik=300, kirim=None, jam=time.time, sinkron=False, min_aliran=3):
        self.aktif = bool((token and chat_id) or kirim)
        self.token, self.chat_id = token, chat_id
        self.kirim = kirim or (lambda teks: kirim_telegram(self.token, self.chat_id, teks))
        self.path_log, self.jeda, self.nama_server = path_log, jeda_detik, nama_server
        self.jendela_detik, self.jam, self.sinkron = jendela_detik, jam, sinkron
        self.min_aliran = max(1, int(min_aliran))
        self.terakhir, self.ditahan = {}, {}
        self.menunggu = {}                 # ip -> [(waktu, kejadian)] anomali yang belum mencapai ambang notifikasi
        self.tidak_dikirim = 0             # anomali yang tidak pernah mencapai ambang (hanya di log/dashboard)
        self.antrian = queue.Queue(maxsize=1000)
        self._log = None
        self._thread = None
        if self.aktif and not sinkron:
            self._thread = threading.Thread(target=self._pekerja, name="telegram", daemon=True)
            self._thread.start()

    # ------------------------------------------------------------------ dipanggil detektor
    def anomali(self, kejadian):
        """kejadian = list (id, aliran, hasil) dari LogAnomali.catat. Kembalikan jumlah pesan yang diantrekan."""
        if not self.aktif or not kejadian:
            return 0
        per_ip = {}
        for k in kejadian:
            per_ip.setdefault(k[1]["Source IP"], []).append(k)
        kini, n = self.jam(), 0
        for ip, daftar in per_ip.items():
            if kini - self.terakhir.get(ip, -1e18) < self.jeda:
                self.ditahan[ip] = self.ditahan.get(ip, 0) + len(daftar)
                continue
            # ambang notifikasi: >= min_aliran anomali dari IP ini dalam jendela, atau kedua model sepakat
            tunggu = [(t, k) for t, k in self.menunggu.pop(ip, []) if kini - t <= self.jendela_detik]
            tunggu += [(kini, k) for k in daftar]
            if len(tunggu) < self.min_aliran and not any(k[2][2] == "A+C" for _, k in tunggu):
                self.menunggu[ip] = tunggu
                continue
            daftar = [k for _, k in tunggu]
            self.terakhir[ip] = kini
            pesan = {"ip": ip, "teks": susun_pesan(ip, daftar, self.ditahan.pop(ip, 0), self.nama_server,
                                                   self.jendela_detik),
                     "anomali_id": daftar[-1][0], "waktu_log_us": None}   # latensi dihitung dari anomali pemicu
            if len(self.terakhir) > 50_000 or len(self.menunggu) > 50_000:   # cegah memori tumbuh tanpa batas
                batas = kini - max(self.jeda, self.jendela_detik)
                self.terakhir = {k: v for k, v in self.terakhir.items() if v >= batas}
                lama = {k: v for k, v in self.menunggu.items() if v[-1][0] < batas}
                self.tidak_dikirim += sum(len(v) for v in lama.values())
                self.menunggu = {k: v for k, v in self.menunggu.items() if k not in lama}
            if self.sinkron:
                self._kirim_satu(pesan)
            else:
                try:
                    self.antrian.put_nowait(pesan)
                except queue.Full:
                    pass                                          # Telegram tidak terjangkau lama: log tetap lengkap
            n += 1
        return n

    def tutup(self, tunggu=10):
        if self._thread:
            self.antrian.put(None)
            self._thread.join(timeout=tunggu)

    # ------------------------------------------------------------------ thread pengirim
    def _pekerja(self):
        while True:
            pesan = self.antrian.get()
            if pesan is None:
                return
            self._kirim_satu(pesan)

    def _kirim_satu(self, pesan):
        t_kirim = sekarang_us()
        ok, tg_date, ket = self.kirim(pesan["teks"])
        t_terima = sekarang_us()
        if self.path_log:
            if self._log is None:                                 # koneksi sendiri untuk thread ini
                self._log = LogAnomali(self.path_log)
            waktu_log = self._log.db.execute("SELECT waktu_log_us FROM anomali WHERE id = ?",
                                             (pesan["anomali_id"],)).fetchone()
            self._log.catat_notifikasi(src_ip=pesan["ip"], anomali_id=pesan["anomali_id"],
                                       waktu_log_us=waktu_log[0] if waktu_log else None,
                                       waktu_kirim_us=t_kirim, waktu_terima_us=t_terima if ok else None,
                                       telegram_date=tg_date, berhasil=ok, keterangan=ket)
