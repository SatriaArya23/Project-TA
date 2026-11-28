# -*- coding: utf-8 -*-
"""
Log anomali (SQLite).

Tabel:
  anomali      satu baris per aliran yang ditandai anomali (untuk penelusuran,
               dashboard, dan perhitungan metrik pengujian)
  ringkasan    jumlah aliran yang diperiksa & anomali per menit (untuk grafik dashboard)
  notifikasi   setiap pesan Telegram yang dikirim / gagal (untuk mengukur latensi notifikasi)
  status       detak jantung modul deteksi (kapan terakhir memproses paket)
  aliran       SEMUA aliran yang dinilai beserta skor A/C (ringkas, tanpa 75 fitur) -> grafik
               total lalu lintas, dan bahan "periksa ulang" pada loop umpan balik (nids/umpan_balik.py)
  model        versi model yang pernah aktif + ringkasannya (ambang, sebaran skor latih, evaluasi)

Semua waktu disimpan dalam mikrodetik UTC (integer) agar latensi dapat dihitung tepat.
"""
import json
import sqlite3
import time

SKEMA = """
CREATE TABLE IF NOT EXISTS anomali (
    id               INTEGER PRIMARY KEY,
    waktu_mulai_us   INTEGER NOT NULL,   -- paket pertama aliran
    waktu_selesai_us INTEGER NOT NULL,   -- aliran selesai disusun (acuan fitur agregasi)
    waktu_log_us     INTEGER NOT NULL,   -- saat dicatat ke log (t_log)
    src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER, protokol INTEGER,
    oleh             TEXT NOT NULL,      -- 'A', 'C', atau 'A+C'
    skor_a REAL, ambang_a REAL, skor_c REAL, ambang_c REAL,
    paket INTEGER, durasi_us INTEGER,
    agg_ip_aliran INTEGER, agg_ip_port_unik INTEGER, agg_ip_rasio_gagal REAL, agg_ip_aliran_ssh INTEGER,
    agg_s24_ip_unik INTEGER, agg_s24_aliran INTEGER, agg_s24_port_unik INTEGER,
    model_id         INTEGER
);
CREATE INDEX IF NOT EXISTS idx_anomali_waktu ON anomali (waktu_log_us);
CREATE INDEX IF NOT EXISTS idx_anomali_ip ON anomali (src_ip);
CREATE TABLE IF NOT EXISTS ringkasan (
    menit_utc  INTEGER PRIMARY KEY,      -- awal menit, detik epoch
    aliran     INTEGER NOT NULL DEFAULT 0,
    anomali    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS notifikasi (
    id              INTEGER PRIMARY KEY,
    src_ip          TEXT,
    anomali_id      INTEGER,             -- anomali pertama yang memicu pesan
    waktu_log_us    INTEGER,             -- t_log anomali tersebut
    waktu_kirim_us  INTEGER,             -- saat permintaan ke Telegram dikirim
    waktu_terima_us INTEGER,             -- saat Telegram mengonfirmasi pesan (respons API)
    telegram_date   INTEGER,             -- cap waktu pesan dari server Telegram (detik)
    berhasil        INTEGER NOT NULL,
    keterangan      TEXT
);
CREATE TABLE IF NOT EXISTS status (
    kunci TEXT PRIMARY KEY,
    nilai TEXT
);
CREATE TABLE IF NOT EXISTS aliran (
    id               INTEGER PRIMARY KEY,
    waktu_selesai_us INTEGER NOT NULL,
    waktu_mulai_us   INTEGER NOT NULL,
    src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER, protokol INTEGER,
    paket INTEGER,
    skor_a REAL, skor_c REAL,
    oleh   TEXT NOT NULL DEFAULT '',     -- '' bila normal
    model_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_aliran_waktu ON aliran (waktu_selesai_us);
CREATE INDEX IF NOT EXISTS idx_aliran_ip ON aliran (src_ip, waktu_selesai_us);
CREATE TABLE IF NOT EXISTS model (
    id            INTEGER PRIMARY KEY,
    versi         TEXT NOT NULL,
    aktif_sejak_us INTEGER NOT NULL,
    info_json     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS aliran_fitur (
    aliran_id        INTEGER PRIMARY KEY,
    waktu_selesai_us INTEGER NOT NULL,
    model_id         INTEGER,
    vektor_a         TEXT NOT NULL,
    vektor_c         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fitur_waktu ON aliran_fitur (waktu_selesai_us);
"""

KOLOM_AGG = ["agg_ip_aliran", "agg_ip_port_unik", "agg_ip_rasio_gagal", "agg_ip_aliran_ssh",
             "agg_s24_ip_unik", "agg_s24_aliran", "agg_s24_port_unik"]


def sekarang_us():
    return int(time.time() * 1_000_000)


class LogAnomali:
    def __init__(self, path):
        self.path = path
        self.db = sqlite3.connect(path, timeout=30, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode = WAL")
        self.db.execute("PRAGMA busy_timeout = 30000")
        self.db.executescript(SKEMA)
        kolom = {r[1] for r in self.db.execute("PRAGMA table_info(anomali)")}
        if "model_id" not in kolom:                      # log dari versi lama
            self.db.execute("ALTER TABLE anomali ADD COLUMN model_id INTEGER")
        self.db.commit()
        self.model_id = None

    def catat_model(self, info, kini_us=None):
        """Catat model yang sedang dipakai (sekali per versi berturut-turut); simpan id-nya."""
        teks = json.dumps(info)
        r = self.db.execute("SELECT id, versi, info_json FROM model ORDER BY id DESC LIMIT 1").fetchone()
        if r and r[1] == info.get("versi"):
            self.model_id = r[0]
            if r[2] != teks:
                self.db.execute("UPDATE model SET info_json = ? WHERE id = ?", (teks, r[0]))
        else:
            cur = self.db.execute("INSERT INTO model (versi, aktif_sejak_us, info_json) VALUES (?, ?, ?)",
                                  (info.get("versi"), kini_us or sekarang_us(), teks))
            self.model_id = cur.lastrowid
        self.db.commit()
        return self.model_id

    def catat(self, aliran, hasil, model, waktu_log_us=None, vektor=None):
        """aliran & hasil (dari ModelDeteksi.nilai) sejajar. Simpan ringkasan semua aliran, vektor fitur
        untuk aliran di zona batas/anomali (bahan adaptasi), dan detail aliran anomali."""
        per_selesai = waktu_log_us == "selesai"          # putar ulang: t_log = waktu aliran selesai
        t_log = None if per_selesai else (waktu_log_us if waktu_log_us is not None else sekarang_us())
        per_menit, anomali = {}, []
        ba, bc = model.batas_aman() if hasattr(model, "batas_aman") else (model.A.ambang, model.C.ambang)
        xa, xc = vektor if (vektor is not None and len(vektor) == 2) else (None, None)
        fitur_rows = []

        for idx, (f, (sa, sc, oleh)) in enumerate(zip(aliran, hasil)):
            cur_a = self.db.execute(
                "INSERT INTO aliran (waktu_selesai_us, waktu_mulai_us, src_ip, src_port, dst_ip, dst_port, protokol, "
                "paket, skor_a, skor_c, oleh, model_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (int(f["Waktu Selesai"]), int(f.get("_mulai_us") or f["Waktu Selesai"] - f["Flow Duration"]),
                 f["Source IP"], int(f["Source Port"]), f["Destination IP"], int(f["Destination Port"]),
                 int(f["Protocol"]), int(f["Total Fwd Packets"] + f["Total Backward Packets"]), sa, sc, oleh,
                 self.model_id))
            aliran_id = cur_a.lastrowid
            if xa is not None and xc is not None and (oleh or sa >= ba * 0.92 or sc >= bc * 0.92):
                va_s = json.dumps([round(float(x), 4) for x in xa[idx]], separators=(",", ":"))
                vc_s = json.dumps([round(float(x), 4) for x in xc[idx]], separators=(",", ":"))
                fitur_rows.append((aliran_id, int(f["Waktu Selesai"]), self.model_id, va_s, vc_s))

            m = f["Waktu Selesai"] // 60_000_000 * 60
            a, n = per_menit.get(m, (0, 0))
            per_menit[m] = (a + 1, n + (1 if oleh else 0))
            if not oleh:
                continue
            if per_selesai:
                t_log = int(f["Waktu Selesai"])
            mulai = int(f.get("_mulai_us") or f["Waktu Selesai"] - f["Flow Duration"])
            cur = self.db.execute(
                "INSERT INTO anomali (waktu_mulai_us, waktu_selesai_us, waktu_log_us, src_ip, src_port, dst_ip, "
                "dst_port, protokol, oleh, skor_a, ambang_a, skor_c, ambang_c, paket, durasi_us, model_id, "
                + ", ".join(KOLOM_AGG) + ") VALUES (" + ", ".join(["?"] * (16 + len(KOLOM_AGG))) + ")",
                (mulai, int(f["Waktu Selesai"]), t_log, f["Source IP"], int(f["Source Port"]),
                 f["Destination IP"], int(f["Destination Port"]), int(f["Protocol"]), oleh,
                 sa, model.A.ambang, sc, model.C.ambang,
                 int(f["Total Fwd Packets"] + f["Total Backward Packets"]), int(f["Flow Duration"]),
                 self.model_id) + tuple(f[k] for k in KOLOM_AGG))
            anomali.append((cur.lastrowid, f, (sa, sc, oleh)))

        if fitur_rows:
            self.db.executemany(
                "INSERT OR REPLACE INTO aliran_fitur (aliran_id, waktu_selesai_us, model_id, vektor_a, vektor_c) "
                "VALUES (?, ?, ?, ?, ?)", fitur_rows)
        for m, (a, n) in per_menit.items():
            self.db.execute("INSERT INTO ringkasan (menit_utc, aliran, anomali) VALUES (?, ?, ?) "
                            "ON CONFLICT(menit_utc) DO UPDATE SET aliran = aliran + excluded.aliran, "
                            "anomali = anomali + excluded.anomali", (m, a, n))
        self.db.commit()
        return anomali

    def catat_notifikasi(self, **k):
        self.db.execute("INSERT INTO notifikasi (src_ip, anomali_id, waktu_log_us, waktu_kirim_us, waktu_terima_us, "
                        "telegram_date, berhasil, keterangan) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (k.get("src_ip"), k.get("anomali_id"), k.get("waktu_log_us"), k.get("waktu_kirim_us"),
                         k.get("waktu_terima_us"), k.get("telegram_date"), int(k.get("berhasil", 0)),
                         k.get("keterangan")))
        self.db.commit()

    def status(self, **nilai):
        for k, v in nilai.items():
            self.db.execute("INSERT INTO status (kunci, nilai) VALUES (?, ?) "
                            "ON CONFLICT(kunci) DO UPDATE SET nilai = excluded.nilai", (k, str(v)))
        self.db.commit()

    def buang_lama(self, hari, hari_aliran=30):
        """Hapus catatan yang lebih tua dari `hari` hari (retensi); tabel aliran (besar) `hari_aliran` hari."""
        batas_aliran = sekarang_us() - int(hari_aliran * 86400 * 1_000_000)
        self.db.execute("DELETE FROM aliran WHERE waktu_selesai_us < ?", (batas_aliran,))
        self.db.execute("DELETE FROM aliran_fitur WHERE waktu_selesai_us < ?", (batas_aliran,))
        batas = sekarang_us() - int(hari * 86400 * 1_000_000)
        self.db.execute("DELETE FROM anomali WHERE waktu_log_us < ?", (batas,))
        self.db.execute("DELETE FROM notifikasi WHERE waktu_kirim_us < ?", (batas,))
        self.db.execute("DELETE FROM ringkasan WHERE menit_utc < ?", (batas // 1_000_000,))
        self.db.commit()

    def tutup(self):
        self.db.close()
