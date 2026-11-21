# -*- coding: utf-8 -*-
"""
Loop umpan balik (revisi arsitektur, alur pada server):

  Administrator melaporkan  ->  1. PERIKSA ULANG DI MODUL DETEKSI     ->  terdeteksi?  -> ya : usulan ambang baru
  "serangan lolos"              (skor Isolation Forest yang sudah          |                (model versi baru, tanpa latih ulang)
  (IP sumber + rentang waktu)    tersimpan dinilai ulang dengan ambang     tidak
                                 yang diturunkan, dalam batas aman)         v
                                                                     2. MODUL PELATIHAN ULANG (laptop peneliti)

Laporan "alarm palsu" langsung masuk antrean pelatihan ulang sebagai contoh lalu lintas normal.

Modul ini hanya memakai pustaka standar Python (sqlite3, bisect), sehingga dashboard dapat
menjalankannya tanpa numpy/scikit-learn. Skor setiap aliran sudah dicatat modul deteksi di tabel
`aliran`, jadi "menilai ulang" cukup membandingkan skor tersebut dengan ambang yang disesuaikan.
"""
import bisect
import json
import math
import time

# Batas penyesuaian ambang yang masih dianggap aman (contamination = proporsi data latih normal
# yang akan ikut ditandai). Bawaan model: A = 0,001 dan C = 0,01.
BATAS_CONTAMINATION = {"A": 0.01, "C": 0.05}
HARI_DAMPAK = 7


# ------------------------------------------------------------------ sebaran skor data latih
def kontaminasi_dari_skor(kuantil, skor):
    """Proporsi skor data latih yang lebih besar dari `skor` (interpolasi linear).
    kuantil = [[p, q], ...] dengan q = kuantil skor latih pada peluang p (p naik)."""
    ps, qs = [k[0] for k in kuantil], [k[1] for k in kuantil]
    if skor < qs[0]:
        return 1.0
    if skor >= qs[-1]:
        return 0.0
    i = bisect.bisect_right(qs, skor)                  # qs[i-1] <= skor < qs[i]
    q0, q1, p0, p1 = qs[i - 1], qs[i], ps[i - 1], ps[i]
    p = p0 if q1 == q0 else p0 + (p1 - p0) * (skor - q0) / (q1 - q0)
    return max(0.0, 1.0 - p)


def ambang_dari_kontaminasi(kuantil, c):
    """Ambang skor agar proporsi `c` data latih berada di atasnya (kebalikan fungsi di atas)."""
    p = 1.0 - c
    ps, qs = [k[0] for k in kuantil], [k[1] for k in kuantil]
    if p <= ps[0]:
        return qs[0]
    if p >= ps[-1]:
        return qs[-1]
    i = bisect.bisect_right(ps, p)
    p0, p1, q0, q1 = ps[i - 1], ps[i], qs[i - 1], qs[i]
    return q0 if p1 == p0 else q0 + (q1 - q0) * (p - p0) / (p1 - p0)


# ------------------------------------------------------------------ periksa ulang
def _model(db):
    return {r[0]: json.loads(r[1]) for r in db.execute("SELECT id, info_json FROM model ORDER BY id")}


def _acuan(model):
    """model_id -> id versi TERBARU yang memakai hutan Isolation Forest yang sama.

    Penyesuaian ambang (ubah_ambang) tidak mengubah hutan, sehingga skor aliran lama tetap berlaku dan
    dinilai dengan ambang versi terbaru. Model hasil pelatihan ulang punya hutan baru; aliran lama
    tetap dinilai dengan modelnya sendiri (verifikasinya lewat putar ulang rekaman di laptop)."""
    terbaru = {}
    for mid, info in model.items():
        terbaru[info.get("hutan") or info.get("versi") or mid] = mid
    return {mid: terbaru[info.get("hutan") or info.get("versi") or mid] for mid, info in model.items()}


def ambang_model(db, batas=None):
    """model_id -> {"versi", "A": {ambang, batas, kuantil}, "C": {...}}.

    ambang = ambang yang berlaku sekarang (versi terbaru dengan hutan yang sama, seperti periksa_ulang);
    batas  = ambang terendah yang masih dalam batas aman umpan balik (BATAS_CONTAMINATION).
    Aliran yang skornya di antara keduanya "hampir anomali": tidak ditandai, tetapi akan tertangkap
    bila administrator melaporkannya dan ambang diturunkan lewat loop umpan balik."""
    batas = dict(BATAS_CONTAMINATION, **(batas or {}))
    model = _model(db)
    acuan = _acuan(model)
    hasil = {}
    for mid in model:
        info = model[acuan[mid]]
        d = {"versi": info.get("versi")}
        for nama in ("A", "C"):
            m = info.get(nama) or {}
            t, k = m.get("ambang"), m.get("kuantil")
            b = min(t, ambang_dari_kontaminasi(k, batas[nama])) if t is not None and k else t
            d[nama] = {"ambang": t, "batas": b, "kuantil": k}
        hasil[mid] = d
    return hasil


def periksa_ulang(db, jenis, src_ip, mulai_us, akhir_us, batas=None, hari_dampak=HARI_DAMPAK, kini_us=None):
    """Jalankan langkah 1 loop umpan balik. db = koneksi sqlite3 ke log deteksi (boleh baca-saja).

    Kembalikan dict: status, ringkasan aliran, kandidat penyesuaian ambang, dan dampaknya.
    status:
      tidak_ada_aliran       : tidak ada aliran dari IP itu pada rentang waktu (periksa IP/waktu/penangkap)
      sudah_terdeteksi       : (serangan lolos) sebagian aliran ditandai pada ambang yang berlaku sekarang
      terdeteksi_penyesuaian : terdeteksi bila ambang diturunkan dalam batas aman -> usulan ambang
      pelatihan_ulang        : tetap tidak terdeteksi / alarm palsu -> antrean modul pelatihan ulang
    """
    batas = dict(BATAS_CONTAMINATION, **(batas or {}))
    kini_us = kini_us or int(time.time() * 1e6)
    model = _model(db)
    acuan = _acuan(model)

    def ambang(mid, nama):
        info = model.get(acuan.get(mid)) or {}
        return (info.get(nama) or {}).get("ambang")

    def ditandai(mid, sa, sc, oleh):
        ta, tc = ambang(mid, "A"), ambang(mid, "C")
        if ta is None or tc is None:
            return bool(oleh)
        return sa > ta or sc > tc

    rows = db.execute("SELECT model_id, skor_a, skor_c, oleh, dst_port, waktu_selesai_us FROM aliran "
                      "WHERE src_ip = ? AND waktu_selesai_us BETWEEN ? AND ?",
                      (src_ip, int(mulai_us), int(akhir_us))).fetchall()
    hasil = {"jenis": jenis, "src_ip": src_ip, "mulai_us": int(mulai_us), "akhir_us": int(akhir_us),
             "diperiksa_us": kini_us, "batas_contamination": batas, "aliran": len(rows),
             "ditandai": sum(1 for r in rows if ditandai(r[0], r[1], r[2], r[3])), "kandidat": [],
             "versi_acuan": sorted({(model.get(acuan.get(r[0])) or {}).get("versi") or "?" for r in rows})}
    port = {}
    for r in rows:
        port[r[4]] = port.get(r[4], 0) + 1
    hasil["port_teratas"] = sorted(port.items(), key=lambda x: -x[1])[:5]
    if not rows:
        hasil["status"] = "tidak_ada_aliran"
        return hasil

    if jenis == "palsu":
        # Menaikkan ambang secara global akan menghilangkan deteksi lain, jadi alarm palsu
        # dijadikan contoh normal untuk pelatihan ulang.
        hasil["status"] = "pelatihan_ulang" if hasil["ditandai"] else "tidak_ada_alarm"
        return hasil
    if hasil["ditandai"]:
        hasil["status"] = "sudah_terdeteksi"
        return hasil

    # Langkah 1: nilai ulang skor dengan ambang yang diturunkan (per model, per hutan Isolation Forest)
    per_acuan = {}
    for mid, sa, sc, *_ in rows:
        per_acuan.setdefault(acuan.get(mid, mid), []).append((sa, sc))
    awal_dampak = kini_us - int(hari_dampak * 86400e6)
    for mid, skor in per_acuan.items():
        info = model.get(mid) or {}
        sekeluarga = [m for m, a in acuan.items() if a == mid] or [mid]
        tanda = ",".join("?" * len(sekeluarga))
        ta, tc = ambang(mid, "A"), ambang(mid, "C")
        for nama, kol, j in (("A", "skor_a", 0), ("C", "skor_c", 1)):
            m = info.get(nama) or {}
            kuantil = m.get("kuantil")
            maks = max(s[j] for s in skor)
            k = {"model": nama, "model_id": mid, "versi": info.get("versi"), "skor_maks": maks,
                 "ambang_sekarang": m.get("ambang"), "contamination_sekarang": m.get("contamination")}
            if not kuantil or ta is None or tc is None:
                k["catatan"] = "model tidak menyimpan sebaran skor latih"
                hasil["kandidat"].append(k)
                continue
            # aliran paling anomali tepat melewati ambang; dibulatkan ke bawah 8 desimal agar dapat
            # ditulis apa adanya di perintah ubah_ambang.py --ambang-x
            ambang_baru = math.floor((maks - 1e-9) * 1e8) / 1e8
            c_baru = kontaminasi_dari_skor(kuantil, ambang_baru)
            k.update(ambang_baru=ambang_baru, contamination_baru=c_baru, dalam_batas=c_baru <= batas[nama],
                     tertangkap=sum(1 for s in skor if s[j] > ambang_baru))
            # Dampak: aliran lain (bukan IP ini) yang sekarang normal tetapi ikut ditandai pada ambang baru
            n, n_ip = db.execute(
                "SELECT COUNT(*), COUNT(DISTINCT src_ip) FROM aliran WHERE model_id IN (%s) AND src_ip != ? "
                "AND %s > ? AND skor_a <= ? AND skor_c <= ? AND waktu_selesai_us >= ?" % (tanda, kol),
                (*sekeluarga, src_ip, ambang_baru, ta, tc, awal_dampak)).fetchone()
            t_awal = db.execute("SELECT MIN(waktu_selesai_us) FROM aliran WHERE model_id IN (%s) "
                                "AND waktu_selesai_us >= ?" % tanda, (*sekeluarga, awal_dampak)).fetchone()[0] or kini_us
            hari = max((kini_us - t_awal) / 86400e6, 1 / 24)
            k.update(tambahan_aliran=n, tambahan_ip=n_ip, hari_data=round(hari, 2),
                     tambahan_aliran_per_hari=n / hari, tambahan_ip_per_hari=n_ip / hari)
            hasil["kandidat"].append(k)

    layak = [k for k in hasil["kandidat"] if k.get("dalam_batas")]
    if layak:
        hasil["usulan"] = min(layak, key=lambda k: (k["tambahan_ip_per_hari"], k["contamination_baru"]))
        hasil["status"] = "terdeteksi_penyesuaian"
    else:
        hasil["status"] = "pelatihan_ulang"            # langkah 2: modul pelatihan ulang
    return hasil


# ------------------------------------------------------------------ hampir anomali (dashboard & bot)
def kedekatan(am, mid, maks_a, maks_c):
    """Skor tertinggi sekelompok aliran dibanding sebaran skor data latih model `mid`.

    -> [{model, skor, ambang, persentil, persentil_ambang}]; persentil = proporsi data latih yang skornya
    lebih rendah (0,995 = lebih tidak biasa dari 99,5% lalu lintas latih). Aliran ditandai bila
    persentil > persentil_ambang (= 1 - contamination)."""
    m = am.get(mid)
    hasil = []
    for nama, s in (("A", maks_a), ("C", maks_c)):
        k = m and m[nama]["kuantil"]
        if s is None or not k or m[nama]["ambang"] is None:
            continue
        hasil.append({"model": nama, "skor": s, "ambang": m[nama]["ambang"],
                      "persentil": 1 - kontaminasi_dari_skor(k, s),
                      "persentil_ambang": 1 - kontaminasi_dari_skor(k, m[nama]["ambang"])})
    return hasil


def hampir_anomali(db, awal_us, abaikan=None):
    """IP sumber yang TIDAK ditandai sama sekali sejak awal_us, tetapi punya aliran dengan skor di atas
    ambang batas aman umpan balik (BATAS_CONTAMINATION). Bila administrator melaporkannya sebagai
    "serangan lolos", periksa ulang akan dapat mengusulkan ambang baru untuknya. Urut dari aliran
    mendekati ambang terbanyak (pola berulang, mis. brute force lambat, lebih patut dicurigai daripada
    satu aliran aneh), lalu dari yang paling dekat ke ambang. abaikan(ip) -> True untuk melewati IP
    (mis. IP tepercaya)."""
    am = ambang_model(db)
    per = {}
    for mid, m in am.items():
        ta, tc, ba, bc = m["A"]["ambang"], m["C"]["ambang"], m["A"]["batas"], m["C"]["batas"]
        if None in (ta, tc, ba, bc):
            continue
        for ip, n, tanda, dekat, ma, mc, t0, t1 in db.execute(
                "SELECT src_ip, COUNT(*), SUM(oleh != '' OR skor_a > ? OR skor_c > ?), SUM(skor_a > ? OR skor_c > ?), "
                "MAX(skor_a), MAX(skor_c), MIN(waktu_selesai_us), MAX(waktu_selesai_us) FROM aliran "
                "WHERE model_id = ? AND waktu_selesai_us >= ? GROUP BY src_ip", (ta, tc, ba, bc, mid, awal_us)):
            p = per.setdefault(ip, {"src_ip": ip, "aliran": 0, "tanda": 0, "dekat": 0, "awal": t0, "akhir": t1,
                                    "skor": []})
            p["aliran"] += n
            p["tanda"] += tanda or 0
            p["dekat"] += dekat or 0
            p["awal"], p["akhir"] = min(p["awal"], t0), max(p["akhir"], t1)
            if dekat:
                p["skor"] += kedekatan(am, mid, ma, mc)
    daftar = [p for p in per.values() if not p["tanda"] and p["dekat"] and p["skor"]
              and not (abaikan and abaikan(p["src_ip"]))]
    for p in daftar:
        # model yang paling mendekati ambangnya (jarak persentil ke persentil ambang paling kecil)
        p["terdekat"] = min(p["skor"], key=lambda s: s["persentil_ambang"] - s["persentil"])
    daftar.sort(key=lambda p: (-p["dekat"], p["terdekat"]["persentil_ambang"] - p["terdekat"]["persentil"]))
    return daftar


TEKS_STATUS = {
    "tidak_ada_aliran": "Tidak ada aliran dari IP ini pada rentang waktu tersebut",
    "tidak_ada_alarm": "Tidak ada alarm dari IP ini pada rentang waktu tersebut",
    "sudah_terdeteksi": "Sudah terdeteksi oleh model saat ini",
    "terdeteksi_penyesuaian": "Terdeteksi setelah penyesuaian ambang",
    "pelatihan_ulang": "Masuk antrean pelatihan ulang",
    "selesai": "Selesai",
}
