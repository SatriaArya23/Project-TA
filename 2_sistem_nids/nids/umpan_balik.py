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


def _aturan_cocok_row(db, row, aturan_list, am):
    """Cek apakah baris aliran (aliran_id, model_id, dst_port, protokol, paket, skor_a, skor_c)
    sudah cocok dengan salah satu aturan adaptasi aktif."""
    if not aturan_list:
        return None
    from . import adaptasi as ad  # impor lokal agar terhindar dari circular import di atas

    aliran_id, dst_port, protokol, paket = row[0], row[1], row[2], row[3]
    vec_a = vec_c = None
    try:
        fr = db.execute("SELECT vektor_a, vektor_c FROM aliran_fitur WHERE aliran_id = ?", (aliran_id,)).fetchone()
        if fr and fr[0] and fr[1]:
            vec_a = json.loads(fr[0])
            vec_c = json.loads(fr[1])
    except (sqlite3.Error, ValueError):
        pass
    return ad.cocokkan(aturan_list, vec_a=vec_a, vec_c=vec_c, dst_port=dst_port, protokol=protokol, paket=paket)


def periksa_ulang(db, jenis, src_ip, mulai_us, akhir_us, batas=None, hari_dampak=HARI_DAMPAK, kini_us=None,
                  aturan_adaptasi=None):
    """Jalankan langkah 1 loop umpan balik. db = koneksi sqlite3 ke log deteksi (boleh baca-saja).

    Kembalikan dict: status, ringkasan aliran, kandidat penyesuaian ambang, dan dampaknya.
    status:
      tidak_ada_aliran       : tidak ada aliran dari IP itu pada rentang waktu (periksa IP/waktu/penangkap)
      sudah_terdeteksi       : (serangan lolos) sebagian aliran ditandai pada ambang / adaptasi aktif
      terdeteksi_penyesuaian : terdeteksi bila ambang diturunkan dalam batas aman -> usulan ambang
      dapat_diadaptasi_normal: (hampir anomali) tidak ditandai, tetapi dekat ambang dan layak diadaptasi normal
      pelatihan_ulang        : tetap tidak terdeteksi / alarm palsu -> antrean modul pelatihan ulang + adaptasi
    """
    import sqlite3
    batas = dict(BATAS_CONTAMINATION, **(batas or {}))
    kini_us = kini_us or int(time.time() * 1e6)
    model = _model(db)
    acuan = _acuan(model)

    def ambang(mid, nama):
        info = model.get(acuan.get(mid)) or {}
        return (info.get(nama) or {}).get("ambang")

    def ambang_batas(mid):
        am_m = model.get(acuan.get(mid)) or {}
        out = {}
        for nm in ("A", "C"):
            sub = am_m.get(nm) or {}
            t, k = sub.get("ambang"), sub.get("kuantil")
            out[nm] = min(t, ambang_dari_kontaminasi(k, batas[nm])) if t is not None and k else t
        return out["A"], out["C"]

    def ditandai(r):
        mid, sa, sc, oleh = r[0], r[1], r[2], r[3]
        ta, tc = ambang(mid, "A"), ambang(mid, "C")
        tanda_if = (sa > ta or sc > tc) if (ta is not None and tc is not None) else bool(oleh)
        if aturan_adaptasi and len(r) >= 9:
            cocok = _aturan_cocok_row(db, (r[6], r[4], r[7], r[8]), aturan_adaptasi, model)
            if cocok is not None:
                return cocok.get("label") == "anomali"
        return tanda_if

    rows = db.execute("SELECT model_id, skor_a, skor_c, oleh, dst_port, waktu_selesai_us, id, protokol, paket "
                      "FROM aliran WHERE src_ip = ? AND waktu_selesai_us BETWEEN ? AND ?",
                      (src_ip, int(mulai_us), int(akhir_us))).fetchall()
    hasil = {"jenis": jenis, "src_ip": src_ip, "mulai_us": int(mulai_us), "akhir_us": int(akhir_us),
             "diperiksa_us": kini_us, "batas_contamination": batas, "aliran": len(rows),
             "ditandai": sum(1 for r in rows if ditandai(r)), "kandidat": [],
             "versi_acuan": sorted({(model.get(acuan.get(r[0])) or {}).get("versi") or "?" for r in rows}),
             "bisa_adaptasi": bool(rows)}
    port = {}
    for r in rows:
        port[r[4]] = port.get(r[4], 0) + 1
    hasil["port_teratas"] = sorted(port.items(), key=lambda x: -x[1])[:5]
    if not rows:
        hasil["status"] = "tidak_ada_aliran"
        hasil["bisa_adaptasi"] = False
        return hasil

    dekat_hampir = 0
    for r in rows:
        ba, bc = ambang_batas(r[0])
        if (ba is not None and r[1] > ba) or (bc is not None and r[2] > bc):
            dekat_hampir += 1
    hasil["aliran_dekat"] = dekat_hampir

    if jenis == "palsu":
        if hasil["ditandai"]:
            hasil["status"] = "pelatihan_ulang"
        elif dekat_hampir:
            hasil["status"] = "dapat_diadaptasi_normal"
        else:
            hasil["status"] = "tidak_ada_alarm"
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


def _termasuk_selesai(ip, t0, t1, kasus_selesai):
    for k in kasus_selesai or ():
        if k.get("src_ip") == ip and int(k.get("akhir_us", 0)) >= t0 and int(k.get("mulai_us", 0)) <= t1:
            return True
    return False


def hampir_anomali(db, awal_us, abaikan=None, aturan_adaptasi=None, kasus_selesai=None):
    """IP sumber yang TIDAK ditandai sama sekali sejak awal_us, tetapi punya aliran dengan skor di atas
    ambang batas aman umpan balik (BATAS_CONTAMINATION).

    Aliran yang sudah diverifikasi sebagai `selesai` pada umpan balik maupun yang sudah cocok dengan
    aturan adaptasi aktif (`anomali` atau `normal`) tidak lagi ditampilkan sebagai 'hampir anomali'.
    """
    am = ambang_model(db)
    per = {}
    if aturan_adaptasi:
        from . import adaptasi as ad
        try:
            ada_fitur = bool(db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='aliran_fitur'").fetchone())
        except Exception:
            ada_fitur = False
    else:
        ad = None
        ada_fitur = False

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

    # Kecualikan IP/rentang yang sudah diselesaikan atau sudah cocok aturan adaptasi aktif
    daftar = []
    for p in per.values():
        if p["tanda"] or not p["dekat"] or not p["skor"]:
            continue
        if abaikan and abaikan(p["src_ip"]):
            continue
        if _termasuk_selesai(p["src_ip"], p["awal"], p["akhir"], kasus_selesai):
            continue
        if ad and aturan_adaptasi:
            # Cek apakah seluruh aliran 'dekat' milik IP ini sudah tercakup oleh aturan adaptasi aktif
            q = ("SELECT a.id, a.dst_port, a.protokol, a.paket, a.model_id, a.skor_a, a.skor_c "
                 "FROM aliran a WHERE a.src_ip = ? AND a.waktu_selesai_us >= ? AND (a.skor_a > ? OR a.skor_c > ?)")
            # Ambil batas terendah across models untuk pre-filter aman
            min_ba = min(mm["A"]["batas"] for mm in am.values() if mm["A"]["batas"] is not None)
            min_bc = min(mm["C"]["batas"] for mm in am.values() if mm["C"]["batas"] is not None)
            cand_rows = db.execute(q, (p["src_ip"], awal_us, min_ba, min_bc)).fetchall()
            masih_ambigu = False
            for r in cand_rows:
                mm = am.get(r[4])
                if not mm or not (r[5] > mm["A"]["batas"] or r[6] > mm["C"]["batas"]):
                    continue
                vec_a = vec_c = None
                if ada_fitur:
                    fr = db.execute("SELECT vektor_a, vektor_c FROM aliran_fitur WHERE aliran_id = ?", (r[0],)).fetchone()
                    if fr and fr[0] and fr[1]:
                        try:
                            vec_a, vec_c = json.loads(fr[0]), json.loads(fr[1])
                        except ValueError:
                            pass
                if ad.cocokkan(aturan_adaptasi, vec_a=vec_a, vec_c=vec_c, dst_port=r[1], protokol=r[2], paket=r[3]) is None:
                    masih_ambigu = True
                    break
            if cand_rows and not masih_ambigu:
                continue
        daftar.append(p)

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
    "dapat_diadaptasi_normal": "Hampir anomali — siap diadaptasi sebagai lalu lintas normal",
    "pelatihan_ulang": "Masuk antrean pelatihan ulang",
    "selesai": "Selesai",
}
