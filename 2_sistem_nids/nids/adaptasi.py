# -*- coding: utf-8 -*-
"""
Lapisan Adaptasi Berbasis Kemiripan Ruang Fitur Dual-IF (Online Adaptation Layer).

Saat administrator memeriksa lalu lintas `Hampir anomali` / `Umpan balik` dan menetapkannya
sebagai **Anomali** atau **Bukan Anomali (Normal)**, sistem mengekstrak prototipe vektor fitur
ternormalisasi (`StandardScaler(log1p(X))`) kejadian tersebut dari tabel `aliran_fitur`.

Pada penilaian lalu lintas berikutnya (`ModelDeteksi.nilai_detail`) — baik dari IP yang sama maupun
IP baru dengan perilaku yang sama atau mirip — jarak RMS ternormalisasi dihitung terhadap
prototipe aktif:
  * Jika cocok dengan prototipe `anomali`: skor efektif ditingkatkan melewati ambang agar langsung
    ditandai anomali (tidak lagi jatuh ke `hampir anomali`).
  * Jika cocok dengan prototipe `normal`: skor efektif dikalibrasi di bawah batas `hampir anomali`
    agar tidak memicu alarm palsu maupun muncul kembali di `hampir anomali`.

Hanya memakai pustaka standar Python (math, json, datetime), sehingga aman dijalankan baik oleh
`nids-deteksi` maupun oleh dashboard Flask tanpa numpy/scikit-learn.
"""
import json
import math
import time
import uuid
from datetime import datetime, timezone

from .umpan_balik import BATAS_CONTAMINATION


def sekarang_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def id_adaptasi():
    return "ad-%d-%s" % (int(time.time() * 1000), uuid.uuid4().hex[:6])


def _rms_jarak(a, b):
    if not a or not b or len(a) != len(b):
        return float("inf")
    s = 0.0
    n = len(a)
    for x, y in zip(a, b):
        d = x - y
        s += d * d
    return math.sqrt(s / n)


def _rata_vektor(vektor_list):
    n = len(vektor_list)
    dim = len(vektor_list[0])
    pusat = [sum(v[k] for v in vektor_list) / n for k in range(dim)]
    sebar = 0.0
    for v in vektor_list:
        sebar += _rms_jarak(v, pusat) ** 2
    rms_sebar = math.sqrt(sebar / n)
    return [round(x, 4) for x in pusat], rms_sebar


def ekstrak_prototipe(db, src_ip, mulai_us, akhir_us, label, model_info=None,
                      oleh="", catatan="", ub_id=None):
    """Bangun aturan adaptasi dari aliran [mulai_us..akhir_us] milik `src_ip`.

    `label` = 'anomali' atau 'normal'. Kembalikan dict siap disimpan di katalog_model.
    """
    if label not in ("anomali", "normal"):
        raise ValueError("Label adaptasi harus 'anomali' atau 'normal'.")
    rows = db.execute(
        "SELECT a.id, a.dst_port, a.protokol, a.paket, a.skor_a, a.skor_c, a.model_id, "
        "f.vektor_a, f.vektor_c "
        "FROM aliran a LEFT JOIN aliran_fitur f ON f.aliran_id = a.id "
        "WHERE a.src_ip = ? AND a.waktu_selesai_us BETWEEN ? AND ? "
        "ORDER BY a.waktu_selesai_us DESC LIMIT 500",
        (src_ip, int(mulai_us), int(akhir_us)),
    ).fetchall()
    if not rows:
        raise ValueError("Tidak ada rekaman aliran untuk IP %s pada rentang waktu tersebut." % src_ip)

    ports = sorted({int(r[1]) for r in rows if r[1] is not None})
    prots = sorted({int(r[2]) for r in rows if r[2] is not None})
    pakets = [int(r[3]) for r in rows if r[3] is not None]
    ma = max(float(r[4] or 0.0) for r in rows)
    mc = max(float(r[5] or 0.0) for r in rows)

    va_list, vc_list = [], []
    for r in rows:
        if r[7] and r[8]:
            try:
                va = json.loads(r[7])
                vc = json.loads(r[8])
                if isinstance(va, list) and isinstance(vc, list) and va and vc:
                    va_list.append([float(x) for x in va])
                    vc_list.append([float(x) for x in vc])
            except (ValueError, TypeError):
                continue

    # Tentukan fokus (IF-Flow vs IF-Agg) berdasarkan kedekatan/pelampauan ambang model
    fokus = "C"
    ta = tc = None
    hutan = (model_info or {}).get("hutan") or (model_info or {}).get("versi")
    if isinstance(model_info, dict):
        ta = (model_info.get("A") or {}).get("ambang")
        tc = (model_info.get("C") or {}).get("ambang")
    if ta is not None and tc is not None:
        da = ma - float(ta)
        dc = mc - float(tc)
        if da > 0 and dc > 0:
            fokus = "A+C"
        elif da > dc:
            fokus = "A"
        else:
            fokus = "C"

    aturan = {
        "id": id_adaptasi(),
        "ub_id": ub_id,
        "label": label,
        "hutan": hutan,
        "src_ip": src_ip,
        "fokus": fokus,
        "dst_ports": ports[:40],
        "multi_port": len(ports) >= 3,
        "protokol": prots,
        "paket_min": min(pakets) if pakets else 0,
        "paket_maks": max(pakets) if pakets else 0,
        "skor_asal_a": round(ma, 6),
        "skor_asal_c": round(mc, 6),
        "jumlah_sampel": len(rows),
        "mode_cocok": "vektor" if va_list and vc_list else "meta",
        "dibuat_utc": sekarang_utc(),
        "oleh": oleh,
        "keterangan": (catatan or "").strip()[:160],
    }

    if va_list and vc_list:
        ca, s_a = _rata_vektor(va_list)
        cc, s_c = _rata_vektor(vc_list)
        aturan["centroid_a"] = ca
        aturan["centroid_c"] = cc
        # Radius toleransi kemiripan dalam ruang standar log1p:
        # cukup longgar menangkap pola serupa dari IP lain, cukup ketat menjaga false positive
        aturan["radius_a"] = round(max(0.45, min(1.10, 0.45 + 1.5 * s_a)), 4)
        aturan["radius_c"] = round(max(0.45, min(1.15, 0.45 + 1.5 * s_c)), 4)

    return aturan


def _cocok_satu(aturan, vec_a, vec_c, dst_port=None, protokol=None, paket=None):
    """Kembalikan skor jarak >= 0 bila aliran cocok dengan aturan, atau None bila tidak cocok."""
    prots = aturan.get("protokol") or []
    if prots and protokol is not None and int(protokol) not in prots:
        return None

    ports = aturan.get("dst_ports") or []
    label = aturan.get("label")
    # Untuk aturan `normal` (whitelist perilaku), pastikan layanan target tidak meluas ke SSH (port 22)
    # kecuali port 22 memang termasuk dalam pola yang diverifikasi aman.
    if label == "normal" and dst_port is not None and ports:
        if int(dst_port) == 22 and 22 not in ports:
            return None
        if not aturan.get("multi_port") and int(dst_port) not in ports:
            return None

    if aturan.get("mode_cocok") == "vektor" and vec_a is not None and vec_c is not None:
        ca = aturan.get("centroid_a")
        cc = aturan.get("centroid_c")
        ra = float(aturan.get("radius_a", 0.55))
        rc = float(aturan.get("radius_c", 0.55))
        da = _rms_jarak(vec_a, ca) if ca else float("inf")
        dc = _rms_jarak(vec_c, cc) if cc else float("inf")
        fokus = aturan.get("fokus", "C")
        if label == "normal":
            # Aturan normal mensyaratkan subruang utama masuk radius dan subruang lain tidak ekstrem jauh
            if fokus == "A" and da <= ra and dc <= max(1.2, rc * 2.2):
                return da
            if fokus == "C" and dc <= rc and da <= max(1.2, ra * 2.2):
                return dc
            if fokus == "A+C" and da <= ra and dc <= rc:
                return 0.5 * (da + dc)
            return None
        # label == "anomali": tangkap pola yang mirip pada subruang fokus
        if fokus == "A" and da <= ra:
            return da
        if fokus == "C" and dc <= rc:
            # Untuk brute-force satu port spesifik (mis. port 22), cocokkan pula port tujuannya
            if not aturan.get("multi_port") and ports and dst_port is not None and int(dst_port) not in ports:
                return None
            return dc
        if fokus == "A+C" and (da <= ra or dc <= rc):
            return min(da, dc)
        return None

    # Fallback mode metadata (hanya bila aliran_fitur historis tidak tersedia)
    if ports and dst_port is not None and int(dst_port) not in ports:
        return None
    if paket is not None:
        pmin, pmax = int(aturan.get("paket_min") or 0), int(aturan.get("paket_maks") or 0)
        if pmax > 0 and not (max(1, pmin // 2) <= int(paket) <= max(pmax * 2, pmax + 4)):
            return None
    return 0.5


def cocokkan(aturan_list, vec_a=None, vec_c=None, dst_port=None, protokol=None, paket=None):
    """Cari aturan adaptasi yang paling cocok (jarak terkecil; tie-break aturan terbaru)."""
    if not aturan_list:
        return None
    terbaik = None
    for idx, at in enumerate(aturan_list):
        d = _cocok_satu(at, vec_a, vec_c, dst_port=dst_port, protokol=protokol, paket=paket)
        if d is None:
            continue
        kunci = (round(d, 6), -idx)
        if terbaik is None or kunci < terbaik[0]:
            terbaik = (kunci, at)
    return terbaik[1] if terbaik else None


def evaluasi_aliran(sa, sc, pak_a, pak_c, amb_a, amb_c, batas_a, batas_c,
                    aturan_list, vec_a=None, vec_c=None, dst_port=None, protokol=None, paket=None):
    """Terapkan aturan adaptasi ke skor dasar Isolation Forest satu aliran.

    Kembalikan (eff_a, eff_c, oleh, aturan_cocok):
      * Bila cocok dengan aturan 'anomali': skor diangkat sedikit di atas ambang pada fokusnya.
      * Bila cocok dengan aturan 'normal' : skor diturunkan di bawah batas hampir-anomali (`oleh=''`).
      * Bila tidak cocok                   : skor dan `oleh` mengikuti model Isolation Forest apa adanya.
    """
    cocok = cocokkan(aturan_list, vec_a=vec_a, vec_c=vec_c,
                     dst_port=dst_port, protokol=protokol, paket=paket)
    eff_a, eff_c = float(sa), float(sc)
    if cocok is not None:
        if cocok.get("label") == "anomali":
            fokus = cocok.get("fokus", "C")
            if fokus in ("A", "A+C") and eff_a <= amb_a:
                eff_a = float(amb_a) + 0.01
            if fokus in ("C", "A+C") and eff_c <= amb_c:
                eff_c = float(amb_c) + 0.01
        elif cocok.get("label") == "normal":
            target_a = min(amb_a, batas_a) * 0.85
            target_c = min(amb_c, batas_c) * 0.85
            if eff_a > target_a:
                eff_a = float(target_a)
            if eff_c > target_c:
                eff_c = float(target_c)
            return eff_a, eff_c, "", cocok

    oleh = ("A" if pak_a and eff_a > amb_a else "") + ("C" if pak_c and eff_c > amb_c else "")
    return eff_a, eff_c, ("A+C" if oleh == "AC" else oleh), cocok


def batas_default():
    return dict(BATAS_CONTAMINATION)
