# -*- coding: utf-8 -*-
"""Geometri grafik SVG untuk halaman Ringkasan (garis + area, donat, bilah tersegmen).

Semua grafik digambar di server sebagai SVG biasa (tanpa pustaka JavaScript dan tanpa atribut style,
karena CSP dashboard melarang gaya inline). Warna diberikan lewat kelas CSS (`s1`..`s4`, `lain`).
"""
import math

from .harian import _bulat


def _fmt(n):
    return "{:,}".format(int(n)).replace(",", ".")


def _tick(maks):
    """Garis bantu sumbu Y: 0, ¼, ½, ¾, 1 bila nilainya bulat; selain itu 0, ½, 1."""
    if maks % 4 == 0:
        return [maks * i // 4 for i in range(5)]
    if maks % 2 == 0:
        return [0, maks // 2, maks]
    return [0, maks]


def garis(titik, tinggi=200, lebar=1000):
    """titik = [(label_sumbu, nilai, teks_tooltip)] -> geometri grafik garis + area.

    Satu seri per grafik (dua ukuran berbeda skala digambar sebagai dua grafik, bukan dua sumbu)."""
    kiri, kanan, atas, bawah = 46, 14, 12, 28
    w, h = lebar - kiri - kanan, tinggi - atas - bawah
    n = len(titik)
    maks = _bulat(max([v for _, v, _ in titik] + [0]))
    langkah = w / (n - 1) if n > 1 else 0
    pts = []
    for i, (lab, v, tip) in enumerate(titik):
        x = kiri + i * langkah if n > 1 else kiri + w / 2
        y = atas + h - (h * v / maks if maks else 0)
        pts.append({"x": round(x, 1), "y": round(y, 1), "v": v, "lab": lab, "tip": tip})
    d = " ".join(("M" if i == 0 else "L") + "%.1f,%.1f" % (p["x"], p["y"]) for i, p in enumerate(pts))
    dasar = atas + h
    area = (d + " L%.1f,%.1f L%.1f,%.1f Z" % (pts[-1]["x"], dasar, pts[0]["x"], dasar)) if pts else ""
    slot = langkah if n > 1 else w
    sasaran = [{"x": round(p["x"] - slot / 2, 1), "w": round(slot, 1), **p} for p in pts]
    garis_y = [{"y": round(atas + h - h * t / maks, 1), "teks": _fmt(t)} for t in _tick(maks)]
    label = [{"x": p["x"], "teks": p["lab"]} for p in pts if p["lab"]]
    akhir = pts[-1] if pts else None
    return {"lebar": lebar, "tinggi": tinggi, "kiri": kiri, "kanan": lebar - kanan, "atas": atas, "dasar": dasar,
            "d": d, "area": area, "sasaran": sasaran, "garis": garis_y, "label": label, "akhir": akhir,
            "y_label": tinggi - 8, "maks": maks}


def donat(bagian, r=70, tebal=22, celah=2.5):
    """bagian = [(nama, nilai, kelas)] -> busur lingkaran (stroke-dasharray) dengan celah antarbagian."""
    total = sum(v for _, v, _ in bagian)
    keliling = 2 * math.pi * r
    hasil, mulai = [], 0.0
    isi = [b for b in bagian if b[1] > 0]
    for nama, v, kelas in isi:
        panjang = keliling * v / total
        tampil = max(panjang - (celah if len(isi) > 1 else 0), 0.8)
        hasil.append({"nama": nama, "nilai": v, "kelas": kelas, "dash": "%.2f %.2f" % (tampil, keliling - tampil),
                      "offset": "%.2f" % -mulai, "persen": v / total})
        mulai += panjang
    return {"r": r, "tebal": tebal, "busur": hasil, "total": total, "pusat": r + tebal / 2 + 4}


def segmen(bagian, lebar=600, celah=3):
    """Bilah tersegmen (satu keseluruhan dibagi beberapa bagian), celah selebar `celah` antarbagian."""
    total = sum(v for _, v, _ in bagian)
    isi = [b for b in bagian if b[1] > 0]
    ruang = lebar - celah * max(len(isi) - 1, 0)
    hasil, x = [], 0.0
    for nama, v, kelas in isi:
        w = max(ruang * v / total, 2)
        hasil.append({"nama": nama, "x": round(x, 1), "w": round(w, 1), "kelas": kelas, "nilai": v})
        x += w + celah
    return {"lebar": lebar, "bagian": hasil}
