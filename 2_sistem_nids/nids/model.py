# -*- coding: utf-8 -*-
"""
Model deteksi A+C (dua Isolation Forest):
  A = 68 fitur aliran           -> anomali pada satu koneksi (mis. banjir paket)
  C = 7 fitur agregasi          -> anomali perilaku sumber (pemindaian, brute force)
Aliran dianggap anomali bila A ATAU C menandainya.

Skor = -score_samples() Isolation Forest (semakin besar = semakin anomali), dibandingkan
dengan ambang dari kuantil skor data latih pada (1 - contamination).

Transformasi "log" (bawaan sejak penalaan 11 Nov 2026, notebook 07): setiap fitur diubah menjadi
sign(x) * log(1 + |x|) sebelum distandarkan. Fitur jaringan sangat menceng (mis. jumlah byte sesi unduhan besar),
sehingga tanpa transformasi nilai ekstrem yang sah mudah "terisolasi" dan menjadi alarm palsu.
Model lama tanpa kunci "transformasi" tetap dinilai tanpa transformasi.
"""
import json
import warnings
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .agregasi import FITUR_AGREGASI
from .aliran import FITUR
from .umpan_balik import ambang_dari_kontaminasi, kontaminasi_dari_skor

PARAM = dict(n_estimators=100, max_samples=256, random_state=42)
CONTAMINATION_A, CONTAMINATION_C = 0.001, 0.0075          # hasil penalaan pada data VPS perusahaan (notebook 07)


def log_bertanda(X):
    X = np.asarray(X, dtype=float)
    return np.sign(X) * np.log1p(np.abs(X))
# Titik peluang untuk menyimpan sebaran skor data latih: rapat di ekor kanan (tempat ambang berada),
# supaya ambang untuk contamination berapa pun (mis. 0,001-0,05) dapat dihitung ulang tanpa melatih ulang.
P_KUANTIL = sorted(set([round(i / 100, 5) for i in range(0, 90)] + [round(0.9 + i / 1000, 5) for i in range(0, 90)]
                       + [round(0.99 + i / 100000, 5) for i in range(0, 1001)]))


def versi_baru():
    """Nama versi model dari waktu UTC, mis. m20261102-123346-512 (sampai milidetik agar unik)."""
    return datetime.now(timezone.utc).strftime("m%Y%m%d-%H%M%S-%f")[:-3]


def kuantil_skor(s):
    return [[p, float(q)] for p, q in zip(P_KUANTIL, np.quantile(s, P_KUANTIL))]


class SatuModel:
    def __init__(self, d):
        self.model, self.scaler, self.fitur = d["model"], d["scaler"], list(d["fitur"])
        self.ambang, self.contamination = float(d["threshold"]), d.get("contamination")
        self.transformasi = d.get("transformasi")

    def ubah(self, df):
        X = df[self.fitur].to_numpy(dtype=float)
        return log_bertanda(X) if self.transformasi == "log" else X

    def skor(self, df):
        return -self.model.score_samples(self.scaler.transform(self.ubah(df)))


class ModelDeteksi:
    def __init__(self, paket):
        self.A, self.C = SatuModel(paket["A"]), SatuModel(paket["C"])
        self.jendela_detik = int(paket.get("jendela_detik", 300))
        self.info = {k: v for k, v in paket.items() if k not in ("A", "C")}
        self.paket = paket
        self.versi = paket.get("versi") or "tanpa-versi"

    def ringkas(self):
        """Info model yang aman di-JSON-kan (untuk tabel `model` di log dan halaman dashboard)."""
        d = {"versi": self.versi, "jendela_detik": self.jendela_detik}
        for k, v in self.info.items():
            if k == "sumber_intens":
                d["jumlah_sumber_intens"] = len(v)
            elif k != "versi":
                d[k] = v
        for nama in ("A", "C"):
            m = self.paket[nama]
            d[nama] = {"contamination": m.get("contamination"), "ambang": float(m["threshold"]),
                       "jumlah_fitur": len(m["fitur"]), "transformasi": m.get("transformasi"),
                       "kuantil": m.get("kuantil")}
        return json.loads(json.dumps(d, default=str))

    @classmethod
    def muat(cls, path):
        paket = joblib.load(path)
        versi = paket.get("versi_sklearn")
        if versi and versi != sklearn.__version__:
            warnings.warn("Model dilatih dengan scikit-learn %s, sekarang %s. Latih ulang model di mesin ini "
                          "(latih_model.py) agar hasilnya terjamin sama." % (versi, sklearn.__version__))
        return cls(paket)

    def nilai(self, aliran):
        """aliran = list of dict berfitur lengkap -> list of (skor_A, skor_C, oleh) ; oleh = '' bila normal."""
        if not aliran:
            return []
        df = pd.DataFrame(aliran, columns=FITUR + FITUR_AGREGASI)
        sa, sc = self.A.skor(df), self.C.skor(df)
        hasil = []
        for a, c in zip(sa, sc):
            oleh = ("A" if a > self.A.ambang else "") + ("C" if c > self.C.ambang else "")
            hasil.append((float(a), float(c), "A+C" if oleh == "AC" else oleh))
        return hasil


def latih(df_latih, contamination_A=CONTAMINATION_A, contamination_C=CONTAMINATION_C, jendela_detik=300, info=None,
          transformasi="log"):
    """Latih paket model A+C dari tabel fitur (hasil putar ulang). Kembalikan dict siap joblib.dump.
    transformasi = "log" (bawaan) atau None (rancangan awal, hanya standarisasi)."""
    versi = versi_baru()
    paket = {"versi": versi, "hutan": versi, "dilatih_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
             "jendela_detik": jendela_detik, "versi_sklearn": sklearn.__version__, **(info or {})}
    for nama, fitur, c in (("A", FITUR, contamination_A), ("C", FITUR_AGREGASI, contamination_C)):
        X = df_latih[fitur].to_numpy(dtype=float)
        X = log_bertanda(X) if transformasi == "log" else X
        sc = StandardScaler().fit(X)
        m = IsolationForest(**PARAM).fit(sc.transform(X))
        s = -m.score_samples(sc.transform(X))
        paket[nama] = {"model": m, "scaler": sc, "fitur": list(fitur), "contamination": c, "transformasi": transformasi,
                       "threshold": float(np.quantile(s, 1 - c)), "kuantil": kuantil_skor(s)}
    return paket


def ubah_ambang(paket, contamination=None, ambang=None, alasan=""):
    """Versi model baru dengan ambang disesuaikan; hutan Isolation Forest tetap sama (tanpa latih ulang).
    contamination / ambang = {"A": nilai, "C": nilai} (boleh sebagian)."""
    baru = dict(paket)
    riwayat = list(paket.get("riwayat_ambang", []))
    for nama in ("A", "C"):
        m = dict(paket[nama])
        if ambang and ambang.get(nama) is not None:
            m["threshold"] = float(ambang[nama])
            m["contamination"] = (kontaminasi_dari_skor(m["kuantil"], m["threshold"]) if m.get("kuantil") else None)
        elif contamination and contamination.get(nama) is not None:
            if not m.get("kuantil"):
                raise ValueError("Model %s tidak menyimpan sebaran skor latih; latih ulang model." % nama)
            m["contamination"] = float(contamination[nama])
            m["threshold"] = float(ambang_dari_kontaminasi(m["kuantil"], m["contamination"]))
        if m["threshold"] != paket[nama]["threshold"]:
            riwayat.append({"model": nama, "dari": float(paket[nama]["threshold"]), "ke": m["threshold"]})
        baru[nama] = m
    baru.update(versi=versi_baru(), hutan=paket.get("hutan") or paket.get("versi"), induk=paket.get("versi"), alasan=alasan, riwayat_ambang=riwayat,
                diubah_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    return baru
