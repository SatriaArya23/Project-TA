# -*- coding: utf-8 -*-
"""
Terapkan penyesuaian ambang hasil "periksa ulang" (loop umpan balik, langkah 1) sebagai versi model baru.
Hutan Isolation Forest tidak berubah; hanya ambang Model A dan/atau C yang diganti.

  python ubah_ambang.py --model model.joblib --keluar model_baru.joblib --contamination-c 0.023 --alasan "umpan balik #3"
  python ubah_ambang.py --model model.joblib --keluar model_baru.joblib --ambang-c 0.6123

Di server (lalu muat ulang layanan):
  sudo -u nids /opt/nids-deteksi/venv/bin/python /opt/nids-deteksi/ubah_ambang.py \\
       --model /etc/nids-deteksi/model.joblib --keluar /tmp/model_baru.joblib --contamination-c 0.023
  sudo install -m 640 -o root -g nids /tmp/model_baru.joblib /etc/nids-deteksi/model.joblib
  sudo systemctl restart nids-deteksi
"""
import argparse
import os
import sys

import joblib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nids.model import ubah_ambang   # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", required=True)
    ap.add_argument("--keluar", required=True)
    for m in ("a", "c"):
        ap.add_argument("--contamination-" + m, type=float)
        ap.add_argument("--ambang-" + m, type=float)
    ap.add_argument("--alasan", default="")
    a = ap.parse_args()
    if not any([a.contamination_a, a.contamination_c, a.ambang_a, a.ambang_c]):
        ap.error("isi minimal satu dari --contamination-a/c atau --ambang-a/c")

    lama = joblib.load(a.model)
    baru = ubah_ambang(lama, contamination={"A": a.contamination_a, "C": a.contamination_c},
                       ambang={"A": a.ambang_a, "C": a.ambang_c}, alasan=a.alasan)
    joblib.dump(baru, a.keluar)
    print("Versi %s -> %s" % (lama.get("versi"), baru["versi"]))
    for nama in ("A", "C"):
        print("  Model %s: ambang %.6f -> %.6f (contamination %s)" % (
            nama, lama[nama]["threshold"], baru[nama]["threshold"], baru[nama]["contamination"]))
    print("Disimpan: %s" % a.keluar)


if __name__ == "__main__":
    main()
