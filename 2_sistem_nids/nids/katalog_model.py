# -*- coding: utf-8 -*-
"""
Katalog & pengendali model deteksi bersama (Model Registry + Hot-Reload).

* Disimpan di folder bersama (/var/lib/nids-bersama/model/):
    katalog.json         daftar versi model, label profil, ambang/contamination, dan mode aktif
    <berkas>.joblib      berkas hutan Isolation Forest + scaler (dibagi bersama versi turunan ambang)
* Dashboard web (user `tanids`, hanya Flask tanpa scikit-learn/joblib) dapat:
    - mengubah mode deteksi aktif: Dual-IF ('A+C'), IF-Flow saja ('A'), atau IF-Agg saja ('C');
    - membuat versi turunan dengan ambang/contamination baru (dihitung dari `kuantil` dalam katalog.json);
    - mengaktifkan / rollback ke versi model mana pun di katalog;
    - memberi label profil (mis. "Baseline Normal", "Profil Hari Ramai") dan menghapus versi non-aktif.
* Modul deteksi (`nids-deteksi`, user `nids`) memantau `mtime` katalog.json setiap beberapa detik dan
  menerapkan perubahan secara *hot-reload* tanpa perlu restart dan tanpa kehilangan paket.

Hanya memakai pustaka standar + `nids.umpan_balik` (tanpa numpy/joblib/scikit-learn),
sehingga aman diimpor oleh dashboard Flask maupun modul deteksi.
"""
import contextlib
import json
import os
import re
import shutil
import tempfile
import time
from datetime import datetime, timezone

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows (unit test lokal)
    fcntl = None

from .umpan_balik import BATAS_CONTAMINATION, ambang_dari_kontaminasi, kontaminasi_dari_skor

DIR_BAWAAN = "/var/lib/nids-bersama/model"
KATALOG_NAMA = "katalog.json"
ANTREAN_IMPOR_NAMA = "impor_antrean.json"
STATUS_IMPOR_NAMA = "impor_status.json"
MASUK_DIR_NAMA = "masuk"
MAKS_UKURAN_MODEL = 50 * 1024 * 1024     # 50 MB

MODE_OPSI = [
    ("A+C", "Dual-IF (IF-Flow + IF-Agg)", "68 fitur aliran + 7 fitur agregasi"),
    ("A", "IF-Flow saja", "68 fitur per aliran"),
    ("C", "IF-Agg saja", "7 fitur agregasi (300 dtk)"),
]
MODE_VALID = tuple(k for k, _, _ in MODE_OPSI)
MODE_LABEL = {"A+C": "Dual-IF", "A": "IF-Flow saja", "C": "IF-Agg saja"}

BATAS_CONTAMINATION_MIN = {"A": 0.0001, "C": 0.0005}
BATAS_CONTAMINATION_MAKS = dict(BATAS_CONTAMINATION)     # A <= 0.01 (1%), C <= 0.05 (5%)
_NAMA_AMAN = re.compile(r"^[A-Za-z0-9._-]+$")


def sekarang_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def versi_baru():
    return datetime.now(timezone.utc).strftime("m%Y%m%d-%H%M%S-%f")[:-3]


def path_katalog(folder=DIR_BAWAAN):
    return os.path.join(folder, KATALOG_NAMA)


def path_antrean_impor(folder=DIR_BAWAAN):
    return os.path.join(folder, ANTREAN_IMPOR_NAMA)


def path_status_impor(folder=DIR_BAWAAN):
    return os.path.join(folder, STATUS_IMPOR_NAMA)


def dir_masuk(folder=DIR_BAWAAN):
    return os.path.join(folder, MASUK_DIR_NAMA)


def _simpan_json(folder, path_tujuan, data, prefix=".tmp-"):
    os.makedirs(folder, exist_ok=True)
    fd, sementara = tempfile.mkstemp(prefix=prefix, dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1, ensure_ascii=False)
        try:
            os.chmod(sementara, 0o660)
        except OSError:
            pass
        os.replace(sementara, path_tujuan)
    except BaseException:
        if os.path.exists(sementara):
            os.unlink(sementara)
        raise


def baca_status_impor(folder=DIR_BAWAAN):
    try:
        with open(path_status_impor(folder), encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else None
    except (FileNotFoundError, ValueError, OSError):
        return None


def tulis_status_impor(folder, status):
    with _kunci(folder):
        _simpan_json(folder, path_status_impor(folder), status, prefix=".impstat-")


def baca_antrean_impor(folder=DIR_BAWAAN):
    try:
        with open(path_antrean_impor(folder), encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else None
    except (FileNotFoundError, ValueError, OSError):
        return None


def hapus_antrean_impor(folder=DIR_BAWAAN):
    p = path_antrean_impor(folder)
    try:
        os.unlink(p)
    except FileNotFoundError:
        pass


def antre_impor(folder, nama_berkas_masuk, sha256, nama="", alasan="", oleh="",
                sha_diharapkan="", aktifkan=False):
    """Daftarkan tugas validasi & impor berkas .joblib yang baru diunggah oleh admin."""
    nama_berkas_masuk = nama_berkas_aman(nama_berkas_masuk)
    sha_harap = (sha_diharapkan or "").strip().lower()
    if sha_harap and not re.match(r"^[0-9a-f]{64}$", sha_harap):
        raise ValueError("Format SHA-256 tidak valid (harus 64 karakter heksadesimal).")
    tugas = {
        "id": versi_baru(),
        "berkas_masuk": nama_berkas_masuk,
        "sha256": (sha256 or "").strip().lower(),
        "sha_diharapkan": sha_harap,
        "nama": (nama or "").strip()[:80],
        "alasan": (alasan or "").strip()[:200] or "diunggah lewat dashboard",
        "oleh": oleh,
        "aktifkan": bool(aktifkan),
        "diminta_utc": sekarang_utc(),
    }
    status = {
        "id": tugas["id"],
        "status": "menunggu",
        "nama": tugas["nama"] or nama_berkas_masuk,
        "sha256": tugas["sha256"],
        "oleh": oleh,
        "waktu_utc": tugas["diminta_utc"],
        "pesan": "Menunggu validasi otomatis oleh layanan nids-model...",
    }
    with _kunci(folder):
        _simpan_json(folder, path_status_impor(folder), status, prefix=".impstat-")
        _simpan_json(folder, path_antrean_impor(folder), tugas, prefix=".impant-")
    return tugas


def _katalog_kosong():
    return {"aktif": None, "mode": "A+C", "revisi": 0, "diperbarui_utc": None, "diperbarui_oleh": "", "model": []}


@contextlib.contextmanager
def _kunci(folder):
    if fcntl is None:
        yield
        return
    os.makedirs(folder, exist_ok=True)
    lock_path = os.path.join(folder, ".katalog.lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o660)
    try:
        try:
            os.fchmod(fd, 0o660)
        except OSError:
            pass
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _baca_tanpa_kunci(folder):
    p = path_katalog(folder)
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return _katalog_kosong()
    if not isinstance(data, dict):
        return _katalog_kosong()
    hasil = _katalog_kosong()
    hasil.update(data)
    if hasil.get("mode") not in MODE_VALID:
        hasil["mode"] = "A+C"
    hasil["model"] = [m for m in (hasil.get("model") or []) if isinstance(m, dict) and m.get("versi")]
    hasil["revisi"] = int(hasil.get("revisi") or 0)
    return hasil


def _simpan_tanpa_kunci(folder, data):
    os.makedirs(folder, exist_ok=True)
    p = path_katalog(folder)
    fd, sementara = tempfile.mkstemp(prefix=".katalog-", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1, ensure_ascii=False)
        try:
            os.chmod(sementara, 0o660)
        except OSError:
            pass
        os.replace(sementara, p)
    except BaseException:
        if os.path.exists(sementara):
            os.unlink(sementara)
        raise


def baca(folder=DIR_BAWAAN):
    with _kunci(folder):
        return _baca_tanpa_kunci(folder)


def cari(data, versi):
    for m in data.get("model", []):
        if m.get("versi") == versi:
            return m
    return None


def nama_berkas_aman(nama):
    if not nama or "/" in nama or "\\" in nama or ".." in nama or not _NAMA_AMAN.match(nama):
        raise ValueError("Nama berkas model tidak valid.")
    return nama


def path_berkas_model(folder, entri):
    berkas = nama_berkas_aman(entri.get("berkas", ""))
    return os.path.join(folder, berkas)


def _salin_joblib(sumber, tujuan):
    folder = os.path.dirname(os.path.abspath(tujuan))
    os.makedirs(folder, exist_ok=True)
    fd, sementara = tempfile.mkstemp(prefix=".model-", dir=folder)
    os.close(fd)
    try:
        shutil.copy2(sumber, sementara)
        try:
            os.chmod(sementara, 0o640)
        except OSError:
            pass
        os.replace(sementara, tujuan)
    except BaseException:
        if os.path.exists(sementara):
            os.unlink(sementara)
        raise


def _entri_dari_ringkas(ringkas, berkas, nama=None, oleh="sistem"):
    entri = json.loads(json.dumps(ringkas, default=str))
    versi = entri.get("versi") or versi_baru()
    entri["versi"] = versi
    entri["berkas"] = berkas
    entri["nama"] = (nama or entri.get("nama") or "").strip()[:80]
    entri["dibuat_utc"] = entri.get("dilatih_utc") or sekarang_utc()
    entri["oleh"] = entri.get("oleh") or oleh
    entri.setdefault("hutan", versi)
    return entri


def daftar_dari_file(folder, path_joblib, ringkas_info, nama=None, oleh="sistem", aktifkan=False):
    """Daftarkan berkas .joblib ke katalog bersama (menyalin ke folder bersama bila belum ada)."""
    versi = ringkas_info.get("versi") or versi_baru()
    berkas = nama_berkas_aman("%s.joblib" % versi)
    tujuan = os.path.join(folder, berkas)
    with _kunci(folder):
        data = _baca_tanpa_kunci(folder)
        if os.path.abspath(path_joblib) != os.path.abspath(tujuan) and not os.path.exists(tujuan):
            _salin_joblib(path_joblib, tujuan)
        ada = cari(data, versi)
        if ada is None:
            entri = _entri_dari_ringkas(ringkas_info, berkas, nama=nama or "Model Awal", oleh=oleh)
            data["model"].insert(0, entri)
        else:
            entri = ada
            if nama:
                entri["nama"] = nama.strip()[:80]
            if not entri.get("berkas"):
                entri["berkas"] = berkas
        if "adaptasi" in entri:
            pass
        if aktifkan or not data.get("aktif"):
            data["aktif"] = entri["versi"]
            data["revisi"] += 1
            data["diperbarui_utc"] = sekarang_utc()
            data["diperbarui_oleh"] = oleh
        _simpan_tanpa_kunci(folder, data)
        return entri


def pastikan_awal(folder, path_joblib, ringkas_info):
    """Dipanggil modul deteksi saat mulai: pastikan model awal terdaftar, lalu kembalikan
    (data_katalog, entri_aktif) agar pilihan model/mode/ambang admin tetap berlaku saat restart."""
    daftar_dari_file(folder, path_joblib, ringkas_info, nama=ringkas_info.get("nama") or "Baseline Awal",
                     oleh="sistem", aktifkan=False)
    data = baca(folder)
    entri = cari(data, data.get("aktif"))
    if entri is None or not os.path.exists(path_berkas_model(folder, entri)):
        entri = cari(data, ringkas_info.get("versi"))
    return data, entri


def atur_mode(folder, mode, oleh=""):
    """Ubah mode deteksi aktif ('A+C', 'A', atau 'C')."""
    if mode not in MODE_VALID:
        raise ValueError("Mode deteksi tidak dikenal (pilih Dual-IF, IF-Flow saja, atau IF-Agg saja).")
    with _kunci(folder):
        data = _baca_tanpa_kunci(folder)
        if not data["model"]:
            raise ValueError("Belum ada model di katalog.")
        data["mode"] = mode
        data["revisi"] += 1
        data["diperbarui_utc"] = sekarang_utc()
        data["diperbarui_oleh"] = oleh
        _simpan_tanpa_kunci(folder, data)
        return data


def aktifkan(folder, versi, oleh=""):
    """Aktifkan (atau rollback ke) versi model yang sudah tersimpan di katalog."""
    with _kunci(folder):
        data = _baca_tanpa_kunci(folder)
        entri = cari(data, versi)
        if entri is None:
            raise ValueError("Versi model %s tidak ditemukan di katalog." % versi)
        p = path_berkas_model(folder, entri)
        if not os.path.exists(p):
            raise ValueError("Berkas model %s tidak ditemukan di server." % entri.get("berkas"))
        data["aktif"] = entri["versi"]
        data["revisi"] += 1
        data["diperbarui_utc"] = sekarang_utc()
        data["diperbarui_oleh"] = oleh
        _simpan_tanpa_kunci(folder, data)
        return entri


def ubah_nama(folder, versi, nama, oleh=""):
    """Ubah nama profil / label manusiawi sebuah model di katalog."""
    nama = (nama or "").strip()[:80]
    if not nama:
        raise ValueError("Nama profil model tidak boleh kosong.")
    with _kunci(folder):
        data = _baca_tanpa_kunci(folder)
        entri = cari(data, versi)
        if entri is None:
            raise ValueError("Versi model %s tidak ditemukan di katalog." % versi)
        entri["nama"] = nama
        if data.get("aktif") == versi:
            data["revisi"] += 1
        data["diperbarui_utc"] = sekarang_utc()
        data["diperbarui_oleh"] = oleh
        _simpan_tanpa_kunci(folder, data)
        return entri


def _validasi_contamination(nama_sub, nilai):
    c = float(nilai)
    lo, hi = BATAS_CONTAMINATION_MIN[nama_sub], BATAS_CONTAMINATION_MAKS[nama_sub]
    label = "IF-Flow" if nama_sub == "A" else "IF-Agg"
    if c < lo or c > hi:
        raise ValueError("Contamination %s harus antara %.2f%% dan %.2f%%." % (label, lo * 100, hi * 100))
    return c


def buat_turunan_ambang(folder, versi_sumber=None, contamination_a=None, contamination_c=None,
                        ambang_a=None, ambang_c=None, nama="", alasan="", oleh="", aktifkan_langsung=True):
    """Buat versi model turunan dengan ambang/contamination baru tanpa melatih ulang pohon.
    Berbagi berkas `.joblib` induknya; aman dipanggil dari dashboard Flask tanpa scikit-learn."""
    if all(x is None for x in (contamination_a, contamination_c, ambang_a, ambang_c)):
        raise ValueError("Isi minimal satu nilai contamination atau ambang baru.")
    with _kunci(folder):
        data = _baca_tanpa_kunci(folder)
        if not data["model"]:
            raise ValueError("Belum ada model di katalog.")
        sumber_versi = versi_sumber or data.get("aktif") or data["model"][0]["versi"]
        sumber = cari(data, sumber_versi)
        if sumber is None:
            raise ValueError("Versi model sumber %s tidak ditemukan." % sumber_versi)
        if not os.path.exists(path_berkas_model(folder, sumber)):
            raise ValueError("Berkas model induk %s tidak ditemukan di server." % sumber.get("berkas"))

        baru = json.loads(json.dumps(sumber))
        riwayat = list(baru.get("riwayat_ambang") or [])
        berubah = False

        spec = [("A", contamination_a, ambang_a), ("C", contamination_c, ambang_c)]
        for kode, c_req, t_req in spec:
            if c_req is None and t_req is None:
                continue
            sub = dict(baru.get(kode) or {})
            kuantil = sub.get("kuantil")
            ambang_lama = float(sub["ambang"])
            if t_req is not None:
                t_baru = float(t_req)
                if kuantil:
                    c_baru = kontaminasi_dari_skor(kuantil, t_baru)
                    _validasi_contamination(kode, c_baru)
                else:
                    c_baru = sub.get("contamination")
            else:
                c_baru = _validasi_contamination(kode, c_req)
                if not kuantil:
                    raise ValueError("Model induk tidak memiliki data sebaran skor (kuantil) untuk %s." % kode)
                t_baru = float(ambang_dari_kontaminasi(kuantil, c_baru))
            if abs(t_baru - ambang_lama) > 1e-12 or sub.get("contamination") != c_baru:
                berubah = True
                riwayat.append({"model": kode, "dari": ambang_lama, "ke": t_baru, "contamination": c_baru})
                sub["ambang"] = t_baru
                sub["contamination"] = c_baru
                baru[kode] = sub

        if not berubah:
            raise ValueError("Nilai ambang dan contamination sama dengan model aktif saat ini.")

        v = versi_baru()
        while cari(data, v) is not None:
            time.sleep(0.002)
            v = versi_baru()
        baru["versi"] = v
        baru["induk"] = sumber["versi"]
        baru["hutan"] = sumber.get("hutan") or sumber["versi"]
        baru["dilatih_utc"] = sumber.get("dilatih_utc")
        baru["dibuat_utc"] = sekarang_utc()
        baru["alasan"] = (alasan or "").strip()[:200] or "penyesuaian ambang dari dashboard"
        baru["nama"] = (nama or "").strip()[:80] or ("%s (disesuaikan)" % (sumber.get("nama") or sumber["versi"]))[:80]
        baru["oleh"] = oleh
        baru["riwayat_ambang"] = riwayat

        data["model"].insert(0, baru)
        if aktifkan_langsung:
            data["aktif"] = v
            data["revisi"] += 1
        data["diperbarui_utc"] = sekarang_utc()
        data["diperbarui_oleh"] = oleh
        _simpan_tanpa_kunci(folder, data)
        return baru


def _salin_turunan_katalog(sumber, versi, alasan, nama="", oleh=""):
    baru = json.loads(json.dumps(sumber))
    baru["versi"] = versi
    baru["induk"] = sumber["versi"]
    baru["hutan"] = sumber.get("hutan") or sumber["versi"]
    baru["dilatih_utc"] = sumber.get("dilatih_utc")
    baru["dibuat_utc"] = sekarang_utc()
    baru["alasan"] = (alasan or "").strip()[:200]
    if nama:
        baru["nama"] = nama.strip()[:80]
    baru["oleh"] = oleh
    return baru


def tambah_adaptasi(folder, aturan, versi_sumber=None, contamination_a=None, contamination_c=None,
                    ambang_a=None, ambang_c=None, nama="", alasan="", oleh=""):
    """Buat versi model adaptif baru yang membawa prototipe ruang fitur (`adaptasi`) dan opsional
    penyesuaian ambang, lalu langsung mengaktifkannya via hot-reload tanpa restart."""
    with _kunci(folder):
        data = _baca_tanpa_kunci(folder)
        if not data["model"]:
            raise ValueError("Belum ada model di katalog.")
        sumber_versi = versi_sumber or data.get("aktif") or data["model"][0]["versi"]
        sumber = cari(data, sumber_versi)
        if sumber is None:
            raise ValueError("Versi model sumber %s tidak ditemukan." % sumber_versi)
        if not os.path.exists(path_berkas_model(folder, sumber)):
            raise ValueError("Berkas model induk %s tidak ditemukan di server." % sumber.get("berkas"))

        v = versi_baru()
        while cari(data, v) is not None:
            time.sleep(0.002)
            v = versi_baru()

        label_teks = "anomali" if aturan.get("label") == "anomali" else "bukan anomali"
        alasan_teks = (alasan or "").strip()[:200] or ("adaptasi %s (%s)" % (label_teks, aturan.get("src_ip") or "-"))
        nama_teks = (nama or "").strip()[:80] or (sumber.get("nama") or sumber["versi"])
        baru = _salin_turunan_katalog(sumber, v, alasan_teks, nama=nama_teks, oleh=oleh)

        # Opsional perbarui ambang sekaligus jika ikut diusulkan
        riwayat = list(baru.get("riwayat_ambang") or [])
        for kode, c_req, t_req in (("A", contamination_a, ambang_a), ("C", contamination_c, ambang_c)):
            if c_req is None and t_req is None:
                continue
            sub = dict(baru.get(kode) or {})
            kuantil = sub.get("kuantil")
            ambang_lama = float(sub["ambang"])
            if t_req is not None:
                t_baru = float(t_req)
                c_baru = kontaminasi_dari_skor(kuantil, t_baru) if kuantil else sub.get("contamination")
                if c_baru is not None:
                    _validasi_contamination(kode, c_baru)
            else:
                c_baru = _validasi_contamination(kode, c_req)
                if not kuantil:
                    raise ValueError("Model induk tidak memiliki data sebaran skor (kuantil) untuk %s." % kode)
                t_baru = float(ambang_dari_kontaminasi(kuantil, c_baru))
            if abs(t_baru - ambang_lama) > 1e-12:
                riwayat.append({"model": kode, "dari": ambang_lama, "ke": t_baru, "contamination": c_baru})
                sub["ambang"] = t_baru
                sub["contamination"] = c_baru
                baru[kode] = sub
        baru["riwayat_ambang"] = riwayat

        daftar_ad = [dict(a) for a in (baru.get("adaptasi") or [])
                     if not (a.get("ub_id") and aturan.get("ub_id") and a["ub_id"] == aturan["ub_id"])]
        daftar_ad.insert(0, dict(aturan))
        baru["adaptasi"] = daftar_ad

        data["model"].insert(0, baru)
        data["aktif"] = v
        data["revisi"] += 1
        data["diperbarui_utc"] = sekarang_utc()
        data["diperbarui_oleh"] = oleh
        _simpan_tanpa_kunci(folder, data)
        return baru


def hapus_adaptasi(folder, id_aturan, oleh=""):
    """Hapus satu aturan adaptasi dari model aktif dengan membuat versi baru tanpa aturan itu."""
    with _kunci(folder):
        data = _baca_tanpa_kunci(folder)
        if not data["model"]:
            raise ValueError("Belum ada model di katalog.")
        sumber = cari(data, data.get("aktif")) or data["model"][0]
        lama = list(sumber.get("adaptasi") or [])
        sisa = [a for a in lama if a.get("id") != id_aturan]
        if len(sisa) == len(lama):
            return None
        v = versi_baru()
        while cari(data, v) is not None:
            time.sleep(0.002)
            v = versi_baru()
        baru = _salin_turunan_katalog(sumber, v, "hapus aturan adaptasi %s" % id_aturan,
                                      nama=sumber.get("nama") or sumber["versi"], oleh=oleh)
        baru["adaptasi"] = sisa
        data["model"].insert(0, baru)
        data["aktif"] = v
        data["revisi"] += 1
        data["diperbarui_utc"] = sekarang_utc()
        data["diperbarui_oleh"] = oleh
        _simpan_tanpa_kunci(folder, data)
        return baru


def hapus(folder, versi, oleh=""):
    """Hapus versi model non-aktif dari katalog; hapus berkas .joblib hanya bila tak lagi dirujuk versi lain."""
    with _kunci(folder):
        data = _baca_tanpa_kunci(folder)
        entri = cari(data, versi)
        if entri is None:
            return None
        if data.get("aktif") == versi:
            raise ValueError("Model yang sedang aktif tidak dapat dihapus. Aktifkan versi lain terlebih dahulu.")
        if len(data["model"]) <= 1:
            raise ValueError("Minimal satu model harus tersisa di katalog.")
        data["model"] = [m for m in data["model"] if m.get("versi") != versi]
        berkas = entri.get("berkas")
        masih_dipakai = any(m.get("berkas") == berkas for m in data["model"])
        data["diperbarui_utc"] = sekarang_utc()
        data["diperbarui_oleh"] = oleh
        _simpan_tanpa_kunci(folder, data)
        if berkas and not masih_dipakai:
            p = os.path.join(folder, berkas)
            if os.path.exists(p):
                try:
                    os.unlink(p)
                except OSError:
                    pass
        return entri


class PengawasModel:
    """Memantau perubahan katalog.json (berdasarkan mtime_ns + revisi) untuk hot-reload di modul deteksi."""

    def __init__(self, folder=DIR_BAWAAN, periksa_detik=5, jam=time.monotonic):
        self.folder, self.interval, self.jam = folder, periksa_detik, jam
        self._mtime, self._t_periksa, self._revisi = None, None, None

    def periksa(self, paksa=False):
        """Kembalikan (entri_aktif, mode, path_joblib) bila ada perubahan, atau None bila tidak berubah."""
        kini = self.jam()
        if not paksa and self._t_periksa is not None and kini - self._t_periksa < self.interval:
            return None
        self._t_periksa = kini
        p = path_katalog(self.folder)
        try:
            mtime = os.stat(p).st_mtime_ns
        except OSError:
            return None
        if not paksa and mtime == self._mtime:
            return None
        self._mtime = mtime
        try:
            data = baca(self.folder)
        except (OSError, ValueError):
            return None
        revisi = data.get("revisi", 0)
        if not paksa and self._revisi == revisi:
            return None
        entri = cari(data, data.get("aktif"))
        if entri is None:
            return None
        try:
            berkas = path_berkas_model(self.folder, entri)
        except ValueError:
            return None
        if not os.path.exists(berkas):
            return None
        self._revisi = revisi
        return entri, data.get("mode", "A+C"), berkas
