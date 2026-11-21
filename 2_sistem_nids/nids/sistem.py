# -*- coding: utf-8 -*-
"""Kondisi server tempat sensor NIDS berjalan (CPU, RAM, disk, waktu hidup).

Dipakai dashboard (bagian Kondisi server), bot Telegram (/status), dan pemantau kesehatan (pantau.py):
server penuh / kehabisan memori = deteksi bisa berhenti diam-diam.
Dibaca dari /proc (Linux); di sistem lain (mis. laptop Windows saat pengujian) hasilnya None.
Hanya memakai pustaka standar.
"""
import os
import shutil


def _meminfo():
    data = {}
    with open("/proc/meminfo") as f:
        for baris in f:
            k, v = baris.split(":", 1)
            data[k] = int(v.split()[0]) * 1024
    return data


def kondisi(path_disk="/"):
    if not os.path.exists("/proc/loadavg"):
        return None
    try:
        with open("/proc/loadavg") as f:
            beban = [float(x) for x in f.read().split()[:3]]
        cpu = os.cpu_count() or 1
        mem = _meminfo()
        total, tersedia = mem.get("MemTotal", 0), mem.get("MemAvailable", 0)
        disk = shutil.disk_usage(path_disk)
        with open("/proc/uptime") as f:
            hidup = float(f.read().split()[0])
    except (OSError, ValueError):
        return None
    return {
        "cpu_inti": cpu,
        "beban": beban,                                            # rata-rata 1 / 5 / 15 menit
        "cpu_persen": min(beban[1] / cpu, 1.0),                     # beban 5 menit dibagi jumlah inti
        "ram_total": total, "ram_pakai": total - tersedia,
        "ram_persen": (total - tersedia) / total if total else 0,
        "disk_total": disk.total, "disk_pakai": disk.used,
        "disk_persen": disk.used / disk.total if disk.total else 0,
        "hidup_hari": hidup / 86400,
    }
