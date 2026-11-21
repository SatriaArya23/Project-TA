# -*- coding: utf-8 -*-
"""Dugaan jenis kejadian dari fitur agregasi. Dipakai pesan Telegram dan dashboard.

Sengaja tanpa dependensi (tanpa numpy), supaya dashboard bisa memakainya tanpa pustaka model.
"""


def dugaan(f):
    """Perkiraan jenis kejadian dari fitur agregasi (hanya petunjuk untuk administrator, bukan label model)."""
    if f["agg_ip_port_unik"] >= 10:
        return "Pemindaian port"
    if f["agg_ip_aliran_ssh"] >= 5:
        return "Percobaan login SSH berulang (brute force)"
    if f["agg_ip_aliran"] >= 50 and f["agg_ip_port_unik"] <= 3:
        return "Banjir koneksi (indikasi DoS)"
    if f["agg_ip_aliran_ssh"] >= 1:
        return "Akses SSH tidak biasa"
    return "Pola koneksi tidak biasa"
