# -*- coding: utf-8 -*-
"""Kondisi server (CPU, RAM, disk): kodenya di paket nids (nids.sistem), dipakai bersama bot & pemantau."""
from . import statistik  # noqa: F401  (menyiapkan sys.path untuk paket nids)
from nids.sistem import kondisi  # noqa: E402,F401
