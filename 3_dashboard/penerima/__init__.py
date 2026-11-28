# -*- coding: utf-8 -*-
"""Server penerima rekaman lalu lintas + dashboard baca-saja (TA NIDS)."""
import os
from datetime import timedelta

from flask import Flask, jsonify, request, url_for
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from . import db


def create_app(uji=None):
    app = Flask(__name__)
    app.config.update(
        DATA_DIR=os.environ.get("PENERIMA_DATA_DIR", "/var/lib/ta-nids-server"),
        SECRET_KEY=os.environ.get("PENERIMA_SECRET_KEY"),
        MAX_UPLOAD_MB=int(os.environ.get("PENERIMA_MAX_UPLOAD_MB", "512")),
        MIN_FREE_MB=int(os.environ.get("PENERIMA_MIN_FREE_MB", "2048")),
        SESSION_COOKIE_SECURE=os.environ.get("PENERIMA_COOKIE_SECURE", "1") == "1",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_NAME="tanids_sesi",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
        BEHIND_PROXY=os.environ.get("PENERIMA_BEHIND_PROXY", "1") == "1",
        # berkas statis (CSS, JS, logo) disimpan browser 30 hari; URL-nya membawa versi (?v=waktu ubah),
        # jadi perubahan tetap langsung terlihat. Satu halaman = satu permintaan, penting lewat jaringan lambat.
        SEND_FILE_MAX_AGE_DEFAULT=timedelta(days=30),
        # log modul deteksi (nids-deteksi), dibaca baca-saja oleh halaman Deteksi
        DETEKSI_DB=os.environ.get("PENERIMA_DETEKSI_DB", "/var/lib/nids-deteksi/deteksi.db"),
        # daftar IP tepercaya bersama modul deteksi (ditulis halaman IP tepercaya, khusus administrator)
        TEPERCAYA_PATH=os.environ.get("PENERIMA_TEPERCAYA", "/var/lib/nids-bersama/ip_tepercaya.json"),
        # daftar IP diblokir bersama layanan firewall nids-blokir (ditulis admin lewat dashboard atau Telegram)
        BLOKIR_PATH=os.environ.get("PENERIMA_BLOKIR", "/var/lib/nids-bersama/ip_diblokir.json"),
        BLOKIR_STATUS_PATH=os.environ.get("PENERIMA_BLOKIR_STATUS", "/var/lib/nids-bersama/ip_diblokir_status.json"),
        # katalog model bersama (switch / rollback model, mode Dual-IF / IF-Flow / IF-Agg, unggah .joblib)
        MODEL_DIR=os.environ.get("PENERIMA_MODEL_DIR", "/var/lib/nids-bersama/model"),
        # kendali perekam lalu lintas (traffic-recorder) dari Tab Rekaman
        REKAM_CMD_PATH=os.environ.get("PENERIMA_REKAM_CMD", "/var/lib/nids-bersama/rekam_perintah.json"),
        REKAM_STATUS_PATH=os.environ.get("PENERIMA_REKAM_STATUS", "/var/lib/nids-bersama/rekam_status.json"),
        # konfigurasi multi-AI bersama dashboard & bot Telegram (OpenAI, Gemini, Claude, OpenAI-Compatible)
        AI_CONFIG_PATH=os.environ.get("PENERIMA_AI_CONFIG", "/var/lib/nids-bersama/ai_konfig.json"),
        # antrean audit lintas layanan (Telegram Bot, worker impor model)
        AUDIT_EKSTERNAL_PATH=os.environ.get("PENERIMA_AUDIT_EKSTERNAL", "/var/lib/nids-bersama/audit_eksternal.jsonl"),
    )
    if uji:
        app.config.update(uji)
    if not app.config["SECRET_KEY"]:
        raise RuntimeError("PENERIMA_SECRET_KEY belum diatur")
    app.config["DB_PATH"] = os.path.join(app.config["DATA_DIR"], "penerima.db")
    app.config["BERKAS_DIR"] = os.path.join(app.config["DATA_DIR"], "berkas")
    # Batas Flask sedikit di atas batas aplikasi, supaya pesan 413 berasal dari kode kita.
    app.config["MAX_CONTENT_LENGTH"] = (app.config["MAX_UPLOAD_MB"] + 1) * 1024 * 1024

    os.makedirs(app.config["BERKAS_DIR"], exist_ok=True)
    db.inisialisasi(app.config["DB_PATH"])
    app.teardown_appcontext(db.tutup)

    if app.config["BEHIND_PROXY"]:
        # gunicorn hanya mendengar di 127.0.0.1, jadi header dari nginx dapat dipercaya.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    from . import api, deteksi, web
    app.register_blueprint(api.bp)
    app.register_blueprint(web.bp)
    app.register_blueprint(deteksi.bp)
    app.teardown_appcontext(deteksi.tutup_deteksi)

    @app.template_global()
    def aset(nama):
        """URL berkas statis + versi (waktu ubah berkas) untuk cache browser yang aman."""
        try:
            v = int(os.path.getmtime(os.path.join(app.static_folder, nama)))
        except OSError:
            v = 0
        return url_for("static", filename=nama, v=v)

    @app.after_request
    def header_keamanan(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Content-Security-Policy",
                                "default-src 'self'; frame-ancestors 'none'; form-action 'self'")
        if request.endpoint != "static":
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.errorhandler(HTTPException)
    def galat_http(e):
        if request.path.startswith("/api/"):
            return jsonify(error=e.description or e.name), e.code
        return e

    return app
