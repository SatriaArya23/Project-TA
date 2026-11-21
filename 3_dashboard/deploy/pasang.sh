#!/usr/bin/env bash
# Pasang atau perbarui server penerima di Ubuntu (sebagai root, dari folder repositori):
#
#   sudo bash deploy/pasang.sh --domain penerima.example.com
#   sudo bash deploy/pasang.sh --tanpa-domain      # server tanpa domain (mis. VPS uji): tanpa nginx/sertifikat,
#                                                  # dashboard hanya di 127.0.0.1:PORT, dibuka lewat terowongan SSH:
#                                                  #   ssh -L 8090:127.0.0.1:8090 root@<ip-server>  -> http://localhost:8090
#
# Aman dijalankan ulang: konfigurasi, kunci rahasia, basis data, dan berkas diterima dipertahankan.
set -euo pipefail

DOMAIN=""; PORT=8090; TANPA_DOMAIN=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain) DOMAIN="$2"; shift 2 ;;
        --port)   PORT="$2"; shift 2 ;;
        --tanpa-domain) TANPA_DOMAIN=1; shift ;;
        *) echo "Opsi tidak dikenal: $1"; exit 1 ;;
    esac
done
[[ $EUID -eq 0 ]] || { echo "Jalankan sebagai root."; exit 1; }
if [[ $TANPA_DOMAIN -eq 0 ]]; then
    [[ "$DOMAIN" =~ ^[a-z0-9.-]+\.[a-z]{2,}$ ]] || { echo "Wajib: --domain nama.host.anda (atau --tanpa-domain)"; exit 1; }
fi
[[ "$PORT" =~ ^[0-9]+$ ]] || { echo "Port tidak valid"; exit 1; }

SRC="$(cd "$(dirname "$0")/.." && pwd)"
APP=/opt/ta-nids-server; DATA=/var/lib/ta-nids-server; ETC=/etc/ta-nids-server
NGINX_CONF=/etc/nginx/sites-available/ta-nids-server
ok() { echo "[ok] $*"; }

# 1. paket dan user
export DEBIAN_FRONTEND=noninteractive
dpkg -s python3-venv >/dev/null 2>&1 || { apt-get update -qq; apt-get install -y -qq python3-venv >/dev/null; }
id tanids >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --no-create-home --shell /usr/sbin/nologin tanids
install -d -o tanids -g tanids -m 750 "$DATA"
install -d -o root -g tanids -m 750 "$ETC"
ok "user tanids dan folder data siap"

# 2. konfigurasi (dibuat sekali)
if [[ ! -f "$ETC/config.env" ]]; then
    umask 077
    cat > "$ETC/config.env" <<EOF
PENERIMA_DATA_DIR=$DATA
PENERIMA_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
PENERIMA_MAX_UPLOAD_MB=512
PENERIMA_MIN_FREE_MB=2048
PENERIMA_COOKIE_SECURE=$((1 - TANPA_DOMAIN))
PENERIMA_BEHIND_PROXY=$((1 - TANPA_DOMAIN))
EOF
    umask 022
    chown root:tanids "$ETC/config.env"; chmod 640 "$ETC/config.env"
    ok "konfigurasi baru dibuat di $ETC/config.env"
fi

# 3. kode aplikasi + venv
install -d -m 755 "$APP"
rm -rf "$APP/penerima"
cp -r "$SRC/penerima" "$SRC/kelola.py" "$SRC/wsgi.py" "$SRC/requirements.txt" "$APP/"
# pembaca pcap bersama (paket nids dari folder nids-deteksi), dipakai untuk statistik rekaman
NIDS_SRC=""
for p in "$SRC/nids" "$SRC/../2_sistem_nids/nids" "$SRC/../nids-deteksi/nids"; do [[ -d "$p" ]] && { NIDS_SRC="$p"; break; }; done
[[ -n "$NIDS_SRC" ]] || { echo "Paket nids tidak ditemukan (salin folder 2_sistem_nids di samping 3_dashboard)." >&2; exit 1; }
rm -rf "$APP/nids"
cp -r "$NIDS_SRC" "$APP/nids"
find "$APP/penerima" "$APP/nids" -name __pycache__ -prune -exec rm -rf {} +
chown -R root:root "$APP/penerima" "$APP/nids" "$APP/kelola.py" "$APP/wsgi.py" "$APP/requirements.txt"
[[ -x "$APP/venv/bin/python" ]] || python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q --disable-pip-version-check -r "$APP/requirements.txt"
install -m 755 "$SRC/deploy/tanids-kelola" /usr/local/bin/tanids-kelola
ok "aplikasi terpasang di $APP"

# 4. layanan systemd
sed "s/__PORT__/$PORT/" "$SRC/deploy/ta-nids-server.service" > /etc/systemd/system/ta-nids-server.service
systemctl daemon-reload
systemctl enable ta-nids-server.service >/dev/null 2>&1
systemctl restart ta-nids-server.service
sleep 2
systemctl is-active --quiet ta-nids-server.service || { journalctl -u ta-nids-server -n 30 --no-pager; exit 1; }
curl -fsS "http://127.0.0.1:$PORT/api/v1/health" >/dev/null && ok "layanan ta-nids-server berjalan (127.0.0.1:$PORT)"

if [[ $TANPA_DOMAIN -eq 1 ]]; then
    echo
    echo "[ok] mode tanpa domain: dashboard hanya di 127.0.0.1:$PORT (tidak dibuka ke internet)."
    echo "     Dari laptop: ssh -L $PORT:127.0.0.1:$PORT root@<ip-server>  lalu buka http://localhost:$PORT"
    echo "     Akun admin: sudo tanids-kelola pengguna-tambah <username> --peran admin"
    exit 0
fi

# 5. nginx + sertifikat
pasang_nginx() {   # $1 = templat
    sed "s/__DOMAIN__/$DOMAIN/g; s/__PORT__/$PORT/g" "$1" > "$NGINX_CONF.baru"
    cp -f "$NGINX_CONF" "$NGINX_CONF.lama" 2>/dev/null || true
    mv "$NGINX_CONF.baru" "$NGINX_CONF"
    ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/ta-nids-server
    if ! nginx -t 2>/tmp/nginx-t.log; then
        cat /tmp/nginx-t.log
        if [[ -f "$NGINX_CONF.lama" ]]; then mv "$NGINX_CONF.lama" "$NGINX_CONF"
        else rm -f "$NGINX_CONF" /etc/nginx/sites-enabled/ta-nids-server; fi
        echo "nginx -t gagal; konfigurasi dikembalikan, nginx TIDAK dimuat ulang."; exit 1
    fi
    rm -f "$NGINX_CONF.lama"
    local baris_awal
    baris_awal=$(wc -l < /var/log/nginx/error.log 2>/dev/null || echo 0)
    systemctl reload nginx
    sleep 2        # beri waktu worker nginx memuat konfigurasi baru
    # Sebagian kesalahan (mis. zona bersama berubah) baru ketahuan saat reload, bukan saat nginx -t.
    if tail -n +"$((baris_awal + 1))" /var/log/nginx/error.log 2>/dev/null | grep -q "\[emerg\]"; then
        tail -n +"$((baris_awal + 1))" /var/log/nginx/error.log | grep "\[emerg\]"
        echo "PERINGATAN: nginx menolak konfigurasi baru dan tetap memakai yang lama."; exit 1
    fi
}
if [[ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
    pasang_nginx "$SRC/deploy/nginx-penerima-http.conf"
    certbot certonly --nginx -d "$DOMAIN" --non-interactive --agree-tos \
        --deploy-hook "systemctl reload nginx"
    ok "sertifikat Let's Encrypt untuk $DOMAIN dibuat (diperpanjang otomatis oleh certbot.timer)"
fi
pasang_nginx "$SRC/deploy/nginx-penerima.conf"
ok "nginx melayani https://$DOMAIN"

curl -fsS "https://$DOMAIN/api/v1/health" >/dev/null && ok "uji https://$DOMAIN/api/v1/health berhasil"
echo
echo "Langkah berikutnya (sekali saja):"
echo "  sudo tanids-kelola instalasi-tambah <nama-server>"
echo "  sudo tanids-kelola token-buat --peran upload --instalasi <nama-server> --label <label> --keluar - > token.txt"
echo "  sudo tanids-kelola pengguna-tambah <username> --peran admin"
