#!/usr/bin/env bash
# Pasang / perbarui modul deteksi real-time (sebagai root, dari folder nids-deteksi):
#
#   sudo bash deploy/pasang-deteksi.sh --nama-server "Server Uji" [--antarmuka eth0] \
#        [--model model.joblib | --latih fitur.parquet [--sampai YYYY-MM-DD]]
#
# --model : pakai berkas model yang sudah dilatih (versi scikit-learn harus sama dengan di server)
# --latih : latih model di server ini dari fitur hasil 'deteksi.py putar-ulang --fitur' (disarankan)
# Menyesuaikan ambang dari halaman Umpan balik: lihat ubah_ambang.py (model versi baru tanpa latih ulang).
# Telegram (opsional): isi /etc/nids-deteksi/rahasia.env (izin 600) lalu restart layanan:
#   TELEGRAM_TOKEN=...
#   TELEGRAM_CHAT_ID=...
set -euo pipefail

NAMA=""; IFACE=""; MODEL=""; FITUR=""; SAMPAI=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --nama-server) NAMA="$2"; shift 2 ;;
        --antarmuka)   IFACE="$2"; shift 2 ;;
        --model)       MODEL="$2"; shift 2 ;;
        --latih)       FITUR="$2"; shift 2 ;;
        --sampai)      SAMPAI="$2"; shift 2 ;;
        *) echo "Opsi tidak dikenal: $1"; exit 1 ;;
    esac
done
[[ $EUID -eq 0 ]] || { echo "Jalankan sebagai root."; exit 1; }
[[ -n "$NAMA" ]] || { echo "Wajib: --nama-server \"...\""; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
APP=/opt/nids-deteksi; DATA=/var/lib/nids-deteksi; ETC=/etc/nids-deteksi
IFACE="${IFACE:-$(ip route show default | awk '{print $5; exit}')}"
ok() { echo "[ok] $*"; }

export DEBIAN_FRONTEND=noninteractive
for p in tcpdump python3-venv; do
    dpkg -s "$p" >/dev/null 2>&1 || { apt-get update -qq; apt-get install -y -qq "$p" >/dev/null; }
done
id nids >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --no-create-home --shell /usr/sbin/nologin nids
install -d -o nids -g nids -m 750 "$DATA"
install -d -o root -g nids -m 750 "$ETC"
# folder bersama: daftar IP tepercaya & IP diblokir ditulis dashboard (user tanids) & bot (user nids), grup nids
install -d -o root -g nids -m 2770 /var/lib/nids-bersama
for f in /var/lib/nids-bersama/ip_diblokir.json; do
    [[ -f "$f" ]] || printf '{"entri": []}\n' > "$f"
    chown root:nids "$f"; chmod 660 "$f"
done
touch /var/lib/nids-bersama/.ip_diblokir.lock
chown root:nids /var/lib/nids-bersama/.ip_diblokir.lock
chmod 660 /var/lib/nids-bersama/.ip_diblokir.lock

install -d -m 755 "$APP"
rm -rf "$APP/nids"
cp -r "$SRC/nids" "$SRC/deteksi.py" "$SRC/bot.py" "$SRC/pantau.py" "$SRC/blokir.py" "$SRC/latih_model.py" "$SRC/ubah_ambang.py" "$SRC/requirements.txt" "$APP/"
find "$APP" -name __pycache__ -prune -exec rm -rf {} +
chown -R root:root "$APP/nids" "$APP/deteksi.py" "$APP/bot.py" "$APP/pantau.py" "$APP/blokir.py" "$APP/latih_model.py" "$APP/ubah_ambang.py" "$APP/requirements.txt"
[[ -x "$APP/venv/bin/python" ]] || python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q --disable-pip-version-check -r "$APP/requirements.txt"
ok "kode & dependensi di $APP ($("$APP/venv/bin/python" -c 'import sklearn; print("scikit-learn", sklearn.__version__)'))"

if [[ -n "$FITUR" ]]; then
    "$APP/venv/bin/python" "$APP/latih_model.py" "$FITUR" --keluar "$ETC/model.joblib" ${SAMPAI:+--sampai "$SAMPAI"}         --evaluasi "$SRC/deploy/evaluasi_rancangan.json"
    ok "model dilatih di server ini"
elif [[ -n "$MODEL" ]]; then
    install -m 640 -o root -g nids "$MODEL" "$ETC/model.joblib"
    ok "model disalin"
fi
[[ -f "$ETC/model.joblib" ]] || { echo "Belum ada model: jalankan ulang dengan --latih atau --model"; exit 1; }
chown root:nids "$ETC/model.joblib"; chmod 640 "$ETC/model.joblib"

cat > "$ETC/config.env" <<EOF
ANTARMUKA=$IFACE
NAMA_SERVER="$NAMA"
JEDA_NOTIFIKASI=600
MIN_ALIRAN_NOTIF=3
EOF
chmod 640 "$ETC/config.env"; chown root:nids "$ETC/config.env"
if [[ ! -f "$ETC/rahasia.env" ]]; then
    printf "# isi lalu: systemctl restart nids-deteksi\n#TELEGRAM_TOKEN=\n#TELEGRAM_CHAT_ID=\n" > "$ETC/rahasia.env"
fi
chmod 600 "$ETC/rahasia.env"; chown root:root "$ETC/rahasia.env"

install -m 644 "$SRC/deploy/nids-deteksi.service" /etc/systemd/system/nids-deteksi.service
systemctl daemon-reload
systemctl enable nids-deteksi.service >/dev/null 2>&1
systemctl restart nids-deteksi.service
sleep 4
systemctl is-active --quiet nids-deteksi.service || { journalctl -u nids-deteksi -n 30 --no-pager; exit 1; }
journalctl -u nids-deteksi -n 3 --no-pager -o cat
ok "layanan nids-deteksi berjalan (antarmuka $IFACE). Log anomali: $DATA/deteksi.db"

# bot Telegram (/status, /ringkasan, /ip, /hampir, /blokir, /buka, /diblokir) + pemantau kesehatan + sinkron firewall
install -m 644 "$SRC/deploy/nids-bot.service" "$SRC/deploy/nids-pantau.service" "$SRC/deploy/nids-pantau.timer" \
    "$SRC/deploy/nids-blokir.service" "$SRC/deploy/nids-blokir.path" "$SRC/deploy/nids-blokir.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable nids-bot.service nids-pantau.timer nids-blokir.path nids-blokir.timer >/dev/null 2>&1
systemctl restart nids-bot.service
systemctl restart nids-pantau.timer
systemctl restart nids-blokir.path
systemctl restart nids-blokir.timer
"$APP/venv/bin/python" "$APP/blokir.py" >/dev/null 2>&1 || true
ok "bot Telegram (nids-bot), pemantau (nids-pantau.timer), dan firewall blokir IP (nids-blokir.path/.timer) aktif"

# Dashboard (ta-nids-server, user tanids) membaca log deteksi dalam mode baca-saja lewat grup nids
chmod 750 "$DATA"; find "$DATA" -maxdepth 1 -name 'deteksi.db*' -exec chmod 640 {} +
if id tanids >/dev/null 2>&1; then
    usermod -aG nids tanids
    if [[ -f /etc/ta-nids-server/config.env ]] && ! grep -q '^PENERIMA_DETEKSI_DB=' /etc/ta-nids-server/config.env; then
        echo "PENERIMA_DETEKSI_DB=$DATA/deteksi.db" >> /etc/ta-nids-server/config.env
    fi
    if [[ -f /etc/ta-nids-server/config.env ]] && ! grep -q '^PENERIMA_TEPERCAYA=' /etc/ta-nids-server/config.env; then
        echo "PENERIMA_TEPERCAYA=/var/lib/nids-bersama/ip_tepercaya.json" >> /etc/ta-nids-server/config.env
    fi
    if [[ -f /etc/ta-nids-server/config.env ]] && ! grep -q '^PENERIMA_BLOKIR=' /etc/ta-nids-server/config.env; then
        echo "PENERIMA_BLOKIR=/var/lib/nids-bersama/ip_diblokir.json" >> /etc/ta-nids-server/config.env
    fi
    if [[ -f /etc/ta-nids-server/config.env ]] && ! grep -q '^PENERIMA_BLOKIR_STATUS=' /etc/ta-nids-server/config.env; then
        echo "PENERIMA_BLOKIR_STATUS=/var/lib/nids-bersama/ip_diblokir_status.json" >> /etc/ta-nids-server/config.env
    fi
    systemctl restart ta-nids-server.service
    ok "dashboard ta-nids-server terhubung ke log deteksi (menu Deteksi & Umpan balik)"
else
    echo "[i] ta-nids-server belum terpasang di server ini; halaman Deteksi aktif setelah dashboard dipasang."
fi
