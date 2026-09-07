#!/usr/bin/env bash
# Install GhostLoot panel as systemd + the VPS helper.
# Usage: sudo ./install.sh
set -euo pipefail

DEST=/opt/evilginx-dashboard

if [ ! -f evilginx-dashboard ]; then
  echo "No encuentro el binario 'evilginx-dashboard' en este directorio." >&2
  exit 1
fi

mkdir -p "$DEST"
cp evilginx-dashboard "$DEST/"
chmod +x "$DEST/evilginx-dashboard"

cat >/etc/systemd/system/ghostloot.service <<EOF
[Unit]
Description=GhostLoot panel (127.0.0.1:8090)
After=network.target

[Service]
Type=simple
ExecStart=${DEST}/evilginx-dashboard -addr 127.0.0.1:8090 -db /root/.evilginx/data.db
Restart=on-failure
RestartSec=2
User=root
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

install -m 0755 ghostloot-host.sh /usr/local/bin/ghostloot-host

systemctl daemon-reload
systemctl enable --now ghostloot

echo
echo "Panel en 127.0.0.1:8090 (solo local). Desde el portátil:"
echo "  ghostloot"
echo
echo "Logs:    journalctl -u ghostloot -f"
echo "Parar:   systemctl stop ghostloot"
echo "Update:  copia el binario a $DEST y 'systemctl restart ghostloot'"
