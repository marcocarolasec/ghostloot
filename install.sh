#!/usr/bin/env bash
# Instala el Evilginx Loot Dashboard como servicio systemd.
# Uso: sudo ./install.sh
set -euo pipefail

DEST=/opt/evilginx-dashboard

if [ ! -f evilginx-dashboard ]; then
  echo "No encuentro el binario 'evilginx-dashboard' en este directorio." >&2
  exit 1
fi

mkdir -p "$DEST"
cp evilginx-dashboard "$DEST/"
chmod +x "$DEST/evilginx-dashboard"
cp evilginx-dashboard.service /etc/systemd/system/evilginx-dashboard.service

systemctl daemon-reload
systemctl enable --now evilginx-dashboard

echo
echo "Instalado y arrancado. Estado:"
systemctl status evilginx-dashboard --no-pager | head -6 || true
echo
echo "Escucha en 127.0.0.1:8090 (solo local). Para verlo desde tu equipo:"
echo "  ssh -i <clave> -L 8090:127.0.0.1:8090 <user>@<host>"
echo "  y abre http://localhost:8090"
echo
echo "Logs:    journalctl -u evilginx-dashboard -f"
echo "Parar:   systemctl stop evilginx-dashboard"
echo "Actualizar: copia el binario nuevo a $DEST y 'systemctl restart evilginx-dashboard'"
