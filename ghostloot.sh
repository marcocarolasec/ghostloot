#!/usr/bin/env bash
# Laptop: one command for the campaign.
#   ghostloot            start whatever is down, open the panel
#   ghostloot status
#   ghostloot console    Evilginx REPL
# Never kills other SSH sessions. Never uses port 8080 (GoPhish).
set -euo pipefail

HOST="${GHOSTLOOT_HOST:?set GHOSTLOOT_HOST (user@host)}"
KEY="${GHOSTLOOT_KEY:?set GHOSTLOOT_KEY (path to SSH key)}"
PORT="${GHOSTLOOT_PORT:-8090}"
URL="http://127.0.0.1:${PORT}/"
CTL="${GHOSTLOOT_CTL:-$HOME/.ssh/ghostloot.ctl}"
REMOTE="${GHOSTLOOT_REMOTE:-/usr/local/bin/ghostloot-host}"

cmd="${1:-up}"

alive() { curl -sf -o /dev/null --max-time 2 "$URL"; }

ssh_base=(ssh -i "$KEY" -o IdentitiesOnly=yes -o ControlMaster=auto -o ControlPath="$CTL" -o ControlPersist=8h -o ServerAliveInterval=30 -o ServerAliveCountMax=3)

mux_ok() { ssh -O check -o ControlPath="$CTL" "$HOST" >/dev/null 2>&1; }

port_holder() { lsof -nP -iTCP:"$PORT" -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $1,$2; exit}'; }

ensure_tunnel() {
  mkdir -p "$HOME/.ssh"
  chmod 700 "$HOME/.ssh"
  if alive; then return 0; fi
  if mux_ok; then
    ssh -O exit -o ControlPath="$CTL" "$HOST" >/dev/null 2>&1 || true
    rm -f "$CTL"
  fi
  if alive; then return 0; fi
  local who
  who="$(port_holder || true)"
  if [[ -n "$who" ]]; then
    echo "localhost:${PORT} ocupado (${who}) y no responde el panel." >&2
    echo "No mato procesos. Libera el puerto o cambia GHOSTLOOT_PORT." >&2
    exit 1
  fi
  if [[ ! -f "$KEY" ]]; then
    echo "No hay clave SSH en $KEY" >&2
    exit 1
  fi
  ssh -fN "${ssh_base[@]}" -o ExitOnForwardFailure=yes -L "${PORT}:127.0.0.1:${PORT}" "$HOST"
}

remote() { "${ssh_base[@]}" "$HOST" "$@"; }

open_panel() {
  if command -v open >/dev/null 2>&1; then open "$URL"
  elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL"
  fi
}

wait_local() {
  local i
  for i in $(seq 1 30); do
    if alive; then return 0; fi
    sleep 0.2
  done
  return 1
}

usage() {
  cat <<EOF
ghostloot            arranca lo que falte y abre el panel
ghostloot status     túnel + panel + evilginx
ghostloot console    REPL de Evilginx (tmux attach)
ghostloot help
EOF
}

case "$cmd" in
  help|-h|--help) usage; exit 0 ;;
  status)
    ensure_tunnel
    echo "túnel     $(if alive; then echo "up   $URL"; else echo "down $URL"; fi)"
    remote "$REMOTE status" 2>/dev/null || echo "vps       (ghostloot-host no instalado)"
    ;;
  console)
    ensure_tunnel
    remote "$REMOTE up" >/dev/null
    exec "${ssh_base[@]}" -t "$HOST" "$REMOTE console"
    ;;
  restart-panel)
    ensure_tunnel
    remote "$REMOTE restart-panel"
    wait_local || { echo "panel no responde en $URL" >&2; exit 1; }
    echo "panel     up   $URL"
    ;;
  up|"")
    ensure_tunnel
    remote "$REMOTE up"
    wait_local || { echo "túnel ok, pero $URL no responde. En el VPS: $REMOTE status" >&2; exit 1; }
    open_panel
    echo "GhostLoot  $URL"
    echo "REPL       ghostloot console"
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
