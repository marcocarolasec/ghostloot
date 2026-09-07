#!/usr/bin/env bash
# GhostLoot operator CLI — same binary on the server and on your laptop.
#
#   Server:  sudo ./install.sh
#   Laptop:  ./install-local.sh && ghostloot init user@host /path/to/key
#   Daily:   ghostloot
#
# Never kills unrelated SSH. Panel always binds 127.0.0.1.
set -euo pipefail

HOST_CONF="${GHOSTLOOT_HOST_CONF:-/etc/ghostloot.conf}"
CLIENT_CONF="${GHOSTLOOT_CLIENT_CONF:-$HOME/.ghostloot/config}"
CTL="${GHOSTLOOT_CTL:-$HOME/.ssh/ghostloot.ctl}"

usage() {
  cat <<'EOF'
ghostloot              start whatever is down, open the panel
ghostloot status
ghostloot console      attach to the Evilginx tmux session
ghostloot init user@host /path/to/key [port]
ghostloot help

Server (once):  sudo ./install.sh
Laptop (once):  ./install-local.sh && ghostloot init user@host /path/to/key
EOF
}

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "need $1 in PATH" >&2; exit 1; }; }

load_kv() {
  local file="$1"
  [[ -f "$file" ]] || return 1
  # shellcheck disable=SC1090
  set -a
  # only KEY=value lines
  # shellcheck disable=SC1091
  . "$file"
  set +a
}

mode() {
  if [[ -f "$HOST_CONF" ]]; then
    echo host
  elif [[ -f "$CLIENT_CONF" ]] || [[ -n "${GHOSTLOOT_HOST:-}" ]]; then
    echo client
  else
    echo none
  fi
}

# ---- host (the box that runs Evilginx) ----

load_host() {
  db="${db:-/root/.evilginx/data.db}"
  addr="${addr:-127.0.0.1:8090}"
  panel_bin="${panel_bin:-/opt/ghostloot/ghostloot}"
  evilginx_cmd="${evilginx_cmd:-}"
  tmux_session="${tmux_session:-evilginx}"
  load_kv "$HOST_CONF" || true
  db="${GHOSTLOOT_DB:-$db}"
  addr="${GHOSTLOOT_ADDR:-$addr}"
  panel_bin="${GHOSTLOOT_BIN:-$panel_bin}"
  evilginx_cmd="${GHOSTLOOT_EVILGINX_CMD:-$evilginx_cmd}"
  tmux_session="${GHOSTLOOT_TMUX:-$tmux_session}"
}

panel_http() { curl -sf -o /dev/null --max-time 1 "http://${addr}/"; }

evilginx_up() { pgrep -x evilginx2 >/dev/null 2>&1 || pgrep -x evilginx >/dev/null 2>&1; }

start_panel() {
  if panel_http; then return 0; fi
  if [[ -f /etc/systemd/system/ghostloot.service ]]; then
    sudo systemctl start ghostloot
    return 0
  fi
  if [[ ! -x "$panel_bin" ]]; then
    echo "panel binary not found: $panel_bin (run sudo ./install.sh)" >&2
    return 1
  fi
  if command -v tmux >/dev/null 2>&1 && ! sudo tmux has-session -t ghostloot 2>/dev/null; then
    sudo tmux new-session -d -s ghostloot "$panel_bin -addr $addr -db $db"
  else
    echo "cannot start panel: install systemd unit via sudo ./install.sh" >&2
    return 1
  fi
}

start_evilginx() {
  if evilginx_up; then return 0; fi
  if [[ -z "$evilginx_cmd" ]]; then
    return 0
  fi
  need_cmd tmux
  if tmux has-session -t "$tmux_session" 2>/dev/null; then
    tmux send-keys -t "$tmux_session" "$evilginx_cmd" C-m
  else
    tmux new-session -d -s "$tmux_session" -n main "$evilginx_cmd"
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

host_status() {
  load_host
  local p="down" e="down"
  if panel_http; then p="up"; fi
  if evilginx_up; then e="up"; fi
  printf "panel     %s   %s\n" "$p" "$addr"
  if [[ -n "$evilginx_cmd" ]]; then
    printf "evilginx  %s   tmux %s\n" "$e" "$tmux_session"
  else
    printf "evilginx  %s   (not configured — set evilginx_cmd in %s)\n" "$e" "$HOST_CONF"
  fi
}

host_up() {
  load_host
  start_panel
  start_evilginx
  wait_panel || { host_status; echo "panel not answering at $addr" >&2; exit 1; }
  host_status
}

host_restart_panel() {
  load_host
  if [[ -f /etc/systemd/system/ghostloot.service ]]; then
    sudo systemctl restart ghostloot
  else
    echo "no systemd unit ghostloot.service" >&2
    exit 1
  fi
  wait_panel || { echo "panel did not come back" >&2; exit 1; }
  host_status
}

host_console() {
  load_host
  if ! tmux has-session -t "$tmux_session" 2>/dev/null; then
    echo "no tmux session '$tmux_session'. Start Evilginx or set tmux_session in $HOST_CONF." >&2
    exit 1
  fi
  exec tmux attach -t "$tmux_session"
}

# ---- client (your laptop) ----

load_client() {
  host="${GHOSTLOOT_HOST:-}"
  key="${GHOSTLOOT_KEY:-}"
  port="${GHOSTLOOT_PORT:-8090}"
  if [[ -f "$CLIENT_CONF" ]]; then
    # shellcheck disable=SC1090
    set -a
    # shellcheck disable=SC1091
    . "$CLIENT_CONF"
    set +a
  fi
  host="${GHOSTLOOT_HOST:-$host}"
  key="${GHOSTLOOT_KEY:-$key}"
  port="${GHOSTLOOT_PORT:-$port}"
  url="http://127.0.0.1:${port}/"
  if [[ -z "$host" || -z "$key" ]]; then
    echo "No laptop config. Once:" >&2
    echo "  ghostloot init user@host /path/to/ssh-key" >&2
    exit 1
  fi
  if [[ ! -f "$key" ]]; then
    echo "SSH key not found: $key" >&2
    exit 1
  fi
  ssh_base=(ssh -i "$key" -o IdentitiesOnly=yes -o ControlMaster=auto -o ControlPath="$CTL" -o ControlPersist=8h -o ServerAliveInterval=30 -o ServerAliveCountMax=3)
}

alive() { curl -sf -o /dev/null --max-time 2 "$url"; }

mux_ok() { ssh -O check -o ControlPath="$CTL" "$host" >/dev/null 2>&1; }

port_holder() { lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $1,$2; exit}'; }

ensure_tunnel() {
  mkdir -p "$HOME/.ssh"
  chmod 700 "$HOME/.ssh"
  if alive; then return 0; fi
  if mux_ok; then
    ssh -O exit -o ControlPath="$CTL" "$host" >/dev/null 2>&1 || true
    rm -f "$CTL"
  fi
  if alive; then return 0; fi
  local who
  who="$(port_holder || true)"
  if [[ -n "$who" ]]; then
    echo "localhost:${port} is busy (${who}) and is not the panel." >&2
    echo "Set port= in $CLIENT_CONF or GHOSTLOOT_PORT. I will not kill it." >&2
    exit 1
  fi
  ssh -fN "${ssh_base[@]}" -o ExitOnForwardFailure=yes -L "${port}:127.0.0.1:${port}" "$host"
}

remote() {
  "${ssh_base[@]}" "$host" "export PATH=/usr/local/bin:/usr/sbin:/usr/bin:/bin; if command -v ghostloot >/dev/null; then ghostloot $*; else echo 'GhostLoot is not installed on the server. Run: sudo ./install.sh' >&2; exit 1; fi"
}

wait_local() {
  local i
  for i in $(seq 1 30); do
    if alive; then return 0; fi
    sleep 0.2
  done
  return 1
}

open_panel() {
  if command -v open >/dev/null 2>&1; then open "$url"
  elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$url"
  fi
}

client_up() {
  load_client
  ensure_tunnel
  remote up
  wait_local || { echo "tunnel is up but $url is not answering. On the server: ghostloot status" >&2; exit 1; }
  open_panel
  echo "GhostLoot  $url"
  echo "REPL       ghostloot console"
}

client_status() {
  load_client
  ensure_tunnel
  echo "tunnel    $(if alive; then echo "up   $url"; else echo "down $url"; fi)"
  remote status
}

client_console() {
  load_client
  ensure_tunnel
  remote up >/dev/null
  exec "${ssh_base[@]}" -t "$host" 'export PATH=/usr/local/bin:$PATH; exec ghostloot console'
}

client_restart_panel() {
  load_client
  ensure_tunnel
  remote restart-panel
  wait_local || { echo "panel not answering at $url" >&2; exit 1; }
  echo "panel     up   $url"
}

do_init() {
  local h="${1:-}" k="${2:-}" p="${3:-8090}"
  if [[ -z "$h" && -t 0 ]]; then
    read -r -p "SSH host (user@ip): " h
    read -r -p "SSH key path: " k
    read -r -p "Panel port [8090]: " p
    p="${p:-8090}"
  fi
  if [[ -z "$h" || -z "$k" ]]; then
    echo "usage: ghostloot init user@host /path/to/key [port]" >&2
    exit 2
  fi
  k="${k/#\~/$HOME}"
  if [[ ! -f "$k" ]]; then
    echo "key not found: $k" >&2
    exit 1
  fi
  mkdir -p "$HOME/.ghostloot"
  chmod 700 "$HOME/.ghostloot"
  {
    printf 'host=%q\n' "$h"
    printf 'key=%q\n' "$k"
    printf 'port=%q\n' "$p"
  } >"$CLIENT_CONF"
  chmod 600 "$CLIENT_CONF"
  echo "wrote $CLIENT_CONF"
  echo "next: ghostloot"
}

cmd="${1:-up}"
shift || true

case "$cmd" in
  help|-h|--help) usage; exit 0 ;;
  init) do_init "${1:-}" "${2:-}" "${3:-}" ;;
  *)
    case "$(mode)" in
      host)
        case "$cmd" in
          up|"") host_up ;;
          status) host_status ;;
          console) host_console ;;
          restart-panel) host_restart_panel ;;
          *) usage >&2; exit 2 ;;
        esac
        ;;
      client)
        case "$cmd" in
          up|"") client_up ;;
          status) client_status ;;
          console) client_console ;;
          restart-panel) client_restart_panel ;;
          *) usage >&2; exit 2 ;;
        esac
        ;;
      none)
        echo "GhostLoot is not configured on this machine." >&2
        echo >&2
        echo "  On the Evilginx server:  sudo ./install.sh" >&2
        echo "  On your laptop:          ghostloot init user@host /path/to/key" >&2
        exit 1
        ;;
    esac
    ;;
esac
