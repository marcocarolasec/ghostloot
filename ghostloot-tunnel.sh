#!/usr/bin/env bash
# Laptop helper: open GhostLoot at localhost:8090, starting ssh -L only if needed.
# Never kills an existing tunnel. Set GHOSTLOOT_HOST and GHOSTLOOT_KEY.
set -euo pipefail

HOST="${GHOSTLOOT_HOST:?set GHOSTLOOT_HOST (user@host)}"
KEY="${GHOSTLOOT_KEY:?set GHOSTLOOT_KEY (path to SSH key)}"
PORT="${GHOSTLOOT_PORT:-8090}"
URL="http://127.0.0.1:${PORT}/"

alive() { curl -sf -o /dev/null --max-time 2 "$URL"; }

open_panel() {
  if command -v open >/dev/null 2>&1; then open "$URL"
  elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL"
  fi
  echo "GhostLoot · $URL"
}

if alive; then open_panel; exit 0; fi
if [[ ! -f "$KEY" ]]; then echo "No SSH key at $KEY" >&2; exit 1; fi

ssh -fN \
  -i "$KEY" \
  -o IdentitiesOnly=yes \
  -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=30 \
  -o ServerAliveCountMax=3 \
  -L "${PORT}:127.0.0.1:${PORT}" \
  "$HOST" 2>/tmp/ghostloot-tunnel.err || true

for _ in $(seq 1 20); do
  if alive; then open_panel; exit 0; fi
  sleep 0.3
done

echo "Tunnel started but $URL is not answering." >&2
if [[ -s /tmp/ghostloot-tunnel.err ]]; then echo "ssh: $(tr '\n' ' ' </tmp/ghostloot-tunnel.err)" >&2; fi
echo "Port busy? lsof -iTCP:${PORT} -sTCP:LISTEN" >&2
exit 1
