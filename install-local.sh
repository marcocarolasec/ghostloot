#!/usr/bin/env bash
# Put `ghostloot` on this laptop's PATH. No root needed.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BINDIR="${GHOSTLOOT_BINDIR:-$HOME/.local/bin}"

mkdir -p "$BINDIR"
install -m 0755 "$HERE/ghostloot.sh" "$BINDIR/ghostloot"

echo "installed $BINDIR/ghostloot"
case ":$PATH:" in
  *":$BINDIR:"*) ;;
  *)
    echo "add $BINDIR to PATH, e.g.  echo 'export PATH=\"$BINDIR:\$PATH\"' >> ~/.zshrc"
    ;;
esac

if [[ -f $HOME/.ghostloot/config ]]; then
  echo "config ok  $HOME/.ghostloot/config"
  echo "next:      ghostloot"
else
  echo "next:      ghostloot init user@your-server /path/to/ssh-key"
fi
