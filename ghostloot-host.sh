#!/usr/bin/env bash
# Back-compat name. The command is `ghostloot`.
HERE="$(cd "$(dirname "$0")" && pwd)"
exec "$HERE/ghostloot.sh" "$@"
