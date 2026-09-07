#!/usr/bin/env bash
# Back-compat name. Use ghostloot.sh
exec "$(cd "$(dirname "$0")" && pwd)/ghostloot.sh" "$@"
