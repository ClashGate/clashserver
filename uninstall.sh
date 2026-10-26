#!/usr/bin/env bash
# clashserver 卸载入口（等同于 clashserver uninstall）
set -Eeuo pipefail
HERE="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
exec bash "$HERE/scripts/cmd/clashserver.sh" uninstall "$@"
