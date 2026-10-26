#!/usr/bin/env bash
# clashserver 一键安装入口
#
#   curl -fsSL https://raw.githubusercontent.com/saulsburyroy/clashserver/main/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/saulsburyroy/clashserver/main/install.sh | bash -s -- -d 你的域名
#
# 通过 curl|bash 运行时只有本文件：先从公开仓库下载完整文件（直连 GitHub，不使用任何代理），
# 再交给 scripts/cmd/clashserver.sh 执行安装。参数说明：bash install.sh help
set -Eeuo pipefail

REPO_TARBALL=https://github.com/saulsburyroy/clashserver/archive/refs/heads/main.tar.gz
_src=${BASH_SOURCE[0]:-}
if [[ -n $_src && -f $_src ]]; then HERE="$(cd "$(dirname "$_src")" && pwd)"; else HERE=""; fi

die() { printf '\033[1;31m错误：\033[0m%s\n' "$*" >&2; exit 1; }

if [[ -n $HERE && -f $HERE/scripts/cmd/clashserver.sh ]]; then
  CS_DEFAULT_ACTION=install exec bash "$HERE/scripts/cmd/clashserver.sh" "$@"
fi

command -v curl >/dev/null || die "缺少 curl，请先执行：apt-get install -y curl"
command -v tar >/dev/null || die "缺少 tar，请先执行：apt-get install -y tar"
tmp=$(mktemp -d /tmp/clashserver.XXXXXX)
printf '正在从 GitHub 下载 clashserver……\n'
curl -fsSL --retry 3 "$REPO_TARBALL" | tar -xz -C "$tmp" --strip-components=1 \
  || { rm -rf "$tmp"; die "下载失败：$REPO_TARBALL（请确认服务器可以访问 GitHub）"; }
[[ -f $tmp/scripts/cmd/clashserver.sh ]] || { rm -rf "$tmp"; die "下载的文件不完整"; }
CS_BOOTSTRAP_TMP=$tmp CS_DEFAULT_ACTION=install exec bash "$tmp/scripts/cmd/clashserver.sh" "$@"
