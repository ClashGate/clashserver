# shellcheck shell=bash
# clashserver 公共函数：常量、日志、交互、环境持久化、下载与安装文件

REPO_TARBALL=https://github.com/saulsburyroy/clashserver/archive/refs/heads/main.tar.gz
SELF_BIN=/usr/local/bin/clashserver
BIN=/usr/local/bin/mihomo
CONF_DIR=/etc/mihomo
CONF=$CONF_DIR/config.yaml
STATE=$CONF_DIR/nodes.tsv          # name port uuid private pub shortid sni
FRAG_REALITY=$CONF_DIR/listeners.reality.yaml
FRAG_EXTRA=$CONF_DIR/listeners.extra.yaml   # owned by the panel
CLIENT_DIR=/root/clashserver-client
UNIT=/etc/systemd/system/mihomo.service
LIB_DIR=/usr/local/lib/clashserver
CS_ETC=/etc/clashserver
ENV_FILE=$CS_ETC/clashserver.env
PANEL_CFG=$CS_ETC/panel.json
CADDYFILE=/etc/caddy/Caddyfile
CADDY_KEYRING=/usr/share/keyrings/caddy-stable-archive-keyring.gpg
CADDY_LIST=/etc/apt/sources.list.d/caddy-stable.list
REPO_API=https://api.github.com/repos/MetaCubeX/mihomo/releases/latest
LE_STAGING=https://acme-staging-v02.api.letsencrypt.org/directory
REALITY_SNI=www.sc.com
DOMAIN_RE='^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'

MODE=no-cert MODE_SET=0 NODES=3 VPS_NAME="" SERVER_IP="" FORCE=0
DOMAIN="" EMAIL="" TLS=production PANEL_PORT=8088
CADDY_OURS=0 PANEL_PASS="" PANEL_HASH="" SUB_TOKEN="" WARNINGS=()
STEP=0; TOTAL=8

log()  { printf '\033[1;34m[%d/%d]\033[0m %s\n' "$((++STEP))" "$TOTAL" "$*"; }

info() { printf '    %s\n' "$*"; }

warn() { printf '\033[1;33m警告：\033[0m%s\n' "$*" >&2; WARNINGS+=("$*"); }

die()  { printf '\033[1;31m错误：\033[0m%s\n' "$*" >&2; exit 1; }

need_root() { [[ $EUID -eq 0 ]] || die "请以 root 身份运行（可先执行 sudo -i 再运行安装命令）"; }

# ------------------------------------------------------------ one-click helpers
has_tty() { [[ -t 1 ]] && { : </dev/tty; } 2>/dev/null; }

ask() { # ask "提示" 默认值  -> 读取 /dev/tty（curl|bash 时 stdin 是脚本本身）
  local ans=""
  printf '%s' "$1" >/dev/tty
  read -r ans </dev/tty || true
  printf '%s' "${ans:-$2}"
}

check_os() {
  [[ -r /etc/os-release ]] || die "无法识别操作系统"
  . /etc/os-release
  [[ "${ID:-}" == debian || "${ID_LIKE:-}" == *debian* ]] || die "仅支持 Debian 系统（当前：${ID:-未知}）"
  command -v systemctl >/dev/null || die "需要 systemd"
}

arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    armv7l) echo armv7 ;;
    *) die "不支持的 CPU 架构：$(uname -m)" ;;
  esac
}

load_env() { # persisted install settings; CLI flags given this run win
  [[ -r $ENV_FILE ]] || return 0
  local k v
  while IFS='=' read -r k v; do
    v=${v%\"}; v=${v#\"}
    case "$k" in
      VPS_NAME)   [[ -n $VPS_NAME ]]  || VPS_NAME=$v ;;
      SERVER_IP)  [[ -n $SERVER_IP ]] || SERVER_IP=$v ;;
      MODE|DOMAIN|TLS|PANEL_PORT|CADDY_OURS) printf -v "$k" '%s' "$v" ;;
    esac
  done < "$ENV_FILE"
}

save_env() {
  install -d -m 755 "$CS_ETC"
  cat > "$ENV_FILE" <<EOF
MODE="$MODE"
VPS_NAME="$VPS_NAME"
SERVER_IP="$SERVER_IP"
DOMAIN="$DOMAIN"
TLS="$TLS"
PANEL_PORT="$PANEL_PORT"
CADDY_OURS="$CADDY_OURS"
EOF
  chmod 644 "$ENV_FILE"
}

svc_state() {
  local st
  st=$(systemctl is-active "$1" 2>/dev/null || true)
  case $st in
    active)   printf '\033[1;32m运行中\033[0m' ;;
    inactive) printf '\033[1;31m已停止\033[0m' ;;
    failed)   printf '\033[1;31m失败\033[0m' ;;
    *)        printf '%s' "${st:-未知}" ;;
  esac
}

require_installed() { [[ -f $STATE ]] || die "尚未安装，请先运行一键安装命令"; }

require_panel() { [[ $MODE == auto-cert && -f $PANEL_CFG ]] || die "该功能仅在自动证书模式下提供（当前：无证书模式）"; }

tls_label() {
  case $TLS in
    staging)  printf 'Let'"'"'s Encrypt 测试证书（不受信任）' ;;
    internal) printf 'Caddy 内部 CA（仅开发调试）' ;;
    *)        printf 'Let'"'"'s Encrypt 正式证书' ;;
  esac
}

fetch_repo() { # 下载公开仓库 main 分支到目录 $1（直连 GitHub，不用任何代理）
  printf '正在从 GitHub 下载 clashserver 文件……\n'
  curl -fsSL --retry 3 "$REPO_TARBALL" | tar -xz -C "$1" --strip-components=1 \
    || { rm -rf "$1"; die "下载失败：$REPO_TARBALL（请确认服务器可以访问 GitHub）"; }
  [[ -f $1/install.sh && -f $1/scripts/cmd/clashserver.sh ]] || { rm -rf "$1"; die "下载的文件不完整"; }
}

install_files() { # 把源码树 $CS_HOME 安装到 $LIB_DIR（先写新目录再整体替换），并把 clashserver 命令链接进 PATH
  local new=$LIB_DIR.new d
  rm -rf "$new"; install -d -m 755 "$new"
  for d in install.sh uninstall.sh panel resources scripts; do cp -r "$CS_HOME/$d" "$new/"; done
  rm -rf "$new/panel/__pycache__"
  chmod 755 "$new/install.sh" "$new/uninstall.sh" "$new/scripts/cmd/clashserver.sh" "$new/scripts/certsync.sh" "$new/panel/panel.py"
  rm -rf "$LIB_DIR.old"
  if [[ -d $LIB_DIR ]]; then mv "$LIB_DIR" "$LIB_DIR.old"; fi
  mv "$new" "$LIB_DIR"
  rm -rf "$LIB_DIR.old"
  ln -sfn "$LIB_DIR/scripts/cmd/clashserver.sh" "$SELF_BIN"
}
