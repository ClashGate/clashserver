#!/usr/bin/env bash
# clashserver: one-click Mihomo server installer for Debian.
# Usage: sudo ./install.sh [install|update|uninstall|info|reset-password] [options]
#   --mode no-cert|auto-cert   default no-cert (phase 1: VLESS+Reality only)
#   --nodes N --name NAME --ip ADDR --force
#   auto-cert: --domain DOMAIN [--email EMAIL] [--tls-staging | --tls-internal] [--panel-port PORT]
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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

MODE=no-cert NODES=3 VPS_NAME="" SERVER_IP="" FORCE=0
DOMAIN="" EMAIL="" TLS=production PANEL_PORT=8088
CADDY_OURS=0 PANEL_PASS="" WARNINGS=()
STEP=0; TOTAL=7

log()  { printf '\033[1;34m[%d/%d]\033[0m %s\n' "$((++STEP))" "$TOTAL" "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '\033[1;33mWARN:\033[0m %s\n' "$*" >&2; WARNINGS+=("$*"); }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
trap 'die "failed at line $LINENO: $BASH_COMMAND"' ERR

need_root() { [[ $EUID -eq 0 ]] || die "run as root (sudo)"; }

check_os() {
  [[ -r /etc/os-release ]] || die "cannot detect OS"
  . /etc/os-release
  [[ "${ID:-}" == debian || "${ID_LIKE:-}" == *debian* ]] || die "Debian (or derivative) required, got ${ID:-unknown}"
  command -v systemctl >/dev/null || die "systemd required"
}

arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    armv7l) echo armv7 ;;
    *) die "unsupported arch $(uname -m)" ;;
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

install_deps() {
  log "Installing dependencies"
  local missing=()
  for c in curl gzip jq openssl; do command -v "$c" >/dev/null || missing+=("$c"); done
  command -v ss >/dev/null || missing+=(iproute2)
  if [[ $MODE == auto-cert ]]; then
    command -v python3 >/dev/null || missing+=(python3)
    command -v gpg >/dev/null || missing+=(gnupg)
    command -v getent >/dev/null || missing+=(libc-bin)
  fi
  if ((${#missing[@]})); then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}" ca-certificates >/dev/null
  fi
}

install_core() {
  log "Installing latest stable Mihomo"
  local a rel tag url tmp
  a=$(arch)
  rel=$(curl -fsSL --retry 3 "$REPO_API") || die "cannot query GitHub releases (network?)"
  tag=$(jq -r .tag_name <<<"$rel")
  # stable "latest" endpoint already excludes prereleases; plain build name: mihomo-linux-<arch>-<tag>.gz
  url=$(jq -r --arg n "mihomo-linux-${a}-${tag}.gz" '.assets[] | select(.name==$n) | .browser_download_url' <<<"$rel")
  [[ -n "$url" ]] || die "no asset mihomo-linux-${a}-${tag}.gz in release $tag"
  tmp=$(mktemp)
  curl -fL --retry 3 -o "$tmp" "$url" || die "download failed: $url"
  gzip -dc "$tmp" > "$BIN.new" && rm -f "$tmp"
  chmod 755 "$BIN.new"
  "$BIN.new" -v >/dev/null || die "downloaded binary does not run"
  mv "$BIN.new" "$BIN"
  info "installed $tag -> $BIN"
}

detect_ip() {
  [[ -n "$SERVER_IP" ]] && return
  for u in https://api.ipify.org https://ifconfig.me https://ipv4.icanhazip.com; do
    SERVER_IP=$(curl -fsS -4 --max-time 5 "$u" 2>/dev/null | tr -d '[:space:]') && [[ -n "$SERVER_IP" ]] && return
  done
  die "cannot detect public IP; pass --ip ADDR"
}

rand_port() {
  local p
  while :; do
    p=$((RANDOM % 20000 + 20000))
    grep -q "	$p	" "$STATE" 2>/dev/null && continue
    [[ $p == "$PANEL_PORT" ]] && continue
    ss -ltun 2>/dev/null | grep -q ":$p " && continue
    echo "$p"; return
  done
}

ensure_user() {
  id mihomo >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin mihomo
  install -d -m 750 -o root -g mihomo "$CONF_DIR"
}

gen_nodes() {
  log "Generating $NODES VLESS+Reality nodes"
  : > "$STATE"; chmod 640 "$STATE"
  local i kp priv pub
  for ((i = 1; i <= NODES; i++)); do
    kp=$("$BIN" generate reality-keypair)
    priv=$(awk '/PrivateKey/{print $2}' <<<"$kp")
    pub=$(awk '/PublicKey/{print $2}' <<<"$kp")
    [[ -n "$priv" && -n "$pub" ]] || die "reality keypair generation failed"
    printf 'vless-reality-%d\t%s\t%s\t%s\t%s\t%s\t%s\n' "$i" "$(rand_port)" \
      "$(cat /proc/sys/kernel/random/uuid)" "$priv" "$pub" "$(openssl rand -hex 4)" \
      "$REALITY_SNI" >> "$STATE"
  done
}

validate_conf() {
  local d rc=0
  d=$(mktemp -d)
  SAFE_PATHS=$CONF_DIR "$BIN" -t -d "$d" -f "$CONF" >/dev/null || rc=$?
  rm -rf "$d"
  return "$rc"
}

# config.yaml = template with @@LISTENERS@@ <- reality fragment + panel (extra) fragment.
# Mirrors assemble_config() in panel/panel.py.
assemble_config() {
  awk -v r="$FRAG_REALITY" -v e="$FRAG_EXTRA" '
    /^@@LISTENERS@@$/ { while ((getline l < r) > 0) print l; while ((getline l < e) > 0) print l; next }
    { print }' "$LIB_DIR/server.yaml.tpl" > "$CONF.new"
  chmod 640 "$CONF.new"; chown root:mihomo "$CONF.new"
  mv -f "$CONF.new" "$CONF"
}

render_server() {
  log "Writing server config"
  local listeners="" name port uuid priv pub sid sni
  while IFS=$'\t' read -r name port uuid priv pub sid sni; do
    listeners+="  - name: $name
    type: vless
    port: $port
    listen: 0.0.0.0
    users:
      - username: user
        uuid: $uuid
        flow: xtls-rprx-vision
    reality-config:
      dest: $sni:443
      private-key: $priv
      short-id:
        - $sid
      server-names:
        - $sni
"
  done < "$STATE"
  install -d -m 755 "$LIB_DIR"
  install -m 644 "$SCRIPT_DIR/templates/server.yaml.tpl" "$LIB_DIR/server.yaml.tpl"
  printf '%s' "$listeners" > "$FRAG_REALITY"
  [[ -f $FRAG_EXTRA ]] || : > "$FRAG_EXTRA"
  chmod 640 "$FRAG_REALITY" "$FRAG_EXTRA"
  chown root:mihomo "$FRAG_REALITY" "$FRAG_EXTRA" "$STATE"
  assemble_config
  validate_conf || die "generated server config failed validation (mihomo -t)"
}

proxy_line() { # name port uuid pub sid sni
  printf '{"name":"%s|Clash|Reality","type":"vless","server":"%s","port":%s,"uuid":"%s","tls":true,"flow":"xtls-rprx-vision","client-fingerprint":"safari","skip-cert-verify":false,"reality-opts":{"public-key":"%s","short-id":"%s"},"network":"tcp","udp":true,"servername":"%s"}' \
    "$VPS_NAME-$1" "$SERVER_IP" "$2" "$3" "$4" "$5" "$6"
}

render_client() {
  log "Writing client config"
  local proxies="" names="" name port uuid priv pub sid sni line
  while IFS=$'\t' read -r name port uuid priv pub sid sni; do
    line=$(proxy_line "$name" "$port" "$uuid" "$pub" "$sid" "$sni")
    proxies+="    - $line"$'\n'
    names+="      - \"$VPS_NAME-$name|Clash|Reality\""$'\n'
  done < "$STATE"
  install -d -m 700 "$CLIENT_DIR"
  awk -v p="${proxies%$'\n'}" -v n="${names%$'\n'}" \
    '/^@@PROXIES@@$/{print p; next} /^@@PROXY_NAMES@@$/{print n; next} {print}' \
    "$SCRIPT_DIR/templates/client.yaml.tpl" > "$CLIENT_DIR/mihomo-client.yaml"
  chmod 600 "$CLIENT_DIR/mihomo-client.yaml"
  { echo "proxies:"; printf '%s' "$proxies"; } > "$CLIENT_DIR/proxies.yaml"
  chmod 600 "$CLIENT_DIR/proxies.yaml"
}

setup_service() {
  log "Setting up mihomo systemd service"
  install -m 644 "$SCRIPT_DIR/systemd/mihomo.service" "$UNIT"
  systemctl daemon-reload
  systemctl enable mihomo >/dev/null 2>&1
  systemctl restart mihomo
}

# ------------------------------------------------------------ auto-cert mode
preflight_cert() {
  [[ -n $DOMAIN ]] || die "--mode auto-cert requires --domain DOMAIN"
  DOMAIN=${DOMAIN,,}
  [[ $DOMAIN =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || die "invalid domain: $DOMAIN"
  [[ $PANEL_PORT =~ ^[0-9]+$ ]] && ((PANEL_PORT > 1024 && PANEL_PORT < 65536)) || die "--panel-port must be 1025-65535"
  local busy
  busy=$(ss -Hltnp 2>/dev/null | awk '$4 ~ /:(80|443)$/' | grep -v '"caddy"' || true)
  [[ -z $busy ]] || die "ports 80/443 are used by another process (stop it first):
$busy"
  if [[ $TLS == production ]]; then
    printf '\033[1;33mNOTE:\033[0m issuing a PRODUCTION Let'"'"'s Encrypt certificate. Use --tls-staging while testing (rate limits).\n'
  fi
}

check_dns() {
  [[ $TLS == internal ]] && return 0
  local ips
  ips=$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' || true)
  if [[ -z $ips ]]; then
    warn "$DOMAIN does not resolve. Create an A record -> $SERVER_IP (Cloudflare: DNS only / grey cloud recommended)."
  elif [[ " $ips " != *" $SERVER_IP "* ]]; then
    warn "$DOMAIN resolves to $ips, not $SERVER_IP. If this is a Cloudflare proxied (orange) record HTTP-01 may still work; otherwise fix DNS."
  else
    info "DNS ok: $DOMAIN -> $SERVER_IP"
  fi
}

install_caddy() {
  log "Installing Caddy"
  if command -v caddy >/dev/null; then
    if [[ -f $CADDYFILE ]] && ! grep -q '^# clashserver managed' "$CADDYFILE" && ! grep -q '/usr/share/caddy' "$CADDYFILE"; then
      die "existing customised $CADDYFILE found; refusing to overwrite (custom reverse-proxy mode is phase 3)"
    fi
    info "using existing $(caddy version | head -n1)"
    return
  fi
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https >/dev/null
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor --yes -o "$CADDY_KEYRING" \
    || die "cannot fetch Caddy repo key"
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt > "$CADDY_LIST" || die "cannot fetch Caddy repo list"
  chmod 644 "$CADDY_KEYRING" "$CADDY_LIST"
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq caddy >/dev/null || die "apt install caddy failed"
  CADDY_OURS=1
  save_env
  info "installed $(caddy version | head -n1)"
}

write_caddyfile() {
  log "Writing Caddyfile ($DOMAIN, tls=$TLS)"
  local g="	admin localhost:2019" site=""
  [[ -n $EMAIL ]] && g+=$'\n'"	email $EMAIL"
  [[ $TLS == staging ]] && g+=$'\n'"	acme_ca $LE_STAGING"
  [[ $TLS == internal ]] && site="	tls internal"
  [[ -f $CADDYFILE && ! -f $CADDYFILE.clashserver.bak ]] && ! grep -q '^# clashserver managed' "$CADDYFILE" \
    && cp -a "$CADDYFILE" "$CADDYFILE.clashserver.bak"
  awk -v g="$g" -v s="$site" -v d="$DOMAIN" -v p="$PANEL_PORT" '
    /^@@GLOBAL_OPTS@@$/ { print g; next }
    /^@@SITE_TLS@@$/    { if (s != "") print s; next }
    { gsub(/@@DOMAIN@@/, d); gsub(/@@PANEL_PORT@@/, p); print }' \
    "$SCRIPT_DIR/templates/Caddyfile.tpl" > "$CADDYFILE.new"
  caddy validate --config "$CADDYFILE.new" --adapter caddyfile >/dev/null 2>&1 \
    || { caddy validate --config "$CADDYFILE.new" --adapter caddyfile >&2 || true; die "Caddyfile validation failed"; }
  mv -f "$CADDYFILE.new" "$CADDYFILE"
  chmod 644 "$CADDYFILE"
  systemctl enable caddy >/dev/null 2>&1
  systemctl restart caddy
}

sync_cert() {
  log "Waiting for certificate and syncing to $CONF_DIR/certs"
  install -m 755 "$SCRIPT_DIR/scripts/certsync.sh" "$LIB_DIR/certsync.sh"
  install -m 644 "$SCRIPT_DIR/systemd/clashserver-certsync.service" /etc/systemd/system/
  install -m 644 "$SCRIPT_DIR/systemd/clashserver-certsync.timer" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now clashserver-certsync.timer >/dev/null 2>&1
  local i
  for ((i = 0; i < 40; i++)); do
    if "$LIB_DIR/certsync.sh" >/dev/null 2>&1; then
      info "certificate synced: $CONF_DIR/certs/{fullchain,privkey}.pem (root:mihomo 0640)"
      su -s /bin/sh mihomo -c "test -r $CONF_DIR/certs/privkey.pem" || die "mihomo user cannot read synced key"
      return 0
    fi
    sleep 3
  done
  warn "no certificate after 120s. Check: DNS A record -> $SERVER_IP, ports 80/443 open, 'journalctl -u caddy -n 50'. Then run: systemctl start clashserver-certsync"
}

setup_panel() {
  log "Setting up clashserve panel"
  install -d -m 755 "$LIB_DIR" "$CS_ETC"
  install -m 755 "$SCRIPT_DIR/panel/panel.py" "$LIB_DIR/panel.py"
  [[ -f $CS_ETC/inbounds.json ]] || { echo '[]' > "$CS_ETC/inbounds.json"; chmod 600 "$CS_ETC/inbounds.json"; }
  set_panel_password
  install -m 644 "$SCRIPT_DIR/systemd/clashserve.service" /etc/systemd/system/clashserve.service
  systemctl daemon-reload
  systemctl enable clashserve >/dev/null 2>&1
  systemctl restart clashserve
}

set_panel_password() {
  local hash
  PANEL_PASS=$(openssl rand -base64 32 | tr -dc 'A-Za-z0-9' | head -c 20)
  hash=$(printf '%s\n' "$PANEL_PASS" | python3 "$LIB_DIR/panel.py" hash-password)
  jq -n --arg h "$hash" --argjson p "$PANEL_PORT" \
    '{username:"admin", password_hash:$h, listen:"127.0.0.1", port:$p}' > "$PANEL_CFG.new"
  chmod 600 "$PANEL_CFG.new"; mv -f "$PANEL_CFG.new" "$PANEL_CFG"
}

# ------------------------------------------------------------ verify / output
verify() {
  log "Verifying"
  sleep 2
  systemctl is-active --quiet mihomo || { journalctl -u mihomo -n 20 --no-pager >&2; die "mihomo service is not active"; }
  local name port rest
  while IFS=$'\t' read -r name port rest; do
    ss -ltn | grep -q ":$port " || die "listener $name not listening on $port"
    info "listening: $name :$port"
  done < "$STATE"
  [[ $MODE == auto-cert ]] || return 0
  local i
  for ((i = 0; i < 10; i++)); do curl -fsS "http://127.0.0.1:$PANEL_PORT/healthz" >/dev/null 2>&1 && break; sleep 1; done
  ((i < 10)) || { journalctl -u clashserve -n 20 --no-pager >&2; die "panel not responding on 127.0.0.1:$PANEL_PORT"; }
  info "panel: 127.0.0.1:$PANEL_PORT ok"
  if curl -fsSk --max-time 10 --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/healthz" >/dev/null 2>&1; then
    info "caddy: https://$DOMAIN -> panel ok"
  else
    warn "https://$DOMAIN not serving yet (certificate pending?). See 'journalctl -u caddy -n 50'."
  fi
}

print_panel() {
  printf '\nPanel:    https://%s\n' "$DOMAIN"
  printf 'Username: admin\n'
  [[ -n $PANEL_PASS ]] && printf 'Password: %s   (shown once; reset with: %s reset-password)\n' "$PANEL_PASS" "$0"
  case $TLS in
    staging)  printf 'TLS:      Let'"'"'s Encrypt STAGING (browser will warn; not publicly trusted)\n' ;;
    internal) printf 'TLS:      Caddy internal CA (dev only, not publicly trusted)\n' ;;
  esac
}

print_summary() {
  printf '\n\033[1;32mInstall complete.\033[0m Open these TCP ports in your cloud firewall:'
  [[ $MODE == auto-cert ]] && printf ' 80 443'
  awk -F'\t' '{printf " %s", $2}' "$STATE"; printf '\n\n'
  cat "$CLIENT_DIR/proxies.yaml"
  printf '\nClient config directory: %s\n  - mihomo-client.yaml (full client config)\n  - proxies.yaml\n' "$CLIENT_DIR"
  [[ $MODE == auto-cert ]] && print_panel
  if ((${#WARNINGS[@]})); then
    printf '\n\033[1;33mWarnings:\033[0m\n'; printf '  - %s\n' "${WARNINGS[@]}"
  fi
}

# ------------------------------------------------------------ actions
do_install() {
  need_root; check_os
  if [[ -f $STATE ]]; then
    ((FORCE)) || die "already installed ($STATE exists). Use 'info', 'update', 'uninstall', or re-run with --force to wipe and reinstall."
    warn "--force: removing previous installation"
    ( do_uninstall ) >/dev/null
  fi
  [[ $MODE == auto-cert ]] && TOTAL=12
  [[ -n $VPS_NAME ]] || VPS_NAME=$(hostname)
  install_deps
  [[ $MODE == auto-cert ]] && preflight_cert
  detect_ip; save_env
  install_core; ensure_user; gen_nodes; render_server; render_client; setup_service
  if [[ $MODE == auto-cert ]]; then
    check_dns; install_caddy; write_caddyfile; sync_cert; setup_panel
  fi
  verify
  print_summary
}

do_update() {
  need_root; STEP=0; TOTAL=2
  install_deps; install_core
  systemctl restart mihomo; info "restarted"
}

do_info() {
  [[ -f $STATE ]] || die "not installed"
  load_env
  [[ -n $VPS_NAME ]] || VPS_NAME=$(hostname)
  detect_ip
  echo "proxies:"
  while IFS=$'\t' read -r name port uuid priv pub sid sni; do
    echo "    - $(proxy_line "$name" "$port" "$uuid" "$pub" "$sid" "$sni")"
  done < "$STATE"
  echo "Client config directory: $CLIENT_DIR"
  [[ $MODE == auto-cert ]] && printf 'Panel: https://%s (admin)\n' "$DOMAIN"
  return 0
}

do_reset_password() {
  need_root; load_env
  [[ $MODE == auto-cert && -f $PANEL_CFG ]] || die "panel not installed (auto-cert mode only)"
  set_panel_password
  systemctl restart clashserve
  printf 'Panel: https://%s\nUsername: admin\nPassword: %s\n' "$DOMAIN" "$PANEL_PASS"
}

do_uninstall() {
  need_root; load_env
  systemctl disable --now clashserve clashserver-certsync.timer clashserver-certsync.service 2>/dev/null || true
  rm -f /etc/systemd/system/clashserve.service /etc/systemd/system/clashserver-certsync.{service,timer}
  if [[ $CADDY_OURS == 1 ]]; then
    systemctl disable --now caddy 2>/dev/null || true
    DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq caddy >/dev/null 2>&1 || true
    rm -rf /etc/caddy /var/lib/caddy "$CADDY_KEYRING" "$CADDY_LIST"
  elif [[ -f $CADDYFILE ]] && grep -q '^# clashserver managed' "$CADDYFILE"; then
    if [[ -f $CADDYFILE.clashserver.bak ]]; then mv -f "$CADDYFILE.clashserver.bak" "$CADDYFILE"; fi
    systemctl reload caddy 2>/dev/null || true
  fi
  systemctl disable --now mihomo 2>/dev/null || true
  rm -f "$UNIT" "$BIN"
  systemctl daemon-reload
  rm -rf "$CONF_DIR" "$CLIENT_DIR" /var/lib/mihomo "$LIB_DIR" "$CS_ETC"
  if id mihomo >/dev/null 2>&1; then userdel mihomo || true; fi
  echo "Uninstalled mihomo, panel, Caddy (if installed by clashserver), certificates, config and client files."
}

ACTION=install
while (($#)); do
  case "$1" in
    install|update|uninstall|info|reset-password) ACTION=$1 ;;
    --mode)   MODE=${2:?}; shift ;;
    --no-cert) MODE=no-cert ;;
    --nodes)  NODES=${2:?}; shift ;;
    --name)   VPS_NAME=${2:?}; shift ;;
    --ip)     SERVER_IP=${2:?}; shift ;;
    --force)  FORCE=1 ;;
    --domain) DOMAIN=${2:?}; shift ;;
    --email)  EMAIL=${2:?}; shift ;;
    --tls-staging)  TLS=staging ;;
    --tls-internal) TLS=internal ;;
    --panel-port)   PANEL_PORT=${2:?}; shift ;;
    -h|--help) sed -n 2,6p "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
  shift
done
[[ $MODE == no-cert || $MODE == auto-cert ]] || die "--mode must be no-cert or auto-cert"
[[ $NODES =~ ^[1-9][0-9]*$ ]] || die "--nodes must be a positive integer"

"do_${ACTION//-/_}"
