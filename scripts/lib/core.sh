# shellcheck shell=bash
# clashserver Mihomo 相关：依赖、内核、Reality 节点、服务端/客户端配置、systemd

install_deps() {
  log "安装依赖"
  local missing=()
  for c in curl gzip jq openssl; do command -v "$c" >/dev/null || missing+=("$c"); done
  command -v ss >/dev/null || missing+=(iproute2)
  if [[ $MODE == auto-cert ]]; then
    command -v python3 >/dev/null || missing+=(python3)
    command -v socat >/dev/null || missing+=(socat)     # acme.sh standalone 模式需要
    command -v getent >/dev/null || missing+=(libc-bin)
  fi
  if ((${#missing[@]})); then
    info "apt 安装：${missing[*]}"
    local i
    for i in 1 2 3; do apt-get update -qq >/dev/null 2>&1 && break; ((i < 3)) || die "apt-get update 失败，请检查软件源和网络"; sleep 5; done
    for i in 1 2 3; do
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}" ca-certificates >/dev/null 2>&1 && break
      ((i < 3)) || die "依赖安装失败：${missing[*]}"; sleep 5
    done
  fi
}

install_core() {
  log "安装最新稳定版 Mihomo 内核"
  local a rel tag url tmp
  a=$(arch)
  rel=$(curl -fsSL --retry 3 "$REPO_API") || die "无法获取 Mihomo 版本信息（请确认服务器可以访问 GitHub）"
  tag=$(jq -r .tag_name <<<"$rel")
  # stable "latest" endpoint already excludes prereleases; plain build name: mihomo-linux-<arch>-<tag>.gz
  url=$(jq -r --arg n "mihomo-linux-${a}-${tag}.gz" '.assets[] | select(.name==$n) | .browser_download_url' <<<"$rel")
  [[ -n "$url" ]] || die "版本 $tag 中没有找到 mihomo-linux-${a}-${tag}.gz"
  tmp=$(mktemp)
  curl -fsSL --retry 3 -o "$tmp" "$url" || die "下载失败：$url"
  gzip -dc "$tmp" > "$BIN.new" && rm -f "$tmp"
  chmod 755 "$BIN.new"
  "$BIN.new" -v >/dev/null || die "下载的 Mihomo 无法运行"
  mv "$BIN.new" "$BIN"
  info "已安装 $tag -> $BIN"
}

detect_ip() {
  [[ -n "$SERVER_IP" ]] && return
  for u in https://api.ipify.org https://ifconfig.me https://ipv4.icanhazip.com; do
    SERVER_IP=$(curl -fsS -4 --max-time 5 "$u" 2>/dev/null | tr -d '[:space:]') && [[ -n "$SERVER_IP" ]] && return
  done
  if has_tty; then
    while [[ ! $SERVER_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; do
      SERVER_IP=$(ask '无法自动探测公网 IP，请手动输入本机公网 IPv4：' '')
    done
    return
  fi
  die "无法探测公网 IP，请检查服务器网络"
}

rand_port() {
  local p
  while :; do
    p=$((RANDOM % 20000 + 20000))
    grep -q "	$p	" "$STATE" 2>/dev/null && continue
    [[ $p == "$PANEL_PORT" || $p == "${CONTROLLER_PORT:-7896}" ]] && continue
    ss -ltun 2>/dev/null | grep -q ":$p " && continue
    echo "$p"; return
  done
}

ensure_user() {
  id mihomo >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin mihomo
  install -d -m 750 -o root -g mihomo "$CONF_DIR"
}

gen_nodes() {
  log "生成 $NODES 个 VLESS Reality 节点"
  : > "$STATE"; chmod 640 "$STATE"
  local i kp priv pub
  for ((i = 1; i <= NODES; i++)); do
    kp=$("$BIN" generate reality-keypair)
    priv=$(awk '/PrivateKey/{print $2}' <<<"$kp")
    pub=$(awk '/PublicKey/{print $2}' <<<"$kp")
    [[ -n "$priv" && -n "$pub" ]] || die "Reality 密钥对生成失败"
    printf 'vless-reality-%d\t%s\t%s\t%s\t%s\t%s\t%s\n' "$i" "$(rand_port)" \
      "$(cat /proc/sys/kernel/random/uuid)" "$priv" "$pub" "$(openssl rand -hex 4)" \
      "$REALITY_SNI" >> "$STATE"
  done
}

validate_conf() {
  local d rc=0
  d=$(mktemp -d)
  mkdir -p "$d/ui"   # 避免 mihomo -t 校验时临时下载 external-ui
  SAFE_PATHS=$CONF_DIR "$BIN" -t -d "$d" -f "$CONF" >/dev/null || rc=$?
  rm -rf "$d"
  return "$rc"
}

ensure_mihomo_secret() {
  [[ $MODE == auto-cert ]] || return 0
  if [[ -z ${MIHOMO_SECRET:-} ]]; then
    MIHOMO_SECRET=$(openssl rand -base64 32 | tr -dc 'A-Za-z0-9' | head -c 20)
    save_env
  fi
}

render_controller() {
  if [[ $MODE == auto-cert ]]; then
    ensure_mihomo_secret
    [[ -f $CONF_DIR/certs/fullchain.pem && -f $CONF_DIR/certs/privkey.pem ]] \
      || "$LIB_DIR/scripts/certctl.sh" selfsign >/dev/null
    cat > "$FRAG_CONTROLLER" <<EOF
external-controller-tls: "0.0.0.0:${CONTROLLER_PORT:-7896}"
tls:
  certificate: $CONF_DIR/certs/fullchain.pem
  private-key: $CONF_DIR/certs/privkey.pem
external-controller-cors:
  allow-origins:
    - '*'
  allow-private-network: true
secret: "$MIHOMO_SECRET"
external-ui: ui
external-ui-url: "https://github.com/Zephyruso/zashboard/releases/latest/download/dist-cdn-fonts.zip"
EOF
  else
    echo "# No external-controller in no-cert mode." > "$FRAG_CONTROLLER"
  fi
  chmod 640 "$FRAG_CONTROLLER"; chown root:mihomo "$FRAG_CONTROLLER"
}

# config.yaml = template with @@CONTROLLER@@ and @@LISTENERS@@ <- reality fragment + panel (extra) fragment.
# Mirrors assemble_config() in panel/panel.py.
assemble_config() {
  [[ -f $FRAG_CONTROLLER ]] || render_controller
  awk -v c="$FRAG_CONTROLLER" -v r="$FRAG_REALITY" -v e="$FRAG_EXTRA" '
    /^@@CONTROLLER@@$/ { while ((getline l < c) > 0) print l; next }
    /^@@LISTENERS@@$/  { while ((getline l < r) > 0) print l; while ((getline l < e) > 0) print l; next }
    { print }' "$LIB_DIR/resources/server.yaml.tpl" > "$CONF.new"
  chmod 640 "$CONF.new"; chown root:mihomo "$CONF.new"
  mv -f "$CONF.new" "$CONF"
}

render_server() {
  log "写入服务端配置"
  render_controller
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
  printf '%s' "$listeners" > "$FRAG_REALITY"
  [[ -f $FRAG_EXTRA ]] || : > "$FRAG_EXTRA"
  chmod 640 "$FRAG_REALITY" "$FRAG_EXTRA"
  chown root:mihomo "$FRAG_REALITY" "$FRAG_EXTRA" "$STATE"
  assemble_config
  validate_conf || die "生成的服务端配置未通过校验（mihomo -t）"
}

proxy_line() { # name port uuid pub sid sni
  printf '{"name":"%s|Clash|Reality","type":"vless","server":"%s","port":%s,"uuid":"%s","tls":true,"flow":"xtls-rprx-vision","client-fingerprint":"safari","skip-cert-verify":false,"reality-opts":{"public-key":"%s","short-id":"%s"},"network":"tcp","udp":true,"servername":"%s"}' \
    "$VPS_NAME-$1" "$SERVER_IP" "$2" "$3" "$4" "$5" "$6"
}

render_client() {
  log "生成客户端配置"
  local proxies="" names="" name port uuid priv pub sid sni line cname
  while IFS=$'\t' read -r name port uuid priv pub sid sni; do
    [[ -n $name ]] || continue
    line=$(proxy_line "$name" "$port" "$uuid" "$pub" "$sid" "$sni")
    proxies+="    - $line"$'\n'
    names+="      - \"$VPS_NAME-$name|Clash|Reality\""$'\n'
  done < "$STATE"
  if [[ -f $CS_ETC/inbounds.json ]]; then
    while IFS=$'\t' read -r line cname; do
      [[ -n $line ]] || continue
      proxies+="    - $line"$'\n'
      names+="      - $cname"$'\n'
    done < <(jq -r '.[] | "\(.client | tojson)\t\(.client.name | tojson)"' "$CS_ETC/inbounds.json" 2>/dev/null || true)
  fi
  install -d -m 700 "$CLIENT_DIR"
  awk -v p="${proxies%$'\n'}" -v n="${names%$'\n'}" \
    '/^@@PROXIES@@$/{print p; next} /^@@PROXY_NAMES@@$/{print n; next} {print}' \
    "$LIB_DIR/resources/client.yaml.tpl" > "$CLIENT_DIR/mihomo-client.yaml"
  chmod 600 "$CLIENT_DIR/mihomo-client.yaml"
  { echo "proxies:"; printf '%s' "$proxies"; } > "$CLIENT_DIR/proxies.yaml"
  chmod 600 "$CLIENT_DIR/proxies.yaml"
}

open_firewall() { # 本机启用了 ufw 时自动放行所需端口（云服务商安全组仍需自行放行）
  command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active' || return 0
  local p ports=()
  if [[ $MODE == auto-cert ]]; then
    [[ ${CERT_MODE:-port} == port ]] && ports+=(80/tcp)
    [[ $PANEL_PORT == 80 && ${CERT_MODE:-port} == port ]] || ports+=("$PANEL_PORT/tcp")
    ports+=("${CONTROLLER_PORT:-7896}/tcp")
  fi
  while IFS=$'\t' read -r _ p _; do ports+=("$p/tcp"); done < "$STATE"
  for p in "${ports[@]}"; do ufw allow "$p" >/dev/null 2>&1 || true; done
  info "检测到 ufw 已启用，已放行：${ports[*]}"
}

setup_service() {
  log "配置 systemd 服务"
  install -m 644 "$LIB_DIR/scripts/init/mihomo.service" "$UNIT"
  systemctl daemon-reload
  systemctl enable mihomo >/dev/null 2>&1
  systemctl restart mihomo
}
