# shellcheck shell=bash
# clashserver 自动证书模式：Caddy + Let's Encrypt、证书同步

# ------------------------------------------------------------ auto-cert mode
preflight_cert() {
  [[ -n $DOMAIN ]] || die "自动证书模式需要域名：-d 你的域名"
  DOMAIN=${DOMAIN,,}
  [[ $DOMAIN =~ $DOMAIN_RE ]] || die "域名格式不正确：$DOMAIN"
  [[ $PANEL_PORT =~ ^[0-9]+$ ]] && ((PANEL_PORT > 1024 && PANEL_PORT < 65536)) || die "--panel-port 必须在 1025-65535 之间"
  local busy
  busy=$(ss -Hltnp 2>/dev/null | awk '$4 ~ /:(80|443)$/' | grep -v '"caddy"' || true)
  [[ -z $busy ]] || die "80/443 端口已被其他程序占用，请先停止：
$busy"
}

check_dns() {
  [[ $TLS == internal ]] && return 0
  local ips
  ips=$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' || true)
  if [[ -z $ips ]]; then
    warn "域名 $DOMAIN 无法解析。请添加 A 记录指向 $SERVER_IP（Cloudflare 请设为灰云 DNS only）"
  elif [[ " $ips " != *" $SERVER_IP "* ]]; then
    warn "域名 $DOMAIN 解析到 ${ips% }，而不是本机 $SERVER_IP。若是 Cloudflare 橙云请改为灰云，否则证书可能申请失败"
  else
    info "域名解析正常：$DOMAIN -> $SERVER_IP"
  fi
}

install_caddy() {
  log "安装 Caddy"
  if command -v caddy >/dev/null; then
    if [[ -f $CADDYFILE ]] && ! grep -q '^# clashserver managed' "$CADDYFILE" && ! grep -q '/usr/share/caddy' "$CADDYFILE"; then
      die "检测到已自定义的 $CADDYFILE，为避免覆盖已停止（自定义反代模式将在后续版本支持）"
    fi
    info "使用已有的 $(caddy version | head -n1)"
    return
  fi
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https >/dev/null
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor --yes -o "$CADDY_KEYRING" \
    || die "无法获取 Caddy 软件源密钥"
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt > "$CADDY_LIST" || die "无法获取 Caddy 软件源"
  chmod 644 "$CADDY_KEYRING" "$CADDY_LIST"
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq caddy >/dev/null || die "Caddy 安装失败"
  CADDY_OURS=1
  save_env
  info "已安装 $(caddy version | head -n1)"
}

write_caddyfile() {
  log "写入 Caddyfile（$DOMAIN，证书：$(tls_label)）"
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
    "$LIB_DIR/resources/Caddyfile.tpl" > "$CADDYFILE.new"
  caddy validate --config "$CADDYFILE.new" --adapter caddyfile >/dev/null 2>&1 \
    || { caddy validate --config "$CADDYFILE.new" --adapter caddyfile >&2 || true; die "Caddyfile 校验失败"; }
  mv -f "$CADDYFILE.new" "$CADDYFILE"
  chmod 644 "$CADDYFILE"
  systemctl enable caddy >/dev/null 2>&1
  systemctl restart caddy
}

sync_cert() {
  log "等待证书签发并同步给 Mihomo"
  install -m 644 "$LIB_DIR/scripts/init/clashserver-certsync.service" "$LIB_DIR/scripts/init/clashserver-certsync.timer" \
    /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now clashserver-certsync.timer >/dev/null 2>&1
  local i
  for ((i = 0; i < 40; i++)); do
    if "$LIB_DIR/scripts/certsync.sh" >/dev/null 2>&1; then
      info "证书已同步到 $CONF_DIR/certs/（root:mihomo 0640）"
      su -s /bin/sh mihomo -c "test -r $CONF_DIR/certs/privkey.pem" || die "mihomo 用户无法读取证书私钥"
      return 0
    fi
    sleep 3
  done
  warn "120 秒内未拿到证书。请检查：域名 A 记录是否指向 $SERVER_IP、80/443 端口是否放行、日志 journalctl -u caddy -n 50；修复后执行 systemctl start clashserver-certsync"
}
