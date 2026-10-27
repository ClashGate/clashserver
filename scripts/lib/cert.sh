# shellcheck shell=bash
# clashserver 自动证书模式：acme.sh 申请 Let's Encrypt 证书，Mihomo 入站与面板直接共用

# ------------------------------------------------------------ auto-cert mode
preflight_cert() {
  [[ -n $DOMAIN ]] || die "自动证书模式需要域名"
  DOMAIN=${DOMAIN,,}
  [[ -n ${PANEL_PORT:-} ]] || PANEL_PORT=$(rand_port)
  [[ $PANEL_PORT =~ ^[0-9]+$ ]] && ((PANEL_PORT >= 1 && PANEL_PORT <= 65535)) || die "管理面板端口无效：$PANEL_PORT"
  [[ $PANEL_PORT != "${CONTROLLER_PORT:-7896}" ]] || die "管理面板端口不能与 Mihomo 控制端口（${CONTROLLER_PORT:-7896}）相同"
  local busy
  busy=$(ss -Hltnp "sport = :$PANEL_PORT or sport = :${CONTROLLER_PORT:-7896}" 2>/dev/null || true)
  [[ -z $busy ]] || die "端口 $PANEL_PORT / ${CONTROLLER_PORT:-7896} 已被占用，请先停止占用程序：
$busy"
  if [[ ${CERT_MODE:-port} == dns ]]; then
    [[ $DOMAIN =~ $WILDCARD_DOMAIN_RE ]] || die "域名格式不正确：$DOMAIN"
    [[ $TLS == internal || -n ${CF_TOKEN:-} ]] || die "DNS API 模式需要提供 Cloudflare API Token"
  else
    [[ $DOMAIN != \*.* ]] || die "通配符域名（$DOMAIN）仅支持「DNS API 模式」"
    [[ $DOMAIN =~ $DOMAIN_RE ]] || die "域名格式不正确：$DOMAIN"
    busy=$(ss -Hltnp 'sport = :80' 2>/dev/null || true)
    [[ -z $busy ]] || die "80 端口已被其他程序占用（端口模式申请证书需要临时占用 80 端口），请先停止占用程序或改用「DNS API 模式」：
$busy"
  fi
}

check_dns() {
  # 开发自签模式或 DNS API 模式无需检查本机 A/AAAA 记录（DNS API 通过添加 TXT 记录验证，且支持泛域名）
  [[ $TLS == internal || ${CERT_MODE:-port} == dns ]] && return 0
  local ips v6 mine6 a bad6=""
  ips=$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' || true)
  # AAAA：Let's Encrypt 优先走 IPv6 验证，AAAA 指向别处（或本机没有该 IPv6）会导致申请失败
  v6=$(getent ahostsv6 "$DOMAIN" 2>/dev/null | awk '$1 !~ /^::ffff:/ {print $1}' | sort -u || true)
  mine6=$(ip -6 addr show scope global 2>/dev/null | awk '/inet6/{sub(/\/.*/, "", $2); print $2}' || true)
  for a in $v6; do grep -qxF "$a" <<<"$mine6" || bad6+="$a "; done
  local msg=""
  if [[ -z $ips ]]; then
    msg="域名 $DOMAIN 无法解析。请添加 A 记录指向 $SERVER_IP（Cloudflare 请设为灰云 DNS only）"
  elif [[ " $ips " != *" $SERVER_IP "* ]]; then
    msg="域名 $DOMAIN 解析到 ${ips% }，而不是本机 $SERVER_IP。若是 Cloudflare 橙云请改为灰云，否则端口模式无法申请证书"
  elif [[ -n $bad6 ]]; then
    msg="域名 $DOMAIN 有 AAAA 记录 ${bad6% }，但它不是本机的 IPv6 地址。Let's Encrypt 会优先用 IPv6 验证，请删除该 AAAA 记录（或改为本机 IPv6）"
  else
    info "域名解析正常：$DOMAIN -> $SERVER_IP"; return 0
  fi
  warn "$msg"
  # 交互安装时让用户决定：现在修 DNS 再装，或先装上（临时证书），解析生效后自动签发
  if has_tty && [[ $(ask '域名解析不正确，仍要继续安装吗？（继续则先用临时证书，解析生效后每小时自动重试签发）[Y/n]：' y) == [nN]* ]]; then
    printf '已取消。请先把域名 A 记录指向 %s，再重新运行安装命令。\n' "$SERVER_IP"; exit 0
  fi
  return 0
}

install_acme() { # 证书申请工具 acme.sh（与常见一键脚本相同；固定版本，装到 /etc/clashserver/acme.sh，不改 root 的 crontab / profile）
  log "安装证书申请工具 acme.sh"
  [[ $TLS == internal ]] && { info "开发模式（自签证书），跳过"; return 0; }
  if [[ -x $ACME_HOME/acme.sh ]] && "$ACME_HOME/acme.sh" --home "$ACME_HOME" --version 2>/dev/null | grep -q "v$ACMESH_VERSION"; then
    info "已存在 acme.sh v$ACMESH_VERSION"; return 0
  fi
  local url tmp opts=()
  url="https://github.com/acmesh-official/acme.sh/archive/refs/tags/$ACMESH_VERSION.tar.gz"
  tmp=$(mktemp -d)
  curl -fsSL --retry 3 "$url" | tar -xz -C "$tmp" --strip-components=1 || { rm -rf "$tmp"; die "下载 acme.sh 失败：$url"; }
  [[ -n $EMAIL ]] && opts+=(--accountemail "$EMAIL")
  ( cd "$tmp" && ./acme.sh --install --home "$ACME_HOME" --no-cron --no-profile "${opts[@]}" >/dev/null 2>&1 ) \
    || { rm -rf "$tmp"; die "acme.sh 安装失败"; }
  rm -rf "$tmp"
  chmod 700 "$ACME_HOME"
  info "已安装 acme.sh v$ACMESH_VERSION -> $ACME_HOME（续期由 clashserver-cert.timer 负责）"
}

issue_cert() {
  log "申请证书（$DOMAIN，$(cert_mode_label)，$(tls_label)）"
  install -d -m 700 "$ACME_HOME"
  install -m 644 "$LIB_DIR/scripts/init/clashserver-cert.service" "$LIB_DIR/scripts/init/clashserver-cert.timer" \
    /etc/systemd/system/
  systemctl daemon-reload
  local out rc=0
  out=$("$LIB_DIR/scripts/certctl.sh" issue 2>&1) || rc=$?
  ( umask 077; printf '%s\n' "$out" > "$CS_ETC/cert-install.log" )
  if ((rc == 0)); then
    info "证书已就绪：$CONF_DIR/certs/（$(cert_issuer)，到期 $(cert_enddate)；Mihomo 与面板共用）"
  else
    # 只显示关键信息：certctl 提示 + acme.sh 的错误行（完整输出：/etc/clashserver/cert-install.log）
    printf '%s\n' "$out" | grep -iE '^certctl:|error|invalid|fail|timeout|refused|unauthorized|connection' | tail -n 8 >&2 || true
    "$LIB_DIR/scripts/certctl.sh" selfsign >/dev/null
    if [[ ${CERT_MODE:-port} == dns ]]; then
      warn "证书申请失败，已先用临时自签证书启动。请检查 Cloudflare API Token 是否具备 $DOMAIN 的 DNS 编辑权限；系统每小时自动重试，也可执行 clashserver cert 立即重试"
    else
      warn "证书申请失败，已先用临时自签证书启动。请检查：域名 A 记录是否指向 $SERVER_IP、80 端口是否放行；系统每小时自动重试，也可执行 clashserver cert 立即重试"
    fi
  fi
  su -s /bin/sh mihomo -c "test -r $CONF_DIR/certs/privkey.pem" || die "mihomo 用户无法读取证书私钥"
  systemctl enable --now clashserver-cert.timer >/dev/null 2>&1
}

cert_is_temp() { openssl x509 -noout -subject -in "$CONF_DIR/certs/fullchain.pem" 2>/dev/null | grep -q 'clashserver temporary'; }

cert_enddate() { openssl x509 -noout -enddate -in "$CONF_DIR/certs/fullchain.pem" 2>/dev/null | cut -d= -f2; }

cert_issuer() { # 颁发者 CN（如 R11 / E7 / Fake LE Intermediate X1）
  openssl x509 -noout -issuer -in "$CONF_DIR/certs/fullchain.pem" 2>/dev/null | sed -n 's/.*CN *= *\([^,/]*\).*/\1/p'
}

cert_days_left() { # 剩余整天数；无证书输出空
  local end
  end=$(cert_enddate); [[ -n $end ]] || return 0
  echo $((($(date -d "$end" +%s) - $(date +%s)) / 86400))
}

cert_last_run() { # 上次自动续期任务的结果（systemd）
  local res ts
  res=$(systemctl show clashserver-cert.service -p Result --value 2>/dev/null || true)
  ts=$(systemctl show clashserver-cert.service -p ExecMainExitTimestamp --value 2>/dev/null || true)
  [[ -n $ts && $ts != n/a ]] || { echo "尚未运行"; return 0; }
  if [[ $res == success ]]; then printf '成功（%s）' "$ts"; else printf '\033[1;31m失败\033[0m（%s，clashserver log 查看原因）' "$ts"; fi
}

migrate_lego() { # 旧版本（lego）-> acme.sh：update 时调用；保留当前证书，后台换由 acme.sh 管理
  [[ $MODE == auto-cert && $TLS != internal ]] || return 0
  [[ -x $ACME_HOME/acme.sh ]] && return 0
  info "证书工具迁移：lego -> acme.sh"
  install_acme
  local rc=0
  "$LIB_DIR/scripts/certctl.sh" issue || rc=$?
  ((rc == 0)) || warn "acme.sh 首次申请未成功，现有证书继续使用；系统每小时自动重试，也可执行 clashserver cert"
  rm -rf /usr/local/bin/lego "$CS_ETC/acme"
}
