#!/usr/bin/env bash
# clashserver 管理命令（安装后链接为 /usr/local/bin/clashserver）
# 不带参数：已安装 -> 中文管理菜单；未安装 -> 安装。clashserver help 查看全部子命令。
set -Eeuo pipefail

ORIG_ARGS=("$@")
CS_HOME=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../.." && pwd)
for _lib in common core cert panel; do
  # shellcheck source=/dev/null
  . "$CS_HOME/scripts/lib/$_lib.sh"
done
trap 'die "第 $LINENO 行执行失败：$BASH_COMMAND"' ERR
if [[ -n ${CS_BOOTSTRAP_TMP:-} ]]; then trap 'rm -rf "$CS_BOOTSTRAP_TMP"' EXIT; fi

usage() {
  cat <<'EOF'
clashserver —— Mihomo 代理服务端管理命令

用法：clashserver [子命令]
  （不带参数）       打开中文交互菜单
  status            查看运行状态（服务、端口、证书）
  info              查看节点配置（proxies 片段、客户端配置目录、订阅链接）
  sub               查看订阅链接（自动证书模式）
  reset-sub         更换订阅链接，旧链接立即失效
  passwd            修改面板密码（自定义）
  reset-password    重置面板密码（随机生成）
  restart           重启 Mihomo
  update            更新 Mihomo 内核 + clashserver 自身（update core / update self 只更新其一）
  log               查看最近日志
  uninstall         卸载
  install           重新安装（按提示选择模式）
  help              显示本帮助

一键安装：curl -fsSL https://raw.githubusercontent.com/saulsburyroy/clashserver/main/install.sh | bash
EOF
}

interactive_setup() {
  has_tty || return 0
  local menu=0
  if ((!MODE_SET)); then
    menu=1
    printf '\n\033[1mclashserver 一键安装\033[0m\n\n'
    printf '请选择安装模式：\n'
    printf '  1) 无证书模式（默认）：仅 VLESS Reality 节点，安装后输出客户端配置\n'
    printf '  2) 自动证书模式：需要一个已解析到本机的域名，提供 HTTPS 管理面板和订阅链接\n'
    local c
    while :; do
      c=$(ask '请输入 [1/2]（回车默认 1）：' 1)
      case $c in 1) MODE=no-cert; break ;; 2) MODE=auto-cert; break ;; *) printf '请输入 1 或 2\n' ;; esac
    done
  fi
  [[ $MODE == auto-cert ]] || return 0
  while [[ -z $DOMAIN || ! ${DOMAIN,,} =~ $DOMAIN_RE ]]; do
    [[ -n $DOMAIN ]] && printf '域名格式不正确：%s\n' "$DOMAIN"
    DOMAIN=$(ask '请输入域名（需已将 A 记录解析到本机）：' '')
  done
  ((menu)) || return 0   # 开发用隐藏参数 -d 启动时不再追问
  if [[ -z $EMAIL ]]; then EMAIL=$(ask '证书通知邮箱（可选，回车跳过）：' ''); fi
  return 0
}

check_existing() {
  [[ -f $STATE ]] || return 0
  if has_tty; then
    [[ $(ask '检测到已安装 clashserver，是否卸载后重新安装？节点和密钥都会重新生成 [y/N]：' n) == [yY]* ]] \
      || { printf '已取消。查看现有节点：clashserver info\n'; exit 0; }
  else
    die "已安装（存在 $STATE）。查看节点：clashserver info；如需重装请在终端中运行 clashserver install"
  fi
  printf '正在卸载旧的安装……\n'
  ( CS_IN_REINSTALL=1 do_uninstall ) >/dev/null
}

# ------------------------------------------------------------ verify / output
verify() {
  log "检查运行状态"
  sleep 2
  systemctl is-active --quiet mihomo || { journalctl -u mihomo -n 20 --no-pager >&2; die "mihomo 服务未能启动"; }
  local name port rest
  while IFS=$'\t' read -r name port rest; do
    ss -ltn | grep -q ":$port " || die "节点 $name 未在端口 $port 监听"
    info "监听中：$name :$port"
  done < "$STATE"
  [[ $MODE == auto-cert ]] || return 0
  local i
  for ((i = 0; i < 10; i++)); do curl -fsS "http://127.0.0.1:$PANEL_PORT/healthz" >/dev/null 2>&1 && break; sleep 1; done
  ((i < 10)) || { journalctl -u clashserve -n 20 --no-pager >&2; die "面板未在 127.0.0.1:$PANEL_PORT 响应"; }
  info "面板：127.0.0.1:$PANEL_PORT 正常"
  local base="http://127.0.0.1:$PANEL_PORT/sub"
  curl -fsS "$base/$SUB_TOKEN/mihomo.yaml" | grep -q '^proxies:' || die "订阅接口没有返回 mihomo 配置"
  [[ $(curl -s -o /dev/null -w '%{http_code}' "$base/wrongtoken0000000000000000/mihomo.yaml") == 404 ]] \
    || die "订阅接口未拒绝错误的 token"
  info "订阅链接：需要 token（错误 token 返回 404）正常"
  if curl -fsSk --max-time 10 --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/healthz" >/dev/null 2>&1; then
    info "Caddy：https://$DOMAIN -> 面板 正常"
  else
    warn "https://$DOMAIN 暂时无法访问（证书可能尚未签发），可查看 journalctl -u caddy -n 50"
  fi
}

print_summary() {
  printf '\n\033[1;32m✔ 安装完成！\033[0m\n\n'
  printf '请在云服务商的防火墙 / 安全组放行以下 TCP 端口：'
  [[ $MODE == auto-cert ]] && printf ' 80 443'
  awk -F'\t' '{printf " %s", $2}' "$STATE"; printf '\n'
  if [[ $MODE == auto-cert ]]; then
    printf '\n\033[1mmihomo 订阅链接\033[0m（导入 mihomo / Clash 客户端即可；链接即凭证，泄露后执行 clashserver reset-sub 更换）：\n'
    printf '  \033[1;36m%s\033[0m\n' "$(sub_url)"
    [[ $TLS == production ]] || printf '  注意：当前为%s，客户端可能拒绝下载订阅\n' "$(tls_label)"
    printf '\n\033[1m管理面板\033[0m\n'
    printf '  地址：https://%s\n  用户名：admin\n' "$DOMAIN"
    [[ -n $PANEL_PASS ]] && printf '  密码：%s（仅显示一次；可用 clashserver passwd 修改）\n' "$PANEL_PASS"
    printf '  证书：%s\n' "$(tls_label)"
    printf '\n本地客户端配置备份：%s\n' "$CLIENT_DIR"
  else
    printf '\n\033[1m客户端 proxies 片段\033[0m\n'
    cat "$CLIENT_DIR/proxies.yaml"
    printf '\n\033[1m客户端配置目录\033[0m：%s\n' "$CLIENT_DIR"
    printf '  - mihomo-client.yaml（完整 mihomo 客户端配置）\n  - proxies.yaml（仅节点片段）\n'
  fi
  printf '\n管理：运行 \033[1mclashserver\033[0m 打开中文管理菜单（clashserver help 查看全部子命令）\n'
  if ((${#WARNINGS[@]})); then
    printf '\n\033[1;33m需要注意：\033[0m\n'; printf '  - %s\n' "${WARNINGS[@]}"
  fi
}

# ------------------------------------------------------------ actions
do_install() {
  check_os
  if [[ $CS_HOME -ef $LIB_DIR ]]; then # 从已安装副本运行（clashserver install）：先复制出来，避免重装时删掉自己
    local tmp
    tmp=$(mktemp -d /tmp/clashserver.XXXXXX)
    cp -r "$LIB_DIR"/. "$tmp"/
    CS_BOOTSTRAP_TMP=$tmp CS_DEFAULT_ACTION=install exec bash "$tmp/scripts/cmd/clashserver.sh" "${ORIG_ARGS[@]}"
  fi
  interactive_setup
  check_existing
  [[ $MODE == auto-cert ]] && TOTAL=14
  [[ -n $VPS_NAME ]] || VPS_NAME=$(hostname)
  install_deps
  [[ $MODE == auto-cert ]] && preflight_cert
  detect_ip; save_env
  install_core; ensure_user; log "安装 clashserver 文件"; install_files; gen_nodes; render_server; render_client; setup_service
  if [[ $MODE == auto-cert ]]; then
    check_dns; install_caddy; write_caddyfile; sync_cert; setup_panel
  fi
  verify
  print_summary
}

# clashserver update [core|self]：默认同时更新 Mihomo 内核与 clashserver 自身（脚本、面板、模板、unit）
do_update() {
  require_installed; load_env
  local what=${UPDATE_WHAT:-all}
  STEP=0; TOTAL=$([[ $what == all ]] && echo 4 || echo 3)
  install_deps
  [[ $what == self ]] || install_core
  [[ $what == core ]] || update_self
  log "重启服务"
  validate_conf || die "配置未通过校验（mihomo -t），未重启"
  systemctl restart mihomo
  [[ $MODE == auto-cert ]] && systemctl restart clashserve
  sleep 1
  info "Mihomo：$(svc_state mihomo)"
  return 0
}

update_self() {
  log "更新 clashserver 脚本与面板"
  local tmp
  tmp=$(mktemp -d /tmp/clashserver.XXXXXX)
  fetch_repo "$tmp"
  CS_HOME=$tmp install_files   # 整体替换 $LIB_DIR；正在运行的脚本已读入内存，不受影响
  rm -rf "$tmp"
  install -m 644 "$LIB_DIR/scripts/init/mihomo.service" "$UNIT"
  if [[ $MODE == auto-cert ]]; then
    install -m 644 "$LIB_DIR/scripts/init/clashserve.service" "$LIB_DIR/scripts/init/clashserver-certsync.service" \
      "$LIB_DIR/scripts/init/clashserver-certsync.timer" /etc/systemd/system/
  fi
  systemctl daemon-reload
  # 用新模板重新组装配置；校验失败则回滚
  cp -a "$CONF" "$CONF.bak"
  assemble_config
  if validate_conf; then rm -f "$CONF.bak"; else mv -f "$CONF.bak" "$CONF"; warn "新模板生成的配置未通过校验，已保留原配置"; fi
  info "clashserver 已更新到 GitHub main 最新版"
}

do_status() {
  require_installed; load_env
  printf '\033[1m运行状态\033[0m\n'
  printf '  安装模式：%s\n' "$([[ $MODE == auto-cert ]] && echo '自动证书模式' || echo '无证书模式')"
  printf '  Mihomo：%s  %s\n' "$(svc_state mihomo)" "$("$BIN" -v 2>/dev/null | head -n1 | awk '{print $3}')"
  if [[ $MODE == auto-cert ]]; then
    printf '  Caddy：%s    面板：%s\n' "$(svc_state caddy)" "$(svc_state clashserve)"
    printf '  域名：%s（证书：%s）\n' "$DOMAIN" "$(tls_label)"
    if [[ -f $CONF_DIR/certs/fullchain.pem ]]; then
      printf '  证书到期：%s\n' "$(openssl x509 -noout -enddate -in "$CONF_DIR/certs/fullchain.pem" | cut -d= -f2)"
    else
      printf '  证书：\033[1;31m尚未同步\033[0m（systemctl start clashserver-certsync）\n'
    fi
  fi
  printf '  节点端口：\n'
  local name port rest
  while IFS=$'\t' read -r name port rest; do
    if ss -ltn | grep -q ":$port "; then printf '    %-18s %-6s \033[1;32m监听中\033[0m\n' "$name" "$port"
    else printf '    %-18s %-6s \033[1;31m未监听\033[0m\n' "$name" "$port"; fi
  done < "$STATE"
}

do_info() {
  [[ -f $STATE ]] || die "尚未安装"
  load_env
  [[ -n $VPS_NAME ]] || VPS_NAME=$(hostname)
  detect_ip
  echo "proxies:"
  while IFS=$'\t' read -r name port uuid priv pub sid sni; do
    echo "    - $(proxy_line "$name" "$port" "$uuid" "$pub" "$sid" "$sni")"
  done < "$STATE"
  printf '客户端配置目录：%s\n' "$CLIENT_DIR"
  if [[ $MODE == auto-cert ]]; then
    SUB_TOKEN=$(panel_cfg_get sub_token)
    printf '管理面板：https://%s（用户名 admin）\n' "$DOMAIN"
    [[ -n $SUB_TOKEN ]] && printf '订阅链接：%s\n' "$(sub_url)"
  fi
  return 0
}

do_sub() {
  require_installed; load_env; require_panel
  SUB_TOKEN=$(panel_cfg_get sub_token)
  [[ -n $SUB_TOKEN ]] || die "未找到订阅 token，可执行 clashserver reset-sub 生成"
  printf 'mihomo 订阅链接（链接即凭证，请勿外泄）：\n  %s\n' "$(sub_url)"
}

do_reset_sub() {
  load_env
  [[ $MODE == auto-cert && -f $PANEL_CFG ]] || die "订阅链接仅在自动证书模式下提供"
  PANEL_HASH=$(panel_cfg_get password_hash)
  SUB_TOKEN=$(new_sub_token)
  write_panel_cfg
  systemctl restart clashserve
  printf '新的订阅链接（旧链接已失效）：\n  %s\n' "$(sub_url)"
}

do_passwd() {
  require_installed; load_env; require_panel
  has_tty || die "需要在终端中运行；或使用 clashserver reset-password 随机重置"
  local p1 p2
  while :; do
    printf '请输入新密码（至少 8 位）：' >/dev/tty; read -rs p1 </dev/tty; printf '\n' >/dev/tty
    printf '请再次输入：' >/dev/tty; read -rs p2 </dev/tty; printf '\n' >/dev/tty
    if [[ $p1 != "$p2" ]]; then printf '两次输入不一致，请重试\n'
    elif ((${#p1} < 8)); then printf '密码太短，至少 8 位\n'
    else break; fi
  done
  PANEL_HASH=$(printf '%s\n' "$p1" | python3 "$LIB_DIR/panel/panel.py" hash-password)
  SUB_TOKEN=$(panel_cfg_get sub_token)
  write_panel_cfg
  systemctl restart clashserve
  printf '面板密码已修改。登录地址：https://%s（用户名 admin）\n' "$DOMAIN"
}

do_reset_password() {
  load_env
  [[ $MODE == auto-cert && -f $PANEL_CFG ]] || die "未安装管理面板（仅自动证书模式提供）"
  set_panel_password
  systemctl restart clashserve
  printf '管理面板：https://%s\n用户名：admin\n新密码：%s\n' "$DOMAIN" "$PANEL_PASS"
}

do_restart() {
  require_installed
  validate_conf || die "当前配置未通过校验（mihomo -t），未重启"
  systemctl restart mihomo
  sleep 1
  printf 'Mihomo：%s\n' "$(svc_state mihomo)"
}

do_log() {
  require_installed; load_env
  journalctl -u mihomo -n 50 --no-pager
  [[ $MODE == auto-cert ]] && { echo; journalctl -u caddy -u clashserve -n 30 --no-pager; }
  return 0
}

do_menu() {
  require_installed; load_env
  has_tty || { usage; return 0; }
  local items=() labels=() i c
  items+=(status info);          labels+=("查看运行状态" "查看节点配置")
  if [[ $MODE == auto-cert ]]; then
    items+=(sub reset-sub passwd reset-password)
    labels+=("查看订阅链接" "更换订阅链接" "修改面板密码（自定义）" "重置面板密码（随机）")
  fi
  items+=(restart log update uninstall); labels+=("重启 Mihomo" "查看日志" "更新（内核 + 脚本）" "卸载")
  while :; do
    printf '\n\033[1mclashserver 管理菜单\033[0m（%s' "$([[ $MODE == auto-cert ]] && echo "自动证书模式 · $DOMAIN" || echo '无证书模式')"
    printf '）  Mihomo：%s\n' "$(svc_state mihomo)"
    for i in "${!items[@]}"; do printf '  %d) %s\n' "$((i + 1))" "${labels[$i]}"; done
    printf '  0) 退出\n'
    c=$(ask '请选择：' 0)
    [[ $c == 0 ]] && return 0
    if [[ $c =~ ^[0-9]+$ ]] && ((c >= 1 && c <= ${#items[@]})); then
      printf '\n'
      ( STEP=0; "do_${items[$((c - 1))]//-/_}" ) || true
      [[ ${items[$((c - 1))]} == uninstall && ! -f $STATE ]] && return 0
      ask '按回车返回菜单……' '' >/dev/null
    else
      printf '无效选项：%s\n' "$c"
    fi
  done
}

do_uninstall() {
  load_env
  if [[ ${CS_IN_REINSTALL:-0} != 1 ]] && has_tty; then
    [[ $(ask '确定卸载 clashserver？所有节点、证书和配置都会被删除 [y/N]：' n) == [yY]* ]] || { echo "已取消"; return 0; }
  fi
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
  rm -f "$UNIT" "$BIN" "$SELF_BIN"
  systemctl daemon-reload
  rm -rf "$CONF_DIR" "$CLIENT_DIR" /var/lib/mihomo "$LIB_DIR" "$LIB_DIR.new" "$LIB_DIR.old" "$CS_ETC"
  if id mihomo >/dev/null 2>&1; then userdel mihomo || true; fi
  echo "已卸载：Mihomo、管理面板、证书、配置、客户端文件，以及由本脚本安装的 Caddy。"
}

ACTION=""
while (($#)); do
  case "$1" in
    install|update|uninstall|info|status|sub|passwd|restart|log|menu|reset-password|reset-sub) ACTION=$1 ;;
    core|self) [[ $ACTION == update ]] || die "未知参数：$1"; UPDATE_WHAT=$1 ;;
    help) usage; exit 0 ;;
    # 以下为开发/测试用隐藏参数，不写入用户文档
    -d|--domain) DOMAIN=${2:?缺少域名}; MODE=auto-cert; MODE_SET=1; shift ;;
    --staging|--tls-staging) TLS=staging ;;
    --tls-internal) TLS=internal ;;
    -h|--help) usage; exit 0 ;;
    *) die "未知参数：$1（查看帮助：-h）" ;;
  esac
  shift
done

# 无子命令：由 install.sh 调用 -> 安装；已安装时直接运行 clashserver -> 管理菜单；未安装 -> 安装
if [[ -z $ACTION ]]; then
  if [[ -n ${CS_DEFAULT_ACTION:-} ]]; then ACTION=$CS_DEFAULT_ACTION
  elif [[ -f $STATE ]]; then ACTION=menu
  else ACTION=install; fi
fi
need_root
"do_${ACTION//-/_}"

