# shellcheck shell=bash
# clashserver 管理面板与订阅链接

setup_panel() {
  log "配置管理面板"
  install -d -m 755 "$CS_ETC"
  [[ -f $CS_ETC/inbounds.json ]] || { echo '[]' > "$CS_ETC/inbounds.json"; chmod 600 "$CS_ETC/inbounds.json"; }
  set_panel_password
  install -m 644 "$LIB_DIR/scripts/init/clashserve.service" /etc/systemd/system/clashserve.service
  systemctl daemon-reload
  systemctl enable clashserve >/dev/null 2>&1
  systemctl restart clashserve
}

panel_cfg_get() { jq -r --arg k "$1" '.[$k] // empty' "$PANEL_CFG" 2>/dev/null || true; }

new_sub_token() { openssl rand -hex 24; }

sub_url() { printf 'https://%s/sub/%s/mihomo.yaml' "$DOMAIN" "$SUB_TOKEN"; }

write_panel_cfg() { # PANEL_HASH + SUB_TOKEN -> panel.json (0600, root only)
  jq -n --arg h "$PANEL_HASH" --arg t "$SUB_TOKEN" --argjson p "$PANEL_PORT" \
    '{username:"admin", password_hash:$h, listen:"127.0.0.1", port:$p, sub_token:$t}' > "$PANEL_CFG.new"
  chmod 600 "$PANEL_CFG.new"; mv -f "$PANEL_CFG.new" "$PANEL_CFG"
}

set_panel_password() { # new random password; keeps an existing subscription token
  PANEL_PASS=$(openssl rand -base64 32 | tr -dc 'A-Za-z0-9' | head -c 20)
  PANEL_HASH=$(printf '%s\n' "$PANEL_PASS" | python3 "$LIB_DIR/panel/panel.py" hash-password)
  [[ -n $SUB_TOKEN ]] || SUB_TOKEN=$(panel_cfg_get sub_token)
  [[ -n $SUB_TOKEN ]] || SUB_TOKEN=$(new_sub_token)
  write_panel_cfg
}
