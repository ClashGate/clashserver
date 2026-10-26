# DEV_NOTES（过程录）

供之后同步到 Notion 规格页「开发备注」。格式：日期 · 类型（决策/问题/卡点）· 内容。

## 决策
- 2026-10-27 · 决策 · 用 `DEV_NOTES.md` 记录过程（已由云电脑助手经 Notion MCP 追加到规格页「开发备注」；本文件继续作本地过程录）。
- 2026-10-27 · 决策 · 交付结构：`install.sh` + `systemd/mihomo.service` + `templates/{server,client}.yaml.tpl`；节点状态存 `/etc/mihomo/nodes.tsv`，服务端/客户端配置均由其渲染。
- 2026-10-27 · 决策 · 默认 3 个 VLESS+Reality 节点（`--nodes N`），端口随机 20000–39999，UUID/short-id 随机，SNI 固定 `www.sc.com`；密钥用 `mihomo generate reality-keypair`（无需 xray）。
- 2026-10-27 · 决策 · 内核下载取 GitHub `releases/latest`（天然排除预发布），选 `mihomo-linux-<arch>-<tag>.gz`。
- 2026-10-27 · 决策 · 服务以非 root 用户 `mihomo` 运行；服务端不开放 controller/面板。
- 2026-10-27 · 决策 · 客户端配置目录：`/root/clashserver-client`（安装结束打印）。
- 2026-10-27 · 决策 · 已预留 `update`、`uninstall`、`info` 子命令。

## 产品拍板（2026-10-27）
- SNI 写死 `www.sc.com`（reality dest/server-names 与客户端 servername），去掉内置池轮换。
- 客户端规则保留 `GEOIP,CN,DIRECT`。
- IPv6 / 多 IP 本阶段不做。
- `curl|bash` 自举等仓库公开后再做；私仓阶段保持同目录依赖 `systemd/` + `templates/`。
- README 等 Debian 实测后再写。

## 卡点
- 尚未在干净 Debian 上实测（agent 沙箱无网络/无 systemd），仅做静态检查。

## 实测（2026-10-27）
- Docker：本机 CLI `/home/box/bin/docker`，必须 `DOCKER_HOST=tcp://127.0.0.1:2375`（无 unix sock；勿 apt 装 docker.io）。
- 环境：`jrei/systemd-debian:12` 容器（例：`cs-test`）。
- 命令：`./install.sh install --nodes 2 --name testvps --ip 203.0.113.10`
- **PASS**：mihomo systemd `active`；两端口监听；`mihomo -t` 成功；SNI=`www.sc.com`；proxies.yaml + `/root/clashserver-client/` 生成；含 `GEOIP,CN,DIRECT`；内核 Mihomo Meta v1.19.33。
- 实测中修复并保留：awk 占位符改为整行匹配 `^@@…@@$`；systemd 使用 `StateDirectory=mihomo`，`-d /var/lib/mihomo`（避免只读 /etc 写 cache/geodata）；uninstall 清理 `/var/lib/mihomo`。

## 第二阶段启动（2026-10-27）
- 一阶段验收 PASS；开始自动证书模式 + 面板骨架（见 PHASE2_BRIEF.md）。

- 测试约束：CF DNS 可用；LE 用 staging；重点测面板；节点只验 VLESS Reality（不依赖证书）。

- 验收补充：容器内 VLESS Reality 经 mixed-port 端到端通；已知边角：install 中途失败后 nodes.tsv 残留挡再装，二阶段加 --force 或失败回滚。

- Bugfix: 最小 Debian 无 `ss`；`install_deps` 补装 `iproute2`（verify/rand_port 依赖）。干净镜像上曾因此假失败。

- 重测 PASS（4268a6a）：干净 jrei/systemd-debian:12，装前无 ss，装后 Verifying 通过；uninstall 干净。
- 已知：`info` 未保存 install 时的 --name/--ip（回落 hostname/公网 IP）。

- 面板须能添加 hy2 / snell / TrustTunnel（只做配置，不测通）；验收节点仍以 VLESS Reality 为主。

- 用户要求：生成/面板字段以根目录 serve.yaml listeners 为准精简，勿 invent。

## 第二阶段脚手架（2026-10-27，auto-cert + 面板）
### 交付
- `install.sh --mode auto-cert --domain D [--email E] [--tls-staging|--tls-internal] [--panel-port 8088]`；默认仍 `no-cert`（一阶段行为不变）。
- 新增：`templates/Caddyfile.tpl`、`scripts/certsync.sh`、`systemd/clashserve.service`、`systemd/clashserver-certsync.{service,timer}`、`panel/panel.py`。
- 新子命令：`reset-password`；新参数：`--force`（已装时先完整卸载再装，解决 nodes.tsv 残留）。
- `/etc/clashserver/clashserver.env` 持久化 MODE/VPS_NAME/SERVER_IP/DOMAIN/TLS/PANEL_PORT/CADDY_OURS；`info` 读取它（命令行 `--name/--ip` 优先）。两种模式都写。

### 决策
- **面板技术栈**：Python3 标准库（`http.server`），零第三方依赖、无需编译/发版；auto-cert 模式才装 `python3`。仅监听 `127.0.0.1:8088`，由 Caddy HTTPS 反代。
- **面板权限**：以 root 运行（需改 `/etc/mihomo` 并调用 `systemctl`），systemd 加 `ProtectSystem=strict` + `ReadWritePaths=/etc/mihomo /etc/clashserver`、`ProtectHome`、`PrivateTmp`。后续可改为专用用户 + polkit 规则。
- **登录**：账号 `admin`，安装时生成 20 位随机密码（仅打印一次），PBKDF2-SHA256 60 万轮存 `/etc/clashserver/panel.json`(0600)。会话 Cookie `HttpOnly; SameSite=Strict`（经 HTTPS 时加 `Secure`），表单带 CSRF token，同 IP 10 分钟内失败 5 次锁定。
- **证书**：Caddy 官方 apt 源安装，HTTP-01（需 80/443）。`--tls-staging` → 全局 `acme_ca` 指向 LE staging；`--tls-internal` → `tls internal`（无公网域名时打通路径用）。不加则走生产 LE 并提示。
- **Cloudflare**：DNS-01 需自编译 caddy-dns/cloudflare 插件，本阶段不做；CF 只用于配 A 记录（建议灰云 DNS only）。安装时检查域名解析并告警，不中断。
- **证书同步**：`certsync.sh` 从 `/var/lib/caddy/.local/share/caddy/certificates/*/<domain>/` 取最新证书复制到 `/etc/mihomo/certs/{fullchain,privkey}.pem`（root:mihomo 0640，目录 0750），有变化才重启 mihomo；timer 每小时跑一次（兼顾 internal CA 的短期证书）。安装时轮询最长 120s，并用 `su mihomo` 实测可读。
- **SAFE_PATHS**：mihomo ≥1.19.6 限制文件路径必须在 home 目录内；unit 加 `Environment=SAFE_PATHS=/etc/mihomo`，`-t` 校验时同样设置。
- **配置组装**：`config.yaml` = `server.yaml.tpl` 中 `@@LISTENERS@@` ← `listeners.reality.yaml`（install 生成）+ `listeners.extra.yaml`（面板生成）。bash `assemble_config` 与 `panel.py assemble_config()` 逻辑一致。模板复制到 `/usr/local/lib/clashserver/`。
- **面板入站**：支持 vless-reality / hysteria2 / snell / trusttunnel，结构对齐本地 `serve.yaml`（仅学结构，密钥全部随机生成）。hy2、trusttunnel 依赖已同步证书，缺证书时拒绝添加；snell 用 `obfs-opts: tls + www.sc.com`，可选 v4/v5。监听器以 JSON flow mapping 写入 YAML（避免转义问题）。每次改动先 `mihomo -t`，失败则回滚三份文件并重启。新增/删除后用 restart（保证新端口生效）。
- **重载按钮**：先 `mihomo -t` 再 `systemctl reload mihomo`（SIGHUP）。⚠️ 待 E2E 确认 mihomo 对 SIGHUP 的处理；若不支持则改为 restart 或 external-controller `PUT /configs`。
- **zashboard / external-ui**：本迭代不挂（需 external-controller + secret），后置。
- **卸载**：停用并删除 clashserve、certsync timer、`/usr/local/lib/clashserver`、`/etc/clashserver`、`/etc/mihomo/certs`；Caddy 若为本脚本安装（`CADDY_OURS=1`）则 purge 并删 `/etc/caddy`、`/var/lib/caddy`、apt 源与 keyring；若 Caddy 原本就有，则恢复 `Caddyfile.clashserver.bak`。已有自定义 Caddyfile 时拒绝覆盖（第三阶段再做）。
- **serve.yaml**：仅本地参考，已在 `.gitignore`；提交一律显式列路径，禁止 `git add -A`。

### 自测（本地沙箱，无 systemd/网络/docker）
- `bash -n install.sh scripts/certsync.sh`、`python3 -m py_compile panel/panel.py` 通过。
- 面板冒烟（假根目录 + 假 mihomo/systemctl）：healthz、未登录跳转、错密 401、登录、仪表盘状态、CSRF 拒绝、重启、重载、添加 4 类入站、`-t` 失败回滚、端口冲突、`/api/status`、删除、登出、登录限流 — 全部 PASS。
- 渲染：Caddyfile（staging/internal）、`assemble_config`、env 持久化往返（CLI `--ip` 优先）PASS。

### 待 E2E（jrei/systemd-debian:12 + 真实域名/CF）
- no-cert 回归；auto-cert `--tls-internal`（容器）与 `--tls-staging`（VPS + CF A 记录）全流程；面板登录/仪表盘/重启/重载；Reality 连通；`--force` 重装；uninstall 清理 Caddy。
- 真实 mihomo 对 hy2/snell/trusttunnel 监听器的 `-t` 校验（只校验配置，不测通）。

## 仓库调整（2026-10-27 02:01）
- 暂停一切 git push。私有归档仓库改为 `clashserverbuild`；公开仓库 `clashserver` 将干净重建（永不含 serve.yaml）。
- 产品原则：先搭简单的大框架，细节后补。

## 仓库布局与产品原则（2026-10-27）
- **产品原则**：先做简单功能，先把整个项目大框架端到端跑通，之后再加功能和细节。
- **私有开发存档**：`saulsburyroy/clashserverbuild`（private，含完整开发历史，早期 commit 里有 serve.yaml，私有可接受）。本地 remote 名 `build`，分支 `build-archive` 跟踪 `build/main`。
- **公开仓库**：`saulsburyroy/clashserver`（public），从当前工作树全新 orphan 历史起步，不含任何 serve.yaml。本地 remote 名 `origin`，`main` 跟踪 `origin/main`。日常开发提交推 `origin`。
- **serve.yaml 永不公开**：只留本地给 AI 参考；`.gitignore` 已忽略；提交一律显式列路径，禁止 `git add -A`。
- 安装说明见根目录 `README.md`。
