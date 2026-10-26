# Clash Server — 第二阶段：自动证书模式 + 面板起步

一阶段已验收 PASS。本阶段按 Notion 规格推进。仓库：https://github.com/saulsburyroy/clashserver

## 本迭代聚焦（先做这些，别发散）
1. **域名 + Let’s Encrypt + Caddy**
   - 安装模式：`--mode auto-cert`（或交互选择「自动证书」）
   - 用户提供域名；安装 Caddy；用 LE 申请证书（HTTP-01，需 80/443）
   - Caddy HTTPS 反代到 clashserve 面板
2. **面板骨架（clashserve）**
   - 最小可用：登录页（admin + 随机强密码）、仪表盘显示 Mihomo 状态、一键重启/重载
   - 安装结束打印：`https://域名`、账号 admin、随机密码、以及 zashboard 地址（若挂 external-ui）
3. **Mihomo 证书路径可读**
   - 服务端配置里 certificate / private-key 必须指向 Caddy/LE 证书（或同步到 `/etc/mihomo/certs/`）且 mihomo 用户可读
   - 可先做依赖证书的入站中的一种作验证（参考 `serve.yaml`），与 Reality 并存亦可

## 明确后置
- 傻瓜模式全套协议表单、订阅二维码、流量统计、Docker 版、第三阶段自定义反代细节可后做
- 不要破坏已通过的无证书模式（`--mode no-cert` / 默认保持一阶段行为）

## 非功能
- Debian 优先；systemd；一键卸载覆盖 Caddy/面板/证书目录
- 进度提示与错误建议；过程写入 `DEV_NOTES.md`（会同步 Notion）
- 卡死才提问；能自测就在 Docker/`jrei/systemd-debian` 里测（注意 LE 在无公网域名时用 dry-run/mock/自签兜底方案并写清）

## LE 实测注意
容器无真实公网域名时：实现应支持 `--domain` + 可选 `--email`；提供 `--tls-staging` 或「无公网时写入自签/跳过签发但打通路径」的开发开关，并在 DEV_NOTES 说明。真实 LE 签发留给有域名的 VPS。

## 参考
- Notion：https://app.notion.com/p/405d196df40f80fa8a30f85b335807ab
- serve.yaml listeners / tls 字段
- Caddy 官方 Debian 安装与 Caddyfile reverse_proxy
- Mihomo wiki：https://wiki.metacubex.one/en/

## 成功标准（本里程碑）
- `install.sh`（或拆分脚本）支持 auto-cert 模式脚手架可运行到：装 Caddy、写 Caddyfile、证书目录对 mihomo 可读、面板进程能起（可用 mock TLS）、无证书模式回归不坏
- DEV_NOTES 记录决策；代码 push 到 main

## 测试约束（用户 2026-10-27 补充）
1. **Cloudflare DNS 可用**（账户已授权）：可用其配 DNS 做证书验证。
2. **Let’s Encrypt 优先 staging/测试证书**（`--tls-staging` 默认建议开启或强提示），避免生产额度被拉黑。
3. **实测重点：clashserver 面板跑通**（登录、仪表盘、重启/重载）。
4. **节点**：只验证 **VLESS Reality** 通不通；Reality 节点本身不依赖证书（证书主要用于面板 HTTPS / 后续需证入站）。

## 面板节点类型（用户 2026-10-27 补充）
面板必须支持**添加/配置**以下入站类型（在 VLESS Reality 之外）：
- **hysteria2（hy2）**
- **snell**
- **TrustTunnel**

约束：
- 这三类只需面板录入与写入 Mihomo listeners 的能力；**不要做功能测通**（staging 证书场景测不通）。
- 对外/验收节点仍以 **VLESS Reality** 为主。
- 参考 `serve.yaml` 里对应 listener 结构精简即可。

## 参考配置
服务端结构以仓库根目录 `serve.yaml` 为准精简（学字段，勿照抄打码密钥）。面板 hy2/snell/TrustTunnel 字段对齐该文件 listeners。
