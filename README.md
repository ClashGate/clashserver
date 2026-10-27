<h1 align="center">
  clashserver
</h1>

<p align="center">
  Debian VPS 上的 Mihomo 代理服务端一键部署与管理工具<br />
  <sub>一条命令装好节点，自带中文管理控制台与订阅链接</sub>
</p>

<p align="center">
  <img alt="Platform: Debian" src="https://img.shields.io/badge/platform-Debian-A81D33?logo=debian&amp;logoColor=white" />
  <img alt="Init: systemd" src="https://img.shields.io/badge/init-systemd-blue" />
  <img alt="Core: Mihomo" src="https://img.shields.io/badge/core-Mihomo-6f42c1" />
  <img alt="Language: Shell" src="https://img.shields.io/github/languages/top/saulsburyroy/clashserver" />
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-green" /></a>
</p>

## ✨ 特性

- **简单模式**：一条 `curl | bash` 命令，中文交互，直接回车即可完成安装；默认值覆盖常见场景，无需记参数。
- **三种模式**：
  - **无证书模式**（默认）：VLESS Reality 节点（默认入站名 `VlessReality`），不需要域名，安装后直接输出带完整 Fake-IP DNS 与分流规则的客户端配置。
  - **自动证书模式**：自动申请并续期 Let's Encrypt 证书（支持**端口模式**与 **DNS API 模式**），Mihomo 节点与 HTTPS 管理面板共用同一张证书，提供订阅链接，无需额外的 Web 服务器。
  - **手动证书模式**：使用用户自备的域名证书（放入 `/etc/clashserve/certs/` 目录并自动校验有效性），提供 HTTPS 管理面板和订阅链接。
- **统一目录收纳（`/etc/clashserve`）**：Mihomo 内核、服务端配置、TLS 证书、管理面板、客户端配置备份全部统一收纳在 `/etc/clashserve/` 下，并自动迁移兼容旧版 `/etc/mihomo`、`/etc/clashserver`、`/var/lib/mihomo`、`/root/clashserver-client` 路径。
- **管理控制台（v0.55）**：采用分栏标签页与全览双模式信息架构：
  - **14 种入站监听器（Listeners）**：对齐 MetaCubeX 官方 Wiki，支持添加与删除 VLESS Reality、Shadowsocks (`aes-128-gcm` / `aes-256-gcm`)、Hysteria2、Snell、TrustTunnel、VLESS（TLS / XHTTP / WS / gRPC / `mlkem768x25519plus` 原生加密）、VMess、AnyTLS、TUIC v5、ShadowQUIC、Mieru、Sudoku、HTTP、SOCKS5 入站（默认开启 `udp: true`），支持点击「查看节点配置」弹窗编辑并复制单行（简单）或多行（易读）mihomo 节点格式。
  - **服务端出站与外部订阅（`proxies:` & `proxy-providers:`）**：支持一键导入外部订阅链接写入 `proxy-providers:`（含 `gstatic 204` 健康检查），支持粘贴单行 JSON / Flow 或多行 YAML 节点（含 `easytier`、`tailscale` 等扩展协议）追加到服务端 `proxies:`，并提供「查看节点配置」弹窗编辑与单行/多行复制。
  - **mihomo 服务端配置 & 自定义配置模式**：Zashboard 控制面板同样采用安装时分配的**随机空闲高端口**，并将全量 URL 编码后的 API Secret 直接拼接到 Zashboard HTTPS 地址末尾，提供「打开地址」与「复制地址」按钮；支持粘贴整份自备服务端配置、一键「自动修改证书路径」与「更新 mihomo 服务端配置」，应用后自动同步刷新入站 Listeners 列表与客户端订阅。
- **订阅链接**：`https://域名:端口/sub/<随机串>/mihomo.yaml`，内置基于 ACL4SSR 规则的完整 Fake-IP 客户端模板（包含 `🚀 节点选择`、`♻️ 自动选择`、`🌍 国外媒体`、`📲 电报信息`、`Ⓜ️ 微软服务`、`🍎 苹果服务`、`📢 谷歌FCM`、`🎯 全球直连`、`🛑 全球拦截`、`🍃 应用净化`、`🐟 漏网之鱼`），带随机凭证，可随时更换。
- **`clashserver` 命令**：安装后直接输入 `clashserver` 打开中文管理菜单；常用操作都有短子命令。
- **安全默认**：管理面板端口、Zashboard 控制端口、节点端口、UUID、密钥、密码全部随机生成；面板自身提供 HTTPS，登录失败次数限制；改配置前先 `mihomo -t` 校验，失败自动回滚。

## 📦 安装

以 root 身份执行：

```bash
curl -fsSL https://raw.githubusercontent.com/saulsburyroy/clashserver/main/install.sh | bash
```

按提示选择模式，**直接回车即为无证书模式**。

已有域名，想要管理面板和订阅链接：可在顶层菜单选择 **2) 自动证书模式**（随后在证书方式中选择 **1) 端口模式** 或 **2) DNS API 模式**）或 **3) 手动证书模式**：

- **端口模式**（自动证书默认）：申请 / 续期证书时临时占用 **80** 端口；需将域名 A 记录指向本机并放行 TCP 80（Cloudflare 请设为 **灰云 DNS only**）。
- **DNS API 模式**（自动证书）：填写 Cloudflare API Token 自动完成域名验证，**无需开放 80 / 443 端口**，支持 `*.example.com` 泛域名。
- **手动证书模式**：按提示将自备证书（`fullchain.pem` 与 `privkey.pem`）放入 `/etc/clashserve/certs/` 目录，检测证书有效性通过后自动完成部署。
- 环境：Debian 12（推荐）、systemd、root，服务器可直连 GitHub。管理面板与 Zashboard 控制接口均在安装时自动选取**随机空闲高端口**提供 HTTPS（无需占用 443，安装输出与面板中均会明确展示端口）。

## 🚀 快速上手

**无证书模式**：安装结束会打印 `proxies` 片段，并生成完整客户端配置：

```text
/etc/clashserve/client/mihomo-client.yaml   # 完整 mihomo 客户端配置（兼容软链 /root/clashserver-client）
/etc/clashserve/client/proxies.yaml         # 仅节点片段
```

**自动证书 / 手动证书模式**：安装结束会打印订阅链接和面板账号：

```text
订阅链接：https://你的域名:<面板随机端口>/sub/<随机串>/mihomo.yaml   ← 导入 mihomo / Clash 客户端
管理面板：https://你的域名:<面板随机端口>   用户名 admin   密码（仅显示一次）
```

之后随时运行：

```bash
clashserver
```

打开中文管理菜单，查看状态、节点、订阅链接，修改面板密码等。

## ⌨️ 命令一览

```text
用法：
  clashserver [子命令]

子命令：
  （不带参数）        打开中文交互菜单
  status             运行状态（服务、端口、证书）
  info               节点配置：proxies 片段、客户端配置目录、订阅链接
  sub                查看订阅链接（自动证书模式）
  reset-sub          更换订阅链接，旧链接立即失效
  passwd             修改面板密码（自定义）
  reset-secret       重置 Zashboard API 密钥（随机）
  cert               立即申请 / 续期证书（平时自动续期）
  restart            重启 Mihomo
  log                查看最近日志
  update             更新 Mihomo 内核 + clashserver 自身
  uninstall          卸载
  install            重新安装（按提示选择模式）
  help               显示帮助
```

## 🖥️ 管理面板与订阅（证书模式）

- 面板地址 `https://你的域名:<随机端口>`（安装时自动分配随机空闲高端口），用户名 `admin`，密码安装时随机生成且**只显示一次**。修改：`clashserver passwd`；忘记：在服务器上执行 `clashserver reset-password`。
- 证书模式默认开启 Mihomo `external-controller-tls`（安装时自动分配**随机空闲高端口**，持久化于 `CONTROLLER_PORT`）与 **Zashboard**（`external-ui`）。在面板「mihomo 服务端配置」卡片中，Zashboard HTTPS 地址已直接拼接 `hostname`/`port`/`secret` 参数，点击「打开地址」即可免填直连，点击「复制地址」即可复制含密钥的完整地址。
- 支持在控制台启用**自定义 mihomo 服务端配置模式**：可粘贴整份自备服务端配置，点击「自动修改证书路径」将 TLS 证书与私钥一键修正为 `/etc/clashserve/certs/fullchain.pem` 与 `/etc/clashserve/certs/privkey.pem`（不会误改 Reality 的 `private-key`），点击「更新 mihomo 服务端配置」即可通过 `mihomo -t` 校验并生效，同时自动刷新入站 Listeners 列表与客户端订阅。
- 证书由 [acme.sh](https://github.com/acmesh-official/acme.sh) 申请（可选**端口模式**或 **DNS API 模式**），存放在 `/etc/clashserve/certs/`，每小时检查、到期前自动续期。
- 订阅链接内容包含全部入站节点，每次请求实时生成，并自动同步更新 `/etc/clashserve/client/` 本地客户端文件与本机 `ufw` 防火墙规则。

## 🔄 更新

```bash
clashserver update
```

更新不会改变节点、密钥、面板密码和订阅链接；若从旧版（0.4 及更早版本）升级，会自动将 `/etc/mihomo`、`/etc/clashserver`、`/var/lib/mihomo`、`/usr/local/lib/clashserver`、`/root/clashserver-client` 迁移合并至 `/etc/clashserve/` 并保留兼容软链。

## 🗑️ 卸载

```bash
clashserver uninstall
```

删除 `/etc/clashserve`（含 Mihomo、acme.sh、面板、证书、配置、客户端文件）、systemd 服务和 `clashserver` 命令。需要保留的客户端配置请提前备份。

## 📂 目录结构（统一收口于 `/etc/clashserve`）

```text
/etc/clashserve/
  mihomo                   # Mihomo 内核二进制（软链至 /usr/local/bin/mihomo）
  config.yaml              # Mihomo 服务端主配置（运行工作目录 -d /etc/clashserve）
  custom_config.yaml       # 自定义服务端配置模式下的完整配置（启用时存在）
  certs/                   # TLS 证书目录（fullchain.pem / privkey.pem，相对路径 certs/*）
  client/                  # 本地客户端配置备份（mihomo-client.yaml / proxies.yaml）
  acme.sh/                 # acme.sh 自动证书程序与账户目录
  clashserver.env          # 安装环境与随机端口持久化配置
  panel.json               # 管理面板配置与订阅 token
  inbounds.json            # 面板添加的入站节点记录
  proxies.json             # 面板添加的服务端出站节点记录
  providers.json           # 面板导入的外部订阅源（proxy-providers）记录
  panel/panel.py           # 管理面板（Python 标准库，无第三方依赖）
  resources/               # 服务端 / 客户端配置模板
  scripts/                 # CLI 脚本、公共库、certctl.sh 与 systemd unit
```

旧版路径（`/etc/mihomo`、`/etc/clashserver`、`/var/lib/mihomo`、`/usr/local/lib/clashserver`、`/root/clashserver-client`）在升级或启动时会自动迁移至 `/etc/clashserve/` 并建立兼容软链接。

## ⚠️ 特别声明

- 本项目仅用于学习和研究 Shell 与网络技术，不得将项目内容用于违反适用法律法规及相关规定的活动。
- 本项目保留对本声明进行补充或修改的权利。使用本项目前，请阅读并遵守本声明。

## 📄 许可证

[MIT](LICENSE)
