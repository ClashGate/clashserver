<h1 align="center">
  clashserver
</h1>

<p align="center">
  Debian VPS 上的 Mihomo 代理服务端一键部署与管理工具<br />
  <sub>一条命令装好节点，自带中文管理面板与订阅链接</sub>
</p>

<p align="center">
  <img alt="Platform: Debian" src="https://img.shields.io/badge/platform-Debian-A81D33?logo=debian&amp;logoColor=white" />
  <img alt="Init: systemd" src="https://img.shields.io/badge/init-systemd-blue" />
  <img alt="Core: Mihomo" src="https://img.shields.io/badge/core-Mihomo-6f42c1" />
  <img alt="Language: Shell" src="https://img.shields.io/github/languages/top/saulsburyroy/clashserver" />
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-green" /></a>
</p>

## ✨ 特性

- **傻瓜式一键**：一条 `curl | bash` 命令，中文交互，直接回车即可完成安装；默认值覆盖常见场景，无需记参数。
- **两种模式**：
  - **无证书模式**（默认）：VLESS Reality 节点，不需要域名，安装后直接输出客户端配置。
  - **自动证书模式**：自动申请并续期 Let's Encrypt 证书（支持**端口模式**与 **DNS API 模式**），Mihomo 节点与 HTTPS 管理面板共用同一张证书，提供订阅链接，无需额外的 Web 服务器。
- **管理面板**：中文 Web 面板，查看 Mihomo 状态、一键重启 / 重载、立即申请 / 续期证书，添加或删除 VLESS Reality / Shadowsocks (SS) / Hysteria2 / Snell / TrustTunnel 入站，内置 Mihomo 控制面板（Zashboard）HTTPS 入口与密钥卡片，支持复制订阅链接或全部节点配置。
- **订阅链接**：`https://域名:端口/sub/<随机串>/mihomo.yaml`，带随机凭证，可随时更换。
- **`clashserver` 命令**：安装后直接输入 `clashserver` 打开中文管理菜单；常用操作都有短子命令。
- **安全默认**：端口、UUID、密钥、密码全部随机生成；面板自身提供 HTTPS（不经反代），登录失败次数限制；改配置前先 `mihomo -t` 校验，失败自动回滚。

## 📦 安装

以 root 身份执行：

```bash
curl -fsSL https://raw.githubusercontent.com/saulsburyroy/clashserver/main/install.sh | bash
```

按提示选择模式，**直接回车即为无证书模式**。

已有域名，想要管理面板和订阅链接：选择 **2) 自动证书模式**，按提示选择证书申请方式：

- **端口模式**（默认）：申请 / 续期证书时临时占用 **80** 端口；需将域名 A 记录指向本机并放行 TCP 80（Cloudflare 请设为 **灰云 DNS only**）。
- **DNS API 模式**：填写 Cloudflare API Token 自动完成域名验证，**无需开放 80 / 443 端口**，支持 `*.example.com` 泛域名。
- 环境：Debian 12（推荐）、systemd、root，服务器可直连 GitHub。管理面板在安装时自动选取**随机空闲高端口**提供 HTTPS（无需占用 443，安装输出与面板中均会明确展示端口）。

## 🚀 快速上手

**无证书模式**：安装结束会打印 `proxies` 片段，并生成完整客户端配置：

```
/root/clashserver-client/mihomo-client.yaml   # 完整 mihomo 客户端配置
/root/clashserver-client/proxies.yaml         # 仅节点片段
```

**自动证书模式**：安装结束会打印订阅链接和面板账号：

```
订阅链接：https://你的域名:<随机端口>/sub/<随机串>/mihomo.yaml   ← 导入 mihomo / Clash 客户端
管理面板：https://你的域名:<随机端口>   用户名 admin   密码（仅显示一次）
控制面板：https://你的域名:7896/ui/   （Zashboard，面板内支持一键带参免填打开与重置密钥）
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
  reset-password     重置面板密码（随机）
  reset-secret       重置 Zashboard API 密钥（随机）
  cert               立即申请 / 续期证书（平时自动续期）
  restart            重启 Mihomo
  log                查看最近日志
  update             更新 Mihomo 内核 + clashserver 自身
  uninstall          卸载
  install            重新安装（按提示选择模式）
  help               显示帮助
```

## 🖥️ 管理面板与订阅（自动证书模式）

- 面板地址 `https://你的域名:<随机端口>`（安装时自动分配随机空闲高端口），用户名 `admin`，密码安装时随机生成且**只显示一次**。修改：`clashserver passwd`；忘记：在服务器上执行 `clashserver reset-password`。
- 自动证书模式默认开启 Mihomo `external-controller-tls`（默认端口 **7896**）与 **Zashboard**（`external-ui`），管理面板内提供带 `hostname`/`port`/`secret` 参数的一键直连按钮及 API 密钥复制/重置功能（CLI 亦可执行 `clashserver reset-secret`），用于出站策略分流与连接管理。
- 证书由 [acme.sh](https://github.com/acmesh-official/acme.sh) 申请（可选**端口模式**或 **DNS API 模式**），存放在 `/etc/mihomo/certs/`，每小时检查、到期前自动续期：面板自动换用新证书（不重启）；Mihomo 控制面板及用到证书的 Hysteria2 / TrustTunnel 节点会自动重启 Mihomo 加载。若安装时证书尚未签发成功，会先用临时证书启动，检查配置后执行 `clashserver cert`（或在面板点击「立即申请 / 续期证书」）即可。`clashserver status` 可查看证书到期时间和上次自动续期结果。
- 订阅链接内容包含全部节点（含面板中新增的节点），每次请求实时生成。默认安装创建 1 个 VLESS Reality 入站节点，后续在面板增删节点会自动同步更新 `/root/clashserver-client/` 本地客户端文件，并在本机启用 `ufw` 时自动放行新节点端口、回收已删除节点端口（含 UDP）。
- **链接即凭证**：没有正确的随机串一律返回 404。泄露后执行 `clashserver reset-sub` 更换，旧链接立即失效。
- 支持添加 VLESS Reality、Shadowsocks（经典 AEAD `aes-128-gcm` 等）、Hysteria2、Snell、TrustTunnel 入站。Hysteria2 / Snell / TrustTunnel 目前只做配置写入，尚未做连通性验证；推荐使用 VLESS Reality 或 Shadowsocks。

## 🔄 更新

```bash
# 同时更新 Mihomo 内核与 clashserver（脚本、面板、模板）
clashserver update

# 只更新其一
clashserver update core
clashserver update self
```

更新不会改变节点、密钥、面板密码和订阅链接。

## 🗑️ 卸载

```bash
clashserver uninstall
```

删除 Mihomo、acme.sh、systemd 服务、面板、证书、配置、客户端文件和 `clashserver` 命令。需要保留的客户端配置请提前备份。

## ❓ 常见问题

<details>
<summary><b>证书申请失败 / 面板提示「尚未签发」</b></summary>

安装时若证书尚未签发成功，会先用临时证书启动（浏览器会提示不安全），之后每小时自动重试。请按所选方式确认：

- **端口模式**：
  1. 域名 A 记录指向本机公网 IP；Cloudflare 设为 **灰云（DNS only）**；如有 AAAA（IPv6）记录，须指向本机 IPv6，否则请删除；
  2. 云服务商防火墙 / 安全组放行 **TCP 80**，且 80 端口没有被 nginx、apache 等其他程序占用。
- **DNS API 模式**：
  1. Cloudflare API Token 具备该域名所在区域的 **DNS 编辑**权限。

修好后执行 `clashserver cert`（或在面板点击「立即申请 / 续期证书」）立即重试；`clashserver log` 可查看自动续期日志，安装时的申请记录在 `/etc/clashserver/cert-install.log`。
</details>

<details>
<summary><b>忘记面板密码</b></summary>

在服务器上执行 `clashserver reset-password`，会生成新的随机密码并显示一次；想自定义密码用 `clashserver passwd`。
</details>

<details>
<summary><b>订阅链接泄露了</b></summary>

执行 `clashserver reset-sub`，旧链接立即失效，再把新链接导入客户端。
</details>

<details>
<summary><b>安装提示 80 端口被占用</b></summary>

**端口模式**申请证书时临时使用 80 端口。你可以改选 **DNS API 模式**（无需 80 端口），或先停止占用 80 的程序（如 `systemctl disable --now nginx`）再安装。
</details>

## 📂 目录结构

```text
install.sh               # 一键安装入口（curl|bash 时自动下载其余文件）
uninstall.sh             # 卸载入口
panel/panel.py           # 管理面板（Python 标准库，无第三方依赖）
resources/               # 服务端 / 客户端配置模板
scripts/
  cmd/clashserver.sh     # clashserver 命令：菜单与子命令
  lib/                   # 公共函数：common / core / cert / panel
  init/                  # systemd unit
  certctl.sh             # 证书申请 / 续期（acme.sh），部署给 Mihomo 与面板
```

安装后文件位于 `/usr/local/lib/clashserver/`，配置在 `/etc/mihomo/` 与 `/etc/clashserver/`，命令为 `/usr/local/bin/clashserver`。

## 🗺️ 路线图

1. ✅ 无证书模式：VLESS Reality 一键安装
2. 🚧 自动证书模式：Let's Encrypt 证书 + HTTPS 面板 + 订阅链接
3. ⏳ 自定义反代模式
4. ⏳ 流量统计、权限、Docker 等

## ⚠️ 特别声明

- 本项目仅用于学习和研究 Shell 与网络技术，不得将项目内容用于违反适用法律法规及相关规定的活动。
- 本项目保留对本声明进行补充或修改的权利。使用本项目前，请阅读并遵守本声明。

## 📄 许可证

[MIT](LICENSE)
