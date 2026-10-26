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
  - **自动证书模式**：自动安装 Caddy、申请 Let's Encrypt 证书，提供 HTTPS 管理面板和订阅链接。
- **管理面板**：中文 Web 面板，查看 Mihomo 状态、一键重启 / 重载，添加 VLESS Reality / Hysteria2 / Snell / TrustTunnel 入站，复制订阅链接。
- **订阅链接**：`https://域名/sub/<随机串>/mihomo.yaml`，带随机凭证，可随时更换。
- **`clashserver` 命令**：安装后直接输入 `clashserver` 打开中文管理菜单；常用操作都有短子命令。
- **安全默认**：端口、UUID、密钥、密码全部随机生成；面板仅本机监听、由 Caddy HTTPS 反代；改配置前先 `mihomo -t` 校验，失败自动回滚。

## 📦 安装

以 root 身份执行：

```bash
curl -fsSL https://raw.githubusercontent.com/saulsburyroy/clashserver/main/install.sh | bash
```

按提示选择模式，**直接回车即为无证书模式**。

已有域名，想要管理面板和订阅链接：选择 **2) 自动证书模式**，按提示输入域名即可。

- 环境：Debian 12（推荐）、systemd、root，服务器可直连 GitHub。
- 自动证书模式需要：域名 A 记录指向本机，公网可访问 **80 / 443**；Cloudflare 请设为 **灰云（DNS only）**。

## 🚀 快速上手

**无证书模式**：安装结束会打印 `proxies` 片段，并生成完整客户端配置：

```
/root/clashserver-client/mihomo-client.yaml   # 完整 mihomo 客户端配置
/root/clashserver-client/proxies.yaml         # 仅节点片段
```

**自动证书模式**：安装结束会打印订阅链接和面板账号：

```
订阅链接：https://你的域名/sub/<随机串>/mihomo.yaml   ← 导入 mihomo / Clash 客户端
管理面板：https://你的域名   用户名 admin   密码（仅显示一次）
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
  restart            重启 Mihomo
  log                查看最近日志
  update             更新 Mihomo 内核 + clashserver 自身
  uninstall          卸载
  install            重新安装（按提示选择模式）
  help               显示帮助
```

## 🖥️ 管理面板与订阅（自动证书模式）

- 面板地址 `https://你的域名`，用户名 `admin`，密码安装时随机生成且**只显示一次**。修改：`clashserver passwd`；忘记：`clashserver reset-password`。
- 订阅链接内容包含全部节点（含面板中新增的节点），每次请求实时生成。
- **链接即凭证**：没有正确的随机串一律返回 404。泄露后执行 `clashserver reset-sub` 更换，旧链接立即失效。
- Hysteria2 / Snell / TrustTunnel 目前只做配置写入，尚未做连通性验证；推荐使用 VLESS Reality。

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

删除 Mihomo、systemd 服务、面板、证书、配置、客户端文件和 `clashserver` 命令；Caddy 若由本工具安装则一并卸载，若原本已存在则恢复原 Caddyfile。需要保留的客户端配置请提前备份。

## 📂 目录结构

```text
install.sh               # 一键安装入口（curl|bash 时自动下载其余文件）
uninstall.sh             # 卸载入口
panel/panel.py           # 管理面板（Python 标准库，无第三方依赖）
resources/               # 服务端 / 客户端 / Caddyfile 模板
scripts/
  cmd/clashserver.sh     # clashserver 命令：菜单与子命令
  lib/                   # 公共函数：common / core / cert / panel
  init/                  # systemd unit
  certsync.sh            # Caddy 证书同步给 Mihomo
```

安装后文件位于 `/usr/local/lib/clashserver/`，配置在 `/etc/mihomo/` 与 `/etc/clashserver/`，命令为 `/usr/local/bin/clashserver`。

## 🗺️ 路线图

1. ✅ 无证书模式：VLESS Reality 一键安装
2. 🚧 自动证书模式：Caddy + LE + 面板 + 订阅链接
3. ⏳ 自定义反代模式
4. ⏳ 流量统计、权限、Docker 等

## ⚠️ 特别声明

- 本项目仅用于学习和研究 Shell 与网络技术，不得将项目内容用于违反适用法律法规及相关规定的活动。
- 本项目保留对本声明进行补充或修改的权利。使用本项目前，请阅读并遵守本声明。

## 📄 许可证

[MIT](LICENSE)
