<h1 align="center">
  clashserver
</h1>

<p align="center">
  Mihomo 的最后一公里<br />
  <sub>VPS 上的 Mihomo 服务端</sub>
</p>

<p align="center">
  <img alt="Platform: Linux" src="https://img.shields.io/badge/platform-Ubuntu%20%7C%20Debian%20%7C%20Rocky%20%7C%20Alma%20%7C%20Fedora%20%7C%20CentOS-blue" />
  <img alt="Init: systemd" src="https://img.shields.io/badge/init-systemd-blue" />
  <img alt="Core: Mihomo" src="https://img.shields.io/badge/core-Mihomo-6f42c1" />
  <img alt="Language: Shell" src="https://img.shields.io/github/languages/top/saulsburyroy/clashserver" />
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-green" /></a>
</p>

## ✨ 特性

- **三种安装模式**：
  - **无证书模式**（默认）：无需域名，直接部署 VLESS Reality 节点并生成完整客户端配置。
  - **自动证书模式**：自动申请并续期 Let's Encrypt 证书（支持 **端口模式** 与 **DNS API 模式**），提供 HTTPS 管理面板与订阅链接。
  - **手动证书模式**：使用 `/etc/clashserve/certs/` 下的自备证书，校验通过后开启 HTTPS 管理面板与订阅链接。
- **Web 管理控制台（v0.6）**：
  - **14 种入站协议**：VLESS Reality、Shadowsocks、Hysteria2、Snell、TrustTunnel、VLESS、VMess、AnyTLS、TUIC v5、ShadowQUIC、Mieru、Sudoku、HTTP、SOCKS5，支持弹窗查看/编辑单行或多行节点配置。
  - **出站与外部订阅**：支持导入外部订阅为 `proxy-providers:`，或粘贴 JSON / YAML 节点（含 `easytier`、`tailscale`）追加到服务端 `proxies:`。
  - **服务端与自定义配置**：内置 Zashboard 免填直连地址（随机高端口 + URL 编码 Secret）；支持粘贴整份自定义服务端配置、一键修正证书路径并同步入站与客户端订阅。
- **默认安全策略**：
  - **Reality SNI 池**：内置主流域名池，生成节点时随机抽取，不写死单一 SNI。
  - **VLESS Encryption**：VLESS 节点默认调用 `mihomo generate vless-x25519` 生成密钥对，服务端 `decryption` 与客户端 `encryption` 成对写入。
  - **随机端口与自动校验**：面板、Zashboard、节点端口、UUID 与密钥全部随机生成；每次修改先经 `mihomo -t` 校验，失败自动回滚。

## 📦 安装

**系统要求**：`root` 权限、`systemd` 服务管理器，支持主流服务端 Linux 发行版（**Ubuntu / Debian** `apt`，**Rocky Linux / AlmaLinux / Fedora / CentOS** 等 `dnf` / `yum`），服务器可访问 GitHub。

```bash
curl -fsSL https://raw.githubusercontent.com/saulsburyroy/clashserver/main/install.sh | bash
```

- **直接回车**：进入无证书模式，安装完成后输出节点配置并写入 `/etc/clashserve/client/`。
- **证书模式**：按提示选择自动证书（端口模式需解析 A 记录并放行 TCP 80；DNS API 模式需 Cloudflare Token，支持泛域名）或手动证书（放入 `fullchain.pem` 与 `privkey.pem`），安装完成后输出 HTTPS 管理面板地址与客户端订阅链接 `https://域名:端口/sub/<token>/mihomo.yaml`。

## ⌨️ 命令

安装后直接执行 `clashserver` 打开中文交互菜单，或使用子命令：

```text
clashserver [status | info | sub | reset-sub | passwd | reset-password | reset-secret | cert | restart | log | update | uninstall | install | help]
```

## 📂 目录结构

所有文件统一收纳于 `/etc/clashserve/`（旧版 `/etc/mihomo`、`/etc/clashserver`、`/var/lib/mihomo` 等路径自动迁移并保留软链）：

```text
/etc/clashserve/
  mihomo                 # Mihomo 内核二进制（软链 /usr/local/bin/mihomo）
  config.yaml            # 服务端运行配置（自定义模式下由 custom_config.yaml 同步）
  certs/                 # TLS 证书（fullchain.pem / privkey.pem，Mihomo 与面板共用）
  client/                # 本地客户端配置备份（mihomo-client.yaml / proxies.yaml）
  acme.sh/               # acme.sh 自动证书目录
  panel/panel.py         # HTTPS 管理面板（Python 3 标准库）
  resources/             # 服务端与 ACL4SSR 客户端配置模板
  scripts/               # CLI 脚本、公共库、certctl.sh 与 systemd unit
```

## ⚠️ 特别声明

- 本项目仅用于学习和研究 Shell 与网络技术，不得将项目内容用于违反适用法律法规及相关规定的活动。
- 使用本项目前，请阅读并遵守本声明。

## 📄 许可证

[MIT](LICENSE)
