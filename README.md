<h1 align="center">clashserver</h1>

<p align="center">
  Mihomo 的最后一公里 · VPS 上的 Mihomo 服务端 (v0.8)
</p>

<p align="center">
  <img alt="Platform: Linux" src="https://img.shields.io/badge/platform-Ubuntu%20%7C%20Debian%20%7C%20Rocky%20%7C%20Alma%20%7C%20Fedora%20%7C%20CentOS-blue" />
  <img alt="Init: systemd" src="https://img.shields.io/badge/init-systemd-blue" />
  <img alt="Core: Mihomo" src="https://img.shields.io/badge/core-Mihomo-10b981" />
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-green" /></a>
</p>

## ✨ 核心特性

- **三种安装模式**：**无证书模式**（默认直出 VLESS Reality 节点）、**自动证书模式**（Let's Encrypt 端口 / DNS API 自动续期）、**手动证书模式**（自备 `/etc/clashserve/certs/` 证书）。
- **HTTPS 管理面板（v0.8）**：
  - **开箱即用**：支持 12 种入站协议（VLESS Reality、Hysteria2、Snell V5、Shadowsocks、AnyTLS、TUIC v5、TrustTunnel、ShadowQUIC、Mieru、Sudoku、HTTP、SOCKS5），安全参数（加密方式、混淆、SNI 池、指纹等）全部内置锁定，支持一键**重置密码/密钥**。
  - **首页直达**：订阅链接（支持一键更换）、入站节点、Zashboard 控制台（含免填直连地址与 API 密钥）常驻首页。
  - **双向实时同步**：支持外部订阅（`proxy-providers`）、出站节点（含 `easytier` / `tailscale`）、易读配置转换，以及独立高级页自定义服务端配置（支持自动修正证书路径与一键恢复默认 VlessReality 配置），所有改动经 `mihomo -t` 校验后同步至服务端与客户端订阅。

## 📦 一键安装

支持 `systemd` 主流 Linux 发行版（Ubuntu / Debian / Rocky / Alma / Fedora / CentOS，需 `root` 权限）：

```bash
curl -fsSL https://raw.githubusercontent.com/saulsburyroy/clashserver/main/install.sh | bash
```

## ⌨️ 常用命令

直接执行 `clashserver` 打开中文交互菜单，或使用子命令：

```text
clashserver [status | info | sub | reset-sub | passwd | reset-password | reset-secret | cert | restart | log | update | uninstall | install | help]
```

## 📂 核心目录

所有文件收纳于 `/etc/clashserve/`（旧版目录自动迁移）：

- `config.yaml` / `custom_config.yaml`：服务端配置
- `certs/`：TLS 证书（`fullchain.pem` / `privkey.pem`）
- `client/`：本地生成的客户端配置与节点片段（`mihomo-client.yaml` / `proxies.yaml`）
- `panel/`：Web 管理面板

## ⚠️ 声明与许可

本项目仅用于网络与自动化技术学习研究，请遵守所在地法律法规。[MIT License](LICENSE)
