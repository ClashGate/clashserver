# Clash Server

基于 [Mihomo (Clash Meta)](https://github.com/MetaCubeX/mihomo) 内核的 VPS 一键代理服务端部署脚本。
One-click Mihomo proxy server installer for a Debian VPS.

> 状态：早期开发中。当前目标是先跑通整体框架（安装 → 节点 → 面板 → 卸载），功能与细节后续再补。
> Status: early development — big framework first, details later.

## 功能 / Features

- **no-cert 模式**（默认）：不装 Caddy、不申请证书、无面板；直接生成若干 **VLESS + Reality** 节点。
- **auto-cert 模式**：安装 Caddy 申请证书（Let's Encrypt），并提供 Web 管理面板。
  - 面板可添加 / 删除入站：VLESS Reality、Hysteria2、Snell、TrustTunnel（hy2 / snell / TrustTunnel 目前只做配置，尚未做连通性验证）。
  - 证书由 `clashserver-certsync.timer` 每小时同步给 Mihomo。
- 安装完成后打印客户端 `proxies` 片段，并生成一份 mihomo 客户端配置（路径会打印出来，默认 `/root/clashserver-client`）。
- 支持 `update`（更新 Mihomo 内核）、`info`、`uninstall`、`reset-password`。

## 环境要求 / Requirements

- **Debian 12**（推荐，其他 Debian 系未充分测试），使用 systemd
- root 权限，可访问 GitHub（下载 Mihomo release）
- auto-cert 模式另需：一个域名的 A 记录指向 VPS，且 **80 / 443** 端口可从公网访问（HTTP-01 验证）

依赖（`curl gzip jq openssl iproute2` 等，auto-cert 时还有 `python3`、Caddy）由脚本自动安装。

## 安装 / Install

```bash
git clone https://github.com/saulsburyroy/clashserver.git
cd clashserver
sudo ./install.sh install            # 默认 no-cert，3 个 Reality 节点
```

### no-cert 模式

```bash
sudo ./install.sh install --nodes 2 --name myvps
# 指定公网 IP（不指定则自动探测）
sudo ./install.sh install --nodes 2 --name myvps --ip 203.0.113.10
```

### auto-cert 模式

```bash
# 生产证书（Let's Encrypt 正式环境）
sudo ./install.sh install --mode auto-cert --domain proxy.example.com --email you@example.com

# 测试：Let's Encrypt staging（浏览器会提示证书不受信任，用于避免触发正式环境限额）
sudo ./install.sh install --mode auto-cert --domain proxy.example.com --tls-staging

# 本地 / 无公网域名调试：Caddy 内部 CA（仅开发用）
sudo ./install.sh install --mode auto-cert --domain panel.test --tls-internal
```

| 证书选项 | 说明 |
|---|---|
| （默认） | Let's Encrypt 正式证书，公开可信 |
| `--tls-staging` | LE staging，不受信任，用于测试流程 |
| `--tls-internal` | Caddy 自签内部 CA，仅开发调试 |

### Cloudflare 说明

目前只支持 HTTP-01 验证，**不支持** Cloudflare DNS-01。如果域名托管在 Cloudflare，请把 A 记录设为 **DNS only（灰云）**，不要开启代理（橙云），否则证书申请和代理流量都会出问题。

## 管理面板 / Panel（auto-cert）

- 地址：`https://<你的域名>/`（Caddy 反代到本机 `127.0.0.1:8088`，可用 `--panel-port` 修改内部端口）
- 用户名：`admin`
- 密码：安装时随机生成，**只打印一次**，请立刻保存。忘记密码：

```bash
sudo ./install.sh reset-password
```

## 常用命令 / Commands

```bash
sudo ./install.sh info        # 查看节点 / 客户端配置
sudo ./install.sh update      # 更新 Mihomo 内核
sudo ./install.sh uninstall   # 卸载
sudo ./install.sh install --force ...   # 已安装或上次中途失败时，先完整卸载再重装
```

| 参数 | 说明 |
|---|---|
| `--mode no-cert\|auto-cert` | 安装模式，默认 `no-cert`（`--no-cert` 同义） |
| `--nodes N` | Reality 节点数量，默认 3 |
| `--name NAME` | 节点名中的 VPS 名称，默认主机名 |
| `--ip IP` | 客户端配置中使用的服务器 IP，默认自动探测 |
| `--domain D` / `--email E` | auto-cert 的域名 / ACME 邮箱 |
| `--tls-staging` / `--tls-internal` | 证书来源（见上表） |
| `--panel-port P` | 面板本地监听端口，默认 8088 |
| `--force` | 先卸载再安装 |

## 卸载 / Uninstall

```bash
sudo ./install.sh uninstall
```

会删除 Mihomo、systemd 服务、面板、证书、配置与客户端文件；Caddy 若由本脚本安装则一并卸载，若原本已存在则恢复原 Caddyfile。

## 目录结构 / Layout

```
install.sh            # 安装 / 卸载 / 更新入口
templates/            # 服务端、客户端、Caddyfile 模板
panel/panel.py        # 面板（Python 标准库，无第三方依赖）
scripts/certsync.sh   # Caddy 证书同步到 Mihomo
systemd/              # systemd unit
```

## 关于 serve.yaml

开发时会参考一份本地的 `serve.yaml`（真实服务端配置样例），它**不随仓库发布**（已在 `.gitignore` 中）。仓库内的配置全部由模板生成，密钥、端口、UUID 均在安装时随机生成。

## 路线图 / Roadmap

1. ✅ no-cert：VLESS Reality 一键安装
2. 🚧 auto-cert：Caddy + LE + 面板（框架已通，细节完善中）
3. ⏳ 自定义反代模式
4. ⏳ 流量统计、权限、Docker 等
