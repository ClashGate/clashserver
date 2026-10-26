# Clash Server — 第一阶段：无证书模式一键安装

来源：Notion《项目名称：Clash Server》+ 产品经理确认优先事项。  
仓库工作区：`/workspace/clashserver`（拟名 clashserver）。

## 角色
在 Antigravity 里用 Claude 写代码。可按判断发挥，不必死抠字面；拿不定主意时停下提问，不要硬烧 token。

## 项目目标（摘要）
基于 **Mihomo** 内核的 VPS 一键代理服务端部署。开发优先级必须遵守：
1. **第一阶段（当前）**：无证书模式完整可用
2. 第二阶段：自动证书模式（Caddy + Let’s Encrypt + 面板）
3. 第三阶段：自定义反代模式
4. 流量统计、复杂权限、Docker 等全部延后

## 第一阶段必须做
- **不**安装 Caddy，**不**申请证书，**不**提供面板
- 直接在 Mihomo 中配置若干 **VLESS + Reality** 节点（listeners）
- 优先支持 **Debian**；安装 **最新稳定版 Mihomo**；创建 **systemd** 服务
- 安装完成后输出客户端可用的 proxies YAML 片段，例如：
  ```yaml
  proxies:
    - {"name":"vps名称|Clash|Reality","type":"vless","server":"xxxxxxx","port":xxxx,"uuid":"xxxxxxxxxx","tls":true,"flow":"xtls-rprx-vision","client-fingerprint":"safari","skip-cert-verify":false,"reality-opts":{"public-key":"xxxxxxxxx0","short-id":"xxxxxx"},"network":"tcp","udp":true,"servername":"www.sc.com"}
  ```
- 同时默认生成一份 **mihomo 客户端配置**（含上述节点）；因无证书，不生成订阅链接，写到本地文件夹，并**把该文件夹绝对路径打印给用户**
- 支持一键卸载；安装过程有清晰进度与错误提示；支持更新 Mihomo 内核（可后置但接口预留更好）
- Reality 私钥等用合适工具生成（如 `xray x25519` / mihomo 文档推荐方式）；端口、UUID、密码随机

## 明确不做（本阶段）
面板、TLS 证书、Caddy、依赖证书的入站（anytls / hysteria2 / vmess-ws / xhttp+cert 等可后置）。`serve.yaml` 里有证书入站仅作结构参考。

## 参考
- Notion：https://app.notion.com/p/405d196df40f80fa8a30f85b335807ab
- 安装合并思路：https://github.com/nelvko/clash-for-linux-install（`.clashctl/data/mixin.yaml` → `runtime.yaml`）
- Mihomo 文档：https://wiki.metacubex.one/en/
- 参考服务端配置：本目录 `serve.yaml`（secrets 已打码；学结构，勿照抄假密钥）

## 建议交付物
- `install.sh`（或 `scripts/install-nocert.sh`）：root 下一键；可参数指定无证书模式
- systemd unit
- 服务端配置模板 / 生成逻辑（listeners 精简自 serve.yaml 的 Reality 部分）
- 客户端配置生成到本地目录 + README

## 成功标准（第一可运行里程碑）
干净 Debian 上跑通：Mihomo 已装、systemd active、≥1 个 VLESS+Reality listener 在听、终端打印 proxies 片段与客户端配置目录路径。

## 过程记录
开发问题、决策、卡点追加到 Notion 规格页「开发备注」：https://app.notion.com/p/405d196df40f80fa8a30f85b335807ab
重要备注同时通知产品经理。
