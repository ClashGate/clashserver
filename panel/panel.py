#!/usr/bin/env python3
"""clashserve v0.4 - minimal admin panel for clashserver (certificate modes).

Stdlib only (Debian python3). Serves HTTPS itself with the same certificate
Mihomo uses (/etc/mihomo/certs); no reverse proxy.
Features: admin login, Mihomo status dashboard, restart/reload, cert renewal,
mihomo server config viewer (authenticated) & outbound proxies manager,
add/delete inbounds (vless-reality, shadowsocks, hysteria2, snell, trusttunnel).

Subcommands:
  panel.py hash-password            read password on stdin, print hash
  panel.py serve --config FILE      run the HTTP server
"""
import argparse
import base64
import calendar
import hashlib
import hmac
import html
import json
import os
import random
import re
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid as uuidlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse, quote

VERSION = "0.4"

# CLASHSERVER_ROOT lets the panel run against a fake tree for local testing.
ROOT = os.environ.get("CLASHSERVER_ROOT", "")
ENV_FILE = ROOT + "/etc/clashserver/clashserver.env"
INBOUNDS = ROOT + "/etc/clashserver/inbounds.json"
PROXIES_JSON = ROOT + "/etc/clashserver/proxies.json"
MIHOMO_DIR = ROOT + "/etc/mihomo"
CONF = MIHOMO_DIR + "/config.yaml"
NODES_TSV = MIHOMO_DIR + "/nodes.tsv"
FRAG_CONTROLLER = MIHOMO_DIR + "/controller.yaml"
FRAG_REALITY = MIHOMO_DIR + "/listeners.reality.yaml"
FRAG_EXTRA = MIHOMO_DIR + "/listeners.extra.yaml"
FRAG_PROXIES = MIHOMO_DIR + "/proxies.extra.yaml"
TEMPLATE = ROOT + "/usr/local/lib/clashserver/resources/server.yaml.tpl"
CLIENT_TEMPLATE = ROOT + "/usr/local/lib/clashserver/resources/client.yaml.tpl"
CLIENT_DIR = ROOT + "/root/clashserver-client"
CERTCTL = ROOT + "/usr/local/lib/clashserver/scripts/certctl.sh"
CERT = "/etc/mihomo/certs/fullchain.pem"   # paths as seen by mihomo (not ROOT-prefixed)
KEY = "/etc/mihomo/certs/privkey.pem"
MIHOMO_BIN = os.environ.get("MIHOMO_BIN", "/usr/local/bin/mihomo")
SYSTEMCTL = os.environ.get("SYSTEMCTL", "systemctl")
UFW_BIN = os.environ.get("UFW_BIN", "ufw")
REALITY_SNI = "www.sc.com"
PBKDF2_ITER = 600_000
SESSION_TTL = 12 * 3600
TYPES = ("vless-reality", "shadowsocks", "hysteria2", "snell", "trusttunnel")
CERT_TYPES = ("hysteria2", "trusttunnel")
SS_CIPHERS = ("aes-128-gcm", "aes-256-gcm")
SS_CIPHER_LABELS = {
    "aes-128-gcm": "aes-128-gcm（aes128，默认）",
    "aes-256-gcm": "aes-256-gcm（aes256）",
}
STR_KEYS = {
    "name", "type", "server", "uuid", "password", "psk", "public-key", "private-key",
    "short-id", "servername", "sni", "cipher", "flow", "client-fingerprint",
    "username", "network", "path", "host", "mode", "plugin", "obfs", "fingerprint",
}

LOCK = threading.Lock()


# ---------------------------------------------------------------- helpers
def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ITER)
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ITER, base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def verify_password(pw: str, stored: str) -> bool:
    try:
        algo, it, salt, dk = stored.split("$")
        assert algo == "pbkdf2_sha256"
        calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), base64.b64decode(salt), int(it))
        return hmac.compare_digest(calc, base64.b64decode(dk))
    except Exception:
        return False


def read_env() -> dict:
    env = {}
    try:
        with open(ENV_FILE) as f:
            for line in f:
                m = re.match(r"^([A-Z_]+)=(.*)$", line.strip())
                if m:
                    env[m.group(1)] = m.group(2).strip("'\"")
    except FileNotFoundError:
        pass
    return env


def run(cmd, timeout=30, env=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return p.returncode, (p.stdout + p.stderr).strip()
    except Exception as e:  # missing binary, timeout ...
        return 127, str(e)


def load_inbounds() -> list:
    try:
        with open(INBOUNDS) as f:
            return json.load(f)
    except FileNotFoundError:
        return []


def load_server_proxies() -> list:
    try:
        with open(PROXIES_JSON) as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
    except FileNotFoundError:
        pass
    try:
        with open(FRAG_PROXIES) as f:
            raw = f.read().strip()
            if raw:
                return parse_mihomo_proxies("proxies:\n" + raw)
    except Exception:
        pass
    return []


def read_nodes() -> list:
    rows = []
    try:
        with open(NODES_TSV) as f:
            for line in f:
                p = line.rstrip("\n").split("\t")
                if len(p) >= 7:
                    rows.append({"name": p[0], "port": int(p[1]), "uuid": p[2],
                                 "priv": p[3], "pub": p[4], "sid": p[5], "sni": p[6]})
    except FileNotFoundError:
        pass
    return rows


def used_ports(env) -> set:
    ports = {80, 443, int(env.get("PANEL_PORT", "0") or 0), int(env.get("CONTROLLER_PORT", "7896") or 7896)}
    ports |= {n["port"] for n in read_nodes()}
    ports |= {i["port"] for i in load_inbounds()}
    return ports


def pick_port(env) -> int:
    used = used_ports(env)
    for _ in range(1000):
        p = random.randint(20000, 39999)
        if p not in used:
            return p
    raise RuntimeError("没有可用的随机端口")


def reality_keypair():
    rc, out = run([MIHOMO_BIN, "generate", "reality-keypair"])
    priv = re.search(r"PrivateKey:\s*(\S+)", out)
    pub = re.search(r"PublicKey:\s*(\S+)", out)
    if rc != 0 or not priv or not pub:
        raise RuntimeError("Reality 密钥对生成失败：" + out)
    return priv.group(1), pub.group(1)


def certs_present() -> bool:
    return os.path.isfile(ROOT + CERT) and os.path.isfile(ROOT + KEY)


def panel_base_url(env: dict, cfg: dict) -> str:
    host = env.get("DOMAIN", "").removeprefix("*.")
    if not host:
        return ""
    port = int(cfg.get("port") or env.get("PANEL_PORT") or 8443)
    return f"https://{host}" if port == 443 else f"https://{host}:{port}"


def server_config_url(env: dict, cfg: dict) -> str:
    base = panel_base_url(env, cfg)
    return f"{base}/config/server.yaml" if base else "/config/server.yaml"


def zashboard_url(env: dict) -> str:
    host = env.get("DOMAIN", "").removeprefix("*.") or env.get("SERVER_IP", "")
    if not host:
        return ""
    cport = int(env.get("CONTROLLER_PORT") or 7896)
    return f"https://{host}:{cport}/ui/"


def zashboard_connect_url(env: dict) -> str:
    host = env.get("DOMAIN", "").removeprefix("*.") or env.get("SERVER_IP", "")
    if not host:
        return ""
    cport = int(env.get("CONTROLLER_PORT") or 7896)
    secret = env.get("MIHOMO_SECRET", "")
    if not secret:
        return f"https://{host}:{cport}/ui/"
    qs = f"hostname={quote(host)}&port={cport}&secret={quote(secret)}&https=true"
    return f"https://{host}:{cport}/ui/?{qs}#/setup?{qs}"


def write_env_var(key: str, val: str):
    lines = []
    found = False
    try:
        with open(ENV_FILE) as f:
            for line in f:
                if line.startswith(f"{key}="):
                    lines.append(f'{key}="{val}"\n')
                    found = True
                else:
                    lines.append(line)
    except FileNotFoundError:
        pass
    if not found:
        lines.append(f'{key}="{val}"\n')
    atomic_write(ENV_FILE, "".join(lines), 0o600)


def render_controller_fragment(env: dict) -> str:
    if env.get("MODE") != "auto-cert":
        return "# controller disabled in no-cert mode\n"
    cport = env.get("CONTROLLER_PORT") or "7896"
    secret = env.get("MIHOMO_SECRET", "")
    return (
        f'external-controller-tls: "0.0.0.0:{cport}"\n'
        f"tls:\n  certificate: {CERT}\n  private-key: {KEY}\n"
        f"external-controller-cors:\n  allow-origins:\n    - '*'\n  allow-private-network: true\n"
        f'secret: "{secret}"\n'
        f"external-ui: ui\n"
        f'external-ui-url: "https://github.com/Zephyruso/zashboard/releases/latest/download/dist-cdn-fonts.zip"\n'
    )


# ---------------------------------------------------------------- YAML / JSON proxy parser & serializer
def strip_yaml_comment(s: str) -> str:
    in_sq = in_dq = escaped = False
    for i, ch in enumerate(s):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_dq:
            escaped = True
            continue
        if ch == "'" and not in_dq:
            in_sq = not in_sq
        elif ch == '"' and not in_sq:
            in_dq = not in_dq
        elif ch == "#" and not in_sq and not in_dq:
            if i == 0 or s[i - 1].isspace():
                return s[:i].rstrip()
    return s.rstrip()


def split_kv(line: str):
    in_sq = in_dq = escaped = False
    for i, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_dq:
            escaped = True
            continue
        if ch == "'" and not in_dq:
            in_sq = not in_sq
        elif ch == '"' and not in_sq:
            in_dq = not in_dq
        elif ch == ":" and not in_sq and not in_dq:
            if i + 1 == len(line) or line[i + 1].isspace():
                k = line[:i].strip()
                if (k.startswith('"') and k.endswith('"')) or (k.startswith("'") and k.endswith("'")):
                    k = k[1:-1]
                return k, ":", line[i + 1:].strip()
    return line, "", ""


def parse_scalar(val: str, key: str = ""):
    val = val.strip()
    if not val:
        return ""
    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
        if val.startswith('"'):
            try:
                return json.loads(val)
            except Exception:
                return val[1:-1]
        return val[1:-1].replace("''", "'")
    low = val.lower()
    if key not in STR_KEYS:
        if low == "true":
            return True
        if low == "false":
            return False
        if low in ("null", "~"):
            return None
        if re.fullmatch(r"-?(?:0|[1-9]\d*)", val):
            return int(val)
        if re.fullmatch(r"-?\d+\.\d+", val):
            return float(val)
    return val


def split_flow(s: str, sep: str = ",") -> list:
    parts, buf = [], []
    depth_c = depth_b = 0
    in_sq = in_dq = escaped = False
    for ch in s:
        if escaped:
            buf.append(ch)
            escaped = False
            continue
        if ch == "\\" and in_dq:
            buf.append(ch)
            escaped = True
            continue
        if ch == "'" and not in_dq:
            in_sq = not in_sq
        elif ch == '"' and not in_sq:
            in_dq = not in_dq
        elif not in_sq and not in_dq:
            if ch == "{":
                depth_c += 1
            elif ch == "}":
                depth_c -= 1
            elif ch == "[":
                depth_b += 1
            elif ch == "]":
                depth_b -= 1
            elif ch == sep and depth_c == 0 and depth_b == 0:
                parts.append("".join(buf).strip())
                buf = []
                continue
        buf.append(ch)
    if buf or s.endswith(sep):
        parts.append("".join(buf).strip())
    return [p for p in parts if p != ""]


def parse_flow_val(val: str, key: str = ""):
    val = val.strip()
    if val.startswith("{") and val.endswith("}"):
        try:
            obj = json.loads(val)
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass
        inner = val[1:-1].strip()
        if not inner:
            return {}
        out = {}
        for item in split_flow(inner, ","):
            k, sep, v = split_kv(item)
            if not sep:
                raise ValueError(f"无法解析字段：{item}")
            out[k] = parse_flow_val(v, k)
        return out
    if val.startswith("[") and val.endswith("]"):
        try:
            arr = json.loads(val)
            if isinstance(arr, list):
                return arr
        except Exception:
            pass
        inner = val[1:-1].strip()
        if not inner:
            return []
        return [parse_flow_val(x, key) for x in split_flow(inner, ",")]
    return parse_scalar(val, key)


def parse_yaml_lines(lines: list, idx: int = 0, min_indent: int = 0):
    if idx >= len(lines):
        return None, idx
    ind0, txt0 = lines[idx]
    if ind0 < min_indent:
        return None, idx
    if txt0 == "-" or txt0.startswith("- "):
        arr = []
        seq_indent = ind0
        while idx < len(lines):
            ind, txt = lines[idx]
            if ind < seq_indent or not (txt == "-" or txt.startswith("- ")):
                break
            if ind != seq_indent:
                raise ValueError(f"YAML 列表缩进不一致：{txt}")
            rest = txt[1:].strip()
            idx += 1
            if not rest:
                sub, idx = parse_yaml_lines(lines, idx, seq_indent + 1)
                arr.append(sub)
            elif rest.startswith("{") and rest.endswith("}"):
                arr.append(parse_flow_val(rest))
            else:
                k, sep, v = split_kv(rest)
                if sep:
                    item_indent = ind + 2
                    virtual = [(item_indent, rest)]
                    while idx < len(lines) and lines[idx][0] >= item_indent:
                        virtual.append(lines[idx])
                        idx += 1
                    sub, _ = parse_yaml_lines(virtual, 0, item_indent)
                    arr.append(sub)
                else:
                    arr.append(parse_flow_val(rest))
        return arr, idx
    else:
        mapping = {}
        map_indent = ind0
        while idx < len(lines):
            ind, txt = lines[idx]
            if ind < map_indent:
                break
            if txt == "-" or txt.startswith("- "):
                break
            if ind != map_indent:
                raise ValueError(f"YAML 映射缩进不一致：{txt}")
            k, sep, v = split_kv(txt)
            if not sep:
                raise ValueError(f"无效的 YAML 行：{txt}")
            idx += 1
            if v:
                mapping[k] = parse_flow_val(v, k)
            else:
                if idx < len(lines) and lines[idx][0] >= map_indent:
                    nxt_ind, nxt_txt = lines[idx]
                    if nxt_ind > map_indent or (nxt_ind == map_indent and (nxt_txt == "-" or nxt_txt.startswith("- "))):
                        sub, idx = parse_yaml_lines(lines, idx, map_indent)
                        mapping[k] = sub
                    else:
                        mapping[k] = ""
                else:
                    mapping[k] = ""
        return mapping, idx


def parse_mihomo_proxies(raw: str) -> list:
    """Parse single-line JSON or multi-line YAML mihomo node configs; normalize with udp: True."""
    s = (raw or "").strip()
    if not s:
        raise ValueError("请输入 mihomo 节点配置（单行 JSON 或多行 YAML）")
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", s):
        raise ValueError("不支持分享链接（如 vless://、ss://），请粘贴 mihomo 配置格式（JSON 或 YAML）")
    parsed = None
    if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
        try:
            parsed = json.loads(s)
        except Exception:
            try:
                parsed = parse_flow_val(s)
            except Exception:
                parsed = None
    if parsed is None:
        lines = []
        for raw_line in s.splitlines():
            cleaned = strip_yaml_comment(raw_line.expandtabs(2))
            if not cleaned.strip():
                continue
            ind = len(cleaned) - len(cleaned.lstrip(" "))
            lines.append((ind, cleaned.strip()))
        if not lines:
            raise ValueError("节点配置为空")
        if all(txt.startswith("{") and txt.endswith("}") for _, txt in lines):
            parsed = [parse_flow_val(txt) for _, txt in lines]
        else:
            parsed, end_idx = parse_yaml_lines(lines, 0, 0)
            if end_idx < len(lines):
                raise ValueError(f"无法解析第 {end_idx + 1} 行附近的配置：{lines[end_idx][1]}")
    if isinstance(parsed, dict) and "proxies" in parsed and isinstance(parsed["proxies"], list):
        items = parsed["proxies"]
    elif isinstance(parsed, dict):
        items = [parsed]
    elif isinstance(parsed, list):
        items = parsed
    else:
        raise ValueError("仅支持 mihomo 节点配置格式（单行 JSON 或多行 YAML）")
    if not items:
        raise ValueError("未找到任何节点配置")
    out = []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("每个节点必须是键值对对象（需包含 name、type、server、port）")
        node = dict(item)
        for req in ("name", "type", "server", "port"):
            if req not in node or node[req] in ("", None):
                raise ValueError(f"节点缺少必填字段：{req}")
        node["name"] = str(node["name"]).strip()
        node["type"] = str(node["type"]).strip()
        node["server"] = str(node["server"]).strip()
        try:
            port = int(node["port"])
            if not 1 <= port <= 65535:
                raise ValueError()
            node["port"] = port
        except Exception:
            nm, pt = node["name"], node["port"]
            raise ValueError(f"节点「{nm}」端口无效：{pt}")
        for k in list(node.keys()):
            if k in STR_KEYS and node[k] is not None and not isinstance(node[k], (dict, list)):
                node[k] = str(node[k])
        if "udp" not in node or node["udp"] is None:
            node["udp"] = True
        out.append(node)
    return out


def yaml_scalar(v, key: str = "") -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "null"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    if s == "":
        return '""'
    if (key in STR_KEYS and re.fullmatch(r"0\d+|-?\d+(\.\d+)?", s)) or s.lower() in (
        "true", "false", "null", "yes", "no", "on", "off", "~"
    ):
        return json.dumps(s, ensure_ascii=False)
    if re.fullmatch(r"[A-Za-z0-9._/+@-]+", s) and not s.startswith("-"):
        return s
    return json.dumps(s, ensure_ascii=False)


def dump_yaml_map(d: dict, indent: int = 4, first_dash: bool = False) -> list:
    priority = ("name", "type", "server", "port")
    keys = [k for k in priority if k in d] + [k for k in d if k not in priority]
    lines = []
    for idx, k in enumerate(keys):
        v = d[k]
        prefix = (" " * (indent - 2) + "- ") if (idx == 0 and first_dash) else (" " * indent)
        ks = k if re.fullmatch(r"[A-Za-z0-9._-]+", str(k)) else json.dumps(str(k), ensure_ascii=False)
        if isinstance(v, dict):
            if not v:
                lines.append(f"{prefix}{ks}: {{}}")
            else:
                lines.append(f"{prefix}{ks}:")
                lines.extend(dump_yaml_map(v, indent + 2, False))
        elif isinstance(v, list):
            if not v:
                lines.append(f"{prefix}{ks}: []")
            else:
                lines.append(f"{prefix}{ks}:")
                for elem in v:
                    if isinstance(elem, dict):
                        lines.extend(dump_yaml_map(elem, indent + 4, True))
                    else:
                        lines.append(" " * (indent + 2) + "- " + yaml_scalar(elem, k))
        else:
            lines.append(f"{prefix}{ks}: {yaml_scalar(v, k)}")
    return lines


def dump_yaml_proxies(proxies: list) -> str:
    """Render a list of proxy dicts as multi-line YAML items (2-space indented `- `)."""
    lines = []
    for p in proxies:
        lines.extend(dump_yaml_map(p, indent=4, first_dash=True))
    return "\n".join(lines) + ("\n" if lines else "")


# ---------------------------------------------------------------- inbound model
def build_inbound(kind: str, form: dict, env: dict) -> dict:
    if kind not in TYPES:
        raise ValueError("未知的入站类型")
    if kind in CERT_TYPES and not certs_present():
        raise ValueError(f"{kind} 需要 TLS 证书，未找到 {CERT}（请先在服务器执行 clashserver cert）")
    port_s = form.get("port", "").strip()
    if port_s:
        if not port_s.isdigit() or not 1 <= int(port_s) <= 65535:
            raise ValueError("端口无效（1-65535）")
        port = int(port_s)
        if port in used_ports(env):
            raise ValueError(f"端口 {port} 已被占用")
    else:
        port = pick_port(env)
    existing_names = {n["name"] for n in read_nodes()} | {i["name"] for i in load_inbounds()}
    name = form.get("name", "").strip()
    if not name:
        if kind == "vless-reality":
            name = "VlessReality" if "VlessReality" not in existing_names else f"VlessReality-{port}"
        else:
            name = f"{kind}-{port}"
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,48}", name):
        raise ValueError("名称仅限 1-48 位字母、数字及 . _ -")
    if name in existing_names:
        raise ValueError(f"入站名称「{name}」已存在")
    vps = env.get("VPS_NAME", "vps")
    ip = env.get("SERVER_IP", "")
    domain = env.get("DOMAIN", "").removeprefix("*.")
    insecure = env.get("CERT_MODE") != "manual" and env.get("TLS", "") in ("staging", "internal")
    base = {"name": name, "port": port, "listen": "0.0.0.0"}
    label = f"{vps}-{name}"

    if kind == "vless-reality":
        priv, pub = reality_keypair()
        uid, sid = str(uuidlib.uuid4()), secrets.token_hex(4)
        listener = {**base, "type": "vless", "udp": True,
                    "users": [{"username": "user", "uuid": uid, "flow": "xtls-rprx-vision"}],
                    "reality-config": {"dest": f"{REALITY_SNI}:443", "private-key": priv,
                                       "short-id": [sid], "server-names": [REALITY_SNI]}}
        client = {"name": f"{label}|Clash|Reality", "type": "vless", "server": ip, "port": port,
                  "uuid": uid, "tls": True, "flow": "xtls-rprx-vision", "client-fingerprint": "safari",
                  "skip-cert-verify": False, "reality-opts": {"public-key": pub, "short-id": sid},
                  "network": "tcp", "udp": True, "servername": REALITY_SNI}
    elif kind == "shadowsocks":
        cipher = (form.get("ss_cipher") or "aes-128-gcm").strip()
        if cipher not in SS_CIPHERS:
            raise ValueError("不支持的 Shadowsocks 加密方式（仅支持 aes-128-gcm 与 aes-256-gcm）")
        pw = secrets.token_urlsafe(16)
        listener = {"name": name, "type": "shadowsocks", "udp": True, "port": port,
                    "listen": "0.0.0.0", "password": pw, "cipher": cipher}
        client = {"name": f"{label}|Clash|SS", "type": "ss", "server": ip, "port": port,
                  "cipher": cipher, "password": pw, "udp": True}
    elif kind == "hysteria2":
        pw = secrets.token_urlsafe(18)
        listener = {**base, "type": "hysteria2", "users": {"user": pw},
                    "certificate": CERT, "private-key": KEY, "alpn": ["h3"],
                    "ignore-client-bandwidth": False}
        client = {"name": f"{label}|Clash|Hy2", "type": "hysteria2", "server": domain, "port": port,
                  "password": pw, "sni": domain, "alpn": ["h3"], "skip-cert-verify": insecure,
                  "udp": True}
    elif kind == "snell":
        version = int(form.get("snell_version") or 5)
        if version not in (4, 5):
            raise ValueError("snell 版本只能是 4 或 5")
        psk = base64.b64encode(secrets.token_bytes(16)).decode()
        listener = {**base, "type": "snell", "psk": psk, "version": version, "udp": True,
                    "obfs-opts": {"mode": "tls", "host": REALITY_SNI}}
        client = {"name": f"{label}|Clash|Snell", "type": "snell", "server": ip, "port": port,
                  "psk": psk, "version": version, "udp": True,
                  "obfs-opts": {"mode": "tls", "host": REALITY_SNI}}
    else:  # trusttunnel
        user = form.get("tt_user", "").strip() or "user"
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", user):
            raise ValueError("TrustTunnel 用户名无效（1-32 位字母、数字及 . _ -）")
        pw = secrets.token_urlsafe(18)
        listener = {**base, "type": "trusttunnel", "users": [{"username": user, "password": pw}],
                    "certificate": CERT, "private-key": KEY, "network": ["tcp", "udp"],
                    "congestion-controller": "bbr"}
        # client fields for trusttunnel are best-effort (not connectivity-tested yet)
        client = {"name": f"{label}|Clash|TrustTunnel", "type": "trusttunnel", "server": domain,
                  "port": port, "username": user, "password": pw, "sni": domain,
                  "skip-cert-verify": insecure, "udp": True}
    return {"id": secrets.token_hex(6), "kind": kind, "port": port, "name": name,
            "created": int(time.time()), "listener": listener, "client": client}


def render_nodes_tsv(nodes: list) -> str:
    return "".join(
        f"{n['name']}\t{n['port']}\t{n['uuid']}\t{n['priv']}\t{n['pub']}\t{n['sid']}\t{n['sni']}\n"
        for n in nodes
    )


def render_reality(nodes: list) -> str:
    out = []
    for n in nodes:
        out.append(
            f"  - name: {n['name']}\n"
            f"    type: vless\n"
            f"    udp: true\n"
            f"    port: {n['port']}\n"
            f"    listen: 0.0.0.0\n"
            f"    users:\n"
            f"      - username: user\n"
            f"        uuid: {n['uuid']}\n"
            f"        flow: xtls-rprx-vision\n"
            f"    reality-config:\n"
            f"      dest: {n['sni']}:443\n"
            f"      private-key: {n['priv']}\n"
            f"      short-id:\n"
            f"        - {n['sid']}\n"
            f"      server-names:\n"
            f"        - {n['sni']}\n"
        )
    return "".join(out)


def render_extra(inbounds: list) -> str:
    # YAML is a superset of JSON: one flow mapping per listener, no escaping pitfalls.
    return "".join("  - " + json.dumps(i["listener"], ensure_ascii=False) + "\n" for i in inbounds)


def assemble_config() -> str:
    """Same logic as core.sh assemble_config: template @@CONTROLLER@@ + @@PROXIES@@ + @@LISTENERS@@."""
    ctrl = ""
    try:
        with open(FRAG_CONTROLLER) as f:
            ctrl = f.read()
    except FileNotFoundError:
        env = read_env()
        if env.get("MODE") == "auto-cert" and env.get("MIHOMO_SECRET"):
            cport = env.get("CONTROLLER_PORT") or "7896"
            ctrl = (
                f'external-controller-tls: "0.0.0.0:{cport}"\n'
                f"tls:\n  certificate: {CERT}\n  private-key: {KEY}\n"
                f"external-controller-cors:\n  allow-origins:\n    - '*'\n  allow-private-network: true\n"
                f'secret: "{env["MIHOMO_SECRET"]}"\n'
                f"external-ui: ui\n"
                f'external-ui-url: "https://github.com/Zephyruso/zashboard/releases/latest/download/dist-cdn-fonts.zip"\n'
            )
    proxies_frag = ""
    try:
        with open(FRAG_PROXIES) as f:
            proxies_frag = f.read()
    except FileNotFoundError:
        pass
    proxies_lines = [l for l in proxies_frag.splitlines() if l.strip()]
    proxies_block = ("proxies:\n" + "\n".join(proxies_lines) + "\n") if proxies_lines else "proxies: []\n"

    block = ""
    for frag in (FRAG_REALITY, FRAG_EXTRA):
        try:
            with open(frag) as f:
                block += f.read()
        except FileNotFoundError:
            pass
    out = []
    with open(TEMPLATE) as f:
        for line in f:
            s = line.rstrip("\n")
            if s == "@@CONTROLLER@@":
                out.append(ctrl)
            elif s == "@@PROXIES@@":
                out.append(proxies_block)
            elif s == "@@LISTENERS@@":
                out.append(block)
            else:
                out.append(line)
    return "".join(out)


def atomic_write(path: str, data: str, mode=0o640):
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
    with os.fdopen(fd, "w") as f:
        f.write(data)
    os.chmod(tmp, mode)
    try:
        st = os.stat(path)
        os.chown(tmp, st.st_uid, st.st_gid)
    except (FileNotFoundError, PermissionError):
        pass
    os.replace(tmp, path)


def validate_config(path=CONF):
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "ui"), exist_ok=True)
        mmdb = ROOT + "/var/lib/mihomo/country.mmdb"
        if os.path.isfile(mmdb):
            try:
                os.symlink(mmdb, os.path.join(d, "country.mmdb"))
            except OSError:
                pass
        env = dict(os.environ, SAFE_PATHS="/etc/mihomo")
        return run([MIHOMO_BIN, "-t", "-d", d, "-f", path], env=env, timeout=60)


def ufw_specs_for_node(kind: str, port: int) -> set:
    p = int(port)
    if kind == "vless-reality":
        return {f"{p}/tcp"}
    if kind == "hysteria2":
        return {f"{p}/udp"}
    return {f"{p}/tcp", f"{p}/udp"}


def collect_ufw_specs(nodes: list, inbounds: list) -> set:
    specs = set()
    for n in nodes:
        specs |= ufw_specs_for_node("vless-reality", n["port"])
    for i in inbounds:
        specs |= ufw_specs_for_node(i["kind"], i["port"])
    return specs


def sync_ufw(old_specs: set, new_specs: set):
    """When ufw is active, allow newly added node ports and delete removed node ports (including UDP)."""
    rc, out = run([UFW_BIN, "status"])
    if rc != 0 or "Status: active" not in out:
        return
    env = read_env()
    protected = {"80/tcp", f"{env.get('PANEL_PORT') or 0}/tcp", f"{env.get('CONTROLLER_PORT') or 7896}/tcp"}
    for spec in sorted(new_specs - old_specs):
        run([UFW_BIN, "allow", spec])
    for spec in sorted((old_specs - new_specs) - protected):
        run([UFW_BIN, "delete", "allow", spec])


def sync_client_files():
    """Keep /root/clashserver-client/{mihomo-client,proxies}.yaml in sync with current nodes and inbounds."""
    try:
        env = read_env()
        proxies = [reality_client(n, env) for n in read_nodes()] + [i["client"] for i in load_inbounds()]
        os.makedirs(CLIENT_DIR, mode=0o700, exist_ok=True)
        atomic_write(CLIENT_DIR + "/mihomo-client.yaml", render_subscription(env), 0o600)
        p_yaml = "proxies:\n" + "".join("    - " + json.dumps(p, ensure_ascii=False) + "\n" for p in proxies)
        atomic_write(CLIENT_DIR + "/proxies.yaml", p_yaml, 0o600)
    except Exception as e:
        sys.stderr.write(f"sync_client_files warning: {e}\n")


def wait_mihomo_ports(timeout=2.0):
    """Poll ss for up to ~2s so all expected ports are listening before responding."""
    expected = {int(n["port"]) for n in read_nodes()} | {int(i["port"]) for i in load_inbounds()}
    env = read_env()
    if env.get("MODE") == "auto-cert":
        expected.add(int(env.get("CONTROLLER_PORT") or 7896))
    if not expected:
        return
    deadline = time.monotonic() + timeout
    while True:
        st = mihomo_status()
        if st["active"] == "active" and expected.issubset(set(st["listening"])):
            return
        if time.monotonic() >= deadline:
            return
        time.sleep(0.15)


def apply_inbounds(new: list):
    """Write inbounds + fragment + config, validate, restart; roll back on failure."""
    cur_nodes = read_nodes()
    old_specs = collect_ufw_specs(cur_nodes, load_inbounds())
    files = (INBOUNDS, FRAG_EXTRA, CONF)
    backup = {}
    for p in files:
        try:
            with open(p) as f:
                backup[p] = f.read()
        except FileNotFoundError:
            backup[p] = None
    try:
        atomic_write(INBOUNDS, json.dumps(new, indent=2, ensure_ascii=False), 0o600)
        atomic_write(FRAG_EXTRA, render_extra(new))
        atomic_write(CONF, assemble_config())
        rc, out = validate_config()
        if rc != 0:
            raise RuntimeError("配置校验失败（mihomo -t）：" + out[-800:])
        rc, out = run([SYSTEMCTL, "restart", "mihomo"])
        if rc != 0:
            raise RuntimeError("重启失败：" + out[-800:])
    except Exception:
        for p, data in backup.items():
            if data is None:
                if os.path.exists(p):
                    os.remove(p)
            else:
                atomic_write(p, data, 0o600 if p == INBOUNDS else 0o640)
        run([SYSTEMCTL, "restart", "mihomo"])
        raise
    sync_client_files()
    sync_ufw(old_specs, collect_ufw_specs(cur_nodes, new))
    wait_mihomo_ports()


def apply_nodes(new_nodes: list):
    """Update install-time VLESS Reality nodes (nodes.tsv + listeners.reality.yaml + config.yaml), validate, restart; roll back on failure."""
    cur_inbs = load_inbounds()
    old_specs = collect_ufw_specs(read_nodes(), cur_inbs)
    files = (NODES_TSV, FRAG_REALITY, CONF)
    backup = {}
    for p in files:
        try:
            with open(p) as f:
                backup[p] = f.read()
        except FileNotFoundError:
            backup[p] = None
    try:
        atomic_write(NODES_TSV, render_nodes_tsv(new_nodes), 0o640)
        atomic_write(FRAG_REALITY, render_reality(new_nodes), 0o640)
        atomic_write(CONF, assemble_config(), 0o640)
        rc, out = validate_config()
        if rc != 0:
            raise RuntimeError("配置校验失败（mihomo -t）：" + out[-800:])
        rc, out = run([SYSTEMCTL, "restart", "mihomo"])
        if rc != 0:
            raise RuntimeError("重启失败：" + out[-800:])
    except Exception:
        for p, data in backup.items():
            if data is None:
                if os.path.exists(p):
                    os.remove(p)
            else:
                atomic_write(p, data, 0o640)
        run([SYSTEMCTL, "restart", "mihomo"])
        raise
    sync_client_files()
    sync_ufw(old_specs, collect_ufw_specs(new_nodes, cur_inbs))
    wait_mihomo_ports()


def apply_server_proxies(new_proxies: list):
    """Write server outbound proxies (proxies.json + proxies.extra.yaml + config.yaml), validate, restart; roll back on failure."""
    files = (PROXIES_JSON, FRAG_PROXIES, CONF)
    backup = {}
    for p in files:
        try:
            with open(p) as f:
                backup[p] = f.read()
        except FileNotFoundError:
            backup[p] = None
    try:
        atomic_write(PROXIES_JSON, json.dumps(new_proxies, indent=2, ensure_ascii=False), 0o600)
        atomic_write(FRAG_PROXIES, dump_yaml_proxies(new_proxies), 0o640)
        atomic_write(CONF, assemble_config(), 0o640)
        rc, out = validate_config()
        if rc != 0:
            raise RuntimeError("配置校验失败（mihomo -t）：" + out[-800:])
        rc, out = run([SYSTEMCTL, "restart", "mihomo"])
        if rc != 0:
            raise RuntimeError("重启失败：" + out[-800:])
    except Exception:
        for p, data in backup.items():
            if data is None:
                if os.path.exists(p):
                    os.remove(p)
            else:
                atomic_write(p, data, 0o600 if p == PROXIES_JSON else 0o640)
        run([SYSTEMCTL, "restart", "mihomo"])
        raise
    wait_mihomo_ports()


def reality_client(n: dict, env: dict) -> dict:
    """Client proxy for an install-time Reality node (same fields as core.sh proxy_line)."""
    return {"name": f"{env.get('VPS_NAME', 'vps')}-{n['name']}|Clash|Reality", "type": "vless",
            "server": env.get("SERVER_IP", ""), "port": n["port"], "uuid": n["uuid"], "tls": True,
            "flow": "xtls-rprx-vision", "client-fingerprint": "safari", "skip-cert-verify": False,
            "reality-opts": {"public-key": n["pub"], "short-id": n["sid"]}, "network": "tcp",
            "udp": True, "servername": n["sni"]}


def render_subscription(env: dict) -> str:
    """Full mihomo client config: install Reality nodes + panel inbounds, via client.yaml.tpl."""
    proxies = [reality_client(n, env) for n in read_nodes()] + [i["client"] for i in load_inbounds()]
    p_lines = "\n".join("    - " + json.dumps(p, ensure_ascii=False) for p in proxies)
    n_lines = "\n".join("      - " + json.dumps(p["name"], ensure_ascii=False) for p in proxies)
    out = []
    with open(CLIENT_TEMPLATE) as f:
        for line in f:
            key = line.rstrip("\n")
            if key == "@@PROXIES@@":
                out.append(p_lines + "\n" if p_lines else "")
            elif key == "@@PROXY_NAMES@@":
                out.append(n_lines + "\n" if n_lines else "")
            else:
                out.append(line)
    return "".join(out)


def mihomo_status() -> dict:
    rc, active = run([SYSTEMCTL, "is-active", "mihomo"])
    _, show = run([SYSTEMCTL, "show", "mihomo", "-p", "ActiveEnterTimestamp,MainPID,NRestarts"])
    props = dict(l.split("=", 1) for l in show.splitlines() if "=" in l)
    _, ver = run([MIHOMO_BIN, "-v"])
    _, ss = run(["ss", "-Hltun"])
    listening = {int(m) for m in re.findall(r":(\d+)\s", ss + " ")}
    cert = {}
    if certs_present():
        _, c = run(["openssl", "x509", "-noout", "-enddate", "-issuer", "-in", ROOT + CERT])
        cert = {"info": c}
    return {"active": active.strip() or "unknown", "since": props.get("ActiveEnterTimestamp", ""),
            "pid": props.get("MainPID", ""), "restarts": props.get("NRestarts", ""),
            "version": ver.splitlines()[0] if ver else "", "listening": sorted(listening),
            "cert": cert}


# ---------------------------------------------------------------- HTTP
CSS = """
:root{--bg:#f3f5f9;--card:#fff;--text:#111827;--muted:#6b7280;--faint:#9ca3af;--line:#e8ebf0;
--primary:#4f46e5;--primary-h:#4338ca;--primary-soft:#eef2ff;--ok:#15803d;--ok-bg:#dcfce7;--bad:#b91c1c;
--bad-bg:#fee2e2;--warn:#b45309;--warn-bg:#fef3c7;--radius:14px;
--shadow:0 1px 2px rgba(16,24,40,.04),0 4px 16px rgba(16,24,40,.06)}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.65 -apple-system,BlinkMacSystemFont,"PingFang SC",
"Hiragino Sans GB","Microsoft YaHei","Noto Sans CJK SC","Segoe UI",sans-serif;-webkit-font-smoothing:antialiased}
a{color:var(--primary);text-decoration:none}
.topbar{background:rgba(255,255,255,.9);backdrop-filter:blur(8px);border-bottom:1px solid var(--line);
position:sticky;top:0;z-index:10}
.topbar .in{max-width:1120px;margin:0 auto;padding:12px 24px;display:flex;align-items:center;gap:14px}
.logo{width:34px;height:34px;border-radius:10px;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;
display:flex;align-items:center;justify-content:center;font-weight:800;font-size:16px;flex:none;
box-shadow:0 4px 10px rgba(99,102,241,.35)}
.brand{display:flex;flex-direction:column;line-height:1.25}.brand b{font-size:16px;letter-spacing:.2px;display:flex;align-items:center;gap:6px}
.brand small{color:var(--muted);font-size:12px}
.chip{display:inline-flex;align-items:center;gap:6px;background:#f3f4f6;color:#374151;border-radius:999px;
padding:3px 12px;font-size:12px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--faint);display:inline-block}
.dot.ok{background:#22c55e;box-shadow:0 0 0 3px #dcfce7}.dot.bad{background:#ef4444;box-shadow:0 0 0 3px #fee2e2}
.dot.warn{background:#f59e0b;box-shadow:0 0 0 3px #fef3c7}
.spacer{flex:1}
main{max-width:1120px;margin:0 auto;padding:28px 24px 56px}
.page-h{display:flex;align-items:flex-end;justify-content:space-between;gap:12px;margin:0 0 20px;flex-wrap:wrap}
.page-h h1{font-size:22px;margin:0;font-weight:700;display:flex;align-items:center;gap:8px}.page-h p{margin:2px 0 0;color:var(--muted)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:20px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);
padding:16px 18px}
.stat .lb{color:var(--muted);font-size:12px;display:flex;align-items:center;gap:6px}
.stat .val{font-size:22px;font-weight:700;margin-top:4px;line-height:1.3;word-break:break-all}
.stat .val small{font-size:13px;font-weight:500;color:var(--muted);margin-left:4px}
.stat .sub{font-size:12px;color:var(--faint);margin-top:2px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:20px;margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);
padding:22px 24px;margin-bottom:20px}
.grid .card{margin-bottom:0}
.card-h{display:flex;align-items:center;gap:10px;margin:0 0 16px;flex-wrap:wrap}
.card-h h2{font-size:16px;margin:0;font-weight:650}.card-h .desc{color:var(--muted);font-size:12px;width:100%;margin-top:-6px}
.kv{display:grid;grid-template-columns:96px 1fr;row-gap:10px;margin:0 0 18px}
.kv dt{color:var(--muted)}.kv dd{margin:0;word-break:break-all}
.pill{display:inline-flex;align-items:center;gap:5px;padding:1px 10px;border-radius:999px;font-size:12px;font-weight:600;
white-space:nowrap}
.pill.ok{background:var(--ok-bg);color:var(--ok)}.pill.bad{background:var(--bad-bg);color:var(--bad)}
.pill.warn{background:var(--warn-bg);color:var(--warn)}.pill.tag{background:var(--primary-soft);color:var(--primary-h)}
.pill.gray{background:#f3f4f6;color:#4b5563}
.k-vless-reality{background:#ede9fe;color:#6d28d9}.k-shadowsocks{background:#fce7f3;color:#be185d}
.k-hysteria2{background:#e0f2fe;color:#0369a1}.k-snell{background:#dcfce7;color:#15803d}
.k-trusttunnel{background:#ffedd5;color:#c2410c}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;border:1px solid var(--line);background:#fff;
color:var(--text);border-radius:9px;padding:8px 16px;font:inherit;font-weight:500;cursor:pointer;
transition:background .15s,border-color .15s,box-shadow .15s}
.btn:hover{background:#f9fafb;border-color:#d1d5db}
.btn.primary{background:var(--primary);border-color:var(--primary);color:#fff;box-shadow:0 1px 2px rgba(79,70,229,.3)}
.btn.primary:hover{background:var(--primary-h)}
.btn.danger{color:var(--bad)}.btn.danger:hover{background:var(--bad-bg);border-color:#fecaca}
.btn.ghost{border-color:transparent;background:transparent;color:var(--muted)}.btn.ghost:hover{background:#f3f4f6;color:var(--text)}
.btn.sm{padding:4px 12px;font-size:12px;border-radius:8px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
form.inline{display:inline}
.flash{display:flex;gap:10px;align-items:flex-start;border-radius:12px;padding:12px 16px;margin-bottom:20px;
word-break:break-all;border:1px solid transparent}
.flash.ok{background:#f0fdf4;color:#14532d;border-color:#bbf7d0}.flash.bad{background:#fef2f2;color:#7f1d1d;border-color:#fecaca}
.list{border:1px solid var(--line);border-radius:12px;overflow:hidden}
.item{padding:14px 16px;border-bottom:1px solid var(--line)}.item:last-child{border-bottom:0}
.item:hover{background:#fafbfc}
.item .top{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.item .nm{font-weight:600;min-width:0;word-break:break-all}
.item .meta{color:var(--muted);font-size:12px;display:flex;gap:14px;flex-wrap:wrap;margin-top:2px}
.item .acts{margin-left:auto;display:flex;gap:8px;align-items:center}
.mono,code,pre,textarea{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
code{background:#f3f4f6;border-radius:5px;padding:1px 6px;font-size:12px;white-space:nowrap}
pre{background:#0f172a;color:#e2e8f0;border-radius:10px;padding:14px;font-size:12px;white-space:pre-wrap;
word-break:break-all;margin:10px 0 0;line-height:1.55}
details>summary{cursor:pointer;color:var(--primary);font-size:12px;list-style:none;display:inline-flex;
align-items:center;gap:4px;user-select:none}
details>summary::-webkit-details-marker{display:none}
details>summary::before{content:"▸";transition:transform .15s}details[open]>summary::before{transform:rotate(90deg)}
.muted{color:var(--muted)}.empty{color:var(--muted);text-align:center;padding:36px 16px}
.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:18px}
label{display:block;font-size:13px;color:#374151;font-weight:500;margin-bottom:6px}
input,select{width:100%;height:38px;padding:0 12px;border:1px solid #d1d5db;border-radius:9px;font:inherit;
background:#fff;color:var(--text)}
textarea{width:100%;min-height:110px;padding:10px 12px;border:1px solid #d1d5db;border-radius:9px;font-size:12px;
line-height:1.5;background:#fff;color:var(--text);resize:vertical}
input::placeholder,textarea::placeholder{color:var(--faint)}
input:focus,select:focus,textarea:focus{outline:0;border-color:var(--primary);box-shadow:0 0 0 3px rgba(99,102,241,.18)}
.hint{font-size:12px;color:var(--muted);margin:14px 0 0}
.notice{font-size:13px;border-radius:10px;padding:10px 14px;margin-top:14px;background:var(--warn-bg);color:#78350f}
.sub-box{display:flex;gap:10px;align-items:stretch;flex-wrap:wrap}
.sub-box .url{flex:1;min-width:240px;background:#f8fafc;border:1px solid var(--line);border-radius:9px;padding:9px 12px;
font-size:12px;word-break:break-all}
.sub-sec{border-top:1px solid var(--line);margin-top:18px;padding-top:18px}
footer{max-width:1120px;margin:0 auto;padding:0 24px 32px;color:var(--faint);font-size:12px;text-align:center}
.login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;
background:radial-gradient(1200px 600px at 10% -10%,#e0e7ff 0,transparent 60%),
radial-gradient(900px 500px at 110% 110%,#ede9fe 0,transparent 60%),var(--bg)}
.login{width:100%;max-width:400px}
.login .card{padding:34px 32px;margin:0}
.login .head{display:flex;align-items:center;gap:12px;margin-bottom:22px}
.login h1{font-size:20px;margin:0;display:flex;align-items:center;gap:8px}.login p.sub{color:var(--muted);margin:0;font-size:13px}
.login .field{margin-bottom:16px}.login .btn{width:100%;height:40px;margin-top:6px}
.login .foot{text-align:center;color:var(--faint);font-size:12px;margin-top:18px}
.err{background:#fef2f2;border:1px solid #fecaca;color:#7f1d1d;border-radius:10px;padding:10px 12px;margin-bottom:16px}
@media (max-width:640px){.hide-sm{display:none}.stats{grid-template-columns:repeat(2,1fr);gap:12px}.stat .val{font-size:18px}.grid{grid-template-columns:1fr}main{padding:20px 14px 40px}.topbar .in{padding:10px 14px}
.card{padding:18px}.item .acts{margin-left:0;width:100%}}
"""

JS = """
function syncKind(){var k=document.getElementById('kind');if(!k)return;var v=k.value;
document.querySelectorAll('[data-kind]').forEach(function(e){e.style.display=e.dataset.kind===v?'':'none'})}
function copyText(id,btn){var t=document.getElementById(id).textContent;var o=btn.textContent;
function done(){btn.textContent='已复制';setTimeout(function(){btn.textContent=o},1500)}
if(navigator.clipboard){navigator.clipboard.writeText(t).then(done,function(){fallback()})}else{fallback()}
function fallback(){var a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();
try{document.execCommand('copy');done()}catch(e){}document.body.removeChild(a)}}
function loadProxyFile(inp){var f=inp.files&&inp.files[0];if(!f)return;
var r=new FileReader();r.onload=function(){var ta=document.getElementById('proxies-raw');if(ta)ta.value=r.result||''};
r.readAsText(f)}
function showFlash(msg,ok){var box=document.getElementById('flash-box');if(!box)return;
var div=document.createElement('div');div.className='flash '+(ok?'ok':'bad');
var b=document.createElement('b');b.textContent=ok?'✓':'!';
var d=document.createElement('div');d.textContent=msg;
div.appendChild(b);div.appendChild(d);box.innerHTML='';box.appendChild(div)}
function bindAjaxForms(root){
(root||document).querySelectorAll('form[data-ajax]').forEach(function(f){
if(f._ajaxBound)return;f._ajaxBound=true;
f.addEventListener('submit',function(ev){
if(!window.fetch)return;
ev.preventDefault();
var btn=f.querySelector('button[type=submit],button:not([type])');
var origTxt=btn?btn.textContent:'';
if(btn){btn.disabled=true;if(f.dataset.busy)btn.textContent=f.dataset.busy}
var body=new URLSearchParams(new FormData(f)).toString();
fetch(f.action,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-Requested-With':'fetch','Accept':'application/json'},body:body,credentials:'same-origin'})
.then(function(r){return r.json().then(function(j){return {status:r.status,data:j}})})
.then(function(res){
var d=res.data||{};
showFlash(d.msg||(d.ok?'操作成功':'操作失败'),!!d.ok);
if(d.stats_html){var sb=document.getElementById('stats-bar');if(sb)sb.outerHTML=d.stats_html}
if(d.inbounds_html){var ic=document.getElementById('inbounds-card');if(ic){ic.outerHTML=d.inbounds_html;bindAjaxForms(document.getElementById('inbounds-card'))}}
if(d.proxies_html){var pc=document.getElementById('proxies-section');if(pc){pc.outerHTML=d.proxies_html;bindAjaxForms(document.getElementById('proxies-section'))}}
if(d.ok){
var p=f.querySelector('input[name=port]');if(p)p.value='';
var n=f.querySelector('input[name=name]');if(n)n.value='';
var ta=f.querySelector('textarea[name=proxies_raw]');if(ta)ta.value='';
var fi=f.querySelector('input[type=file]');if(fi)fi.value='';
}
})
.catch(function(err){showFlash('请求失败：'+err,false)})
.finally(function(){if(btn){btn.disabled=false;btn.textContent=origTxt}});
});
});
}
document.addEventListener('DOMContentLoaded',function(){var k=document.getElementById('kind');
if(k){k.addEventListener('change',syncKind);syncKind()}
bindAjaxForms(document);
document.querySelectorAll('form[data-busy]:not([data-ajax])').forEach(function(f){f.addEventListener('submit',function(){
var b=f.querySelector('button[type=submit],button:not([type])');if(b){b.disabled=true;b.textContent=f.dataset.busy}})})});
"""

STATE_ZH = {"active": ("运行中", "ok"), "inactive": ("已停止", "bad"), "failed": ("失败", "bad"),
            "activating": ("启动中", "warn"), "deactivating": ("停止中", "warn"),
            "reloading": ("重载中", "warn"), "unknown": ("未知", "bad")}
KIND_ZH = {"vless-reality": "VLESS Reality", "shadowsocks": "Shadowsocks (SS)",
           "hysteria2": "Hysteria2", "snell": "Snell", "trusttunnel": "TrustTunnel"}


def short_version(v: str) -> str:
    m = re.search(r"v\d+\.\d+\.\d+\S*", v or "")
    return m.group(0) if m else (v or "")


def parse_since(s: str):
    """systemd 'Mon 2026-10-26 17:55:14 UTC' -> ('2026-10-26 17:55:14 UTC', '1 小时 5 分钟')."""
    m = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\s+(\S+))?", s or "")
    if not m:
        return "", ""
    shown = m.group(1) + (" " + m.group(2) if m.group(2) else "")
    try:
        t = time.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
        ts = calendar.timegm(t) if (m.group(2) or "UTC") == "UTC" else time.mktime(t)
        sec = max(0, int(time.time() - ts))
    except ValueError:
        return shown, ""
    d, h, mi = sec // 86400, sec % 86400 // 3600, sec % 3600 // 60
    up = (f"{d} 天 {h} 小时" if d else f"{h} 小时 {mi} 分钟" if h else f"{mi} 分钟" if mi else "不到 1 分钟")
    return shown, up


def page(title, body, scripts=False):
    js = f"<script>{JS}</script>" if scripts else ""
    return (f"<!doctype html><html lang=zh-CN><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)}</title><style>{CSS}</style>{js}</head><body>{body}</body></html>")


def parse_cert(info: str) -> dict:
    out = {}
    m = re.search(r"notAfter=(.+)", info)
    if m:
        try:
            exp = time.mktime(time.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z"))
            out["expires"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(exp))
            out["days"] = int((exp - time.time()) // 86400)
            out["hours"] = max(0, int((exp - time.time()) // 3600))
        except ValueError:
            out["expires"] = m.group(1).strip()
    m = re.search(r"issuer=(.+)", info)
    if m:
        cn = re.search(r"CN\s*=\s*([^,/]+)", m.group(1))
        out["issuer"] = (cn.group(1) if cn else m.group(1)).strip()
    return out


class Panel(BaseHTTPRequestHandler):
    server_version = "clashserve/" + VERSION
    cfg: dict = {}
    cfg_path: str = ""
    sessions: dict = {}
    fails: dict = {}

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.client_ip(), fmt % args))

    # -- utils
    def client_ip(self):
        return self.client_address[0]   # direct HTTPS, no reverse proxy: never trust X-Forwarded-For

    def is_https(self):
        return bool(self.cfg.get("tls_cert"))

    def is_ajax(self):
        return (self.headers.get("X-Requested-With") == "fetch"
                or "application/json" in (self.headers.get("Accept") or ""))

    def current_sub_token(self) -> str:
        if self.cfg_path:
            try:
                with open(self.cfg_path) as f:
                    d = json.load(f)
                    if d.get("sub_token"):
                        self.cfg["sub_token"] = d["sub_token"]
            except Exception:
                pass
        return self.cfg.get("sub_token", "")

    def send(self, code, body, ctype="text/html; charset=utf-8", headers=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, to, cookie=None):
        h = {"Location": to}
        if cookie:
            h["Set-Cookie"] = cookie
        self.send(303, "", headers=h)

    def flash(self, msg, ok=True):
        self.redirect(f"/?ok={1 if ok else 0}&msg=" + quote(msg[:600]))

    def respond_mutation(self, s, msg: str, ok: bool = True):
        if not self.is_ajax():
            return self.flash(msg, ok)
        env = read_env()
        st = mihomo_status()
        payload = {
            "ok": ok,
            "msg": msg,
            "stats_html": self.render_stats_section(st),
            "inbounds_html": self.render_inbounds_section(s, env, st),
            "proxies_html": self.render_proxies_section(s),
        }
        return self.send(200 if ok else 400, json.dumps(payload, ensure_ascii=False), "application/json; charset=utf-8")

    def simple(self, code, title, text):
        self.send(code, page(title, f"<div class=login-wrap><div class=login><div class=card>"
                                    f"<div class=head><div class=logo>C</div><div><h1>{html.escape(title)}</h1>"
                                    f"<p class=sub>{html.escape(text)}</p></div></div>"
                                    f"<a class='btn primary' href=/>返回控制台</a></div></div></div>"))

    def session(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "cs_session":
                s = self.sessions.get(v)
                if s and s["exp"] > time.time():
                    return v, s
        return None, None

    def form(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 262144:
            raise ValueError("请求体过大")
        raw = self.rfile.read(n).decode()
        return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}

    def check_csrf(self, s, form):
        return hmac.compare_digest(form.get("csrf", ""), s["csrf"])

    # -- routes
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/healthz":
            return self.send(200, "ok", "text/plain")
        if path == "/login":
            return self.send(200, self.login_page())
        if path.startswith("/sub/"):
            return self.do_sub(path)
        tok, s = self.session()
        if not s:
            return self.redirect("/login")
        if path == "/":
            return self.send(200, self.dashboard(s))
        if path in ("/config/server.yaml", "/server.yaml"):
            return self.do_server_config()
        if path == "/api/status":
            st = mihomo_status()
            st["version_panel"] = VERSION
            st["inbounds"] = [{k: i[k] for k in ("id", "kind", "name", "port")} for i in load_inbounds()]
            st["reality_nodes"] = [{"name": n["name"], "port": n["port"]} for n in read_nodes()]
            st["server_proxies"] = [{"name": p["name"], "type": p["type"], "server": p["server"], "port": p["port"]}
                                    for p in load_server_proxies()]
            return self.send(200, json.dumps(st), "application/json")
        self.simple(404, "页面不存在", "请检查地址是否正确。")

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            form = self.form()
        except ValueError:
            return self.send(413, "请求体过大", "text/plain; charset=utf-8")
        if path == "/login":
            return self.do_login(form)
        tok, s = self.session()
        if not s:
            if self.is_ajax():
                return self.send(401, json.dumps({"ok": False, "msg": "登录会话已过期，请刷新页面重新登录"}), "application/json; charset=utf-8")
            return self.redirect("/login")
        if not self.check_csrf(s, form):
            if self.is_ajax():
                return self.send(403, json.dumps({"ok": False, "msg": "会话校验失败，请刷新页面重试"}), "application/json; charset=utf-8")
            return self.simple(403, "会话校验失败", "页面已过期，请刷新后重试。")
        if path == "/logout":
            self.sessions.pop(tok, None)
            return self.redirect("/login", "cs_session=; Max-Age=0; Path=/")
        if path in ("/action/restart", "/action/reload"):
            return self.do_action(path.rsplit("/", 1)[1])
        if path == "/action/cert":
            return self.do_cert_action()
        if path == "/action/reset-secret":
            return self.do_reset_secret()
        if path == "/inbounds/add":
            return self.do_add(s, form)
        if path == "/proxies/add":
            return self.do_add_proxies(s, form)
        if path == "/proxies/delete":
            return self.do_delete_proxy(s, form.get("name", ""))
        m = re.fullmatch(r"/inbounds/([0-9a-f]{12})/delete", path)
        if m:
            return self.do_delete(s, m.group(1))
        m = re.fullmatch(r"/nodes/([A-Za-z0-9._-]{1,48})/delete", path)
        if m:
            return self.do_delete_node(s, m.group(1))
        self.simple(404, "页面不存在", "请检查地址是否正确。")

    def do_server_config(self):
        """GET /config/server.yaml - session-authenticated view of current running server config."""
        try:
            with open(CONF) as f:
                body = f.read()
        except FileNotFoundError:
            body = assemble_config()
        self.send(200, body, "text/plain; charset=utf-8",
                  {"Content-Disposition": 'inline; filename="server.yaml"'})

    def do_sub(self, path):
        """GET /sub/<token>/mihomo.yaml - token-protected subscription; anything else -> 404."""
        m = re.fullmatch(r"/sub/([A-Za-z0-9_-]{16,128})/mihomo\.yaml", path)
        token = self.current_sub_token()
        if not (m and token and hmac.compare_digest(m.group(1), token)):
            return self.send(404, "not found", "text/plain")
        env = read_env()
        try:
            body = render_subscription(env)
        except Exception as e:
            sys.stderr.write(f"subscription render failed: {e}\n")
            return self.send(500, "internal error", "text/plain")
        fname = re.sub(r"[^A-Za-z0-9._-]", "_", env.get("VPS_NAME", "clashserver")) + ".yaml"
        self.send(200, body, "text/yaml; charset=utf-8",
                  {"Content-Disposition": f'inline; filename="{fname}"', "profile-update-interval": "24"})

    def sub_url(self):
        token = self.current_sub_token()
        base = panel_base_url(read_env(), self.cfg)
        return f"{base}/sub/{token}/mihomo.yaml" if (token and base) else ""

    def do_login(self, form):
        ip, now = self.client_ip(), time.time()
        recent = [t for t in self.fails.get(ip, []) if now - t < 600]
        if len(recent) >= 5:
            return self.send(429, self.login_page("尝试次数过多，请 10 分钟后再试。"))
        user, pw = form.get("username", ""), form.get("password", "")
        if hmac.compare_digest(user, self.cfg["username"]) and verify_password(pw, self.cfg["password_hash"]):
            self.fails.pop(ip, None)
            tok = secrets.token_urlsafe(32)
            self.sessions[tok] = {"csrf": secrets.token_urlsafe(24), "exp": now + SESSION_TTL}
            cookie = f"cs_session={tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_TTL}"
            if self.is_https():
                cookie += "; Secure"
            return self.redirect("/", cookie)
        recent.append(now)
        self.fails[ip] = recent
        self.send(401, self.login_page("用户名或密码错误。"))

    def do_action(self, action):
        zh = {"restart": "重启", "reload": "重载"}[action]
        with LOCK:
            if action == "reload":
                rc, out = validate_config()
                if rc != 0:
                    return self.flash("配置校验未通过，未执行重载：" + out[-300:], False)
            rc, out = run([SYSTEMCTL, action, "mihomo"])
            if rc == 0:
                wait_mihomo_ports()
        _, active = run([SYSTEMCTL, "is-active", "mihomo"])
        state = STATE_ZH.get(active.strip(), (active.strip(), ""))[0]
        if rc == 0:
            self.flash(f"{zh}成功，Mihomo 当前状态：{state}", active.strip() == "active")
        else:
            self.flash(f"{zh}失败：{out[-300:]}（Mihomo 当前状态：{state}）", False)

    def do_reset_secret(self):
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        new_secret = "".join(secrets.choice(alphabet) for _ in range(20))
        with LOCK:
            old_env = read_env()
            old_secret = old_env.get("MIHOMO_SECRET", "")
            files = (FRAG_CONTROLLER, CONF)
            backup = {}
            for p in files:
                try:
                    with open(p) as f:
                        backup[p] = f.read()
                except FileNotFoundError:
                    backup[p] = None
            try:
                write_env_var("MIHOMO_SECRET", new_secret)
                env = read_env()
                atomic_write(FRAG_CONTROLLER, render_controller_fragment(env), 0o640)
                atomic_write(CONF, assemble_config(), 0o640)
                rc, out = validate_config()
                if rc != 0:
                    raise RuntimeError("配置校验失败（mihomo -t）：" + out[-300:])
                rc, out = run([SYSTEMCTL, "restart", "mihomo"])
                if rc != 0:
                    raise RuntimeError("重启失败：" + out[-300:])
                wait_mihomo_ports()
            except Exception as e:
                if old_secret:
                    write_env_var("MIHOMO_SECRET", old_secret)
                for p, data in backup.items():
                    if data is not None:
                        atomic_write(p, data, 0o640)
                run([SYSTEMCTL, "restart", "mihomo"])
                return self.flash(f"重置密钥失败：{e}", False)
        self.flash("已重置 Zashboard API 密钥，Mihomo 已重启生效。")

    def do_cert_action(self):
        with LOCK:
            rc, out = run([CERTCTL, "renew"], timeout=180)
        if rc == 0:
            self.flash("证书检查 / 续期完成。")
        else:
            tail = " | ".join(l for l in out.splitlines() if l.strip())[-300:]
            self.flash(f"证书申请 / 续期失败：{tail}", False)

    def do_add(self, s, form):
        env = read_env()
        with LOCK:
            try:
                inb = build_inbound(form.get("kind", ""), form, env)
                apply_inbounds(load_inbounds() + [inb])
            except Exception as e:
                return self.respond_mutation(s, f"添加失败：{e}", False)
        return self.respond_mutation(
            s, f"已添加 {KIND_ZH.get(inb['kind'], inb['kind'])} 入站「{inb['name']}」，端口 {inb['port']}", True)

    def do_delete(self, s, iid):
        with LOCK:
            cur = load_inbounds()
            new = [i for i in cur if i["id"] != iid]
            if len(new) == len(cur):
                return self.respond_mutation(s, "入站不存在或已删除", False)
            try:
                apply_inbounds(new)
            except Exception as e:
                return self.respond_mutation(s, f"删除失败：{e}", False)
        return self.respond_mutation(s, "入站已删除", True)

    def do_delete_node(self, s, name):
        with LOCK:
            cur = read_nodes()
            new = [n for n in cur if n["name"] != name]
            if len(new) == len(cur):
                return self.respond_mutation(s, "入站不存在或已删除", False)
            try:
                apply_nodes(new)
            except Exception as e:
                return self.respond_mutation(s, f"删除失败：{e}", False)
        return self.respond_mutation(s, f"已删除入站「{name}」", True)

    def do_add_proxies(self, s, form):
        raw = form.get("proxies_raw", "")
        with LOCK:
            try:
                added = parse_mihomo_proxies(raw)
                cur = load_server_proxies()
                by_name = {p["name"]: i for i, p in enumerate(cur)}
                merged = list(cur)
                for p in added:
                    if p["name"] in by_name:
                        merged[by_name[p["name"]]] = p
                    else:
                        by_name[p["name"]] = len(merged)
                        merged.append(p)
                apply_server_proxies(merged)
            except Exception as e:
                return self.respond_mutation(s, f"添加服务端 proxies 节点失败：{e}", False)
        names = "、".join(p["name"] for p in added)
        return self.respond_mutation(s, f"已向服务端 proxies: 添加 {len(added)} 个节点（{names}）", True)

    def do_delete_proxy(self, s, name):
        with LOCK:
            cur = load_server_proxies()
            new = [p for p in cur if p["name"] != name]
            if len(new) == len(cur):
                return self.respond_mutation(s, "节点不存在或已删除", False)
            try:
                apply_server_proxies(new)
            except Exception as e:
                return self.respond_mutation(s, f"删除服务端节点失败：{e}", False)
        return self.respond_mutation(s, f"已从服务端 proxies: 删除节点「{name}」", True)

    # -- views & partial sections
    def login_page(self, err=""):
        e = f"<div class=err>{html.escape(err)}</div>" if err else ""
        return page(f"登录 · Clash Serve v{VERSION}", f"""<div class=login-wrap><div class=login><div class=card>
<div class=head><div class=logo>C</div><div><h1>Clash Serve <span class='pill tag'>v{VERSION}</span></h1><p class=sub>服务器管理面板 · 请登录</p></div></div>{e}
<form method=post action=/login>
<div class=field><label for=u>用户名</label><input id=u name=username value=admin autocomplete=username required></div>
<div class=field><label for=p>密码</label><input id=p name=password type=password autocomplete=current-password
placeholder="请输入面板密码" required autofocus></div>
<button class='btn primary'>登 录</button></form>
</div></div></div>""")

    def render_stats_section(self, st: dict) -> str:
        e = html.escape
        listening = set(st["listening"])
        state_txt, state_cls = STATE_ZH.get(st["active"], (st["active"], "bad"))
        _, uptime = parse_since(st["since"]) if st["active"] == "active" else ("", "")
        version = short_version(st["version"])
        nodes, inbs = read_nodes(), load_inbounds()
        ports = [n["port"] for n in nodes] + [i["port"] for i in inbs]
        n_listen = sum(1 for p in ports if p in listening)
        cert = parse_cert(st["cert"].get("info", ""))
        days = cert.get("days")
        hours = cert.get("hours")

        def stat(label, val, sub=""):
            return (f"<div class=stat><div class=lb>{label}</div><div class=val>{val}</div>"
                    f"<div class=sub>{sub or '&nbsp;'}</div></div>")

        if days is not None and days < 1:
            cert_val = f"{hours}<small>小时</small>"
        else:
            cert_val = f"{days}<small>天</small>" if days is not None else ("未知" if cert else "缺失")
        cert_sub = f"到期 {e(cert.get('expires', ''))}" if cert.get("expires") else "证书剩余有效期"
        return "<div class=stats id=stats-bar>" + "".join([
            stat(f"<span class='dot {state_cls}'></span>内核状态", e(state_txt),
                 f"已运行 {uptime}" if uptime else "Mihomo 服务"),
            stat("入站节点", f"{len(ports)}<small>个</small>", f"{n_listen} 个正在监听"),
            stat("证书有效期", cert_val, cert_sub),
            stat("内核版本", e(version or "未知"), f"Clash Serve v{VERSION}"),
        ]) + "</div>"

    def render_inbounds_section(self, s: dict, env: dict, st: dict) -> str:
        e = html.escape
        hid = f"<input type=hidden name=csrf value='{e(s['csrf'])}'>"
        listening = set(st["listening"])
        nodes, inbs = read_nodes(), load_inbounds()

        def state(port):
            return ("<span class='pill ok'><span class='dot ok'></span>监听中</span>" if port in listening
                    else "<span class='pill bad'><span class='dot bad'></span>未监听</span>")

        def client_block(cid, proxy):
            snippet = e("- " + json.dumps(proxy, ensure_ascii=False))
            return (f"<details><summary>查看客户端配置</summary><pre id={cid}>{snippet}</pre>"
                    f"<button type=button class='btn sm' style=margin-top:8px onclick=\"copyText('{cid}',this)\">复制</button>"
                    f"</details>")

        def item(name, kind, port, extra_meta, acts, cid, proxy):
            return (f"<div class=item><div class=top><div><div class=nm>{e(name)}</div>"
                    f"<div class=meta><span>端口 <b class=mono>{port}</b></span>{extra_meta}</div></div>"
                    f"<span class='pill k-{kind}'>{e(KIND_ZH.get(kind, kind))}</span>{state(port)}"
                    f"<div class=acts>{acts}</div></div>{client_block(cid, proxy)}</div>")

        rows = []
        for idx, n in enumerate(nodes):
            acts = (f"<form class=inline method=post action=/nodes/{quote(n['name'])}/delete data-ajax=1 data-busy=正在删除…>{hid}"
                    f"<button class='btn sm danger' onclick=\"return confirm('确定删除入站「{e(n['name'])}」？删除后客户端将无法连接。')\">删除</button></form>")
            rows.append(item(n["name"], "vless-reality", n["port"], "<span>安装时生成</span>",
                             acts, f"r-{idx}", reality_client(n, env)))
        for i in inbs:
            created = time.strftime("%Y-%m-%d %H:%M", time.localtime(i.get("created", 0))) if i.get("created") else ""
            acts = (f"<form class=inline method=post action=/inbounds/{i['id']}/delete data-ajax=1 data-busy=正在删除…>{hid}"
                    f"<button class='btn sm danger' onclick=\"return confirm('确定删除入站「{e(i['name'])}」？删除后客户端将无法连接。')\">删除</button></form>")
            rows.append(item(i["name"], i["kind"], i["port"],
                             f"<span>面板添加{(' · ' + created) if created else ''}</span>",
                             acts, f"c-{i['id']}", i["client"]))
        all_proxies = [reality_client(n, env) for n in nodes] + [i["client"] for i in inbs]
        all_yaml = e("proxies:\n" + "\n".join("  - " + json.dumps(p, ensure_ascii=False) for p in all_proxies))
        copy_all = (f"<div class=spacer></div><pre id=all-proxies style=display:none>{all_yaml}</pre>"
                    f"<button type=button class='btn sm' onclick=\"copyText('all-proxies',this)\">复制全部 proxies</button>"
                    if all_proxies else "")
        body_rows = "".join(rows) or "<div class=empty>暂无入站节点，可在下方添加。</div>"
        return f"""<div class=card id=inbounds-card><div class=card-h><h2>入站节点</h2><span class='pill gray'>共 {len(rows)} 个</span>{copy_all}
<div class=desc>展开「查看客户端配置」可复制单个节点配置，或点击右上角复制全部节点的 proxies 片段。</div></div>
<div class=list>{body_rows}</div></div>"""

    def render_proxies_section(self, s: dict) -> str:
        e = html.escape
        hid = f"<input type=hidden name=csrf value='{e(s['csrf'])}'>"
        srv_proxies = load_server_proxies()
        p_rows = []
        for idx, p in enumerate(srv_proxies):
            yml = e(dump_yaml_proxies([p]).rstrip("\n"))
            pid = f"sp-{idx}"
            del_form = (f"<form class=inline method=post action=/proxies/delete data-ajax=1 data-busy=正在删除…>{hid}"
                        f"<input type=hidden name=name value='{e(p['name'])}'>"
                        f"<button class='btn sm danger' onclick=\"return confirm('确定从服务端 proxies: 删除节点「{e(p['name'])}」？')\">删除</button></form>")
            p_rows.append(
                f"<div class=item><div class=top><div><div class=nm>{e(p['name'])}</div>"
                f"<div class=meta><span>服务器 <b class=mono>{e(str(p['server']))}:{p['port']}</b></span>"
                f"<span>UDP <b class=mono>{'开启' if p.get('udp', True) else '关闭'}</b></span></div></div>"
                f"<span class='pill tag'>{e(str(p['type']))}</span>"
                f"<div class=acts>{del_form}</div></div>"
                f"<details><summary>查看多行 YAML</summary><pre id={pid}>{yml}</pre>"
                f"<button type=button class='btn sm' style=margin-top:8px onclick=\"copyText('{pid}',this)\">复制</button></details></div>"
            )
        list_html = f"<div class=list style='margin-bottom:14px'>{''.join(p_rows)}</div>" if p_rows else ""
        return f"""<div class=sub-sec id=proxies-section>
<div class=card-h style='margin-bottom:10px'><h2 style='font-size:15px'>服务端出站节点（<code>proxies:</code>）</h2>
<span class='pill gray'>已添加 {len(srv_proxies)} 个</span>
<div class=desc>支持粘贴单行 JSON 或多行 YAML 格式的 mihomo 节点配置（或选择节点配置文件），面板会自动转换为多行 YAML 追加到服务端 <code>proxies:</code> 下并默认开启 <code>udp: true</code>（所有策略组已开启 <code>include-all: true</code>，可在 Zashboard 中直接选用）。</div></div>
{list_html}
<form method=post action=/proxies/add data-ajax=1 data-busy=正在写入配置…>{hid}
<div style='margin-bottom:10px'>
<textarea id=proxies-raw name=proxies_raw placeholder='支持粘贴单行 JSON 或多行 YAML，例如：&#10;- {{"name":"HK-01","type":"vless","server":"1.2.3.4","port":443,"uuid":"...","tls":true,"reality-opts":{{"public-key":"...","short-id":"..."}}}}&#10;或：&#10;- name: HK-01&#10;  type: ss&#10;  server: 1.2.3.4&#10;  port: 8388&#10;  cipher: aes-128-gcm&#10;  password: xxx'></textarea>
</div>
<div class=row>
<button class='btn primary' type=submit>添加到服务端 proxies</button>
<label class='btn sm' style='margin:0;cursor:pointer'>选择节点配置文件<input type=file accept='.yaml,.yml,.json,.txt' style='display:none' onchange='loadProxyFile(this)'></label>
</div></form></div>"""

    def dashboard(self, s):
        q = parse_qs(urlparse(self.path).query)
        msg, ok = q.get("msg", [""])[0], q.get("ok", ["1"])[0] == "1"
        env = read_env()
        st = mihomo_status()
        e = html.escape
        hid = f"<input type=hidden name=csrf value='{e(s['csrf'])}'>"
        listening = set(st["listening"])
        state_txt, state_cls = STATE_ZH.get(st["active"], (st["active"], "bad"))
        since, _ = parse_since(st["since"]) if st["active"] == "active" else ("", "")
        version = short_version(st["version"])

        stats = self.render_stats_section(st)

        # --- status card
        status = f"""<div class=card><div class=card-h><h2>Mihomo 内核</h2>
<span class='pill {state_cls}'><span class='dot {state_cls}'></span>{e(state_txt)}</span></div>
<dl class=kv><dt>版本</dt><dd class=mono>{e(version or '未知')}</dd>
<dt>进程 PID</dt><dd class=mono>{e(st['pid'] if st['pid'] not in ('', '0') else '—')}</dd>
<dt>启动时间</dt><dd>{e(since or '—')}</dd>
<dt>自动重启</dt><dd>{e(st['restarts'] or '0')} 次</dd></dl>
<div class=row>
<form class=inline method=post action=/action/restart data-busy=正在重启…>{hid}<button class='btn primary'>重启内核</button></form>
<form class=inline method=post action=/action/reload data-busy=正在重载…>{hid}<button class=btn title='先校验配置，通过后再热重载'>重载配置</button></form>
</div></div>"""

        inbounds = self.render_inbounds_section(s, env, st)

        # --- add inbound form
        opts = "".join(f"<option value={k}>{v}</option>" for k, v in KIND_ZH.items())
        ss_opts = "".join(f"<option value={c}>{SS_CIPHER_LABELS.get(c, c)}</option>" for c in SS_CIPHERS)
        no_cert = "" if certs_present() else "<div class=notice>证书文件缺失，暂时无法添加 Hysteria2 / TrustTunnel（请在服务器执行 clashserver cert）。</div>"
        add = f"""<div class=card><div class=card-h><h2>添加入站</h2></div>
<form method=post action=/inbounds/add data-ajax=1 data-busy=正在添加…>{hid}<div class=form-grid>
<div><label for=kind>协议类型</label><select id=kind name=kind>{opts}</select></div>
<div><label for=port>端口</label><input id=port name=port inputmode=numeric placeholder="留空则随机分配"></div>
<div><label for=nm>名称</label><input id=nm name=name placeholder="留空则自动生成（默认 VlessReality）"></div>
<div data-kind=shadowsocks><label>Shadowsocks 加密方式</label><select name=ss_cipher>{ss_opts}</select></div>
<div data-kind=snell><label>Snell 版本</label><select name=snell_version><option value=5>v5</option><option value=4>v4</option></select></div>
<div data-kind=trusttunnel><label>TrustTunnel 用户名</label><input name=tt_user placeholder="默认 user"></div>
</div><button class='btn primary' type=submit>添加入站</button></form>
<p class=hint>密码、UUID、密钥均自动随机生成，所有生成节点默认开启 <code>udp: true</code>；Hysteria2 / TrustTunnel 使用本机域名证书（与面板共用），Shadowsocks / Snell / Reality 无需证书。
保存前会自动校验配置，校验失败会自动回滚，不影响现有节点。</p>{no_cert}</div>"""

        # --- mihomo 服务端配置 card (formerly Zashboard card)
        zb_url = zashboard_url(env)
        zb_connect = zashboard_connect_url(env)
        zb_secret = env.get("MIHOMO_SECRET", "")
        srv_cfg_url = server_config_url(env, self.cfg)
        cport = int(env.get("CONTROLLER_PORT") or 7896)
        zb_state = ("<span class='pill ok'><span class='dot ok'></span>监听中</span>" if cport in listening
                    else "<span class='pill warn'>未监听</span>")
        open_cfg = f"<a class='btn sm' href='/config/server.yaml' target=_blank rel=noopener>查看运行配置 ↗</a>"
        open_zb = (f"<a class='btn sm primary' href='{e(zb_connect)}' target=_blank rel=noopener>打开 Zashboard ↗</a>"
                   if zb_connect else "")
        reset_zb = (f"<form class=inline method=post action=/action/reset-secret data-busy=正在重置…>"
                    f"{hid}<button class='btn sm' onclick=\"return confirm('确定重置 Zashboard API 密钥？重置后需使用新密钥连接。')\">重置 API 密钥</button></form>")
        proxies_sec = self.render_proxies_section(s)
        server_card = f"""<div class=card><div class=card-h><h2>mihomo 服务端配置</h2>{zb_state}<div class=spacer></div>{open_cfg}{open_zb}{reset_zb}
<div class=desc>管理 Mihomo 服务端运行配置、Zashboard 控制面板（external-controller-tls :{cport}）与服务端出站节点（<code>proxies:</code>）。</div></div>
<div style=margin-bottom:12px><label>当前运行中的服务端配置链接（需面板登录鉴权）</label>
<div class=sub-box><div class='url mono' id=srv-cfg-url>{e(srv_cfg_url)}</div>
<a class=btn href='/config/server.yaml' target=_blank rel=noopener>打开配置</a>
<button type=button class=btn onclick="copyText('srv-cfg-url',this)">复制链接</button></div></div>
<div style=margin-bottom:12px><label>Zashboard HTTPS 地址</label>
<div class=sub-box><div class='url mono' id=zb-url>{e(zb_url or '—')}</div>
<button type=button class=btn onclick="copyText('zb-url',this)">复制地址</button></div></div>
<div><label>API 密钥（Secret）</label>
<div class=sub-box><div class='url mono' id=zb-secret>{e(zb_secret or '—')}</div>
<button type=button class=btn onclick="copyText('zb-secret',this)">复制密钥</button></div></div>
{proxies_sec}</div>"""

        url = self.sub_url()
        if url:
            sub = f"""<div class=card><div class=card-h><h2>订阅链接</h2><span class='pill tag'>mihomo.yaml</span>
<div class=desc>包含全部节点，导入 mihomo / Clash 客户端即可。链接即凭证，请勿外泄；如需更换，在服务器执行 <code>clashserver reset-sub</code>。</div></div>
<div class=sub-box><div class='url mono' id=sub-url>{e(url)}</div>
<button type=button class='btn primary' onclick="copyText('sub-url',this)">复制链接</button></div></div>"""
        else:
            sub = ""
        icon = "✓" if ok else "!"
        fl_inner = f"<div class='flash {'ok' if ok else 'bad'}'><b>{icon}</b><div>{e(msg)}</div></div>" if msg else ""
        fl = f"<div id=flash-box>{fl_inner}</div>"
        vps = env.get("VPS_NAME", "")
        top = f"""<div class=topbar><div class=in><div class=logo>C</div>
<div class=brand><b>Clash Serve <span class='pill tag'>v{VERSION}</span></b><small>服务器管理面板 · {VERSION}</small></div>
<span class='chip hide-sm'><span class='dot {state_cls}'></span>{e(vps or env.get('DOMAIN', ''))}</span><div class=spacer></div>
<form class=inline method=post action=/logout>{hid}<button class='btn sm ghost'>退出登录</button></form></div></div>"""
        head = f"""<div class=page-h><div><h1>控制台 <span class='pill gray'>v{VERSION}</span></h1><p>{e(env.get('DOMAIN', ''))}</p></div>
<a class='btn sm' href=/>刷新</a></div>"""
        foot = f"<footer>Clash Serve v{VERSION} · Mihomo 服务端管理面板</footer>"
        return page(f"控制台 · Clash Serve v{VERSION}",
                    f"{top}<main>{fl}{head}{stats}{status}{server_card}{sub}{inbounds}{add}</main>{foot}",
                    scripts=True)


class TLSServer(ThreadingHTTPServer):
    """HTTPS server: handshake runs in the worker thread (a slow client cannot block accept),
    and the certificate is reloaded automatically when acme.sh renews it (file mtime changes)."""
    daemon_threads = True

    def __init__(self, addr, handler, cert, key):
        self.cert, self.key, self._stamp, self.ctx = cert, key, None, None
        self._reload()
        super().__init__(addr, handler)

    def _reload(self):
        try:
            stamp = (os.stat(self.cert).st_mtime_ns, os.stat(self.key).st_mtime_ns)
        except OSError:
            return
        if stamp == self._stamp:
            return
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_alpn_protocols(["http/1.1"])
        try:
            ctx.load_cert_chain(self.cert, self.key)
        except (OSError, ssl.SSLError) as e:
            sys.stderr.write(f"certificate load failed: {e}\n")
            if self.ctx is None:
                raise
            return
        self.ctx, self._stamp = ctx, stamp
        sys.stderr.write("certificate loaded\n")

    def get_request(self):
        sock, addr = self.socket.accept()
        self._reload()
        sock.settimeout(30)
        return self.ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr

    def finish_request(self, request, client_address):
        try:
            request.do_handshake()
        except (ssl.SSLError, OSError):
            return   # plain HTTP / scanners / aborted handshakes: drop quietly
        super().finish_request(request, client_address)

    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], (ssl.SSLError, ConnectionError, socket.timeout)):
            return
        super().handle_error(request, client_address)


def serve(cfg_path):
    with open(cfg_path) as f:
        cfg = json.load(f)
    Panel.cfg = cfg
    Panel.cfg_path = cfg_path
    addr = (cfg.get("listen", "0.0.0.0"), int(cfg.get("port", 8443)))
    if cfg.get("tls_cert"):
        httpd = TLSServer(addr, Panel, ROOT + cfg["tls_cert"], ROOT + cfg["tls_key"])
        scheme = "https"
    else:   # local development only
        httpd = ThreadingHTTPServer(addr, Panel)
        scheme = "http"
    sys.stderr.write(f"clashserve v{VERSION} listening on {scheme}://{addr[0]}:{addr[1]}\n")
    httpd.serve_forever()


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("hash-password")
    sp = sub.add_parser("serve")
    sp.add_argument("--config", required=True)
    a = ap.parse_args()
    if a.cmd == "hash-password":
        pw = sys.stdin.readline().rstrip("\n")
        if len(pw) < 8:
            sys.exit("密码太短（至少 8 位）")
        print(hash_password(pw))
    else:
        serve(a.config)


if __name__ == "__main__":
    main()
