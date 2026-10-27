#!/usr/bin/env python3
"""clashserve v0.6 - rebuilt admin console for clashserver (certificate modes).

Stdlib only (Python 3). Serves HTTPS itself with the same certificate
Mihomo uses (/etc/clashserve/certs); no reverse proxy.
Unified directory layout under /etc/clashserve with automatic migration from
legacy /etc/mihomo, /etc/clashserver, /var/lib/mihomo, /root/clashserver-client.

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
import shutil
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

VERSION = "0.6"

# CLASHSERVER_ROOT lets the panel run against a fake tree for local testing.
ROOT = os.environ.get("CLASHSERVER_ROOT", "")
CS_ROOT = ROOT + "/etc/clashserve"
ENV_FILE = CS_ROOT + "/clashserver.env"
INBOUNDS = CS_ROOT + "/inbounds.json"
PROXIES_JSON = CS_ROOT + "/proxies.json"
PROVIDERS_JSON = CS_ROOT + "/providers.json"
MIHOMO_DIR = CS_ROOT
CONF = MIHOMO_DIR + "/config.yaml"
CUSTOM_CONF = MIHOMO_DIR + "/custom_config.yaml"
NODES_TSV = MIHOMO_DIR + "/nodes.tsv"
FRAG_CONTROLLER = MIHOMO_DIR + "/controller.yaml"
FRAG_REALITY = MIHOMO_DIR + "/listeners.reality.yaml"
FRAG_EXTRA = MIHOMO_DIR + "/listeners.extra.yaml"
FRAG_PROXIES = MIHOMO_DIR + "/proxies.extra.yaml"
FRAG_PROVIDERS = MIHOMO_DIR + "/providers.extra.yaml"
TEMPLATE = CS_ROOT + "/resources/server.yaml.tpl"
CLIENT_TEMPLATE = CS_ROOT + "/resources/client.yaml.tpl"
CLIENT_DIR = CS_ROOT + "/client"
CERTCTL = CS_ROOT + "/scripts/certctl.sh"
CERT = "/etc/clashserve/certs/fullchain.pem"   # paths as seen by mihomo (not ROOT-prefixed)
KEY = "/etc/clashserve/certs/privkey.pem"
CERT_REL = "certs/fullchain.pem"
KEY_REL = "certs/privkey.pem"
MIHOMO_BIN = os.environ.get("MIHOMO_BIN", CS_ROOT + "/mihomo" if os.path.isfile(CS_ROOT + "/mihomo") else "/usr/local/bin/mihomo")
SYSTEMCTL = os.environ.get("SYSTEMCTL", "systemctl")
UFW_BIN = os.environ.get("UFW_BIN", "ufw")
FIREWALL_CMD_BIN = os.environ.get("FIREWALL_CMD_BIN", "firewall-cmd")
REALITY_SNI_POOL = (
    "www.microsoft.com",
    "www.apple.com",
    "addons.mozilla.org",
    "www.yahoo.com",
    "www.amd.com",
    "www.nvidia.com",
    "www.samsung.com",
    "www.cisco.com",
    "www.oracle.com",
    "www.lovelive-anime.jp",
)
PBKDF2_ITER = 600_000
SESSION_TTL = 12 * 3600


def pick_reality_sni() -> str:
    return random.choice(REALITY_SNI_POOL)

TYPES = (
    "vless-reality", "shadowsocks", "hysteria2", "snell", "trusttunnel",
    "vless", "vmess", "anytls", "tuic", "shadowquic", "mieru", "sudoku", "http", "socks",
)
CERT_TYPES = ("hysteria2", "trusttunnel", "anytls", "tuic")
SS_CIPHERS = ("aes-128-gcm", "aes-256-gcm")
SS_CIPHER_LABELS = {
    "aes-128-gcm": "aes-128-gcm（aes128，默认）",
    "aes-256-gcm": "aes-256-gcm（aes256）",
}
STR_KEYS = {
    "name", "type", "server", "uuid", "password", "psk", "public-key", "private-key",
    "short-id", "servername", "sni", "cipher", "flow", "client-fingerprint",
    "username", "network", "path", "host", "mode", "plugin", "obfs", "fingerprint",
    "network-name", "network-secret", "state-dir", "control-url", "auth-key", "hostname",
    "key", "aead-method", "table-type", "congestion-controller", "udp-relay-mode",
    "decryption", "encryption", "ws-path", "grpc-service-name", "transport",
}

ANYTLS_DEFAULT_PADDING = (
    "stop=7\n"
    "0=40-40\n"
    "1=120-380\n"
    "2=350-550,c,550-1100,c,600-1200,c,500-1000\n"
    "3=12-12,450-950\n"
    "4=480-1100\n"
    "5=500-1200\n"
    "6=450-1000"
)

LOCK = threading.Lock()


# ---------------------------------------------------------------- legacy migration & helpers
def resolve_mihomo_bin() -> str:
    env_bin = os.environ.get("MIHOMO_BIN")
    if env_bin:
        return env_bin
    if os.path.isfile(CS_ROOT + "/mihomo") and os.access(CS_ROOT + "/mihomo", os.X_OK):
        return CS_ROOT + "/mihomo"
    return "/usr/local/bin/mihomo"


def resolve_template_path(rel_path: str) -> str:
    p1 = CS_ROOT + "/" + rel_path
    if os.path.isfile(p1):
        return p1
    p2 = ROOT + "/usr/local/lib/clashserver/" + rel_path
    if os.path.isfile(p2):
        return p2
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    p3 = os.path.join(here, rel_path)
    return p3 if os.path.isfile(p3) else p1


def ensure_unified_root():
    """Migrate legacy scattered directories (/etc/mihomo, /etc/clashserver, etc.) into /etc/clashserve."""
    os.makedirs(CS_ROOT, mode=0o775, exist_ok=True)
    os.makedirs(CLIENT_DIR, mode=0o700, exist_ok=True)
    for legacy in (ROOT + "/etc/clashserver", ROOT + "/etc/mihomo", ROOT + "/var/lib/mihomo", ROOT + "/usr/local/lib/clashserver"):
        if os.path.isdir(legacy) and not os.path.islink(legacy):
            for entry in os.listdir(legacy):
                src = os.path.join(legacy, entry)
                dst = os.path.join(CS_ROOT, entry)
                if not os.path.exists(dst):
                    try:
                        shutil.move(src, dst)
                    except Exception:
                        pass
    old_client = ROOT + "/root/clashserver-client"
    if os.path.isdir(old_client) and not os.path.islink(old_client):
        for entry in os.listdir(old_client):
            src = os.path.join(old_client, entry)
            dst = os.path.join(CLIENT_DIR, entry)
            if not os.path.exists(dst):
                try:
                    shutil.move(src, dst)
                except Exception:
                    pass


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
    for p in (ENV_FILE, ROOT + "/etc/clashserver/clashserver.env"):
        try:
            with open(p) as f:
                for line in f:
                    m = re.match(r"^([A-Z_]+)=(.*)$", line.strip())
                    if m:
                        val = m.group(2).strip()
                        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                            val = val[1:-1]
                        env[m.group(1)] = val
            break
        except FileNotFoundError:
            continue
    return env


def run(cmd, timeout=30, env=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return p.returncode, (p.stdout + p.stderr).strip()
    except Exception as e:
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


def load_proxy_providers() -> dict:
    try:
        with open(PROVIDERS_JSON) as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except FileNotFoundError:
        pass
    return {}


def is_custom_config_mode() -> bool:
    try:
        return os.path.isfile(CUSTOM_CONF) and os.path.getsize(CUSTOM_CONF) > 0
    except OSError:
        return False


def read_nodes() -> list:
    rows = []
    try:
        with open(NODES_TSV) as f:
            for line in f:
                p = line.rstrip("\n").split("\t")
                if len(p) >= 7:
                    rows.append({
                        "name": p[0], "port": int(p[1]), "uuid": p[2],
                        "priv": p[3], "pub": p[4], "sid": p[5], "sni": p[6],
                        "dec": p[7] if len(p) >= 8 else "",
                        "enc": p[8] if len(p) >= 9 else "",
                    })
    except FileNotFoundError:
        pass
    return rows


def get_controller_port(env: dict = None) -> int:
    if is_custom_config_mode():
        try:
            with open(CUSTOM_CONF) as f:
                txt = f.read()
            for pat in (
                r'^\s*external-controller-tls\s*:\s*["\']?[^"\':\s]+:(\d+)',
                r'^\s*external-controller\s*:\s*["\']?[^"\':\s]+:(\d+)',
            ):
                m = re.search(pat, txt, re.M)
                if m:
                    p = int(m.group(1))
                    if 1 <= p <= 65535:
                        return p
        except Exception:
            pass
    if env is None:
        env = read_env()
    try:
        p = int(env.get("CONTROLLER_PORT") or 0)
        if 1 <= p <= 65535:
            return p
    except ValueError:
        pass
    try:
        with open(CONF) as f:
            txt = f.read()
        for pat in (
            r'^\s*external-controller-tls\s*:\s*["\']?[^"\':\s]+:(\d+)',
            r'^\s*external-controller\s*:\s*["\']?[^"\':\s]+:(\d+)',
        ):
            m = re.search(pat, txt, re.M)
            if m:
                return int(m.group(1))
    except Exception:
        pass
    return 7896


def extract_yaml_secret(raw_yaml: str):
    """Extract top-level `secret:` scalar from raw YAML without truncating on `#` or `%` inside quotes."""
    for raw_line in raw_yaml.splitlines():
        expanded = raw_line.expandtabs(2)
        stripped = expanded.lstrip(" ")
        indent = len(expanded) - len(stripped)
        if indent != 0 or not stripped or stripped.startswith("#"):
            continue
        cleaned = strip_yaml_comment(stripped)
        k, sep, v = split_kv(cleaned)
        if sep and k == "secret":
            val = parse_scalar(v, "secret")
            return "" if val is None else str(val)
    return None


def get_mihomo_secret(env: dict = None) -> str:
    if is_custom_config_mode():
        try:
            with open(CUSTOM_CONF) as f:
                sec = extract_yaml_secret(f.read())
            if sec is not None:
                return sec
        except Exception:
            pass
    if env is None:
        env = read_env()
    return env.get("MIHOMO_SECRET", "")


def used_ports(env) -> set:
    ports = {80, 443, int(env.get("PANEL_PORT", "0") or 0), get_controller_port(env)}
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
    rc, out = run([resolve_mihomo_bin(), "generate", "reality-keypair"])
    priv = re.search(r"PrivateKey:\s*(\S+)", out)
    pub = re.search(r"PublicKey:\s*(\S+)", out)
    if rc != 0 or not priv or not pub:
        raise RuntimeError("Reality 密钥对生成失败：" + out)
    return priv.group(1), pub.group(1)


def sudoku_keypair():
    rc, out = run([resolve_mihomo_bin(), "generate", "sudoku-keypair"])
    priv = re.search(r"PrivateKey:\s*(\S+)", out)
    pub = re.search(r"PublicKey:\s*(\S+)", out)
    if rc == 0 and priv and pub:
        return priv.group(1), pub.group(1)
    u = str(uuidlib.uuid4())
    return u, u


def vless_x25519_keypair():
    rc, out = run([resolve_mihomo_bin(), "generate", "vless-x25519"])
    dec = re.search(r'\[Server\]\s*decryption:\s*"([^"]+)"', out)
    enc = re.search(r'\[Client\]\s*encryption:\s*"([^"]+)"', out)
    if rc != 0 or not dec or not enc:
        raise RuntimeError("VLESS 加密密钥生成失败：" + out)
    return dec.group(1), enc.group(1)


def certs_present() -> bool:
    for c, k in ((CERT, KEY), (ROOT + CERT, ROOT + KEY), (ROOT + "/etc/mihomo/certs/fullchain.pem", ROOT + "/etc/mihomo/certs/privkey.pem")):
        if os.path.isfile(c) and os.path.isfile(k):
            return True
    return False


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
    """Return Zashboard HTTPS URL with fully URL-encoded API Secret appended for one-click direct login."""
    host = env.get("DOMAIN", "").removeprefix("*.") or env.get("SERVER_IP", "")
    if not host:
        return ""
    cport = get_controller_port(env)
    secret = get_mihomo_secret(env)
    if not secret:
        return f"https://{host}:{cport}/ui/"
    qs = f"hostname={quote(host, safe='')}&port={cport}&secret={quote(secret, safe='')}&https=true"
    return f"https://{host}:{cport}/ui/#/setup?{qs}"


def zashboard_connect_url(env: dict) -> str:
    return zashboard_url(env)


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
    cport = get_controller_port(env)
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
            if i + 1 == len(line) or line[i + 1].isspace() or line[i + 1] in ('"', "'", "[", "{"):
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
            if not item:
                continue
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
        return [parse_flow_val(x, key) for x in split_flow(inner, ",") if x != ""]
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
            if v in ("|", "|-", "|+", ">", ">-", ">+"):
                blk = []
                blk_indent = None
                while idx < len(lines) and lines[idx][0] > map_indent:
                    b_ind, b_txt = lines[idx]
                    if blk_indent is None:
                        blk_indent = b_ind
                    pad = " " * max(0, b_ind - blk_indent)
                    blk.append(pad + b_txt)
                    idx += 1
                mapping[k] = "\n".join(blk)
            elif v:
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
    """Parse single-line JSON/flow or multi-line YAML mihomo node configs; supports easytier/tailscale/etc."""
    s = (raw or "").strip()
    if not s:
        raise ValueError("请输入 mihomo 节点配置（单行 JSON 或多行 YAML）")
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", s):
        raise ValueError("不支持分享链接（如 vless://、ss://），请粘贴 mihomo 配置格式（JSON 或 YAML；若是订阅链接请在上方「导入外部订阅」中添加）")
    parsed = None
    if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
        try:
            parsed = json.loads(s)
        except Exception:
            if "\n" not in s or (s.startswith("[") and s.endswith("]")):
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
        flow_candidates = []
        all_flow = True
        for _, txt in lines:
            t = txt[1:].strip() if (txt == "-" or txt.startswith("- ")) else txt
            if t.endswith(","):
                t = t[:-1].strip()
            if t.startswith("{") and t.endswith("}"):
                flow_candidates.append(t)
            else:
                all_flow = False
                break
        if all_flow and flow_candidates:
            parsed = [parse_flow_val(t) for t in flow_candidates]
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
            raise ValueError("每个节点必须是键值对对象（需包含 name 与 type）")
        node = dict(item)
        for req in ("name", "type"):
            if req not in node or node[req] in ("", None):
                raise ValueError(f"节点缺少必填字段：{req}")
        node["name"] = str(node["name"]).strip()
        node["type"] = str(node["type"]).strip()
        if "server" in node and node["server"] not in ("", None):
            node["server"] = str(node["server"]).strip()
        if "port" in node and node["port"] not in ("", None):
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


def dump_yaml_providers(providers: dict) -> str:
    """Render proxy-providers dict as 2-space indented YAML mapping entries."""
    lines = []
    for name, cfg in providers.items():
        ks = name if re.fullmatch(r"[A-Za-z0-9._-]+", str(name)) else json.dumps(str(name), ensure_ascii=False)
        lines.append(f"  {ks}:")
        lines.extend(dump_yaml_map(cfg, indent=4, first_dash=False))
    return "\n".join(lines) + ("\n" if lines else "")


def build_proxy_provider(url: str, name: str = "", existing: dict = None) -> tuple:
    """Build a proxy-provider entry matching the 0.5 requirement structure."""
    u = (url or "").strip()
    if not re.match(r"^https?://\S+$", u):
        raise ValueError("请输入有效的 HTTP/HTTPS 订阅链接")
    raw_name = (name or "").strip()
    if not raw_name or raw_name.lower() == "default":
        # Note: Mihomo kernel forbids naming a proxy-provider literally 'default'
        # ("can not defined a provider called `default`"), while path ./default.yaml is valid.
        prov_name = "default-sub" if (existing and "sub" in existing and "default-sub" not in existing) else "sub"
        if raw_name.lower() == "default":
            prov_name = "default-sub"
        path = "./default.yaml" if not existing else f"./{prov_name}.yaml"
    else:
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,48}", raw_name):
            raise ValueError("订阅源名称仅限 1-48 位字母、数字及 . _ -")
        prov_name = raw_name
        path = f"./{prov_name}.yaml"
    entry = {
        "type": "http",
        "url": u,
        "path": path,
        "interval": 3600,
        "proxy": "DIRECT",
        "health-check": {
            "enable": True,
            "url": "https://www.gstatic.com/generate_204",
            "interval": 300,
            "timeout": 5000,
            "lazy": True,
        },
    }
    return prov_name, entry


# ---------------------------------------------------------------- custom server config helpers
def rewrite_cert_paths_in_yaml(raw_yaml: str, env: dict = None) -> tuple:
    """Automatically rewrite TLS certificate/private-key paths in user server config to /etc/clashserve/certs/*.
    Never modifies private-key inside reality-config blocks."""
    lines = raw_yaml.splitlines()
    out = []
    in_reality = False
    reality_indent = 0
    in_providers = False
    providers_indent = 0
    changed = 0

    for line in lines:
        stripped = line.lstrip(" ")
        indent = len(line) - len(stripped)
        if stripped and not stripped.startswith("#"):
            if in_reality and indent <= reality_indent:
                in_reality = False
            if in_providers and indent <= providers_indent:
                in_providers = False
            if re.match(r"^reality-config\s*:", stripped):
                in_reality = True
                reality_indent = indent
                out.append(line)
                continue
            if re.match(r"^proxy-providers\s*:", stripped):
                in_providers = True
                providers_indent = indent
                out.append(line)
                continue
            # Rename reserved provider key `default:` under `proxy-providers:` so mihomo -t passes
            if in_providers and indent == providers_indent + 2 and re.match(r"^default\s*:\s*(#.*)?$", stripped):
                line = (" " * indent) + re.sub(r"^default(\s*:)", r"default-sub\1", stripped, count=1)
                changed += 1
                out.append(line)
                continue
            # Rewrite certificate:
            m_cert = re.match(r"^((?:-\s+)?certificate\s*:\s*)([^#\n]+?)(\s*(?:#.*)?)$", stripped)
            if m_cert:
                cur_val = m_cert.group(2).strip().strip("'\"")
                if cur_val != CERT:
                    changed += 1
                line = (" " * indent) + f"{m_cert.group(1)}{CERT}{m_cert.group(3)}"
                out.append(line)
                continue
            # Rewrite private-key: (ONLY when not inside reality-config)
            if not in_reality:
                m_key = re.match(r"^((?:-\s+)?private-key\s*:\s*)([^#\n]+?)(\s*(?:#.*)?)$", stripped)
                if m_key:
                    cur_val = m_key.group(2).strip().strip("'\"")
                    if "/" in cur_val or "." in cur_val or "key" in cur_val.lower() or "pem" in cur_val.lower():
                        if cur_val != KEY:
                            changed += 1
                        line = (" " * indent) + f"{m_key.group(1)}{KEY}{m_key.group(3)}"
                        out.append(line)
                        continue
        out.append(line)
    res = "\n".join(out) + ("\n" if raw_yaml.endswith("\n") else "")
    return res, changed


def sync_env_from_custom_config(raw_yaml: str):
    """Sync CONTROLLER_PORT and MIHOMO_SECRET from a custom server config if present."""
    for pat in (
        r'^\s*external-controller-tls\s*:\s*["\']?[^"\':\s]+:(\d+)["\']?',
        r'^\s*external-controller\s*:\s*["\']?[^"\':\s]+:(\d+)["\']?',
    ):
        m_port = re.search(pat, raw_yaml, re.M)
        if m_port:
            p = int(m_port.group(1))
            if 1 <= p <= 65535:
                write_env_var("CONTROLLER_PORT", str(p))
                break
    sec = extract_yaml_secret(raw_yaml)
    if sec:
        write_env_var("MIHOMO_SECRET", sec)


def x25519_pub_from_priv(priv_b64: str) -> str:
    """Derive base64url X25519 public key from a 32-byte base64url/base64 X25519 private key via openssl."""
    s = (priv_b64 or "").strip()
    if not s:
        return ""
    try:
        pad = "=" * ((4 - len(s) % 4) % 4)
        raw_priv = base64.urlsafe_b64decode(s + pad) if ("-" in s or "_" in s) else base64.b64decode(s + pad)
        if len(raw_priv) != 32:
            return s
        der_priv = bytes.fromhex("302e020100300506032b656e04220420") + raw_priv
        p = subprocess.run(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
                           input=der_priv, capture_output=True, timeout=5)
        if p.returncode == 0 and len(p.stdout) >= 32:
            return base64.urlsafe_b64encode(p.stdout[-32:]).decode().rstrip("=")
    except Exception:
        pass
    return s


def derive_vless_encryption(dec_str: str) -> str:
    """Convert server VLESS `decryption` string into client `encryption` string."""
    s = (dec_str or "").strip()
    if not s or s == "none":
        return ""
    parts = s.split(".")
    out = []
    for seg in parts:
        if re.fullmatch(r"\d+s", seg):
            out.append("0rtt")
        elif len(seg) in (43, 44) and re.fullmatch(r"[A-Za-z0-9_+=-]+", seg):
            out.append(x25519_pub_from_priv(seg))
        else:
            out.append(seg)
    return ".".join(out)


def extract_top_level_yaml_section(raw_yaml: str, section_key: str):
    """Extract and parse a top-level YAML section (e.g. listeners, proxies, proxy-providers)."""
    lines = []
    in_sec = False
    for raw_line in raw_yaml.splitlines():
        cleaned = strip_yaml_comment(raw_line.expandtabs(2))
        if not cleaned.strip():
            continue
        stripped = cleaned.lstrip(" ")
        indent = len(cleaned) - len(stripped)
        if not in_sec:
            if indent == 0:
                k, sep, v = split_kv(stripped)
                if sep and k == section_key:
                    in_sec = True
                    lines.append((0, stripped))
        else:
            if indent == 0 and not (stripped == "-" or stripped.startswith("- ")):
                break
            lines.append((indent, stripped))
    if not lines:
        return None
    try:
        parsed, _ = parse_yaml_lines(lines, 0, 0)
        if isinstance(parsed, dict):
            return parsed.get(section_key)
    except Exception as e:
        sys.stderr.write(f"extract_top_level_yaml_section({section_key}) warning: {e}\n")
    return None


def _first_user_creds(users_val) -> tuple:
    """Extract (username, password, uuid, flow, alterId) from a listener's `users` field (list or dict)."""
    if isinstance(users_val, list) and users_val:
        u0 = users_val[0]
        if isinstance(u0, dict):
            return (
                str(u0.get("username", "user")),
                str(u0.get("password", "")),
                str(u0.get("uuid", "")),
                str(u0.get("flow", "")),
                int(u0.get("alterId", 0) or 0),
            )
    elif isinstance(users_val, dict) and users_val:
        k, v = next(iter(users_val.items()))
        return str(k), str(v), str(k), "", 0
    return "user", "", "", "", 0


def listener_to_inbound(lst: dict, env: dict, existing_by_name: dict = None) -> dict:
    """Convert a Mihomo server listener dict into an inbound record with a complete client proxy dict."""
    if not isinstance(lst, dict):
        raise ValueError("Invalid listener entry")
    name = str(lst.get("name") or "").strip()
    ltype = str(lst.get("type") or "").strip().lower()
    port = int(lst.get("port") or 0)
    if not name or not ltype or not (1 <= port <= 65535):
        raise ValueError(f"Invalid listener name/type/port: {lst}")

    prev = (existing_by_name or {}).get(name)
    iid = prev["id"] if (prev and prev.get("id")) else secrets.token_hex(6)
    created = prev["created"] if (prev and prev.get("created")) else int(time.time())

    vps = env.get("VPS_NAME", "vps")
    ip = env.get("SERVER_IP", "")
    domain = env.get("DOMAIN", "").removeprefix("*.") or ip
    insecure = env.get("CERT_MODE") != "manual" and env.get("TLS", "") in ("staging", "internal")
    label = f"{vps}-{name}"
    has_cert = bool(lst.get("certificate"))
    srv = domain if has_cert else ip
    user, pw, uid, flow, alter_id = _first_user_creds(lst.get("users"))

    if ltype == "vless" and isinstance(lst.get("reality-config"), dict):
        kind = "vless-reality"
        rcfg = lst["reality-config"]
        snames = rcfg.get("server-names")
        sni = (snames[0] if isinstance(snames, list) and snames else str(rcfg.get("dest", "")).split(":")[0]).strip() or pick_reality_sni()
        sids = rcfg.get("short-id")
        sid = str(sids[0] if isinstance(sids, list) and sids else (sids or "")).strip()
        priv = str(rcfg.get("private-key") or "").strip()
        pub = ""
        if prev and isinstance(prev.get("client"), dict):
            prev_ropts = prev["client"].get("reality-opts") or {}
            if prev.get("listener", {}).get("reality-config", {}).get("private-key") == priv:
                pub = prev_ropts.get("public-key", "")
        if not pub:
            pub = x25519_pub_from_priv(priv)
        client = {
            "name": f"{label}|Clash|Reality", "type": "vless", "server": ip, "port": port,
            "uuid": uid, "tls": True, "flow": flow or "xtls-rprx-vision",
            "client-fingerprint": "safari", "skip-cert-verify": False,
        }
        if lst.get("decryption") and str(lst.get("decryption")) != "none":
            enc = ""
            if prev and isinstance(prev.get("client"), dict) and prev.get("listener", {}).get("decryption") == lst.get("decryption"):
                enc = prev["client"].get("encryption", "")
            if not enc:
                enc = derive_vless_encryption(str(lst["decryption"]))
            if enc:
                client["encryption"] = enc
        client.update({
            "reality-opts": {"public-key": pub, "short-id": sid},
            "network": "tcp", "udp": True, "servername": sni,
        })
    elif ltype == "vless":
        kind = "vless"
        client = {
            "name": f"{label}|Clash|VLESS", "type": "vless", "server": srv, "port": port,
            "uuid": uid, "tls": has_cert, "udp": True,
        }
        if has_cert:
            client["servername"] = domain
            client["skip-cert-verify"] = insecure
            client["client-fingerprint"] = "chrome"
        if isinstance(lst.get("xhttp-config"), dict):
            xcfg = lst["xhttp-config"]
            xopts = {"path": str(xcfg.get("path", "/")), "mode": str(xcfg.get("mode", "auto"))}
            if xcfg.get("x-padding-bytes"):
                xopts["x-padding-bytes"] = str(xcfg["x-padding-bytes"])
            client["network"] = "xhttp"
            client["xhttp-opts"] = xopts
        elif lst.get("ws-path"):
            wpath = str(lst["ws-path"])
            client["network"] = "ws"
            client["ws-opts"] = {"path": wpath, "headers": {"Host": srv}}
        elif lst.get("grpc-service-name"):
            client["network"] = "grpc"
            client["grpc-opts"] = {"grpc-service-name": str(lst["grpc-service-name"])}
        else:
            client["network"] = "tcp"
            if flow:
                client["flow"] = flow
        if lst.get("decryption") and str(lst.get("decryption")) != "none":
            enc = ""
            if prev and isinstance(prev.get("client"), dict) and prev.get("listener", {}).get("decryption") == lst.get("decryption"):
                enc = prev["client"].get("encryption", "")
            if not enc:
                enc = derive_vless_encryption(str(lst["decryption"]))
            if enc:
                client["encryption"] = enc
    elif ltype in ("shadowsocks", "ss"):
        kind = "shadowsocks"
        client = {
            "name": f"{label}|Clash|SS", "type": "ss", "server": ip, "port": port,
            "cipher": str(lst.get("cipher", "aes-128-gcm")),
            "password": str(lst.get("password", pw)), "udp": True,
        }
    elif ltype == "hysteria2":
        kind = "hysteria2"
        alpn = lst.get("alpn") if isinstance(lst.get("alpn"), list) else ["h3"]
        client = {
            "name": f"{label}|Clash|Hy2", "type": "hysteria2", "server": domain, "port": port,
            "password": str(lst.get("password") or pw), "sni": domain, "alpn": alpn,
            "skip-cert-verify": insecure, "udp": True,
        }
        if lst.get("obfs"):
            client["obfs"] = str(lst["obfs"])
            if lst.get("obfs-password"):
                client["obfs-password"] = str(lst["obfs-password"])
    elif ltype == "hysteria2-realm":
        kind = "hysteria2-realm"
        alpn = lst.get("alpn") if isinstance(lst.get("alpn"), list) else ["h2", "http/1.1"]
        client = {
            "name": f"{label}|Clash|Hy2Realm", "type": "hysteria2", "server": domain, "port": port,
            "password": str(lst.get("token") or pw), "sni": domain, "alpn": alpn,
            "skip-cert-verify": insecure, "udp": True,
        }
    elif ltype == "anytls":
        kind = "anytls"
        client = {
            "name": f"{label}|Clash|AnyTLS", "type": "anytls", "server": domain, "port": port,
            "password": str(lst.get("password") or pw), "sni": domain,
            "client-fingerprint": "chrome", "skip-cert-verify": insecure, "udp": True,
        }
    elif ltype == "vmess":
        kind = "vmess"
        client = {
            "name": f"{label}|Clash|VMess", "type": "vmess", "server": srv, "port": port,
            "uuid": uid, "alterId": alter_id, "cipher": "auto", "tls": has_cert, "udp": True,
        }
        if has_cert:
            client["servername"] = domain
            client["skip-cert-verify"] = insecure
            client["client-fingerprint"] = "chrome"
        if lst.get("ws-path"):
            wpath = str(lst["ws-path"])
            client["network"] = "ws"
            client["ws-opts"] = {"path": wpath, "headers": {"Host": srv}}
        elif lst.get("grpc-service-name"):
            client["network"] = "grpc"
            client["grpc-opts"] = {"grpc-service-name": str(lst["grpc-service-name"])}
    elif ltype == "trusttunnel":
        kind = "trusttunnel"
        client = {
            "name": f"{label}|Clash|TrustTunnel", "type": "trusttunnel", "server": domain,
            "port": port, "username": user, "password": pw, "sni": domain,
            "skip-cert-verify": insecure, "udp": True,
        }
    elif ltype == "snell":
        kind = "snell"
        ver = int(lst.get("version") or 5)
        obfs = lst.get("obfs-opts") if isinstance(lst.get("obfs-opts"), dict) else {"mode": "tls", "host": pick_reality_sni()}
        client = {
            "name": f"{label}|Clash|Snell", "type": "snell", "server": ip, "port": port,
            "psk": str(lst.get("psk", "")), "version": ver, "udp": True, "obfs-opts": obfs,
        }
    elif ltype == "tuic":
        kind = "tuic"
        cc = str(lst.get("congestion-controller") or "bbr")
        alpn = lst.get("alpn") if isinstance(lst.get("alpn"), list) else ["h3"]
        client = {
            "name": f"{label}|Clash|TUICv5", "type": "tuic", "server": domain, "port": port,
            "uuid": uid, "password": pw, "sni": domain, "alpn": alpn,
            "congestion-controller": cc, "udp-relay-mode": "native",
            "reduce-rtt": True, "skip-cert-verify": insecure, "udp": True,
        }
    elif ltype == "shadowquic":
        kind = "shadowquic"
        jls_up = lst.get("jls-upstream") if isinstance(lst.get("jls-upstream"), dict) else {}
        jls_addr = str(jls_up.get("addr") or "www.microsoft.com:443")
        jls_host = jls_addr.rsplit(":", 1)[0]
        cc = str(lst.get("congestion-controller") or "bbr")
        zrtt = bool(lst.get("zero-rtt", True))
        client = {
            "name": f"{label}|Clash|ShadowQUIC", "type": "shadowquic", "server": ip, "port": port,
            "username": user, "password": pw, "sni": jls_host, "alpn": ["h3"],
            "congestion-controller": cc, "zero-rtt": zrtt, "udp": True,
        }
    elif ltype == "mieru":
        kind = "mieru"
        tr = str(lst.get("transport") or "TCP").upper()
        client = {
            "name": f"{label}|Clash|Mieru", "type": "mieru", "server": ip, "port": port,
            "transport": tr, "username": user, "password": pw, "udp": True,
        }
    elif ltype == "sudoku":
        kind = "sudoku"
        priv_k = str(lst.get("key", ""))
        if prev and isinstance(prev.get("client"), dict) and prev["client"].get("key"):
            priv_k = prev["client"]["key"]
        client = {
            "name": f"{label}|Clash|Sudoku", "type": "sudoku", "server": ip, "port": port,
            "key": priv_k, "aead-method": str(lst.get("aead-method", "chacha20-poly1305")),
            "padding-min": int(lst.get("padding-min", 2)), "padding-max": int(lst.get("padding-max", 7)),
            "table-type": str(lst.get("table-type", "prefer_ascii")),
            "enable-pure-downlink": bool(lst.get("enable-pure-downlink", True)), "udp": True,
        }
    elif ltype == "http":
        kind = "http"
        client = {
            "name": f"{label}|Clash|HTTP", "type": "http", "server": srv, "port": port,
            "username": user, "password": pw, "tls": has_cert, "udp": True,
        }
        if has_cert:
            client["sni"] = domain
            client["skip-cert-verify"] = insecure
    else:  # socks, socks5, mixed
        kind = "mixed" if ltype == "mixed" else "socks"
        tag = "Mixed" if ltype == "mixed" else "SOCKS5"
        client = {
            "name": f"{label}|Clash|{tag}", "type": "socks5", "server": srv, "port": port,
            "username": user, "password": pw, "tls": has_cert, "udp": True,
        }
        if has_cert:
            client["skip-cert-verify"] = insecure

    return {
        "id": iid, "kind": kind, "port": port, "name": name,
        "created": created, "listener": lst, "client": client,
    }


def parse_custom_config_state(raw_yaml: str, env: dict = None) -> tuple:
    """Parse listeners, proxies, and proxy-providers from a full server YAML config."""
    if env is None:
        env = read_env()
    existing_by_name = {}
    for n in read_nodes():
        rc_inb = {
            "id": secrets.token_hex(6), "kind": "vless-reality", "port": n["port"],
            "name": n["name"], "created": int(time.time()),
            "listener": {"reality-config": {"private-key": n["priv"]}, "decryption": n.get("dec", "")},
            "client": reality_client(n, env),
        }
        existing_by_name[n["name"]] = rc_inb
    for i in load_inbounds():
        existing_by_name[i["name"]] = i

    raw_listeners = extract_top_level_yaml_section(raw_yaml, "listeners")
    new_inbounds = []
    if isinstance(raw_listeners, list):
        for item in raw_listeners:
            if isinstance(item, dict):
                try:
                    new_inbounds.append(listener_to_inbound(item, env, existing_by_name))
                except Exception as e:
                    sys.stderr.write(f"listener_to_inbound warning: {e}\n")

    raw_proxies = extract_top_level_yaml_section(raw_yaml, "proxies")
    new_proxies = []
    if isinstance(raw_proxies, list):
        for p in raw_proxies:
            if isinstance(p, dict) and p.get("name") and p.get("type"):
                node = dict(p)
                if "udp" not in node or node["udp"] is None:
                    node["udp"] = True
                new_proxies.append(node)

    raw_providers = extract_top_level_yaml_section(raw_yaml, "proxy-providers")
    new_providers = raw_providers if isinstance(raw_providers, dict) else {}
    return new_inbounds, new_proxies, new_providers


# ---------------------------------------------------------------- inbound model
def build_inbound(kind: str, form: dict, env: dict) -> dict:
    if kind not in TYPES:
        raise ValueError("未知的入站类型")
    need_cert = kind in CERT_TYPES
    if kind in ("http", "socks") and form.get(f"{kind}_tls") == "1":
        need_cert = True
    if kind == "vmess" and form.get("vmess_tls", "1") == "1":
        need_cert = True
    if kind == "vless" and form.get("vless_tls", "1") == "1":
        need_cert = True
    if need_cert and not certs_present():
        raise ValueError(f"{kind} 启用 TLS 需要域名证书，未找到 {CERT}（请先在服务器执行 clashserver cert）")

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
    domain = env.get("DOMAIN", "").removeprefix("*.") or ip
    insecure = env.get("CERT_MODE") != "manual" and env.get("TLS", "") in ("staging", "internal")
    base = {"name": name, "port": port, "listen": "0.0.0.0"}
    label = f"{vps}-{name}"

    if kind == "vless-reality":
        sni = (form.get("reality_sni") or "").strip() or pick_reality_sni()
        if not re.fullmatch(r"[A-Za-z0-9.-]{1,128}", sni):
            raise ValueError("Reality 伪装域名（SNI）格式无效")
        use_enc = (form.get("reality_enc") or "x25519").strip() != "none"
        priv, pub = reality_keypair()
        uid, sid = str(uuidlib.uuid4()), secrets.token_hex(4)
        listener = {**base, "type": "vless", "udp": True,
                    "users": [{"username": "user", "uuid": uid, "flow": "xtls-rprx-vision"}]}
        client = {"name": f"{label}|Clash|Reality", "type": "vless", "server": ip, "port": port,
                  "uuid": uid, "tls": True, "flow": "xtls-rprx-vision", "client-fingerprint": "safari",
                  "skip-cert-verify": False}
        if use_enc:
            dec, enc = vless_x25519_keypair()
            listener["decryption"] = dec
            client["encryption"] = enc
        listener["reality-config"] = {"dest": f"{sni}:443", "private-key": priv,
                                      "short-id": [sid], "server-names": [sni]}
        client.update({"reality-opts": {"public-key": pub, "short-id": sid},
                       "network": "tcp", "udp": True, "servername": sni})

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
        obfs_pw = (form.get("hy2_obfs_pw") or "").strip()
        listener = {**base, "type": "hysteria2", "users": {"user": pw},
                    "certificate": CERT, "private-key": KEY, "alpn": ["h3"],
                    "ignore-client-bandwidth": False}
        client = {"name": f"{label}|Clash|Hy2", "type": "hysteria2", "server": domain, "port": port,
                  "password": pw, "sni": domain, "alpn": ["h3"], "skip-cert-verify": insecure,
                  "udp": True}
        if obfs_pw:
            listener["obfs"] = "salamander"
            listener["obfs-password"] = obfs_pw
            client["obfs"] = "salamander"
            client["obfs-password"] = obfs_pw

    elif kind == "snell":
        version = int(form.get("snell_version") or 5)
        if version not in (4, 5):
            raise ValueError("snell 版本只能是 4 或 5")
        obfs_mode = (form.get("snell_obfs") or "tls").strip()
        if obfs_mode not in ("tls", "http"):
            obfs_mode = "tls"
        obfs_host = (form.get("snell_host") or "").strip() or pick_reality_sni()
        psk = base64.b64encode(secrets.token_bytes(16)).decode()
        listener = {**base, "type": "snell", "psk": psk, "version": version, "udp": True,
                    "obfs-opts": {"mode": obfs_mode, "host": obfs_host}}
        client = {"name": f"{label}|Clash|Snell", "type": "snell", "server": ip, "port": port,
                  "psk": psk, "version": version, "udp": True,
                  "obfs-opts": {"mode": obfs_mode, "host": obfs_host}}

    elif kind == "trusttunnel":
        user = form.get("tt_user", "").strip() or "user"
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", user):
            raise ValueError("TrustTunnel 用户名无效（1-32 位字母、数字及 . _ -）")
        cc = (form.get("tt_cc") or "bbr").strip()
        if cc not in ("bbr", "cubic"):
            cc = "bbr"
        pw = secrets.token_urlsafe(18)
        listener = {**base, "type": "trusttunnel", "users": [{"username": user, "password": pw}],
                    "certificate": CERT, "private-key": KEY, "network": ["tcp", "udp"],
                    "congestion-controller": cc}
        client = {"name": f"{label}|Clash|TrustTunnel", "type": "trusttunnel", "server": domain,
                  "port": port, "username": user, "password": pw, "sni": domain,
                  "skip-cert-verify": insecure, "udp": True}

    elif kind == "http":
        user = (form.get("http_user") or "user").strip()
        pw = (form.get("http_pass") or "").strip() or secrets.token_urlsafe(14)
        use_tls = form.get("http_tls") == "1"
        listener = {**base, "type": "http", "users": [{"username": user, "password": pw}]}
        if use_tls:
            listener["certificate"] = CERT
            listener["private-key"] = KEY
        client = {"name": f"{label}|Clash|HTTP", "type": "http",
                  "server": domain if use_tls else ip, "port": port,
                  "username": user, "password": pw, "tls": use_tls, "udp": True}
        if use_tls:
            client["sni"] = domain
            client["skip-cert-verify"] = insecure

    elif kind == "socks":
        user = (form.get("socks_user") or "user").strip()
        pw = (form.get("socks_pass") or "").strip() or secrets.token_urlsafe(14)
        use_tls = form.get("socks_tls") == "1"
        listener = {**base, "type": "socks", "udp": True, "users": [{"username": user, "password": pw}]}
        if use_tls:
            listener["certificate"] = CERT
            listener["private-key"] = KEY
        client = {"name": f"{label}|Clash|SOCKS5", "type": "socks5",
                  "server": domain if use_tls else ip, "port": port,
                  "username": user, "password": pw, "tls": use_tls, "udp": True}
        if use_tls:
            client["skip-cert-verify"] = insecure

    elif kind == "vmess":
        uid = str(uuidlib.uuid4())
        net = (form.get("vmess_net") or "ws").strip()
        if net not in ("ws", "tcp", "grpc"):
            net = "ws"
        use_tls = form.get("vmess_tls", "1") == "1"
        raw_path = (form.get("vmess_path") or "").strip()
        path = raw_path if raw_path else ("/" + secrets.token_hex(4))
        if not path.startswith("/"):
            path = "/" + path
        listener = {**base, "type": "vmess", "udp": True,
                    "users": [{"username": "user", "uuid": uid, "alterId": 0}]}
        if net == "ws":
            listener["ws-path"] = path
        elif net == "grpc":
            listener["grpc-service-name"] = path.lstrip("/")
        if use_tls:
            listener["certificate"] = CERT
            listener["private-key"] = KEY
        srv = domain if use_tls else ip
        client = {"name": f"{label}|Clash|VMess", "type": "vmess", "server": srv, "port": port,
                  "uuid": uid, "alterId": 0, "cipher": "auto", "tls": use_tls, "udp": True}
        if use_tls:
            client["servername"] = domain
            client["skip-cert-verify"] = insecure
            client["client-fingerprint"] = "chrome"
        if net == "ws":
            client["network"] = "ws"
            client["ws-opts"] = {"path": path, "headers": {"Host": srv}}
        elif net == "grpc":
            client["network"] = "grpc"
            client["grpc-opts"] = {"grpc-service-name": path.lstrip("/")}

    elif kind == "vless":
        uid = str(uuidlib.uuid4())
        net = (form.get("vless_net") or "tcp").strip()
        if net not in ("tcp", "xhttp", "ws", "grpc"):
            net = "tcp"
        use_tls = form.get("vless_tls", "1") == "1"
        use_enc = (form.get("vless_enc") or "x25519").strip() != "none"
        raw_path = (form.get("vless_path") or "").strip()
        path = raw_path if raw_path else ("/" + secrets.token_hex(4))
        if not path.startswith("/"):
            path = "/" + path
        user_entry = {"username": "user", "uuid": uid}
        if net == "tcp":
            user_entry["flow"] = "xtls-rprx-vision"
        listener = {**base, "type": "vless", "udp": True, "users": [user_entry]}
        if use_tls:
            listener["certificate"] = CERT
            listener["private-key"] = KEY
        srv = domain if use_tls else ip
        client = {"name": f"{label}|Clash|VLESS", "type": "vless", "server": srv, "port": port,
                  "uuid": uid, "tls": use_tls, "udp": True}
        if use_tls:
            client["servername"] = domain
            client["skip-cert-verify"] = insecure
            client["client-fingerprint"] = "chrome"
        if net == "tcp":
            client["network"] = "tcp"
            client["flow"] = "xtls-rprx-vision"
        elif net == "xhttp":
            listener["xhttp-config"] = {"path": path, "mode": "auto", "x-padding-bytes": "100-1000"}
            client["network"] = "xhttp"
            client["xhttp-opts"] = {"path": path, "mode": "auto"}
        elif net == "ws":
            listener["ws-path"] = path
            client["network"] = "ws"
            client["ws-opts"] = {"path": path, "headers": {"Host": srv}}
        elif net == "grpc":
            listener["grpc-service-name"] = path.lstrip("/")
            client["network"] = "grpc"
            client["grpc-opts"] = {"grpc-service-name": path.lstrip("/")}
        if use_enc:
            dec, enc = vless_x25519_keypair()
            listener["decryption"] = dec
            client["encryption"] = enc

    elif kind == "anytls":
        user = (form.get("anytls_user") or "user").strip() or "user"
        fp = (form.get("anytls_fp") or "chrome").strip()
        if fp not in ("chrome", "safari", "firefox", "ios"):
            fp = "chrome"
        use_pad = form.get("anytls_padding", "1") == "1"
        pw = secrets.token_urlsafe(18)
        listener = {**base, "type": "anytls", "users": {user: pw},
                    "certificate": CERT, "private-key": KEY}
        if use_pad:
            listener["padding-scheme"] = ANYTLS_DEFAULT_PADDING
        client = {"name": f"{label}|Clash|AnyTLS", "type": "anytls", "server": domain, "port": port,
                  "password": pw, "sni": domain, "client-fingerprint": fp,
                  "skip-cert-verify": insecure, "udp": True}

    elif kind == "mieru":
        user = (form.get("mieru_user") or "user").strip() or "user"
        transport = (form.get("mieru_transport") or "TCP").strip().upper()
        if transport not in ("TCP", "UDP"):
            transport = "TCP"
        pw = secrets.token_urlsafe(16)
        listener = {**base, "type": "mieru", "transport": transport, "users": {user: pw}}
        client = {"name": f"{label}|Clash|Mieru", "type": "mieru", "server": ip, "port": port,
                  "transport": transport, "username": user, "password": pw, "udp": True}

    elif kind == "sudoku":
        aead = (form.get("sudoku_aead") or "chacha20-poly1305").strip()
        if aead not in ("chacha20-poly1305", "aes-128-gcm", "none"):
            aead = "chacha20-poly1305"
        table = (form.get("sudoku_table") or "prefer_ascii").strip()
        if table not in ("prefer_ascii", "prefer_entropy", "up_ascii_down_entropy", "up_entropy_down_ascii"):
            table = "prefer_ascii"
        pure_dl = form.get("sudoku_pure_downlink", "1") == "1"
        priv_k, pub_k = sudoku_keypair()
        listener = {**base, "type": "sudoku", "key": pub_k, "aead-method": aead,
                    "padding-min": 2, "padding-max": 7, "table-type": table,
                    "enable-pure-downlink": pure_dl}
        client = {"name": f"{label}|Clash|Sudoku", "type": "sudoku", "server": ip, "port": port,
                  "key": priv_k, "aead-method": aead, "padding-min": 2, "padding-max": 7,
                  "table-type": table, "enable-pure-downlink": pure_dl, "udp": True}

    elif kind == "tuic":
        uid = str(uuidlib.uuid4())
        pw = secrets.token_urlsafe(18)
        cc = (form.get("tuic_cc") or "bbr").strip()
        if cc not in ("bbr", "cubic", "new_reno"):
            cc = "bbr"
        udp_mode = (form.get("tuic_udp_mode") or "native").strip()
        if udp_mode not in ("native", "quic"):
            udp_mode = "native"
        listener = {**base, "type": "tuic", "users": {uid: pw},
                    "certificate": CERT, "private-key": KEY,
                    "congestion-controller": cc, "alpn": ["h3"]}
        client = {"name": f"{label}|Clash|TUICv5", "type": "tuic", "server": domain, "port": port,
                  "uuid": uid, "password": pw, "sni": domain, "alpn": ["h3"],
                  "congestion-controller": cc, "udp-relay-mode": udp_mode,
                  "reduce-rtt": True, "skip-cert-verify": insecure, "udp": True}

    else:  # shadowquic
        user = (form.get("sq_user") or "user").strip() or "user"
        jls_addr = (form.get("sq_jls") or "www.microsoft.com:443").strip()
        if ":" not in jls_addr:
            jls_addr += ":443"
        jls_host = jls_addr.rsplit(":", 1)[0]
        cc = (form.get("sq_cc") or "bbr").strip()
        if cc not in ("bbr", "cubic", "new_reno"):
            cc = "bbr"
        zero_rtt = form.get("sq_zero_rtt", "1") == "1"
        pw = secrets.token_urlsafe(18)
        listener = {**base, "type": "shadowquic",
                    "users": [{"username": user, "password": pw}],
                    "jls-upstream": {"addr": jls_addr},
                    "congestion-controller": cc, "zero-rtt": zero_rtt,
                    "quic-version-probe": True, "max-idle-time": 30000,
                    "disable-mtu-discovery": False}
        client = {"name": f"{label}|Clash|ShadowQUIC", "type": "shadowquic", "server": ip, "port": port,
                  "username": user, "password": pw, "sni": jls_host, "alpn": ["h3"],
                  "congestion-controller": cc, "zero-rtt": zero_rtt, "udp": True}

    return {"id": secrets.token_hex(6), "kind": kind, "port": port, "name": name,
            "created": int(time.time()), "listener": listener, "client": client}


def render_nodes_tsv(nodes: list) -> str:
    out = []
    for n in nodes:
        dec = n.get("dec", "")
        enc = n.get("enc", "")
        if dec or enc:
            out.append(f"{n['name']}\t{n['port']}\t{n['uuid']}\t{n['priv']}\t{n['pub']}\t{n['sid']}\t{n['sni']}\t{dec}\t{enc}\n")
        else:
            out.append(f"{n['name']}\t{n['port']}\t{n['uuid']}\t{n['priv']}\t{n['pub']}\t{n['sid']}\t{n['sni']}\n")
    return "".join(out)


def render_reality(nodes: list) -> str:
    out = []
    for n in nodes:
        dec_line = f"    decryption: {n['dec']}\n" if n.get("dec") else ""
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
            f"{dec_line}"
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
    return "".join("  - " + json.dumps(i["listener"], ensure_ascii=False) + "\n" for i in inbounds)


def assemble_config() -> str:
    """Same logic as core.sh assemble_config: custom_config.yaml if active, else template."""
    if is_custom_config_mode():
        with open(CUSTOM_CONF) as f:
            return f.read()
    ctrl = ""
    try:
        with open(FRAG_CONTROLLER) as f:
            ctrl = f.read()
    except FileNotFoundError:
        env = read_env()
        if env.get("MODE") == "auto-cert" and env.get("MIHOMO_SECRET"):
            ctrl = render_controller_fragment(env)

    providers_frag = ""
    try:
        with open(FRAG_PROVIDERS) as f:
            providers_frag = f.read()
    except FileNotFoundError:
        pass
    providers_lines = [l for l in providers_frag.splitlines() if l.strip()]
    providers_block = ("proxy-providers:\n" + "\n".join(providers_lines) + "\n") if providers_lines else ""

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
    tpl_path = resolve_template_path("resources/server.yaml.tpl")
    with open(tpl_path) as f:
        for line in f:
            s = line.rstrip("\n")
            if s == "@@CONTROLLER@@":
                out.append(ctrl)
            elif s == "@@PROXY_PROVIDERS@@":
                if providers_block:
                    out.append(providers_block)
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
        for cert_src in (CS_ROOT + "/certs", ROOT + "/etc/mihomo/certs"):
            if os.path.isdir(cert_src):
                try:
                    os.symlink(cert_src, os.path.join(d, "certs"))
                except OSError:
                    pass
                break
        if os.path.isdir(CS_ROOT):
            for entry in os.listdir(CS_ROOT):
                if entry in ("ui", "certs", "config.yaml", "custom_config.yaml", "panel.json", "clashserver.env"):
                    continue
                src_p = os.path.join(CS_ROOT, entry)
                dst_p = os.path.join(d, entry)
                if (entry in ("ruleset", "zerotier", "tailscale")
                        or entry.endswith((".mmdb", ".dat", ".yaml", ".yml", ".mrs"))):
                    if not os.path.exists(dst_p):
                        try:
                            os.symlink(src_p, dst_p)
                        except OSError:
                            pass
        for mmdb in (CS_ROOT + "/country.mmdb", ROOT + "/var/lib/mihomo/country.mmdb"):
            if os.path.isfile(mmdb) and not os.path.exists(os.path.join(d, "country.mmdb")):
                try:
                    os.symlink(mmdb, os.path.join(d, "country.mmdb"))
                except OSError:
                    pass
                break
        safe = f"{CS_ROOT}:/etc/clashserve:/etc/mihomo"
        test_path = path
        if ROOT and os.path.isfile(path):
            with open(path) as fp:
                txt = fp.read()
            if "/etc/clashserve/certs/" in txt and not os.path.isdir("/etc/clashserve/certs"):
                test_path = os.path.join(d, "test_config.yaml")
                with open(test_path, "w") as fp:
                    fp.write(txt.replace("/etc/clashserve/certs/", CS_ROOT + "/certs/"))
        env = dict(os.environ, SAFE_PATHS=safe)
        rc, out = run([resolve_mihomo_bin(), "-t", "-d", d, "-f", test_path], env=env, timeout=90)
        if rc == 0 and os.path.isdir(CS_ROOT):
            for entry in os.listdir(d):
                if entry in ("ui", "certs", "test_config.yaml"):
                    continue
                src_p = os.path.join(d, entry)
                dst_p = os.path.join(CS_ROOT, entry)
                if os.path.islink(src_p) or os.path.exists(dst_p):
                    continue
                try:
                    shutil.move(src_p, dst_p)
                except Exception:
                    pass
        return rc, out


def ufw_specs_for_node(kind: str, port: int) -> set:
    p = int(port)
    if kind in ("vless-reality", "http"):
        return {f"{p}/tcp"}
    if kind in ("hysteria2", "tuic", "shadowquic"):
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
    """When ufw or firewalld is active, allow newly added node ports and delete removed node ports (including UDP)."""
    env = read_env()
    cport = get_controller_port(env)
    protected = {"80/tcp", f"{env.get('PANEL_PORT') or 0}/tcp", f"{cport}/tcp"}
    rc, out = run([UFW_BIN, "status"])
    if rc == 0 and "Status: active" in out:
        for spec in sorted(new_specs - old_specs):
            run([UFW_BIN, "allow", spec])
        for spec in sorted((old_specs - new_specs) - protected):
            run([UFW_BIN, "delete", "allow", spec])
        return
    rc, _ = run([FIREWALL_CMD_BIN, "--state"])
    if rc == 0:
        changed = False
        for spec in sorted(new_specs - old_specs):
            run([FIREWALL_CMD_BIN, "--permanent", f"--add-port={spec}"])
            changed = True
        for spec in sorted((old_specs - new_specs) - protected):
            run([FIREWALL_CMD_BIN, "--permanent", f"--remove-port={spec}"])
            changed = True
        if changed:
            run([FIREWALL_CMD_BIN, "--reload"])


def sync_client_files():
    """Keep /etc/clashserve/client/{mihomo-client,proxies}.yaml in sync with current nodes and inbounds."""
    try:
        env = read_env()
        proxies = [reality_client(n, env) for n in read_nodes()] + [i["client"] for i in load_inbounds()]
        os.makedirs(CLIENT_DIR, mode=0o700, exist_ok=True)
        atomic_write(CLIENT_DIR + "/mihomo-client.yaml", render_subscription(env), 0o600)
        p_body = "".join("  - " + json.dumps(p, ensure_ascii=False) + "\n" for p in proxies) if proxies else "  []\n"
        atomic_write(CLIENT_DIR + "/proxies.yaml", "proxies:\n" + p_body, 0o600)
    except Exception as e:
        sys.stderr.write(f"sync_client_files warning: {e}\n")


def replace_top_level_yaml_section(raw_yaml: str, section_key: str, new_block: str) -> str:
    """Replace or append a top-level YAML section in raw_yaml."""
    lines = raw_yaml.splitlines()
    out = []
    in_sec = False
    replaced = False
    for line in lines:
        cleaned = strip_yaml_comment(line.expandtabs(2))
        stripped = cleaned.lstrip(" ")
        indent = len(cleaned) - len(stripped)
        if not in_sec:
            if stripped and indent == 0:
                k, sep, _ = split_kv(stripped)
                if sep and k == section_key:
                    in_sec = True
                    replaced = True
                    if new_block.strip():
                        out.append(new_block.rstrip("\n"))
                    continue
            out.append(line)
        else:
            if stripped and indent == 0 and not (stripped == "-" or stripped.startswith("- ")):
                in_sec = False
                out.append(line)
    if not replaced and new_block.strip():
        if out and out[-1].strip():
            out.append("")
        out.append(new_block.rstrip("\n"))
    return "\n".join(out) + "\n"


def _sync_custom_conf_listeners(nodes: list, inbounds: list):
    """When in custom config mode, keep CUSTOM_CONF's `listeners:` block in sync with panel edits."""
    if not is_custom_config_mode():
        return
    try:
        with open(CUSTOM_CONF) as f:
            raw = f.read()
        l_body = render_reality(nodes) + dump_yaml_proxies([i["listener"] for i in inbounds])
        new_block = ("listeners:\n" + l_body) if l_body.strip() else "listeners: []\n"
        updated = replace_top_level_yaml_section(raw, "listeners", new_block)
        atomic_write(CUSTOM_CONF, updated, 0o640)
    except Exception as e:
        sys.stderr.write(f"_sync_custom_conf_listeners warning: {e}\n")


def _sync_custom_conf_proxies(proxies: list):
    if not is_custom_config_mode():
        return
    try:
        with open(CUSTOM_CONF) as f:
            raw = f.read()
        p_body = dump_yaml_proxies(proxies)
        new_block = ("proxies:\n" + p_body) if p_body.strip() else "proxies: []\n"
        updated = replace_top_level_yaml_section(raw, "proxies", new_block)
        atomic_write(CUSTOM_CONF, updated, 0o640)
    except Exception as e:
        sys.stderr.write(f"_sync_custom_conf_proxies warning: {e}\n")


def _sync_custom_conf_providers(providers: dict):
    if not is_custom_config_mode():
        return
    try:
        with open(CUSTOM_CONF) as f:
            raw = f.read()
        pv_body = dump_yaml_providers(providers)
        new_block = ("proxy-providers:\n" + pv_body) if pv_body.strip() else ""
        updated = replace_top_level_yaml_section(raw, "proxy-providers", new_block)
        atomic_write(CUSTOM_CONF, updated, 0o640)
    except Exception as e:
        sys.stderr.write(f"_sync_custom_conf_providers warning: {e}\n")


def wait_mihomo_ports(timeout=2.0):
    """Poll ss for up to ~2s so all expected ports are listening before responding."""
    expected = {int(n["port"]) for n in read_nodes()} | {int(i["port"]) for i in load_inbounds()}
    env = read_env()
    if env.get("MODE") == "auto-cert":
        expected.add(get_controller_port(env))
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
    files = (INBOUNDS, FRAG_EXTRA, CUSTOM_CONF, CONF) if is_custom_config_mode() else (INBOUNDS, FRAG_EXTRA, CONF)
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
        _sync_custom_conf_listeners(cur_nodes, new)
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
    """Update install-time VLESS Reality nodes (nodes.tsv + listeners.reality.yaml + config.yaml), validate, restart."""
    cur_inbs = load_inbounds()
    old_specs = collect_ufw_specs(read_nodes(), cur_inbs)
    files = (NODES_TSV, FRAG_REALITY, CUSTOM_CONF, CONF) if is_custom_config_mode() else (NODES_TSV, FRAG_REALITY, CONF)
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
        _sync_custom_conf_listeners(new_nodes, cur_inbs)
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
    """Write server outbound proxies (proxies.json + proxies.extra.yaml + config.yaml), validate, restart."""
    files = (PROXIES_JSON, FRAG_PROXIES, CUSTOM_CONF, CONF) if is_custom_config_mode() else (PROXIES_JSON, FRAG_PROXIES, CONF)
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
        _sync_custom_conf_proxies(new_proxies)
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


def apply_proxy_providers(new_providers: dict):
    """Write server proxy-providers (providers.json + providers.extra.yaml + config.yaml), validate, restart."""
    files = (PROVIDERS_JSON, FRAG_PROVIDERS, CUSTOM_CONF, CONF) if is_custom_config_mode() else (PROVIDERS_JSON, FRAG_PROVIDERS, CONF)
    backup = {}
    for p in files:
        try:
            with open(p) as f:
                backup[p] = f.read()
        except FileNotFoundError:
            backup[p] = None
    try:
        atomic_write(PROVIDERS_JSON, json.dumps(new_providers, indent=2, ensure_ascii=False), 0o600)
        atomic_write(FRAG_PROVIDERS, dump_yaml_providers(new_providers), 0o640)
        _sync_custom_conf_providers(new_providers)
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
                atomic_write(p, data, 0o600 if p == PROVIDERS_JSON else 0o640)
        run([SYSTEMCTL, "restart", "mihomo"])
        raise
    wait_mihomo_ports()


def apply_custom_config(raw_yaml: str):
    """Validate and apply user-supplied full server config, syncing listeners, outbounds, and client subscription."""
    s = (raw_yaml or "").strip()
    if not s:
        raise ValueError("请输入完整的 mihomo 服务端配置内容")
    s += "\n"
    was_custom = is_custom_config_mode()
    old_specs = collect_ufw_specs(read_nodes(), load_inbounds())
    files = (CUSTOM_CONF, CONF, NODES_TSV, INBOUNDS, PROXIES_JSON, PROVIDERS_JSON)
    backup = {}
    for p in files:
        try:
            with open(p) as f:
                backup[p] = f.read()
        except FileNotFoundError:
            backup[p] = None
    try:
        if not was_custom:
            for p in (NODES_TSV, INBOUNDS, PROXIES_JSON, PROVIDERS_JSON):
                if backup[p] is not None:
                    atomic_write(p + ".tplbak", backup[p], 0o600)
        atomic_write(CUSTOM_CONF, s, 0o640)
        atomic_write(CONF, s, 0o640)
        rc, out = validate_config()
        if rc != 0:
            raise RuntimeError("配置校验失败（mihomo -t）：" + out[-800:])
        sync_env_from_custom_config(s)
        env = read_env()
        new_inbounds, new_proxies, new_providers = parse_custom_config_state(s, env)
        atomic_write(NODES_TSV, "", 0o640)
        atomic_write(INBOUNDS, json.dumps(new_inbounds, indent=2, ensure_ascii=False), 0o600)
        atomic_write(PROXIES_JSON, json.dumps(new_proxies, indent=2, ensure_ascii=False), 0o600)
        atomic_write(PROVIDERS_JSON, json.dumps(new_providers, indent=2, ensure_ascii=False), 0o600)
        rc, out = run([SYSTEMCTL, "restart", "mihomo"])
        if rc != 0:
            raise RuntimeError("重启失败：" + out[-800:])
    except Exception:
        for p, data in backup.items():
            if data is None:
                if os.path.exists(p):
                    os.remove(p)
            else:
                atomic_write(p, data, 0o600 if p.endswith(".json") else 0o640)
        run([SYSTEMCTL, "restart", "mihomo"])
        raise
    sync_client_files()
    sync_ufw(old_specs, collect_ufw_specs([], new_inbounds))
    wait_mihomo_ports()


def reset_to_template_config():
    """Exit custom config mode and re-assemble server config from standard template + fragments."""
    old_specs = collect_ufw_specs(read_nodes(), load_inbounds())
    files = (CUSTOM_CONF, CONF, NODES_TSV, INBOUNDS, PROXIES_JSON, PROVIDERS_JSON)
    backup = {}
    for p in files:
        try:
            with open(p) as f:
                backup[p] = f.read()
        except FileNotFoundError:
            backup[p] = None
    try:
        if os.path.exists(CUSTOM_CONF):
            os.remove(CUSTOM_CONF)
        for p in (NODES_TSV, INBOUNDS, PROXIES_JSON, PROVIDERS_JSON):
            bak_p = p + ".tplbak"
            if os.path.isfile(bak_p):
                with open(bak_p) as f:
                    atomic_write(p, f.read(), 0o600 if p.endswith(".json") else 0o640)
        atomic_write(FRAG_REALITY, render_reality(read_nodes()), 0o640)
        atomic_write(FRAG_EXTRA, render_extra(load_inbounds()), 0o640)
        atomic_write(FRAG_PROXIES, dump_yaml_proxies(load_server_proxies()), 0o640)
        atomic_write(FRAG_PROVIDERS, dump_yaml_providers(load_proxy_providers()), 0o640)
        env = read_env()
        atomic_write(FRAG_CONTROLLER, render_controller_fragment(env), 0o640)
        atomic_write(CONF, assemble_config(), 0o640)
        rc, out = validate_config()
        if rc != 0:
            raise RuntimeError("配置校验失败（mihomo -t）：" + out[-800:])
        rc, out = run([SYSTEMCTL, "restart", "mihomo"])
        if rc != 0:
            raise RuntimeError("重启失败：" + out[-800:])
        for p in (NODES_TSV, INBOUNDS, PROXIES_JSON, PROVIDERS_JSON):
            bak_p = p + ".tplbak"
            if os.path.exists(bak_p):
                os.remove(bak_p)
    except Exception:
        for p, data in backup.items():
            if data is None:
                if os.path.exists(p):
                    os.remove(p)
            else:
                atomic_write(p, data, 0o600 if p.endswith(".json") else 0o640)
        run([SYSTEMCTL, "restart", "mihomo"])
        raise
    sync_client_files()
    sync_ufw(old_specs, collect_ufw_specs(read_nodes(), load_inbounds()))
    wait_mihomo_ports()


def reality_client(n: dict, env: dict) -> dict:
    """Client proxy for an install-time Reality node (same fields as core.sh proxy_line)."""
    d = {
        "name": f"{env.get('VPS_NAME', 'vps')}-{n['name']}|Clash|Reality", "type": "vless",
        "server": env.get("SERVER_IP", ""), "port": n["port"], "uuid": n["uuid"], "tls": True,
        "flow": "xtls-rprx-vision", "client-fingerprint": "safari", "skip-cert-verify": False,
    }
    if n.get("enc"):
        d["encryption"] = n["enc"]
    d.update({
        "reality-opts": {"public-key": n["pub"], "short-id": n["sid"]}, "network": "tcp",
        "udp": True, "servername": n["sni"],
    })
    return d


def render_subscription(env: dict) -> str:
    """Full mihomo client config: install Reality nodes + panel/custom inbounds, via client.yaml.tpl."""
    proxies = [reality_client(n, env) for n in read_nodes()] + [i["client"] for i in load_inbounds()]
    p_lines = "\n".join("  - " + json.dumps(p, ensure_ascii=False) for p in proxies) if proxies else "  []"
    n_lines = "\n".join("      - " + json.dumps(p["name"], ensure_ascii=False) for p in proxies) if proxies else '      - "DIRECT"'
    out = []
    tpl_path = resolve_template_path("resources/client.yaml.tpl")
    with open(tpl_path) as f:
        for line in f:
            key = line.rstrip("\n")
            if key == "@@PROXIES@@":
                out.append(p_lines + "\n")
            elif key == "@@PROXY_NAMES@@":
                out.append(n_lines + "\n")
            else:
                out.append(line)
    return "".join(out)


def mihomo_status() -> dict:
    rc, active = run([SYSTEMCTL, "is-active", "mihomo"])
    _, show = run([SYSTEMCTL, "show", "mihomo", "-p", "ActiveEnterTimestamp,MainPID,NRestarts"])
    props = dict(l.split("=", 1) for l in show.splitlines() if "=" in l)
    _, ver = run([resolve_mihomo_bin(), "-v"])
    _, ss = run(["ss", "-Hltun"])
    listening = {int(m) for m in re.findall(r":(\d+)\s", ss + " ")}
    cert = {}
    if certs_present():
        crt_file = (ROOT + CERT) if os.path.isfile(ROOT + CERT) else (ROOT + "/etc/mihomo/certs/fullchain.pem")
        _, c = run(["openssl", "x509", "-noout", "-enddate", "-issuer", "-in", crt_file])
        cert = {"info": c}
    return {"active": active.strip() or "unknown", "since": props.get("ActiveEnterTimestamp", ""),
            "pid": props.get("MainPID", ""), "restarts": props.get("NRestarts", ""),
            "version": ver.splitlines()[0] if ver else "", "listening": sorted(listening),
            "cert": cert}


# ---------------------------------------------------------------- Rebuilt Console UI & HTTP
CSS = """
:root{
  --bg:#f1f5f9;--card:#ffffff;--surface:#f8fafc;--text:#0f172a;--muted:#475569;--faint:#94a3b8;
  --line:#e2e8f0;--line-strong:#cbd5e1;
  --primary:#4f46e5;--primary-h:#4338ca;--primary-soft:#eef2ff;--primary-ring:rgba(79,70,229,.18);
  --ok:#15803d;--ok-bg:#dcfce7;--bad:#b91c1c;--bad-bg:#fee2e2;--warn:#b45309;--warn-bg:#fef3c7;
  --radius:14px;--shadow:0 1px 3px rgba(15,23,42,.05),0 6px 20px rgba(15,23,42,.04)
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.6 -apple-system,BlinkMacSystemFont,"PingFang SC",
"Hiragino Sans GB","Microsoft YaHei","Noto Sans CJK SC","Segoe UI",sans-serif;-webkit-font-smoothing:antialiased}
a{color:var(--primary);text-decoration:none}
.topbar{background:rgba(15,23,42,.95);backdrop-filter:blur(10px);color:#f8fafc;border-bottom:1px solid rgba(255,255,255,.08);
position:sticky;top:0;z-index:30}
.topbar .in{max-width:1220px;margin:0 auto;padding:12px 24px;display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.logo{width:36px;height:36px;border-radius:10px;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;
display:flex;align-items:center;justify-content:center;font-weight:800;font-size:17px;flex:none;
box-shadow:0 4px 12px rgba(99,102,241,.45)}
.brand{display:flex;flex-direction:column;line-height:1.25}
.brand b{font-size:16px;letter-spacing:.2px;display:flex;align-items:center;gap:8px;color:#fff}
.brand small{color:#94a3b8;font-size:12px}
.chip{display:inline-flex;align-items:center;gap:6px;background:rgba(255,255,255,.1);color:#e2e8f0;border-radius:999px;
padding:4px 12px;font-size:12px;border:1px solid rgba(255,255,255,.12)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--faint);display:inline-block}
.dot.ok{background:#22c55e;box-shadow:0 0 0 3px rgba(34,197,94,.25)}
.dot.bad{background:#ef4444;box-shadow:0 0 0 3px rgba(239,68,68,.25)}
.dot.warn{background:#f59e0b;box-shadow:0 0 0 3px rgba(245,158,11,.25)}
.spacer{flex:1}
main{max-width:1220px;margin:0 auto;padding:24px 24px 56px}
.hero-bar{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);
padding:18px 22px;margin-bottom:18px;display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap}
.hero-meta{display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.hero-meta h1{font-size:19px;margin:0;font-weight:700;display:flex;align-items:center;gap:8px}
.hero-kv{display:flex;gap:16px;flex-wrap:wrap;color:var(--muted);font-size:13px}
.hero-kv span b{color:var(--text);font-weight:600}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px;margin-bottom:18px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);
padding:15px 18px;position:relative;overflow:hidden}
.stat::before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--primary)}
.stat .lb{color:var(--muted);font-size:12px;display:flex;align-items:center;gap:6px;font-weight:500}
.stat .val{font-size:22px;font-weight:750;margin-top:4px;line-height:1.25;word-break:break-all}
.stat .val small{font-size:13px;font-weight:500;color:var(--muted);margin-left:4px}
.stat .sub{font-size:12px;color:var(--faint);margin-top:3px}
.nav-tabs{display:flex;gap:8px;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:6px;
margin-bottom:20px;box-shadow:var(--shadow);flex-wrap:wrap;align-items:center}
.tab-btn{border:0;background:transparent;color:var(--muted);padding:9px 16px;border-radius:9px;font:inherit;
font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:7px;transition:all .15s}
.tab-btn:hover{color:var(--text);background:var(--surface)}
.tab-btn.active{background:var(--primary);color:#fff;box-shadow:0 2px 6px rgba(79,70,229,.3)}
.tab-pane{display:none}
.tab-pane.active,body.show-all .tab-pane{display:block}
.split-2{display:grid;grid-template-columns:1.25fr 1fr;gap:20px;align-items:start}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);
padding:22px 24px;margin-bottom:20px}
.card-h{display:flex;align-items:center;gap:10px;margin:0 0 16px;flex-wrap:wrap}
.card-h h2{font-size:16px;margin:0;font-weight:700}.card-h .desc{color:var(--muted);font-size:12.5px;width:100%;margin-top:-4px}
.pill{display:inline-flex;align-items:center;gap:5px;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.pill.ok{background:var(--ok-bg);color:var(--ok)}.pill.bad{background:var(--bad-bg);color:var(--bad)}
.pill.warn{background:var(--warn-bg);color:var(--warn)}.pill.tag{background:var(--primary-soft);color:var(--primary-h)}
.pill.gray{background:#f1f5f9;color:#475569}
.k-vless-reality,.k-vless{background:#ede9fe;color:#6d28d9}.k-shadowsocks{background:#fce7f3;color:#be185d}
.k-hysteria2,.k-hysteria2-realm,.k-tuic{background:#e0f2fe;color:#0369a1}.k-snell,.k-mieru{background:#dcfce7;color:#15803d}
.k-trusttunnel,.k-anytls{background:#ffedd5;color:#c2410c}.k-vmess{background:#fef3c7;color:#b45309}
.k-sudoku,.k-shadowquic{background:#e0e7ff;color:#3730a3}.k-http,.k-socks,.k-mixed{background:#f1f5f9;color:#334155}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;border:1px solid var(--line-strong);background:#fff;
color:var(--text);border-radius:9px;padding:8px 15px;font:inherit;font-weight:550;cursor:pointer;
transition:background .15s,border-color .15s,box-shadow .15s;white-space:nowrap}
.btn:hover{background:var(--surface);border-color:#94a3b8}
.btn.primary{background:var(--primary);border-color:var(--primary);color:#fff;box-shadow:0 1px 2px rgba(79,70,229,.3)}
.btn.primary:hover{background:var(--primary-h)}
.btn.warn{background:#fffbeb;border-color:#fde68a;color:#92400e}.btn.warn:hover{background:#fef3c7}
.btn.danger{color:var(--bad);border-color:#fecaca}.btn.danger:hover{background:var(--bad-bg);border-color:#fca5a5}
.btn.ghost{border-color:rgba(255,255,255,.18);background:rgba(255,255,255,.08);color:#e2e8f0}
.btn.ghost:hover{background:rgba(255,255,255,.16);color:#fff}
.btn.sm{padding:5px 12px;font-size:12px;border-radius:8px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
form.inline{display:inline}
.flash{display:flex;gap:10px;align-items:flex-start;border-radius:12px;padding:12px 16px;margin-bottom:18px;
word-break:break-all;border:1px solid transparent;font-weight:500}
.flash.ok{background:#f0fdf4;color:#14532d;border-color:#bbf7d0}.flash.bad{background:#fef2f2;color:#7f1d1d;border-color:#fecaca}
.list{border:1px solid var(--line);border-radius:12px;overflow:hidden;background:#fff}
.item{padding:14px 16px;border-bottom:1px solid var(--line)}.item:last-child{border-bottom:0}
.item:hover{background:var(--surface)}
.item .top{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.item .nm{font-weight:650;min-width:0;word-break:break-all}
.item .meta{color:var(--muted);font-size:12px;display:flex;gap:14px;flex-wrap:wrap;margin-top:3px}
.item .acts{margin-left:auto;display:flex;gap:8px;align-items:center}
.mono,code,pre,textarea{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
code{background:#f1f5f9;border-radius:5px;padding:2px 6px;font-size:12px;white-space:nowrap;color:#334155}
pre{background:#0f172a;color:#e2e8f0;border-radius:10px;padding:14px;font-size:12px;white-space:pre-wrap;
word-break:break-all;margin:10px 0 0;line-height:1.55}
details>summary{cursor:pointer;color:var(--primary);font-size:12px;font-weight:500;list-style:none;display:inline-flex;
align-items:center;gap:4px;user-select:none;margin-top:6px}
details>summary::-webkit-details-marker{display:none}
details>summary::before{content:"▸";transition:transform .15s}details[open]>summary::before{transform:rotate(90deg)}
.muted{color:var(--muted)}.empty{color:var(--muted);text-align:center;padding:32px 16px}
.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(195px,1fr));gap:14px;margin-bottom:16px}
label{display:block;font-size:12.5px;color:#334155;font-weight:600;margin-bottom:6px}
input,select{width:100%;height:38px;padding:0 12px;border:1px solid var(--line-strong);border-radius:9px;font:inherit;
background:#fff;color:var(--text)}
textarea{width:100%;min-height:115px;padding:10px 12px;border:1px solid var(--line-strong);border-radius:9px;font-size:12px;
line-height:1.55;background:#fff;color:var(--text);resize:vertical}
textarea.code-ed{background:#0f172a;color:#e2e8f0;border-color:#334155;min-height:320px;font-size:12.5px}
input::placeholder,textarea::placeholder{color:var(--faint)}
input:focus,select:focus,textarea:focus{outline:0;border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-ring)}
.hint{font-size:12px;color:var(--muted);margin:12px 0 0}
.notice{font-size:13px;border-radius:10px;padding:12px 15px;margin:12px 0;background:var(--warn-bg);color:#78350f;border:1px solid #fde68a}
.notice b{color:#92400e}
.sub-box{display:flex;gap:8px;align-items:stretch;flex-wrap:wrap}
.sub-box .url{flex:1;min-width:220px;background:var(--surface);border:1px solid var(--line);border-radius:9px;padding:9px 12px;
font-size:12px;word-break:break-all;display:flex;align-items:center}
.sub-sec{border-top:1px solid var(--line);margin-top:20px;padding-top:20px}
footer{max-width:1220px;margin:0 auto;padding:0 24px 32px;color:var(--faint);font-size:12px;text-align:center}
.login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;
background:radial-gradient(1200px 600px at 10% -10%,#e0e7ff 0,transparent 60%),
radial-gradient(900px 500px at 110% 110%,#ede9fe 0,transparent 60%),var(--bg)}
.login{width:100%;max-width:410px}
.login .card{padding:34px 32px;margin:0}
.login .head{display:flex;align-items:center;gap:12px;margin-bottom:22px}
.login h1{font-size:20px;margin:0;display:flex;align-items:center;gap:8px}.login p.sub{color:var(--muted);margin:0;font-size:13px}
.login .field{margin-bottom:16px}.login .btn{width:100%;height:40px;margin-top:6px}
.err{background:#fef2f2;border:1px solid #fecaca;color:#7f1d1d;border-radius:10px;padding:10px 12px;margin-bottom:16px}
.modal-backdrop{position:fixed;inset:0;background:rgba(15,23,42,.55);backdrop-filter:blur(4px);z-index:100;
display:none;align-items:center;justify-content:center;padding:18px}
.modal-backdrop.open{display:flex}
.modal-box{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);
box-shadow:0 20px 50px rgba(15,23,42,.25);width:100%;max-width:620px;max-height:90vh;display:flex;flex-direction:column;overflow:hidden}
.modal-h{padding:16px 20px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:12px}
.modal-h h3{margin:0;font-size:15px;font-weight:700;word-break:break-all}
.modal-b{padding:18px 20px;overflow-y:auto;display:flex;flex-direction:column;gap:16px}
.modal-sec{display:flex;flex-direction:column;gap:8px}
.modal-sec-h{display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap}
.modal-sec-h label{margin:0;font-size:12.5px;color:#334155;font-weight:650}
textarea.node-ed-single{background:#0f172a;color:#e2e8f0;border-color:#334155;min-height:76px;font-size:12px}
textarea.node-ed-multi{background:#0f172a;color:#e2e8f0;border-color:#334155;min-height:190px;font-size:12px}
.modal-f{padding:12px 20px;border-top:1px solid var(--line);background:var(--surface);display:flex;justify-content:flex-end;gap:10px;flex-wrap:wrap}
@media (max-width:920px){.split-2{grid-template-columns:1fr}}
@media (max-width:640px){.hide-sm{display:none}.stats{grid-template-columns:repeat(2,1fr);gap:10px}.stat .val{font-size:18px}
main{padding:16px 12px 40px}.topbar .in{padding:10px 14px}.card{padding:16px}.item .acts{margin-left:0;width:100%}}
"""

JS = """
function syncKind(){var k=document.getElementById('kind');if(!k)return;var v=k.value;
document.querySelectorAll('[data-kind]').forEach(function(e){
var list=(e.dataset.kind||'').split(',');
e.style.display=list.indexOf(v)>=0?'':'none';
})}
function switchTab(id,btn){
document.body.classList.remove('show-all');
var allBtn=document.getElementById('toggle-all-btn');if(allBtn)allBtn.textContent='展开全部视图';
document.querySelectorAll('.tab-pane').forEach(function(p){p.classList.toggle('active',p.id==='tab-'+id)});
document.querySelectorAll('.tab-btn[data-tab]').forEach(function(b){b.classList.toggle('active',b.dataset.tab===id)});
try{sessionStorage.setItem('cs_tab',id)}catch(e){}
}
function toggleAllTabs(btn){
var on=document.body.classList.toggle('show-all');
btn.textContent=on?'返回分栏视图':'展开全部视图';
}
function copyText(id,btn){var el=document.getElementById(id);if(!el)return;
var t=el.value!==undefined&&el.tagName==='TEXTAREA'?el.value:el.textContent;var o=btn.textContent;
function done(){btn.textContent='已复制';setTimeout(function(){btn.textContent=o},1500)}
if(navigator.clipboard){navigator.clipboard.writeText(t).then(done,function(){fallback()})}else{fallback()}
function fallback(){var a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();
try{document.execCommand('copy');done()}catch(e){}document.body.removeChild(a)}}
function loadFileToTextarea(inp,targetId){var f=inp.files&&inp.files[0];if(!f)return;
var r=new FileReader();r.onload=function(){var ta=document.getElementById(targetId);if(ta)ta.value=r.result||''};
r.readAsText(f)}
function loadProxyFile(inp){loadFileToTextarea(inp,'proxies-raw')}
function openNodeModal(btn){
var m=document.getElementById('node-modal-backdrop');if(!m)return;
var t=document.getElementById('node-modal-title');
var s=document.getElementById('modal-node-single');
var y=document.getElementById('modal-node-multi');
if(t)t.textContent='查看节点配置 · '+(btn.dataset.title||'');
if(s)s.value=btn.dataset.single||'';
if(y)y.value=btn.dataset.multi||'';
m.classList.add('open');
}
function closeNodeModal(){
var m=document.getElementById('node-modal-backdrop');if(m)m.classList.remove('open');
}
function autoFixCertPaths(){
var ta=document.getElementById('custom-config-raw');if(!ta)return;
var certPath='/etc/clashserve/certs/fullchain.pem';
var keyPath='/etc/clashserve/certs/privkey.pem';
var lines=ta.value.split(/\\r?\\n/);
var inReality=false,realityIndent=0,inProviders=false,provIndent=0,changed=0;
for(var i=0;i<lines.length;i++){
var line=lines[i];
var stripped=line.replace(/^ +/,'');
var indent=line.length-stripped.length;
if(stripped&&stripped.charAt(0)!=='#'){
if(inReality&&indent<=realityIndent)inReality=false;
if(inProviders&&indent<=provIndent)inProviders=false;
if(/^reality-config\\s*:/.test(stripped)){inReality=true;realityIndent=indent;continue}
if(/^proxy-providers\\s*:/.test(stripped)){inProviders=true;provIndent=indent;continue}
if(inProviders&&indent===provIndent+2&&/^default\\s*:\\s*(#.*)?$/.test(stripped)){
lines[i]=line.slice(0,indent)+stripped.replace(/^default(\\s*:)/,'default-sub$1');changed++;continue}
var mc=stripped.match(/^((?:-\\s+)?certificate\\s*:\\s*)([^#\\n]+?)(\\s*(?:#.*)?)$/);
if(mc){
var cv=mc[2].trim().replace(/^['"]|['"]$/g,'');
if(cv!==certPath)changed++;
lines[i]=line.slice(0,indent)+mc[1]+certPath+(mc[3]||'');continue}
if(!inReality){
var mk=stripped.match(/^((?:-\\s+)?private-key\\s*:\\s*)([^#\\n]+?)(\\s*(?:#.*)?)$/);
if(mk){
var kv=mk[2].trim().replace(/^['"]|['"]$/g,'');
if(kv.indexOf('/')>=0||kv.indexOf('.')>=0||/key|pem/i.test(kv)){
if(kv!==keyPath)changed++;
lines[i]=line.slice(0,indent)+mk[1]+keyPath+(mk[3]||'');continue}
}}}
}
ta.value=lines.join('\\n');
showFlash('已自动修正 '+changed+' 处证书路径（统一指向 /etc/clashserve/certs/），请点击「更新 mihomo 服务端配置」保存生效。',true);
}
function showFlash(msg,ok){var box=document.getElementById('flash-box');if(!box)return;
var div=document.createElement('div');div.className='flash '+(ok?'ok':'bad');
var b=document.createElement('b');b.textContent=ok?'✓':'!';
var d=document.createElement('div');d.textContent=msg;
div.appendChild(b);div.appendChild(d);box.innerHTML='';box.appendChild(div)}
function postAjaxForm(url,body,attempt){
var ctrl=window.AbortController?new AbortController():null;
var timer=ctrl?setTimeout(function(){ctrl.abort()},120000):null;
var opts={method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-Requested-With':'fetch','Accept':'application/json'},body:body,credentials:'same-origin',cache:'no-store'};
if(ctrl)opts.signal=ctrl.signal;
return fetch(url,opts).then(function(r){
if(timer)clearTimeout(timer);
return r.text().then(function(txt){
var j=null;
try{j=JSON.parse(txt)}catch(e){j={ok:r.ok,msg:txt||('HTTP '+r.status)}}
return {status:r.status,data:j};
});
}).catch(function(err){
if(timer)clearTimeout(timer);
if(err&&err.name==='AbortError'){
throw new Error('请求超时（120s），服务端可能正在下载规则集或校验配置，请稍后刷新页面查看状态');
}
if((attempt||0)<1){
return new Promise(function(resolve){setTimeout(resolve,350)}).then(function(){return postAjaxForm(url,body,(attempt||0)+1)});
}
throw new Error('网络连接中断或被重置（'+((err&&err.message)||err)+'），请重试或刷新页面');
});
}
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
postAjaxForm(f.action,body,0)
.then(function(res){
var d=res.data||{};
showFlash(d.msg||(d.ok?'操作成功':'操作失败'),!!d.ok);
if(d.stats_html){var sb=document.getElementById('stats-bar');if(sb)sb.outerHTML=d.stats_html}
if(d.inbounds_html){var ic=document.getElementById('inbounds-card');if(ic){ic.outerHTML=d.inbounds_html;bindAjaxForms(document.getElementById('inbounds-card'))}}
if(d.proxies_html){var pc=document.getElementById('proxies-section');if(pc){pc.outerHTML=d.proxies_html;bindAjaxForms(document.getElementById('proxies-section'))}}
if(d.providers_html){var pvc=document.getElementById('providers-section');if(pvc){pvc.outerHTML=d.providers_html;bindAjaxForms(document.getElementById('providers-section'))}}
if(d.server_card_html){var sc=document.getElementById('server-config-card');if(sc){sc.outerHTML=d.server_card_html;bindAjaxForms(document.getElementById('server-config-card'))}}
if(d.custom_cfg_html){var cc=document.getElementById('custom-config-section');if(cc){cc.outerHTML=d.custom_cfg_html;bindAjaxForms(document.getElementById('custom-config-section'))}}
if(d.zb_url){var zbu=document.getElementById('zb-url');if(zbu)zbu.textContent=d.zb_url;var zbo=document.getElementById('zb-open-btn');if(zbo)zbo.href=d.zb_url}
if(d.ok){
var p=f.querySelector('input[name=port]');if(p)p.value='';
var n=f.querySelector('input[name=name]');if(n)n.value='';
var u=f.querySelector('input[name=sub_url]');if(u)u.value='';
var pn=f.querySelector('input[name=provider_name]');if(pn)pn.value='';
var ta=f.querySelector('textarea[name=proxies_raw]');if(ta)ta.value='';
var fi=f.querySelector('input[type=file]');if(fi)fi.value='';
}
})
.catch(function(err){showFlash('请求失败：'+((err&&err.message)||err),false)})
.finally(function(){if(btn){btn.disabled=false;btn.textContent=origTxt}});
});
});
}
document.addEventListener('DOMContentLoaded',function(){var k=document.getElementById('kind');
if(k){k.addEventListener('change',syncKind);syncKind()}
try{var saved=sessionStorage.getItem('cs_tab');if(saved&&document.getElementById('tab-'+saved))switchTab(saved)}catch(e){}
bindAjaxForms(document);
document.addEventListener('keydown',function(ev){if(ev.key==='Escape')closeNodeModal()});
document.querySelectorAll('form[data-busy]:not([data-ajax])').forEach(function(f){f.addEventListener('submit',function(){
var b=f.querySelector('button[type=submit],button:not([type])');if(b){b.disabled=true;b.textContent=f.dataset.busy}})})});
"""

STATE_ZH = {"active": ("运行中", "ok"), "inactive": ("已停止", "bad"), "failed": ("失败", "bad"),
            "activating": ("启动中", "warn"), "deactivating": ("停止中", "warn"),
            "reloading": ("重载中", "warn"), "unknown": ("未知", "bad")}
KIND_ZH = {
    "vless-reality": "VLESS Reality（免证书推荐）",
    "shadowsocks": "Shadowsocks / SS（aes128/256）",
    "hysteria2": "Hysteria2（QUIC / TLS）",
    "snell": "Snell（v4 / v5）",
    "trusttunnel": "TrustTunnel（HTTP2/HTTP3）",
    "vless": "VLESS（TLS / XHTTP / WS / 加密）",
    "vmess": "VMess（WS / TCP / gRPC）",
    "anytls": "AnyTLS（TLS 伪装填充）",
    "tuic": "TUIC v5（QUIC / TLS）",
    "shadowquic": "ShadowQUIC（QUIC + JLS）",
    "mieru": "Mieru（TCP / UDP 混淆）",
    "sudoku": "Sudoku（数独矩阵混淆）",
    "http": "HTTP（标准代理）",
    "socks": "SOCKS5（标准代理）",
    "hysteria2-realm": "Hysteria2 Realm",
    "mixed": "Mixed（HTTP + SOCKS5）",
}


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
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionError, ssl.SSLError, socket.timeout):
            pass

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
            "zb_url": zashboard_url(env),
            "stats_html": self.render_stats_section(st),
            "inbounds_html": self.render_inbounds_section(s, env, st),
            "proxies_html": self.render_proxies_section(s),
            "providers_html": self.render_providers_section(s),
            "server_card_html": self.render_server_config_card(s, env, st),
            "custom_cfg_html": self.render_custom_config_section(s, env),
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
        if n > 8 * 1024 * 1024:
            raise ValueError("请求体过大（超过 8MB 限制）")
        chunks = []
        rem = n
        while rem > 0:
            chunk = self.rfile.read(min(rem, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            rem -= len(chunk)
        raw = b"".join(chunks).decode("utf-8", errors="replace")
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
            st["custom_config_mode"] = is_custom_config_mode()
            st["inbounds"] = [{k: i[k] for k in ("id", "kind", "name", "port")} for i in load_inbounds()]
            st["reality_nodes"] = [{"name": n["name"], "port": n["port"]} for n in read_nodes()]
            st["server_proxies"] = [{"name": p.get("name", ""), "type": p.get("type", ""),
                                     "server": p.get("server", ""), "port": p.get("port", "")}
                                    for p in load_server_proxies()]
            st["proxy_providers"] = list(load_proxy_providers().keys())
            return self.send(200, json.dumps(st), "application/json")
        self.simple(404, "页面不存在", "请检查地址是否正确。")

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            form = self.form()
        except ValueError as e:
            if self.is_ajax():
                return self.send(413, json.dumps({"ok": False, "msg": str(e)}), "application/json; charset=utf-8")
            return self.send(413, str(e), "text/plain; charset=utf-8")
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
        if path == "/providers/add":
            return self.do_add_provider(s, form)
        if path == "/providers/delete":
            return self.do_delete_provider(s, form.get("name", ""))
        if path == "/config/custom":
            return self.do_save_custom_config(s, form)
        if path == "/config/reset-template":
            return self.do_reset_template_config(s)
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
            files = (FRAG_CONTROLLER, CUSTOM_CONF, CONF)
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
                if is_custom_config_mode() and backup[CUSTOM_CONF]:
                    updated = re.sub(r'^(\s*secret\s*:\s*).*$', f'\\1"{new_secret}"', backup[CUSTOM_CONF], flags=re.M)
                    atomic_write(CUSTOM_CONF, updated, 0o640)
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
        self.flash("已重置 Zashboard API 密钥，Zashboard 链接已同步更新并重启生效。")

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

    def do_add_provider(self, s, form):
        url = form.get("sub_url", "")
        name = form.get("provider_name", "")
        with LOCK:
            try:
                cur = load_proxy_providers()
                prov_name, entry = build_proxy_provider(url, name, cur)
                merged = dict(cur)
                merged[prov_name] = entry
                apply_proxy_providers(merged)
            except Exception as e:
                return self.respond_mutation(s, f"导入订阅链接失败：{e}", False)
        return self.respond_mutation(
            s, f"已导入订阅源「{prov_name}」（路径 {entry['path']}）到服务端 proxy-providers:", True)

    def do_delete_provider(self, s, name):
        with LOCK:
            cur = load_proxy_providers()
            if name not in cur:
                return self.respond_mutation(s, "订阅源不存在或已删除", False)
            merged = {k: v for k, v in cur.items() if k != name}
            try:
                apply_proxy_providers(merged)
            except Exception as e:
                return self.respond_mutation(s, f"删除订阅源失败：{e}", False)
        return self.respond_mutation(s, f"已删除订阅源「{name}」", True)

    def do_save_custom_config(self, s, form):
        raw = form.get("custom_config_raw", "")
        auto_fix = form.get("auto_fix_certs") == "1"
        with LOCK:
            try:
                env = read_env()
                if auto_fix:
                    raw, _ = rewrite_cert_paths_in_yaml(raw, env)
                apply_custom_config(raw)
            except Exception as e:
                return self.respond_mutation(s, f"更新自定义服务端配置失败：{e}", False)
        return self.respond_mutation(s, "自定义 mihomo 服务端配置已通过校验并应用生效，面板信息已同步更新。", True)

    def do_reset_template_config(self, s):
        with LOCK:
            try:
                reset_to_template_config()
            except Exception as e:
                return self.respond_mutation(s, f"恢复默认模板失败：{e}", False)
        return self.respond_mutation(s, "已退出自定义配置模式，恢复为内置服务端模板并重启生效。", True)

    # -- views & partial sections
    def login_page(self, err=""):
        e = f"<div class=err>{html.escape(err)}</div>" if err else ""
        return page(f"登录 · Clash Serve v{VERSION}", f"""<div class=login-wrap><div class=login><div class=card>
<div class=head><div class=logo>C</div><div><h1>Clash Serve <span class='pill tag'>v{VERSION}</span></h1><p class=sub>服务器管理控制台 · 请登录</p></div></div>{e}
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
        n_out = len(load_server_proxies())
        n_prov = len(load_proxy_providers())
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
        mode_sub = "自定义配置模式" if is_custom_config_mode() else f"{n_out} 个节点 · {n_prov} 个订阅源"
        return "<div class=stats id=stats-bar>" + "".join([
            stat(f"<span class='dot {state_cls}'></span>内核状态", e(state_txt),
                 f"已运行 {uptime}" if uptime else "Mihomo 服务"),
            stat("入站监听器", f"{len(ports)}<small>个</small>", f"{n_listen} 个端口正在监听"),
            stat("服务端出站", f"{n_out + n_prov}<small>项</small>", mode_sub),
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

        def node_cfg_btn(title, proxy):
            single_s = e("- " + json.dumps(proxy, ensure_ascii=False))
            multi_s = e("\n".join(dump_yaml_map(proxy, indent=2, first_dash=True)))
            return (f"<button type=button class='btn sm' data-title='{e(title)}' "
                    f"data-single='{single_s}' data-multi='{multi_s}' "
                    f"onclick=\"openNodeModal(this)\">查看节点配置</button>")

        def item(name, kind, port, extra_meta, del_act, proxy):
            cfg_btn = node_cfg_btn(name, proxy)
            return (f"<div class=item><div class=top><div><div class=nm>{e(name)}</div>"
                    f"<div class=meta><span>端口 <b class=mono>{port}</b></span>{extra_meta}</div></div>"
                    f"<span class='pill k-{kind}'>{e(KIND_ZH.get(kind, kind))}</span>{state(port)}"
                    f"<div class=acts>{cfg_btn}{del_act}</div></div></div>")

        rows = []
        for n in nodes:
            acts = (f"<form class=inline method=post action=/nodes/{quote(n['name'])}/delete data-ajax=1 data-busy=正在删除…>{hid}"
                    f"<button class='btn sm danger' onclick=\"return confirm('确定删除入站「{e(n['name'])}」？删除后客户端将无法连接。')\">删除</button></form>")
            rows.append(item(n["name"], "vless-reality", n["port"], "<span>安装时生成</span>",
                             acts, reality_client(n, env)))
        for i in inbs:
            created = time.strftime("%Y-%m-%d %H:%M", time.localtime(i.get("created", 0))) if i.get("created") else ""
            src_label = "自定义配置同步" if is_custom_config_mode() else "面板添加"
            acts = (f"<form class=inline method=post action=/inbounds/{i['id']}/delete data-ajax=1 data-busy=正在删除…>{hid}"
                    f"<button class='btn sm danger' onclick=\"return confirm('确定删除入站「{e(i['name'])}」？删除后客户端将无法连接。')\">删除</button></form>")
            rows.append(item(i["name"], i["kind"], i["port"],
                             f"<span>{src_label}{(' · ' + created) if created else ''}</span>",
                             acts, i["client"]))
        all_proxies = [reality_client(n, env) for n in nodes] + [i["client"] for i in inbs]
        all_yaml = e("proxies:\n" + "\n".join("  - " + json.dumps(p, ensure_ascii=False) for p in all_proxies))
        copy_all = (f"<div class=spacer></div><pre id=all-proxies style=display:none>{all_yaml}</pre>"
                    f"<button type=button class='btn sm' onclick=\"copyText('all-proxies',this)\">复制全部 proxies</button>"
                    if all_proxies else "")
        body_rows = "".join(rows) or "<div class=empty>暂无入站节点，可在右侧表单添加。</div>"
        return f"""<div class=card id=inbounds-card><div class=card-h><h2>入站节点（Listeners）</h2><span class='pill gray'>共 {len(rows)} 个</span>{copy_all}
<div class=desc>点击「查看节点配置」可在弹窗中编辑并复制一行（简单）或多行（易读）mihomo 节点配置，或点击右上角复制全部节点的 proxies 片段。所有节点变更实时同步到客户端订阅。</div></div>
<div class=list>{body_rows}</div></div>"""

    def render_providers_section(self, s: dict) -> str:
        e = html.escape
        hid = f"<input type=hidden name=csrf value='{e(s['csrf'])}'>"
        providers = load_proxy_providers()
        rows = []
        for idx, (name, cfg) in enumerate(providers.items()):
            yml = e(dump_yaml_providers({name: cfg}).rstrip("\n"))
            pid = f"pp-{idx}"
            url_s = str(cfg.get("url", ""))
            path_s = str(cfg.get("path", f"./{name}.yaml"))
            del_form = (f"<form class=inline method=post action=/providers/delete data-ajax=1 data-busy=正在删除…>{hid}"
                        f"<input type=hidden name=name value='{e(name)}'>"
                        f"<button class='btn sm danger' onclick=\"return confirm('确定删除订阅源「{e(name)}」？')\">删除</button></form>")
            rows.append(
                f"<div class=item><div class=top><div><div class=nm>{e(name)}</div>"
                f"<div class=meta><span>路径 <b class=mono>{e(path_s)}</b></span>"
                f"<span>更新间隔 <b class=mono>{cfg.get('interval', 3600)}s</b></span>"
                f"<span>URL <b class=mono>{e(url_s[:64] + ('…' if len(url_s) > 64 else ''))}</b></span></div></div>"
                f"<span class='pill tag'>http</span>"
                f"<div class=acts>{del_form}</div></div>"
                f"<details><summary>查看 proxy-providers 配置</summary><pre id={pid}>{yml}</pre>"
                f"<button type=button class='btn sm' style=margin-top:8px onclick=\"copyText('{pid}',this)\">复制</button></details></div>"
            )
        list_html = f"<div class=list style='margin-bottom:14px'>{''.join(rows)}</div>" if rows else ""
        return f"""<div class=card id=providers-section>
<div class=card-h><h2>导入外部订阅链接（<code>proxy-providers:</code>）</h2>
<span class='pill gray'>已配置 {len(providers)} 个</span>
<div class=desc>粘贴外部机场或自建节点订阅 URL，自动写入服务端 <code>proxy-providers:</code>（默认 <code>path: ./default.yaml</code>、<code>interval: 3600</code>、<code>proxy: DIRECT</code> 并开启 <code>gstatic 204</code> 健康检查；所有策略组已开启 <code>include-all: true</code> 自动引入）。</div></div>
{list_html}
<form method=post action=/providers/add data-ajax=1 data-busy=正在导入订阅…>{hid}
<div class=form-grid>
<div style='grid-column:span 2'><label for=sub-url-inp>订阅链接（HTTP / HTTPS URL）</label>
<input id=sub-url-inp name=sub_url placeholder="https://example.com/sub.yaml?token=..." required></div>
<div><label for=prov-name-inp>订阅源标识（选填）</label>
<input id=prov-name-inp name=provider_name placeholder="留空默认写入 ./default.yaml"></div>
</div>
<button class='btn primary' type=submit>导入订阅到 proxy-providers</button>
</form></div>"""

    def render_proxies_section(self, s: dict) -> str:
        e = html.escape
        hid = f"<input type=hidden name=csrf value='{e(s['csrf'])}'>"
        srv_proxies = load_server_proxies()
        p_rows = []
        for p in srv_proxies:
            single_s = e("- " + json.dumps(p, ensure_ascii=False))
            multi_s = e("\n".join(dump_yaml_map(p, indent=2, first_dash=True)))
            if p.get("server") and p.get("port"):
                endpoint_meta = f"<span>服务器 <b class=mono>{e(str(p['server']))}:{p['port']}</b></span>"
            elif p.get("server"):
                endpoint_meta = f"<span>服务器 <b class=mono>{e(str(p['server']))}</b></span>"
            elif p.get("network-name"):
                endpoint_meta = f"<span>网络 <b class=mono>{e(str(p['network-name']))}</b></span>"
            elif p.get("hostname"):
                endpoint_meta = f"<span>主机名 <b class=mono>{e(str(p['hostname']))}</b></span>"
            else:
                endpoint_meta = f"<span>类型 <b class=mono>{e(str(p.get('type', '')))}</b></span>"
            cfg_btn = (f"<button type=button class='btn sm' data-title='{e(p['name'])}' "
                       f"data-single='{single_s}' data-multi='{multi_s}' "
                       f"onclick=\"openNodeModal(this)\">查看节点配置</button>")
            del_form = (f"<form class=inline method=post action=/proxies/delete data-ajax=1 data-busy=正在删除…>{hid}"
                        f"<input type=hidden name=name value='{e(p['name'])}'>"
                        f"<button class='btn sm danger' onclick=\"return confirm('确定从服务端 proxies: 删除节点「{e(p['name'])}」？')\">删除</button></form>")
            p_rows.append(
                f"<div class=item><div class=top><div><div class=nm>{e(p['name'])}</div>"
                f"<div class=meta>{endpoint_meta}"
                f"<span>UDP <b class=mono>{'开启' if p.get('udp', True) else '关闭'}</b></span></div></div>"
                f"<span class='pill tag'>{e(str(p['type']))}</span>"
                f"<div class=acts>{cfg_btn}{del_form}</div></div></div>"
            )
        list_html = f"<div class=list style='margin-bottom:14px'>{''.join(p_rows)}</div>" if p_rows else ""
        return f"""<div class=card id=proxies-section>
<div class=card-h><h2>服务端手工出站节点（<code>proxies:</code>）</h2>
<span class='pill gray'>已添加 {len(srv_proxies)} 个</span>
<div class=desc>支持粘贴单行 JSON / YAML Flow 或多行 YAML 格式的 mihomo 节点配置（包含 <code>easytier</code>、<code>tailscale</code>、<code>vless</code>、<code>ss</code> 等任意协议及连字符/点号字段），自动转换为多行 YAML 追加到服务端 <code>proxies:</code> 下并默认开启 <code>udp: true</code>。点击「查看节点配置」可弹窗编辑并复制单行或多行格式。</div></div>
{list_html}
<form method=post action=/proxies/add data-ajax=1 data-busy=正在写入配置…>{hid}
<div style='margin-bottom:10px'>
<textarea id=proxies-raw name=proxies_raw placeholder='支持粘贴单行 JSON / Flow 或多行 YAML，例如：&#10;{{"name":"Grok|EasyTier","type":"easytier","network-name":"jared","network-secret":"...","peers":["tcp://..."],"exit-nodes":["10.144.0.2"],"state-dir":"./easytier-grok","udp":true}}&#10;或标准节点：&#10;- name: HK-01&#10;  type: ss&#10;  server: 1.2.3.4&#10;  port: 8388&#10;  cipher: aes-128-gcm&#10;  password: xxx'></textarea>
</div>
<div class=row>
<button class='btn primary' type=submit>添加到服务端 proxies</button>
<label class='btn sm' style='margin:0;cursor:pointer'>选择节点配置文件<input type=file accept='.yaml,.yml,.json,.txt' style='display:none' onchange='loadProxyFile(this)'></label>
</div></form></div>"""

    def render_server_config_card(self, s: dict, env: dict = None, st: dict = None) -> str:
        e = html.escape
        if env is None:
            env = read_env()
        if st is None:
            st = mihomo_status()
        listening = set(st["listening"])
        hid = f"<input type=hidden name=csrf value='{e(s['csrf'])}'>"
        zb_full_url = zashboard_url(env)
        srv_cfg_url = server_config_url(env, self.cfg)
        cport = get_controller_port(env)
        zb_state = ("<span class='pill ok'><span class='dot ok'></span>控制端口 :" + str(cport) + " 监听中</span>"
                    if cport in listening else f"<span class='pill warn'>控制端口 :{cport} 未监听</span>")
        reset_zb = (f"<form class=inline method=post action=/action/reset-secret data-busy=正在重置…>"
                    f"{hid}<button class='btn sm' onclick=\"return confirm('确定重置 Zashboard API 密钥？重置后需使用新链接连接。')\">重置 API 密钥</button></form>")
        return f"""<div class=card id=server-config-card><div class=card-h><h2>mihomo 服务端配置</h2>{zb_state}<div class=spacer></div>{reset_zb}
<div class=desc>管理 Mihomo 服务端运行配置与 Zashboard 控制面板（随机高端口 <code>:{cport}</code>，API Secret 已全量 URL 编码并拼接到地址末尾，支持一键免填直连）。</div></div>
<div style=margin-bottom:14px><label>Zashboard HTTPS 地址（已包含 API Secret 免填直连参数）</label>
<div class=sub-box><div class='url mono' id=zb-url>{e(zb_full_url or '—')}</div>
<a class='btn primary' id=zb-open-btn href='{e(zb_full_url or "#")}' target=_blank rel=noopener>打开地址</a>
<button type=button class=btn onclick="copyText('zb-url',this)">复制地址</button></div></div>
<div><label>当前运行中的服务端配置链接（需面板登录鉴权）</label>
<div class=sub-box><div class='url mono' id=srv-cfg-url>{e(srv_cfg_url)}</div>
<a class=btn href='/config/server.yaml' target=_blank rel=noopener>打开配置</a>
<button type=button class=btn onclick="copyText('srv-cfg-url',this)">复制链接</button></div></div>
</div>"""

    def render_custom_config_section(self, s: dict, env: dict = None) -> str:
        e = html.escape
        if env is None:
            env = read_env()
        hid = f"<input type=hidden name=csrf value='{e(s['csrf'])}'>"
        custom_active = is_custom_config_mode()
        try:
            with open(CUSTOM_CONF if custom_active else CONF) as f:
                cur_cfg = f.read()
        except FileNotFoundError:
            cur_cfg = assemble_config()
        mode_badge = ("<span class='pill warn'>当前：自定义配置模式</span>" if custom_active
                      else "<span class='pill ok'>当前：标准模板模式</span>")
        reset_btn = (f"<form class=inline method=post action=/config/reset-template data-ajax=1 data-busy=正在恢复…>{hid}"
                     f"<button class='btn sm danger' type=submit onclick=\"return confirm('确定退出自定义配置模式并恢复为内置服务端模板？')\">恢复默认模板</button></form>"
                     if custom_active else "")
        return f"""<div class=card id=custom-config-section>
<div class=card-h><h2>自定义 mihomo 服务端配置模式</h2>{mode_badge}<div class=spacer></div>{reset_btn}
<div class=desc>您可以直接粘贴或编辑整份自备的 mihomo 服务端配置文件（<code>config.yaml</code>），校验通过后立即应用，并自动同步刷新入站 Listeners 列表与客户端订阅。</div></div>
<div class=notice>
<b>⚠️ 醒目提醒：Mihomo 证书目录与相对路径说明</b><br>
1. 本系统已将 Mihomo 运行目录（<code>-d</code>）、配置文件与证书统一收纳在 <code>/etc/clashserve</code>，证书实际位于 <code>/etc/clashserve/certs/fullchain.pem</code> 与 <code>/etc/clashserve/certs/privkey.pem</code>（相对路径即 <code>certs/fullchain.pem</code> 与 <code>certs/privkey.pem</code>）。<br>
2. 若您的自备配置中填写了其他证书路径或相对路径，请点击下方 <b>「自动修改证书路径」</b> 按钮一键修正为本机证书路径（不会误改 Reality 的 <code>private-key</code>），随后点击 <b>「更新 mihomo 服务端配置」</b> 校验并生效。
</div>
<form method=post action=/config/custom data-ajax=1 data-busy="正在校验并更新 mihomo 服务端配置…">{hid}
<div style='margin-bottom:12px'>
<textarea class=code-ed id=custom-config-raw name=custom_config_raw placeholder="在此粘贴完整的 mihomo 服务端 YAML 配置…">{e(cur_cfg)}</textarea>
</div>
<div class=row>
<button type=button class='btn warn' onclick="autoFixCertPaths()">自动修改证书路径</button>
<button type=submit class='btn primary'>更新 mihomo 服务端配置</button>
<label class=btn style='margin:0;cursor:pointer'>从本地文件载入<input type=file accept='.yaml,.yml,.txt' style='display:none' onchange="loadFileToTextarea(this,'custom-config-raw')"></label>
<button type=button class=btn onclick="copyText('custom-config-raw',this)">复制当前配置</button>
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

        # --- Hero Command Bar (replaces oversized standalone Mihomo status card)
        cert_btn = (f"<form class=inline method=post action=/action/cert data-busy=正在续期…>{hid}"
                    f"<button class='btn sm'>校验证书 / 续期</button></form>")
        hero = f"""<div class=hero-bar>
<div class=hero-meta>
<h1>Mihomo 核心控制台 <span class='pill {state_cls}'><span class='dot {state_cls}'></span>{e(state_txt)}</span></h1>
<div class=hero-kv>
<span>版本 <b class=mono>{e(version or '未知')}</b></span>
<span>PID <b class=mono>{e(st['pid'] if st['pid'] not in ('', '0') else '—')}</b></span>
<span>启动于 <b>{e(since or '—')}</b></span>
<span>自动重启 <b>{e(st['restarts'] or '0')} 次</b></span>
<span>统一目录 <code class=mono>/etc/clashserve</code></span>
</div></div>
<div class=row>
<form class=inline method=post action=/action/restart data-busy=正在重启…>{hid}<button class='btn sm primary'>重启内核</button></form>
<form class=inline method=post action=/action/reload data-busy=正在重载…>{hid}<button class='btn sm' title='先校验配置，通过后再热重载'>重载配置</button></form>
{cert_btn}
<a class='btn sm' href=/>刷新状态</a>
</div></div>"""

        inbounds = self.render_inbounds_section(s, env, st)

        # --- Add Inbound Form (14 protocols aligned with MetaCubeX wiki)
        opts = "".join(f"<option value={k}>{KIND_ZH.get(k, k)}</option>" for k in TYPES)
        ss_opts = "".join(f"<option value={c}>{SS_CIPHER_LABELS.get(c, c)}</option>" for c in SS_CIPHERS)
        no_cert = "" if certs_present() else "<div class=notice>证书文件缺失，暂时无法添加需要 TLS 证书的入站协议（请在服务器执行 clashserver cert）。</div>"
        add = f"""<div class=card><div class=card-h><h2>添加入站监听器</h2><span class='pill tag'>支持 14 种协议</span>
<div class=desc>对齐 MetaCubeX 官方 Wiki，密码 / UUID / 密钥自动随机生成，所有生成节点默认开启 <code>udp: true</code>。</div></div>
<form method=post action=/inbounds/add data-ajax=1 data-busy=正在添加…>{hid}<div class=form-grid>
<div><label for=kind>入站协议类型</label><select id=kind name=kind>{opts}</select></div>
<div><label for=port>监听端口</label><input id=port name=port inputmode=numeric placeholder="留空则随机分配空闲高端口"></div>
<div><label for=nm>节点名称</label><input id=nm name=name placeholder="留空则自动生成（默认 VlessReality）"></div>

<div data-kind=vless-reality><label>Reality 伪装域名（SNI）</label><input name=reality_sni placeholder="留空从 SNI 池随机抽取"></div>
<div data-kind=vless-reality><label>VLESS Encryption（vless-x25519）</label><select name=reality_enc><option value=x25519>启用 mlkem768x25519plus（默认）</option><option value=none>不启用</option></select></div>
<div data-kind=shadowsocks><label>Shadowsocks 加密方式</label><select name=ss_cipher>{ss_opts}</select></div>
<div data-kind=hysteria2><label>Salamander 混淆密码（选填）</label><input name=hy2_obfs_pw placeholder="留空不启用 obfs"></div>
<div data-kind=snell><label>Snell 版本</label><select name=snell_version><option value=5>v5（默认）</option><option value=4>v4</option></select></div>
<div data-kind=snell><label>Snell 混淆模式</label><select name=snell_obfs><option value=tls>tls（默认）</option><option value=http>http</option></select></div>
<div data-kind=snell><label>Snell 伪装 Host</label><input name=snell_host placeholder="留空从 SNI 池随机抽取"></div>
<div data-kind=trusttunnel><label>TrustTunnel 用户名</label><input name=tt_user placeholder="默认 user"></div>
<div data-kind=trusttunnel><label>拥塞控制算法</label><select name=tt_cc><option value=bbr>bbr（默认）</option><option value=cubic>cubic</option></select></div>

<div data-kind=vless><label>VLESS 传输层</label><select name=vless_net><option value=tcp>TCP + Vision（默认）</option><option value=xhttp>XHTTP（推荐抗封锁）</option><option value=ws>WebSocket (WS)</option><option value=grpc>gRPC</option></select></div>
<div data-kind=vless><label>VLESS TLS 证书</label><select name=vless_tls><option value=1>启用本机域名证书（默认）</option><option value=0>不启用 TLS（配合原生加密）</option></select></div>
<div data-kind=vless><label>VLESS Encryption（vless-x25519）</label><select name=vless_enc><option value=x25519>启用 mlkem768x25519plus（默认）</option><option value=none>不启用</option></select></div>
<div data-kind=vless><label>XHTTP / WS / gRPC 路径</label><input name=vless_path placeholder="留空自动生成随机路径"></div>

<div data-kind=vmess><label>VMess 传输层</label><select name=vmess_net><option value=ws>WebSocket (WS，默认)</option><option value=tcp>TCP</option><option value=grpc>gRPC</option></select></div>
<div data-kind=vmess><label>VMess TLS 证书</label><select name=vmess_tls><option value=1>启用本机域名证书（默认）</option><option value=0>不启用 TLS</option></select></div>
<div data-kind=vmess><label>WS 路径 / gRPC 服务名</label><input name=vmess_path placeholder="留空自动生成随机路径"></div>

<div data-kind=anytls><label>AnyTLS 用户名</label><input name=anytls_user placeholder="默认 user"></div>
<div data-kind=anytls><label>客户端 TLS 指纹</label><select name=anytls_fp><option value=chrome>chrome（默认）</option><option value=safari>safari</option><option value=firefox>firefox</option><option value=ios>ios</option></select></div>
<div data-kind=anytls><label>Padding 填充方案</label><select name=anytls_padding><option value=1>启用默认 Padding Scheme</option><option value=0>不启用</option></select></div>

<div data-kind=tuic><label>TUIC v5 拥塞控制</label><select name=tuic_cc><option value=bbr>bbr（默认）</option><option value=cubic>cubic</option><option value=new_reno>new_reno</option></select></div>
<div data-kind=tuic><label>UDP 转发模式</label><select name=tuic_udp_mode><option value=native>native（默认）</option><option value=quic>quic</option></select></div>

<div data-kind=shadowquic><label>ShadowQUIC 用户名</label><input name=sq_user placeholder="默认 user"></div>
<div data-kind=shadowquic><label>JLS 回源伪装地址</label><input name=sq_jls placeholder="默认 www.microsoft.com:443"></div>
<div data-kind=shadowquic><label>拥塞控制算法</label><select name=sq_cc><option value=bbr>bbr（默认）</option><option value=cubic>cubic</option><option value=new_reno>new_reno</option></select></div>
<div data-kind=shadowquic><label>0-RTT 握手</label><select name=sq_zero_rtt><option value=1>开启（默认）</option><option value=0>关闭</option></select></div>

<div data-kind=mieru><label>Mieru 传输协议</label><select name=mieru_transport><option value=TCP>TCP（默认）</option><option value=UDP>UDP</option></select></div>
<div data-kind=mieru><label>Mieru 用户名</label><input name=mieru_user placeholder="默认 user"></div>

<div data-kind=sudoku><label>Sudoku AEAD 加密</label><select name=sudoku_aead><option value=chacha20-poly1305>chacha20-poly1305（默认）</option><option value=aes-128-gcm>aes-128-gcm</option><option value=none>none</option></select></div>
<div data-kind=sudoku><label>Sudoku 编码表类型</label><select name=sudoku_table><option value=prefer_ascii>prefer_ascii（默认）</option><option value=prefer_entropy>prefer_entropy</option><option value=up_ascii_down_entropy>up_ascii_down_entropy</option><option value=up_entropy_down_ascii>up_entropy_down_ascii</option></select></div>
<div data-kind=sudoku><label>纯净下行（Pure Downlink）</label><select name=sudoku_pure_downlink><option value=1>开启（默认）</option><option value=0>关闭</option></select></div>

<div data-kind=http><label>HTTP 用户名</label><input name=http_user placeholder="默认 user"></div>
<div data-kind=http><label>HTTP 密码</label><input name=http_pass placeholder="留空自动生成随机密码"></div>
<div data-kind=http><label>启用 HTTPS (TLS)</label><select name=http_tls><option value=0>不启用（默认）</option><option value=1>启用本机域名证书</option></select></div>

<div data-kind=socks><label>SOCKS5 用户名</label><input name=socks_user placeholder="默认 user"></div>
<div data-kind=socks><label>SOCKS5 密码</label><input name=socks_pass placeholder="留空自动生成随机密码"></div>
<div data-kind=socks><label>启用 TLS</label><select name=socks_tls><option value=0>不启用（默认）</option><option value=1>启用本机域名证书</option></select></div>
</div><button class='btn primary' type=submit>添加入站节点</button></form>
<p class=hint>保存前会自动运行 <code>mihomo -t</code> 校验配置，校验失败自动回滚，不影响现有运行中的节点。</p>{no_cert}</div>"""

        # --- Subscription URL card
        url = self.sub_url()
        if url:
            sub = f"""<div class=card><div class=card-h><h2>客户端订阅链接</h2><span class='pill tag'>mihomo.yaml</span>
<div class=desc>包含全部入站节点（内置 ACL4SSR Fake-IP 客户端规则模板：🚀 节点选择、♻️ 自动选择、🌍 国外媒体、📲 电报信息、Ⓜ️ 微软服务、🍎 苹果服务、📢 谷歌FCM、🎯 全球直连、🛑 全球拦截、🍃 应用净化、🐟 漏网之鱼）。链接即凭证，泄露后执行 <code>clashserver reset-sub</code> 更换。</div></div>
<div class=sub-box><div class='url mono' id=sub-url>{e(url)}</div>
<a class=btn href='{e(url)}' target=_blank rel=noopener>预览订阅</a>
<button type=button class='btn primary' onclick="copyText('sub-url',this)">复制订阅链接</button></div></div>"""
        else:
            sub = ""

        server_card = self.render_server_config_card(s, env, st)
        providers_sec = self.render_providers_section(s)
        proxies_sec = self.render_proxies_section(s)
        custom_cfg_sec = self.render_custom_config_section(s, env)

        # --- Navigation Tabs
        nav = """<div class=nav-tabs>
<button type=button class='tab-btn active' data-tab=inbounds onclick="switchTab('inbounds',this)">📡 入站与客户端订阅</button>
<button type=button class='tab-btn' data-tab=outbounds onclick="switchTab('outbounds',this)">🌐 服务端出站与订阅源</button>
<button type=button class='tab-btn' data-tab=server onclick="switchTab('server',this)">⚙️ mihomo 服务端配置 &amp; 自定义配置</button>
<div class=spacer></div>
<button type=button class='btn sm' id=toggle-all-btn onclick="toggleAllTabs(this)">展开全部视图</button>
</div>"""

        tab_inbounds = f"<div class='tab-pane active' id=tab-inbounds>{sub}<div class=split-2>{inbounds}{add}</div></div>"
        tab_outbounds = f"<div class=tab-pane id=tab-outbounds>{providers_sec}{proxies_sec}</div>"
        tab_server = f"<div class=tab-pane id=tab-server>{server_card}{custom_cfg_sec}</div>"

        node_modal = """<div class=modal-backdrop id=node-modal-backdrop onclick="if(event.target===this)closeNodeModal()">
<div class=modal-box role=dialog aria-modal=true aria-labelledby=node-modal-title>
<div class=modal-h><h3 id=node-modal-title>查看节点配置</h3>
<button type=button class='btn sm' onclick="closeNodeModal()">✕</button></div>
<div class=modal-b>
<div class=modal-sec>
<div class=modal-sec-h><label for=modal-node-single>单行格式（简单 · 一行 mihomo 节点配置，可直接编辑）</label>
<button type=button class='btn sm primary' onclick="copyText('modal-node-single',this)">复制一行（简单）</button></div>
<textarea id=modal-node-single class='mono node-ed-single' spellcheck=false></textarea>
</div>
<div class=modal-sec>
<div class=modal-sec-h><label for=modal-node-multi>多行格式（易读 · 多行 YAML 节点配置，可直接编辑）</label>
<button type=button class='btn sm primary' onclick="copyText('modal-node-multi',this)">复制多行（易读）</button></div>
<textarea id=modal-node-multi class='mono node-ed-multi' spellcheck=false></textarea>
</div>
</div>
<div class=modal-f>
<button type=button class=btn onclick="copyText('modal-node-single',this)">复制一行（简单）</button>
<button type=button class=btn onclick="copyText('modal-node-multi',this)">复制多行（易读）</button>
<button type=button class='btn primary' onclick="closeNodeModal()">关闭</button>
</div></div></div>"""

        icon = "✓" if ok else "!"
        fl_inner = f"<div class='flash {'ok' if ok else 'bad'}'><b>{icon}</b><div>{e(msg)}</div></div>" if msg else ""
        fl = f"<div id=flash-box>{fl_inner}</div>"
        vps = env.get("VPS_NAME", "")
        top = f"""<div class=topbar><div class=in><div class=logo>C</div>
<div class=brand><b>Clash Serve <span class='pill tag'>v{VERSION}</span></b><small>Mihomo 服务端管理控制台 · v{VERSION}</small></div>
<span class='chip hide-sm'><span class='dot {state_cls}'></span>{e(vps or env.get('DOMAIN', ''))}</span>
<span class='chip hide-sm'>{e(env.get('DOMAIN', ''))}</span><div class=spacer></div>
<form class=inline method=post action=/logout>{hid}<button class='btn sm ghost'>退出登录</button></form></div></div>"""
        foot = f"<footer>Clash Serve v{VERSION} · 统一目录 /etc/clashserve · Mihomo 服务端管理控制台</footer>"
        return page(f"控制台 · Clash Serve v{VERSION}",
                    f"{top}<main>{fl}{hero}{stats}{nav}{tab_inbounds}{tab_outbounds}{tab_server}{node_modal}</main>{foot}",
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
        sock.settimeout(120)
        return self.ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr

    def finish_request(self, request, client_address):
        try:
            request.do_handshake()
            request.settimeout(180)
        except (ssl.SSLError, OSError):
            return   # plain HTTP / scanners / aborted handshakes: drop quietly
        super().finish_request(request, client_address)

    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], (ssl.SSLError, ConnectionError, socket.timeout)):
            return
        super().handle_error(request, client_address)


def serve(cfg_path):
    ensure_unified_root()
    if not os.path.isfile(cfg_path) and os.path.isfile(CS_ROOT + "/panel.json"):
        cfg_path = CS_ROOT + "/panel.json"
    with open(cfg_path) as f:
        cfg = json.load(f)
    Panel.cfg = cfg
    Panel.cfg_path = cfg_path
    addr = (cfg.get("listen", "0.0.0.0"), int(cfg.get("port", 8443)))
    if cfg.get("tls_cert"):
        cert_p = ROOT + cfg["tls_cert"]
        key_p = ROOT + cfg["tls_key"]
        if not os.path.isfile(cert_p) and os.path.isfile(ROOT + CERT):
            cert_p, key_p = ROOT + CERT, ROOT + KEY
        httpd = TLSServer(addr, Panel, cert_p, key_p)
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
