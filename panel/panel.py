#!/usr/bin/env python3
"""clashserve - minimal admin panel for clashserver (auto-cert mode).

Stdlib only (Debian python3). Serves HTTPS itself with the same certificate
Mihomo uses (/etc/mihomo/certs, issued by acme.sh); no reverse proxy.
Features: admin login, Mihomo status dashboard, restart/reload, cert renewal,
add/delete inbounds (vless-reality, hysteria2, snell, trusttunnel).

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

# CLASHSERVER_ROOT lets the panel run against a fake tree for local testing.
ROOT = os.environ.get("CLASHSERVER_ROOT", "")
ENV_FILE = ROOT + "/etc/clashserver/clashserver.env"
INBOUNDS = ROOT + "/etc/clashserver/inbounds.json"
MIHOMO_DIR = ROOT + "/etc/mihomo"
CONF = MIHOMO_DIR + "/config.yaml"
NODES_TSV = MIHOMO_DIR + "/nodes.tsv"
FRAG_CONTROLLER = MIHOMO_DIR + "/controller.yaml"
FRAG_REALITY = MIHOMO_DIR + "/listeners.reality.yaml"
FRAG_EXTRA = MIHOMO_DIR + "/listeners.extra.yaml"
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
SS_CIPHERS = ("aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305")

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
    name = form.get("name", "").strip() or f"{kind}-{port}"
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,48}", name):
        raise ValueError("名称仅限 1-48 位字母、数字及 . _ -")
    vps = env.get("VPS_NAME", "vps")
    ip = env.get("SERVER_IP", "")
    domain = env.get("DOMAIN", "").removeprefix("*.")
    insecure = env.get("TLS", "") in ("staging", "internal")
    base = {"name": name, "port": port, "listen": "0.0.0.0"}
    label = f"{vps}-{name}"

    if kind == "vless-reality":
        priv, pub = reality_keypair()
        uid, sid = str(uuidlib.uuid4()), secrets.token_hex(4)
        listener = {**base, "type": "vless",
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
            raise ValueError("不支持的 Shadowsocks 加密方式")
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
                  "password": pw, "sni": domain, "alpn": ["h3"], "skip-cert-verify": insecure}
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
                  "skip-cert-verify": insecure}
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
    """Same logic as core.sh assemble_config: template @@CONTROLLER@@ + @@LISTENERS@@ <- reality + extra."""
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
            elif s == "@@LISTENERS@@":
                out.append(block)
            else:
                out.append(line)
    return "".join(out)


def atomic_write(path: str, data: str, mode=0o640):
    d = os.path.dirname(path)
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
    """Poll ss for up to ~2s so all expected ports are listening before redirecting back to dashboard."""
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


def reality_client(n: dict, env: dict) -> dict:
    """Client proxy for an install-time Reality node (same fields as install.sh proxy_line)."""
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
.brand{display:flex;flex-direction:column;line-height:1.25}.brand b{font-size:16px;letter-spacing:.2px}
.brand small{color:var(--muted);font-size:12px}
.chip{display:inline-flex;align-items:center;gap:6px;background:#f3f4f6;color:#374151;border-radius:999px;
padding:3px 12px;font-size:12px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--faint);display:inline-block}
.dot.ok{background:#22c55e;box-shadow:0 0 0 3px #dcfce7}.dot.bad{background:#ef4444;box-shadow:0 0 0 3px #fee2e2}
.dot.warn{background:#f59e0b;box-shadow:0 0 0 3px #fef3c7}
.spacer{flex:1}
main{max-width:1120px;margin:0 auto;padding:28px 24px 56px}
.page-h{display:flex;align-items:flex-end;justify-content:space-between;gap:12px;margin:0 0 20px;flex-wrap:wrap}
.page-h h1{font-size:22px;margin:0;font-weight:700}.page-h p{margin:2px 0 0;color:var(--muted)}
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
.mono,code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
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
input::placeholder{color:var(--faint)}
input:focus,select:focus{outline:0;border-color:var(--primary);box-shadow:0 0 0 3px rgba(99,102,241,.18)}
.hint{font-size:12px;color:var(--muted);margin:14px 0 0}
.notice{font-size:13px;border-radius:10px;padding:10px 14px;margin-top:14px;background:var(--warn-bg);color:#78350f}
.sub-box{display:flex;gap:10px;align-items:stretch;flex-wrap:wrap}
.sub-box .url{flex:1;min-width:240px;background:#f8fafc;border:1px solid var(--line);border-radius:9px;padding:9px 12px;
font-size:12px;word-break:break-all}
footer{max-width:1120px;margin:0 auto;padding:0 24px 32px;color:var(--faint);font-size:12px;text-align:center}
.login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;
background:radial-gradient(1200px 600px at 10% -10%,#e0e7ff 0,transparent 60%),
radial-gradient(900px 500px at 110% 110%,#ede9fe 0,transparent 60%),var(--bg)}
.login{width:100%;max-width:400px}
.login .card{padding:34px 32px;margin:0}
.login .head{display:flex;align-items:center;gap:12px;margin-bottom:22px}
.login h1{font-size:20px;margin:0}.login p.sub{color:var(--muted);margin:0;font-size:13px}
.login .field{margin-bottom:16px}.login .btn{width:100%;height:40px;margin-top:6px}
.login .foot{text-align:center;color:var(--faint);font-size:12px;margin-top:18px}
.err{background:#fef2f2;border:1px solid #fecaca;color:#7f1d1d;border-radius:10px;padding:10px 12px;margin-bottom:16px}
@media (max-width:640px){.hide-sm{display:none}.stats{grid-template-columns:repeat(2,1fr);gap:12px}.stat .val{font-size:18px}.grid{grid-template-columns:1fr}main{padding:20px 14px 40px}.topbar .in{padding:10px 14px}
.card{padding:18px}.item .acts{margin-left:0;width:100%}}
"""

JS = """
function syncKind(){var k=document.getElementById('kind').value;
document.querySelectorAll('[data-kind]').forEach(function(e){e.style.display=e.dataset.kind===k?'':'none'})}
function copyText(id,btn){var t=document.getElementById(id).textContent;var o=btn.textContent;
function done(){btn.textContent='已复制';setTimeout(function(){btn.textContent=o},1500)}
if(navigator.clipboard){navigator.clipboard.writeText(t).then(done,function(){fallback()})}else{fallback()}
function fallback(){var a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();
try{document.execCommand('copy');done()}catch(e){}document.body.removeChild(a)}}
document.addEventListener('DOMContentLoaded',function(){var k=document.getElementById('kind');
if(k){k.addEventListener('change',syncKind);syncKind()}
document.querySelectorAll('form[data-busy]').forEach(function(f){f.addEventListener('submit',function(){
var b=f.querySelector('button[type=submit],button:not([type])');if(b){b.disabled=true;b.textContent=f.dataset.busy}})})});
"""

STATE_ZH = {"active": ("运行中", "ok"), "inactive": ("已停止", "bad"), "failed": ("失败", "bad"),
            "activating": ("启动中", "warn"), "deactivating": ("停止中", "warn"),
            "reloading": ("重载中", "warn"), "unknown": ("未知", "bad")}
TLS_ZH = {"staging": ("LE 测试证书", "warn", "Let's Encrypt 测试（staging）证书不受公众信任，客户端需开启 skip-cert-verify。"),
          "internal": ("自签证书", "warn", "本机自签证书，仅供开发测试，客户端需开启 skip-cert-verify。"),
          "production": ("Let's Encrypt", "ok", "")}
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
    server_version = "clashserve"
    cfg: dict = {}
    sessions: dict = {}
    fails: dict = {}

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.client_ip(), fmt % args))

    # -- utils
    def client_ip(self):
        return self.client_address[0]   # direct HTTPS, no reverse proxy: never trust X-Forwarded-For

    def is_https(self):
        return bool(self.cfg.get("tls_cert"))

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
        if n > 65536:
            raise ValueError("请求体过大")
        raw = self.rfile.read(n).decode()
        return {k: v[0] for k, v in parse_qs(raw).items()}

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
        if path == "/api/status":
            st = mihomo_status()
            st["inbounds"] = [{k: i[k] for k in ("id", "kind", "name", "port")} for i in load_inbounds()]
            st["reality_nodes"] = [{"name": n["name"], "port": n["port"]} for n in read_nodes()]
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
            return self.redirect("/login")
        if not self.check_csrf(s, form):
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
            return self.do_add(form)
        m = re.fullmatch(r"/inbounds/([0-9a-f]{12})/delete", path)
        if m:
            return self.do_delete(m.group(1))
        m = re.fullmatch(r"/nodes/([A-Za-z0-9._-]{1,48})/delete", path)
        if m:
            return self.do_delete_node(m.group(1))
        self.simple(404, "页面不存在", "请检查地址是否正确。")

    def do_sub(self, path):
        """GET /sub/<token>/mihomo.yaml - token-protected subscription; anything else -> 404."""
        m = re.fullmatch(r"/sub/([A-Za-z0-9_-]{16,128})/mihomo\.yaml", path)
        token = self.cfg.get("sub_token", "")
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
        token = self.cfg.get("sub_token", "")
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

    def do_add(self, form):
        env = read_env()
        with LOCK:
            try:
                inb = build_inbound(form.get("kind", ""), form, env)
                apply_inbounds(load_inbounds() + [inb])
            except Exception as e:
                return self.flash(f"添加失败：{e}", False)
        self.flash(f"已添加 {KIND_ZH.get(inb['kind'], inb['kind'])} 入站「{inb['name']}」，端口 {inb['port']}")

    def do_delete(self, iid):
        with LOCK:
            cur = load_inbounds()
            new = [i for i in cur if i["id"] != iid]
            if len(new) == len(cur):
                return self.flash("入站不存在或已删除", False)
            try:
                apply_inbounds(new)
            except Exception as e:
                return self.flash(f"删除失败：{e}", False)
        self.flash("入站已删除")

    def do_delete_node(self, name):
        with LOCK:
            cur = read_nodes()
            new = [n for n in cur if n["name"] != name]
            if len(new) == len(cur):
                return self.flash("入站不存在或已删除", False)
            try:
                apply_nodes(new)
            except Exception as e:
                return self.flash(f"删除失败：{e}", False)
        self.flash(f"已删除入站「{name}」")

    # -- views
    def login_page(self, err=""):
        e = f"<div class=err>{html.escape(err)}</div>" if err else ""
        return page("登录 · Clash Serve", f"""<div class=login-wrap><div class=login><div class=card>
<div class=head><div class=logo>C</div><div><h1>Clash Serve</h1><p class=sub>服务器管理面板 · 请登录</p></div></div>{e}
<form method=post action=/login>
<div class=field><label for=u>用户名</label><input id=u name=username value=admin autocomplete=username required></div>
<div class=field><label for=p>密码</label><input id=p name=password type=password autocomplete=current-password
placeholder="请输入面板密码" required autofocus></div>
<button class='btn primary'>登 录</button></form>
</div></div></div>""")

    def dashboard(self, s):
        q = parse_qs(urlparse(self.path).query)
        msg, ok = q.get("msg", [""])[0], q.get("ok", ["1"])[0] == "1"
        env = read_env()
        st = mihomo_status()
        e = html.escape
        hid = f"<input type=hidden name=csrf value='{e(s['csrf'])}'>"
        listening = set(st["listening"])
        state_txt, state_cls = STATE_ZH.get(st["active"], (st["active"], "bad"))
        since, uptime = parse_since(st["since"]) if st["active"] == "active" else ("", "")
        version = short_version(st["version"])
        nodes, inbs = read_nodes(), load_inbounds()
        ports = [n["port"] for n in nodes] + [i["port"] for i in inbs]
        n_listen = sum(1 for p in ports if p in listening)
        cert = parse_cert(st["cert"].get("info", ""))
        days = cert.get("days")

        # --- summary stats
        def stat(label, val, sub=""):
            return (f"<div class=stat><div class=lb>{label}</div><div class=val>{val}</div>"
                    f"<div class=sub>{sub or '&nbsp;'}</div></div>")
        hours = cert.get("hours")
        if days is not None and days < 1:
            left, cert_val = f"{hours} 小时", f"{hours}<small>小时</small>"
        else:
            left, cert_val = f"{days} 天", (f"{days}<small>天</small>" if days is not None else ("未知" if cert else "缺失"))
        cert_sub = f"到期 {e(cert.get('expires', ''))}" if cert.get("expires") else "证书剩余有效期"
        stats = "<div class=stats>" + "".join([
            stat(f"<span class='dot {state_cls}'></span>内核状态", e(state_txt),
                 f"已运行 {uptime}" if uptime else "Mihomo 服务"),
            stat("入站节点", f"{len(ports)}<small>个</small>", f"{n_listen} 个正在监听"),
            stat("证书有效期", cert_val, cert_sub),
            stat("内核版本", e(version or "未知"), "Mihomo"),
        ]) + "</div>"

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

        # --- tls card
        tls_txt, tls_cls, tls_hint = TLS_ZH.get(env.get("TLS", ""), (env.get("TLS", "") or "未知", "gray", ""))
        cert_mode_zh = "DNS API 模式" if env.get("CERT_MODE") == "dns" else "端口模式"
        if cert:
            days_html = ""
            if days is not None:
                dcls = "ok" if days > 14 else ("warn" if days > 3 or (hours or 0) >= 1 else "bad")
                days_html = f" <span class='pill {dcls}'>剩余 {left}</span>"
            cert_rows = (f"<dt>颁发者</dt><dd>{e(cert.get('issuer', '—'))}</dd>"
                         f"<dt>到期时间</dt><dd>{e(cert.get('expires', '—'))}{days_html}</dd>")
        else:
            cert_rows = "<dt>证书</dt><dd><span class='pill bad'>缺失</span></dd>"
        if "clashserver temporary" in (cert or {}).get("issuer", ""):
            tls_txt, tls_cls = "尚未签发", "bad"
            if env.get("CERT_MODE") == "dns":
                tls_hint = "正式证书尚未申请成功，当前为临时自签证书。请确认 Cloudflare API Token 具备该域名的 DNS 编辑权限；系统每小时自动重试，也可点击下方按钮或执行 clashserver cert 立即重试。"
            else:
                tls_hint = "正式证书尚未申请成功，当前为临时自签证书。请确认域名 A 记录指向本机、TCP 80 已放行；系统每小时自动重试，也可点击下方按钮或执行 clashserver cert 立即重试。"
        elif days is not None and days < 14 and env.get("TLS", "") != "internal":
            tls_hint = (tls_hint + " " if tls_hint else "") + (
                "证书即将到期，自动续期尚未成功（正常情况下到期前 30 天就会续期）。"
                "请检查配置后点击下方按钮或在服务器执行 clashserver cert 查看原因。")
        hint = f"<div class=notice>{e(tls_hint)}</div>" if tls_hint else ""
        pport = int(self.cfg.get("port") or env.get("PANEL_PORT") or 8443)
        tls = f"""<div class=card><div class=card-h><h2>域名与证书</h2><span class='pill {tls_cls}'>{e(tls_txt)}</span></div>
<dl class=kv><dt>面板地址</dt><dd class=mono>{e(panel_base_url(env, self.cfg) or '—')}</dd>
<dt>面板端口</dt><dd class=mono>{pport}（随机高端口）</dd>
<dt>申请方式</dt><dd>{e(cert_mode_zh)}</dd>
<dt>服务器 IP</dt><dd class=mono>{e(env.get('SERVER_IP', '—'))}</dd>{cert_rows}</dl>{hint}
<div class=row style=margin-top:14px>
<form class=inline method=post action=/action/cert data-busy=正在申请/续期…>{hid}<button class='btn sm'>立即申请 / 续期证书</button></form>
</div></div>"""

        # --- inbounds list
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
            acts = (f"<form class=inline method=post action=/nodes/{quote(n['name'])}/delete>{hid}"
                    f"<button class='btn sm danger' onclick=\"return confirm('确定删除入站「{e(n['name'])}」？删除后客户端将无法连接。')\">删除</button></form>")
            rows.append(item(n["name"], "vless-reality", n["port"], "<span>安装时生成</span>",
                             acts, f"r-{idx}", reality_client(n, env)))
        for i in inbs:
            created = time.strftime("%Y-%m-%d %H:%M", time.localtime(i.get("created", 0))) if i.get("created") else ""
            acts = (f"<form class=inline method=post action=/inbounds/{i['id']}/delete>{hid}"
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
        inbounds = f"""<div class=card><div class=card-h><h2>入站节点</h2><span class='pill gray'>共 {len(rows)} 个</span>{copy_all}
<div class=desc>展开「查看客户端配置」可复制单个节点配置，或点击右上角复制全部节点的 proxies 片段。</div></div>
<div class=list>{body_rows}</div></div>"""

        # --- add form
        opts = "".join(f"<option value={k}>{v}</option>" for k, v in KIND_ZH.items())
        ss_opts = "".join(f"<option value={c}>{c}{'（默认）' if c == 'aes-128-gcm' else ''}</option>" for c in SS_CIPHERS)
        no_cert = "" if certs_present() else "<div class=notice>证书文件缺失，暂时无法添加 Hysteria2 / TrustTunnel（请在服务器执行 clashserver cert）。</div>"
        add = f"""<div class=card><div class=card-h><h2>添加入站</h2></div>
<form method=post action=/inbounds/add data-busy=正在添加…>{hid}<div class=form-grid>
<div><label for=kind>协议类型</label><select id=kind name=kind>{opts}</select></div>
<div><label for=port>端口</label><input id=port name=port inputmode=numeric placeholder="留空则随机分配"></div>
<div><label for=nm>名称</label><input id=nm name=name placeholder="留空则自动生成"></div>
<div data-kind=shadowsocks><label>Shadowsocks 加密方式</label><select name=ss_cipher>{ss_opts}</select></div>
<div data-kind=snell><label>Snell 版本</label><select name=snell_version><option value=5>v5</option><option value=4>v4</option></select></div>
<div data-kind=trusttunnel><label>TrustTunnel 用户名</label><input name=tt_user placeholder="默认 user"></div>
</div><button class='btn primary'>添加入站</button></form>
<p class=hint>密码、UUID、密钥均自动随机生成；Hysteria2 / TrustTunnel 使用本机域名证书（与面板共用，自动续期），Shadowsocks / Snell / Reality 无需证书。
保存前会自动校验配置，校验失败会自动回滚，不影响现有节点。</p>{no_cert}</div>"""

        # --- zashboard card
        zb_url = zashboard_url(env)
        zb_connect = zashboard_connect_url(env)
        zb_secret = env.get("MIHOMO_SECRET", "")
        cport = int(env.get("CONTROLLER_PORT") or 7896)
        zb_state = ("<span class='pill ok'><span class='dot ok'></span>监听中</span>" if cport in listening
                    else "<span class='pill warn'>未监听</span>")
        open_zb = (f"<a class='btn sm primary' href='{e(zb_connect)}' target=_blank rel=noopener>打开 Zashboard ↗</a>"
                   if zb_connect else "")
        reset_zb = (f"<form class=inline method=post action=/action/reset-secret data-busy=正在重置…>"
                    f"{hid}<button class='btn sm' onclick=\"return confirm('确定重置 Zashboard API 密钥？重置后需使用新密钥连接。')\">重置 API 密钥</button></form>")
        zashboard = f"""<div class=card><div class=card-h><h2>Mihomo 控制面板（Zashboard）</h2>{zb_state}<div class=spacer></div>{open_zb}{reset_zb}
<div class=desc>用于管理 Mihomo 出站节点、策略组与分流规则（external-controller-tls :{cport}）。点击右上角「打开 Zashboard」可自动带入地址与密钥连接，也可手动复制下方信息。</div></div>
<div style=margin-bottom:12px><label>Zashboard HTTPS 地址</label>
<div class=sub-box><div class='url mono' id=zb-url>{e(zb_url or '—')}</div>
<button type=button class=btn onclick="copyText('zb-url',this)">复制地址</button></div></div>
<div><label>API 密钥（Secret）</label>
<div class=sub-box><div class='url mono' id=zb-secret>{e(zb_secret or '—')}</div>
<button type=button class=btn onclick="copyText('zb-secret',this)">复制密钥</button></div></div></div>"""

        url = self.sub_url()
        if url:
            sub = f"""<div class=card><div class=card-h><h2>订阅链接</h2><span class='pill tag'>mihomo.yaml</span>
<div class=desc>包含全部节点，导入 mihomo / Clash 客户端即可。链接即凭证，请勿外泄；如需更换，在服务器执行 <code>clashserver reset-sub</code>。</div></div>
<div class=sub-box><div class='url mono' id=sub-url>{e(url)}</div>
<button type=button class='btn primary' onclick="copyText('sub-url',this)">复制链接</button></div></div>"""
        else:
            sub = ""
        icon = "✓" if ok else "!"
        fl = f"<div class='flash {'ok' if ok else 'bad'}'><b>{icon}</b><div>{e(msg)}</div></div>" if msg else ""
        vps = env.get("VPS_NAME", "")
        top = f"""<div class=topbar><div class=in><div class=logo>C</div>
<div class=brand><b>Clash Serve</b><small>服务器管理面板</small></div>
<span class='chip hide-sm'><span class='dot {state_cls}'></span>{e(vps or env.get('DOMAIN', ''))}</span><div class=spacer></div>
<form class=inline method=post action=/logout>{hid}<button class='btn sm ghost'>退出登录</button></form></div></div>"""
        head = f"""<div class=page-h><div><h1>控制台</h1><p>{e(env.get('DOMAIN', ''))}</p></div>
<a class='btn sm' href=/>刷新</a></div>"""
        return page("控制台 · Clash Serve",
                    f"{top}<main>{fl}{head}{stats}<div class=grid>{status}{tls}</div>{zashboard}{sub}{inbounds}{add}</main>",
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
    addr = (cfg.get("listen", "0.0.0.0"), int(cfg.get("port", 8443)))
    if cfg.get("tls_cert"):
        httpd = TLSServer(addr, Panel, ROOT + cfg["tls_cert"], ROOT + cfg["tls_key"])
        scheme = "https"
    else:   # local development only
        httpd = ThreadingHTTPServer(addr, Panel)
        scheme = "http"
    sys.stderr.write(f"clashserve listening on {scheme}://{addr[0]}:{addr[1]}\n")
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
