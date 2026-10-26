#!/usr/bin/env python3
"""clashserve - minimal admin panel for clashserver (auto-cert mode).

Stdlib only (Debian python3). Listens on 127.0.0.1 behind Caddy HTTPS.
Features: admin login, Mihomo status dashboard, restart/reload, add/delete inbounds
(vless-reality, hysteria2, snell, trusttunnel) which are written to Mihomo listeners.

Subcommands:
  panel.py hash-password            read password on stdin, print hash
  panel.py serve --config FILE      run the HTTP server
"""
import argparse
import base64
import hashlib
import hmac
import html
import json
import os
import random
import re
import secrets
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
FRAG_REALITY = MIHOMO_DIR + "/listeners.reality.yaml"
FRAG_EXTRA = MIHOMO_DIR + "/listeners.extra.yaml"
TEMPLATE = ROOT + "/usr/local/lib/clashserver/resources/server.yaml.tpl"
CLIENT_TEMPLATE = ROOT + "/usr/local/lib/clashserver/resources/client.yaml.tpl"
CERT = "/etc/mihomo/certs/fullchain.pem"   # paths as seen by mihomo (not ROOT-prefixed)
KEY = "/etc/mihomo/certs/privkey.pem"
MIHOMO_BIN = os.environ.get("MIHOMO_BIN", "/usr/local/bin/mihomo")
SYSTEMCTL = os.environ.get("SYSTEMCTL", "systemctl")
REALITY_SNI = "www.sc.com"
PBKDF2_ITER = 600_000
SESSION_TTL = 12 * 3600
TYPES = ("vless-reality", "hysteria2", "snell", "trusttunnel")
CERT_TYPES = ("hysteria2", "trusttunnel")

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
                                 "pub": p[4], "sid": p[5], "sni": p[6]})
    except FileNotFoundError:
        pass
    return rows


def used_ports(env) -> set:
    ports = {80, 443, int(env.get("PANEL_PORT", "0") or 0)}
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


# ---------------------------------------------------------------- inbound model
def build_inbound(kind: str, form: dict, env: dict) -> dict:
    if kind not in TYPES:
        raise ValueError("未知的入站类型")
    if kind in CERT_TYPES and not certs_present():
        raise ValueError(f"{kind} 需要 TLS 证书，未找到 {CERT}（请先执行 systemctl start clashserver-certsync）")
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
    domain = env.get("DOMAIN", "")
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
        # client schema not verified in E2E (phase-2 scope: config only)
        client = {"name": f"{label}|Clash|TrustTunnel", "type": "trusttunnel", "server": domain,
                  "port": port, "username": user, "password": pw, "sni": domain,
                  "skip-cert-verify": insecure}
    return {"id": secrets.token_hex(6), "kind": kind, "port": port, "name": name,
            "created": int(time.time()), "listener": listener, "client": client}


def render_extra(inbounds: list) -> str:
    # YAML is a superset of JSON: one flow mapping per listener, no escaping pitfalls.
    return "".join("  - " + json.dumps(i["listener"], ensure_ascii=False) + "\n" for i in inbounds)


def assemble_config() -> str:
    """Same logic as install.sh assemble_config: template @@LISTENERS@@ <- reality + extra."""
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
            if line.rstrip("\n") == "@@LISTENERS@@":
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
        env = dict(os.environ, SAFE_PATHS="/etc/mihomo")
        return run([MIHOMO_BIN, "-t", "-d", d, "-f", path], env=env, timeout=60)


def apply_inbounds(new: list):
    """Write inbounds + fragment + config, validate, restart; roll back on failure."""
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
:root{--bg:#f4f6fb;--card:#fff;--text:#1f2937;--muted:#6b7280;--line:#e5e7eb;--primary:#2563eb;
--primary-h:#1d4ed8;--ok:#16a34a;--ok-bg:#dcfce7;--bad:#dc2626;--bad-bg:#fee2e2;--warn:#b45309;--warn-bg:#fef3c7;
--radius:12px;--shadow:0 1px 2px rgba(16,24,40,.05),0 1px 3px rgba(16,24,40,.08)}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",
"PingFang SC","Hiragino Sans GB","Microsoft YaHei","Noto Sans CJK SC",sans-serif}
.topbar{background:var(--card);border-bottom:1px solid var(--line)}
.topbar .in{max-width:1080px;margin:0 auto;padding:14px 20px;display:flex;align-items:center;gap:12px}
.brand{font-weight:700;font-size:17px}.brand span{color:var(--primary)}
.host{color:var(--muted)}.spacer{flex:1}
main{max-width:1080px;margin:0 auto;padding:24px 20px 48px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);
padding:20px 22px;margin-bottom:20px}
.grid .card{margin-bottom:0}.grid{margin-bottom:20px}
.card h2{font-size:15px;margin:0 0 14px;display:flex;align-items:center;gap:8px}
.kv{display:grid;grid-template-columns:88px 1fr;row-gap:8px;margin:0 0 16px}
.kv dt{color:var(--muted)}.kv dd{margin:0;word-break:break-all}
.pill{display:inline-block;padding:1px 10px;border-radius:999px;font-size:12px;font-weight:600}
.pill.ok{background:var(--ok-bg);color:var(--ok)}.pill.bad{background:var(--bad-bg);color:var(--bad)}
.pill.warn{background:var(--warn-bg);color:var(--warn)}.pill.tag{background:#eef2ff;color:#4338ca}
.btn{display:inline-flex;align-items:center;border:1px solid var(--line);background:#fff;color:var(--text);
border-radius:8px;padding:7px 14px;font:inherit;cursor:pointer}
.btn:hover{background:#f9fafb}.btn.primary{background:var(--primary);border-color:var(--primary);color:#fff}
.btn.primary:hover{background:var(--primary-h)}.btn.danger{color:var(--bad)}.btn.danger:hover{background:var(--bad-bg)}
.btn.sm{padding:3px 10px;font-size:12px}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
form.inline{display:inline}
.flash{border-radius:10px;padding:12px 16px;margin-bottom:20px;word-break:break-all}
.flash.ok{background:var(--ok-bg);color:#14532d}.flash.bad{background:var(--bad-bg);color:#7f1d1d}
table{width:100%;border-collapse:collapse}
th{color:var(--muted);font-weight:500;font-size:12px;text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}
td{padding:10px;border-bottom:1px solid var(--line);vertical-align:top}tr:last-child td{border-bottom:0}
td.mono,code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
pre{background:#0f172a;color:#e2e8f0;border-radius:8px;padding:12px;font-size:12px;white-space:pre-wrap;
word-break:break-all;margin:8px 0 0}
details summary{cursor:pointer;color:var(--primary);font-size:12px;display:inline}
.muted{color:var(--muted)}.empty{color:var(--muted);text-align:center;padding:24px}
.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:14px}
label{display:block;font-size:12px;color:var(--muted);margin-bottom:4px}
input,select{width:100%;padding:8px 10px;border:1px solid var(--line);border-radius:8px;font:inherit;background:#fff}
input:focus,select:focus{outline:2px solid #bfdbfe;border-color:var(--primary)}
.hint{font-size:12px;color:var(--muted);margin:12px 0 0}
.login{max-width:380px;margin:12vh auto;padding:0 20px}
.login .card{padding:28px}.login h1{font-size:20px;margin:0 0 4px}.login p.sub{color:var(--muted);margin:0 0 20px}
.login .field{margin-bottom:14px}.login .btn{width:100%;justify-content:center;padding:10px}
.err{background:var(--bad-bg);color:#7f1d1d;border-radius:8px;padding:10px 12px;margin-bottom:14px}
@media (max-width:640px){.hide-sm{display:none}}
"""

JS = """
function syncKind(){var k=document.getElementById('kind').value;
document.querySelectorAll('[data-kind]').forEach(function(e){e.style.display=e.dataset.kind===k?'':'none'})}
function copyText(id,btn){var t=document.getElementById(id).textContent;
navigator.clipboard.writeText(t).then(function(){var o=btn.textContent;btn.textContent='已复制';
setTimeout(function(){btn.textContent=o},1500)})}
document.addEventListener('DOMContentLoaded',function(){var k=document.getElementById('kind');
if(k){k.addEventListener('change',syncKind);syncKind()}});
"""

STATE_ZH = {"active": ("运行中", "ok"), "inactive": ("已停止", "bad"), "failed": ("失败", "bad"),
            "activating": ("启动中", "warn"), "deactivating": ("停止中", "warn"),
            "reloading": ("重载中", "warn")}
TLS_ZH = {"staging": ("LE 测试证书", "warn", "Let's Encrypt staging 证书不受公众信任，客户端需开启 skip-cert-verify"),
          "internal": ("内部 CA", "warn", "Caddy 内部 CA 自签证书，仅供开发测试"),
          "production": ("Let's Encrypt", "ok", "")}
KIND_ZH = {"vless-reality": "VLESS Reality", "hysteria2": "Hysteria2", "snell": "Snell",
           "trusttunnel": "TrustTunnel"}


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
            out["expires"] = time.strftime("%Y-%m-%d", time.localtime(exp))
            out["days"] = int((exp - time.time()) // 86400)
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
        ip = self.client_address[0]
        if ip in ("127.0.0.1", "::1"):
            ip = (self.headers.get("X-Forwarded-For") or ip).split(",")[0].strip()
        return ip

    def is_https(self):
        return self.headers.get("X-Forwarded-Proto") == "https"

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
        self.send(code, page(title, f"<div class=login><div class=card><h1>{html.escape(title)}</h1>"
                                    f"<p class=sub>{html.escape(text)}</p><a class='btn primary' href=/>返回</a>"
                                    f"</div></div>"))

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
            raise ValueError("body too large")
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
        if path == "/inbounds/add":
            return self.do_add(form)
        m = re.fullmatch(r"/inbounds/([0-9a-f]{12})/delete", path)
        if m:
            return self.do_delete(m.group(1))
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
        return f"https://{read_env().get('DOMAIN', '')}/sub/{token}/mihomo.yaml" if token else ""

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
        time.sleep(1)
        _, active = run([SYSTEMCTL, "is-active", "mihomo"])
        state = STATE_ZH.get(active.strip(), (active.strip(), ""))[0]
        if rc == 0:
            self.flash(f"{zh}成功，Mihomo 当前状态：{state}", active.strip() == "active")
        else:
            self.flash(f"{zh}失败：{out[-300:]}（Mihomo 当前状态：{state}）", False)

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

    # -- views
    def login_page(self, err=""):
        e = f"<div class=err>{html.escape(err)}</div>" if err else ""
        return page("登录 · clashserve", f"""<div class=login><div class=card>
<h1>clash<span style=color:var(--primary)>serve</span></h1><p class=sub>服务器管理面板</p>{e}
<form method=post action=/login>
<div class=field><label for=u>用户名</label><input id=u name=username value=admin autocomplete=username></div>
<div class=field><label for=p>密码</label><input id=p name=password type=password autocomplete=current-password autofocus></div>
<button class='btn primary'>登录</button></form></div></div>""")

    def dashboard(self, s):
        q = parse_qs(urlparse(self.path).query)
        msg, ok = q.get("msg", [""])[0], q.get("ok", ["1"])[0] == "1"
        env = read_env()
        st = mihomo_status()
        e = html.escape
        hid = f"<input type=hidden name=csrf value='{e(s['csrf'])}'>"
        listening = set(st["listening"])
        state_txt, state_cls = STATE_ZH.get(st["active"], (st["active"], "bad"))

        # --- status card
        status = f"""<div class=card><h2>Mihomo 内核 <span class='pill {state_cls}'>{e(state_txt)}</span></h2>
<dl class=kv><dt>版本</dt><dd>{e(st['version'] or '未知')}</dd>
<dt>进程 PID</dt><dd>{e(st['pid'] or '-')}</dd>
<dt>启动时间</dt><dd>{e(st['since'] or '-')}</dd>
<dt>重启次数</dt><dd>{e(st['restarts'] or '0')}</dd></dl>
<div class=row>
<form class=inline method=post action=/action/restart>{hid}<button class='btn primary'>重启</button></form>
<form class=inline method=post action=/action/reload>{hid}<button class=btn title='先校验配置，再发送 SIGHUP'>重载配置</button></form>
</div></div>"""

        # --- tls card
        tls_txt, tls_cls, tls_hint = TLS_ZH.get(env.get("TLS", ""), (env.get("TLS", "-"), "tag", ""))
        cert = parse_cert(st["cert"].get("info", ""))
        if cert:
            days = cert.get("days")
            days_html = ""
            if days is not None:
                dcls = "ok" if days > 14 else ("warn" if days > 3 else "bad")
                days_html = f" <span class='pill {dcls}'>剩余 {days} 天</span>"
            cert_rows = (f"<dt>颁发者</dt><dd>{e(cert.get('issuer', '-'))}</dd>"
                         f"<dt>到期时间</dt><dd>{e(cert.get('expires', '-'))}{days_html}</dd>")
        else:
            cert_rows = "<dt>证书</dt><dd><span class='pill bad'>未同步</span></dd>"
        hint = f"<p class=hint>{e(tls_hint)}</p>" if tls_hint else ""
        tls = f"""<div class=card><h2>域名与证书 <span class='pill {tls_cls}'>{e(tls_txt)}</span></h2>
<dl class=kv><dt>面板地址</dt><dd>https://{e(env.get('DOMAIN', '-'))}</dd>
<dt>服务器 IP</dt><dd>{e(env.get('SERVER_IP', '-'))}</dd>{cert_rows}</dl>{hint}</div>"""

        # --- inbounds table
        def state(port):
            return ("<span class='pill ok'>监听中</span>" if port in listening
                    else "<span class='pill bad'>未监听</span>")

        rows = []
        for n in read_nodes():
            rows.append(f"<tr><td>{e(n['name'])}<div class=muted style=font-size:12px>安装时生成 · 客户端配置见 info</div></td>"
                        f"<td><span class='pill tag'>VLESS Reality</span></td><td class=mono>{n['port']}</td>"
                        f"<td>{state(n['port'])}</td><td></td></tr>")
        for i in load_inbounds():
            cid = f"c-{i['id']}"
            snippet = e("- " + json.dumps(i["client"], ensure_ascii=False))
            rows.append(
                f"<tr><td>{e(i['name'])}<details><summary>客户端配置</summary>"
                f"<pre id={cid}>{snippet}</pre>"
                f"<button type=button class='btn sm' style=margin-top:6px onclick=\"copyText('{cid}',this)\">复制</button>"
                f"</details></td>"
                f"<td><span class='pill tag'>{e(KIND_ZH.get(i['kind'], i['kind']))}</span></td>"
                f"<td class=mono>{i['port']}</td><td>{state(i['port'])}</td>"
                f"<td style=text-align:right><form class=inline method=post action=/inbounds/{i['id']}/delete>{hid}"
                f"<button class='btn sm danger' onclick=\"return confirm('确定删除入站「{e(i['name'])}」？')\">删除</button>"
                f"</form></td></tr>")
        body_rows = "".join(rows) or "<tr><td colspan=5 class=empty>暂无入站</td></tr>"
        inbounds = f"""<div class=card><h2>入站节点 <span class=muted style=font-weight:400>共 {len(rows)} 个</span></h2>
<table><tr><th>名称</th><th>类型</th><th>端口</th><th>状态</th><th></th></tr>{body_rows}</table></div>"""

        # --- add form
        opts = "".join(f"<option value={k}>{v}</option>" for k, v in KIND_ZH.items())
        no_cert = "" if certs_present() else "<p class=hint>⚠ 尚未同步证书，Hysteria2 / TrustTunnel 暂不可添加。</p>"
        add = f"""<div class=card><h2>添加入站</h2>
<form method=post action=/inbounds/add>{hid}<div class=form-grid>
<div><label for=kind>类型</label><select id=kind name=kind>{opts}</select></div>
<div><label>端口</label><input name=port inputmode=numeric placeholder="留空则随机"></div>
<div><label>名称</label><input name=name placeholder="留空则自动生成"></div>
<div data-kind=snell><label>Snell 版本</label><select name=snell_version><option value=5>v5</option><option value=4>v4</option></select></div>
<div data-kind=trusttunnel><label>TrustTunnel 用户名</label><input name=tt_user placeholder="默认 user"></div>
</div><button class='btn primary'>添加</button></form>
<p class=hint>密码、UUID、密钥均自动随机生成。Hysteria2 / TrustTunnel 使用已同步的证书，Snell / Reality 无需证书。
保存前会用 <code>mihomo -t</code> 校验，失败自动回滚。</p>{no_cert}</div>"""

        url = self.sub_url()
        if url:
            sub = f"""<div class=card><h2>订阅链接 <span class='pill tag'>mihomo.yaml</span></h2>
<pre id=sub-url>{e(url)}</pre>
<div class=row style=margin-top:10px><button type=button class='btn sm' onclick="copyText('sub-url',this)">复制链接</button>
<span class=muted style=font-size:12px>包含全部节点，将链接导入 mihomo / Clash 客户端即可。链接即凭证，请勿外泄；更换链接：<code>install.sh reset-sub</code></span></div></div>"""
        else:
            sub = ""
        fl = f"<div class='flash {'ok' if ok else 'bad'}'>{e(msg)}</div>" if msg else ""
        top = f"""<div class=topbar><div class=in><div class=brand>clash<span>serve</span></div>
<div class='host hide-sm'>{e(env.get('VPS_NAME', ''))}</div><div class=spacer></div>
<form class=inline method=post action=/logout>{hid}<button class='btn sm'>退出登录</button></form></div></div>"""
        return page("控制台 · clashserve",
                    f"{top}<main>{fl}<div class=grid>{status}{tls}</div>{sub}{inbounds}{add}</main>", scripts=True)


def serve(cfg_path):
    with open(cfg_path) as f:
        cfg = json.load(f)
    Panel.cfg = cfg
    addr = (cfg.get("listen", "127.0.0.1"), int(cfg.get("port", 8088)))
    httpd = ThreadingHTTPServer(addr, Panel)
    sys.stderr.write(f"clashserve listening on {addr[0]}:{addr[1]}\n")
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
            sys.exit("password too short")
        print(hash_password(pw))
    else:
        serve(a.config)


if __name__ == "__main__":
    main()
