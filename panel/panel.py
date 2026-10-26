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
TEMPLATE = ROOT + "/usr/local/lib/clashserver/server.yaml.tpl"
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
    raise RuntimeError("no free port")


def reality_keypair():
    rc, out = run([MIHOMO_BIN, "generate", "reality-keypair"])
    priv = re.search(r"PrivateKey:\s*(\S+)", out)
    pub = re.search(r"PublicKey:\s*(\S+)", out)
    if rc != 0 or not priv or not pub:
        raise RuntimeError("reality keypair generation failed: " + out)
    return priv.group(1), pub.group(1)


def certs_present() -> bool:
    return os.path.isfile(ROOT + CERT) and os.path.isfile(ROOT + KEY)


# ---------------------------------------------------------------- inbound model
def build_inbound(kind: str, form: dict, env: dict) -> dict:
    if kind not in TYPES:
        raise ValueError("unknown type")
    if kind in CERT_TYPES and not certs_present():
        raise ValueError(f"{kind} needs a TLS certificate; {CERT} not found (run certsync)")
    port_s = form.get("port", "").strip()
    if port_s:
        if not port_s.isdigit() or not 1 <= int(port_s) <= 65535:
            raise ValueError("invalid port")
        port = int(port_s)
        if port in used_ports(env):
            raise ValueError(f"port {port} already in use")
    else:
        port = pick_port(env)
    name = form.get("name", "").strip() or f"{kind}-{port}"
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,48}", name):
        raise ValueError("name: 1-48 chars of A-Z a-z 0-9 . _ -")
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
            raise ValueError("snell version must be 4 or 5")
        psk = base64.b64encode(secrets.token_bytes(16)).decode()
        listener = {**base, "type": "snell", "psk": psk, "version": version, "udp": True,
                    "obfs-opts": {"mode": "tls", "host": REALITY_SNI}}
        client = {"name": f"{label}|Clash|Snell", "type": "snell", "server": ip, "port": port,
                  "psk": psk, "version": version, "udp": True,
                  "obfs-opts": {"mode": "tls", "host": REALITY_SNI}}
    else:  # trusttunnel
        user = form.get("tt_user", "").strip() or "user"
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", user):
            raise ValueError("invalid trusttunnel username")
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
            raise RuntimeError("mihomo -t failed: " + out[-800:])
        rc, out = run([SYSTEMCTL, "restart", "mihomo"])
        if rc != 0:
            raise RuntimeError("restart failed: " + out[-800:])
    except Exception:
        for p, data in backup.items():
            if data is None:
                if os.path.exists(p):
                    os.remove(p)
            else:
                atomic_write(p, data, 0o600 if p == INBOUNDS else 0o640)
        run([SYSTEMCTL, "restart", "mihomo"])
        raise


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
CSS = """body{font-family:system-ui,sans-serif;max-width:980px;margin:2em auto;padding:0 1em;color:#222}
h1{font-size:1.4em}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:.35em;text-align:left;font-size:.9em}
.ok{color:#080}.bad{color:#c00}.card{border:1px solid #ddd;border-radius:6px;padding:1em;margin:1em 0}
code{font-size:.78em;word-break:break-all}button{padding:.4em 1em;margin-right:.5em}.msg{background:#ffd;padding:.5em}
input,select{padding:.3em;margin:.2em}"""


def page(title, body):
    return (f"<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width'>"
            f"<title>{html.escape(title)}</title><style>{CSS}</style></head><body>{body}</body></html>")


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
        self.send(404, page("404", "<p>not found</p>"))

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            form = self.form()
        except ValueError:
            return self.send(413, "too large", "text/plain")
        if path == "/login":
            return self.do_login(form)
        tok, s = self.session()
        if not s:
            return self.redirect("/login")
        if not self.check_csrf(s, form):
            return self.send(403, page("403", "<p>bad csrf token</p>"))
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
        self.send(404, page("404", "<p>not found</p>"))

    def do_login(self, form):
        ip, now = self.client_ip(), time.time()
        recent = [t for t in self.fails.get(ip, []) if now - t < 600]
        if len(recent) >= 5:
            return self.send(429, self.login_page("Too many attempts, try again in 10 minutes."))
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
        self.send(401, self.login_page("Invalid username or password."))

    def do_action(self, action):
        with LOCK:
            if action == "reload":
                rc, out = validate_config()
                if rc != 0:
                    return self.redirect("/?msg=" + quote("config invalid, not reloaded: " + out[-300:]))
            rc, out = run([SYSTEMCTL, action, "mihomo"])
        time.sleep(1)
        _, active = run([SYSTEMCTL, "is-active", "mihomo"])
        msg = f"{action}: {'ok' if rc == 0 else 'failed ' + out[-300:]} (mihomo {active.strip()})"
        self.redirect("/?msg=" + quote(msg))

    def do_add(self, form):
        env = read_env()
        with LOCK:
            try:
                inb = build_inbound(form.get("kind", ""), form, env)
                apply_inbounds(load_inbounds() + [inb])
                msg = f"added {inb['kind']} {inb['name']} on port {inb['port']}"
            except Exception as e:
                msg = f"add failed: {e}"
        self.redirect("/?msg=" + quote(msg[:600]))

    def do_delete(self, iid):
        with LOCK:
            cur = load_inbounds()
            new = [i for i in cur if i["id"] != iid]
            if len(new) == len(cur):
                return self.redirect("/?msg=" + quote("no such inbound"))
            try:
                apply_inbounds(new)
                msg = "deleted"
            except Exception as e:
                msg = f"delete failed: {e}"
        self.redirect("/?msg=" + quote(msg[:600]))

    # -- views
    def login_page(self, err=""):
        e = f"<p class=bad>{html.escape(err)}</p>" if err else ""
        return page("clashserve login", f"""<h1>clashserve</h1>{e}
<form method=post action=/login class=card>
<p><input name=username placeholder=username value=admin autocomplete=username></p>
<p><input name=password type=password placeholder=password autocomplete=current-password autofocus></p>
<p><button>Log in</button></p></form>""")

    def dashboard(self, s):
        q = parse_qs(urlparse(self.path).query)
        msg = q.get("msg", [""])[0]
        env = read_env()
        st = mihomo_status()
        csrf = html.escape(s["csrf"])
        hid = f"<input type=hidden name=csrf value='{csrf}'>"
        cls = "ok" if st["active"] == "active" else "bad"
        listening = set(st["listening"])

        def lrow(name, kind, port, extra=""):
            up = "<span class=ok>listening</span>" if port in listening else "<span class=bad>not listening</span>"
            return (f"<tr><td>{html.escape(name)}</td><td>{html.escape(kind)}</td><td>{port}</td>"
                    f"<td>{up}</td><td>{extra}</td></tr>")

        rows = [lrow(n["name"], "vless-reality (install)", n["port"]) for n in read_nodes()]
        for i in load_inbounds():
            snippet = html.escape(json.dumps(i["client"], ensure_ascii=False))
            delete = (f"<form method=post action=/inbounds/{i['id']}/delete style=display:inline>{hid}"
                      f"<button onclick=\"return confirm('delete?')\">delete</button></form>")
            rows.append(lrow(i["name"], i["kind"], i["port"],
                             f"{delete}<details><summary>client proxy</summary><code>- {snippet}</code></details>"))
        tls_note = {"staging": " (LE staging - clients need skip-cert-verify)",
                    "internal": " (Caddy internal CA - dev only)"}.get(env.get("TLS", ""), "")
        cert = html.escape(st["cert"].get("info", "no certificate synced"))
        opts = "".join(f"<option>{t}</option>" for t in TYPES)
        m = f"<p class=msg>{html.escape(msg)}</p>" if msg else ""
        return page("clashserve", f"""<h1>clashserve · {html.escape(env.get('VPS_NAME', ''))}</h1>{m}
<div class=card><h3>Mihomo</h3>
<p>Status: <b class={cls}>{html.escape(st['active'])}</b> · PID {html.escape(st['pid'])} · restarts {html.escape(st['restarts'])}</p>
<p>Since: {html.escape(st['since'])}</p><p>Version: {html.escape(st['version'])}</p>
<form method=post action=/action/restart style=display:inline>{hid}<button>Restart</button></form>
<form method=post action=/action/reload style=display:inline>{hid}<button>Reload (validate + SIGHUP)</button></form>
</div>
<div class=card><h3>TLS</h3><p>Domain: {html.escape(env.get('DOMAIN', ''))}{html.escape(tls_note)}</p><p><code>{cert}</code></p></div>
<div class=card><h3>Inbounds</h3><table><tr><th>name</th><th>type</th><th>port</th><th>state</th><th></th></tr>
{''.join(rows)}</table>
<h4>Add inbound</h4><form method=post action=/inbounds/add>{hid}
<select name=kind>{opts}</select>
<input name=port placeholder="port (blank = random)" size=18>
<input name=name placeholder="name (optional)" size=18>
<select name=snell_version title="snell only"><option value=5>snell v5</option><option value=4>snell v4</option></select>
<input name=tt_user placeholder="trusttunnel user" size=14>
<button>Add</button></form>
<p style=font-size:.85em>hysteria2 / trusttunnel use the synced certificate; snell / reality need none. Changes are validated with <code>mihomo -t</code> and rolled back on failure.</p>
</div>
<form method=post action=/logout>{hid}<button>Log out</button></form>""")


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
