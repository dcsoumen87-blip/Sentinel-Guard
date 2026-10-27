import hmac
import json
import os
import re
import secrets
import time
import uuid
from functools import wraps
from pathlib import Path
from threading import Lock, RLock

from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    render_template_string,
    request,
    session,
    url_for,
)
from jinja2 import DictLoader
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash

app = Flask(__name__)

app.secret_key = os.environ.get("DASHBOARD_SECRET", "")
USERNAME = os.environ.get("DASHBOARD_USER", "")
# Plain text, OR a hash made with:
#   python -c "from werkzeug.security import generate_password_hash as g; print(g('your-password'))"
PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")
LOG_INGEST_TOKEN = os.environ.get("LOG_INGEST_TOKEN", "")

PORT = int(os.environ.get("PORT", "8080"))
LOG_DIR = Path(os.environ.get("LOG_DIR", "data/logs"))
SESSION_SECONDS = int(os.environ.get("SESSION_SECONDS", "7200"))
HEARTBEAT_STALE_SECONDS = 120

if not app.secret_key or not USERNAME or not PASSWORD:
    raise RuntimeError("Set DASHBOARD_SECRET, DASHBOARD_USER and DASHBOARD_PASSWORD.")
if len(app.secret_key) < 32:
    raise RuntimeError("DASHBOARD_SECRET must be at least 32 characters (use a long random string).")

# Render (and most hosts) put a proxy in front. Trust exactly one hop so
# request.remote_addr is the real client IP (needed for login rate limiting).
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# Limit incoming request bodies to 64 KB.
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("INSECURE_DEV_COOKIES") != "1",
    PERMANENT_SESSION_LIFETIME=SESSION_SECONDS,
    # Hard limit from login time. The page auto-refreshes, so a sliding
    # window would never expire while a tab is left open.
    SESSION_REFRESH_EACH_REQUEST=False,
)

LOG_FILES = {
    "sentinel.log": "Application Logs",
    "security.log": "Security Logs",
    "audit.log": "Audit Logs",
}

INGEST_TYPES = {
    "application": "sentinel.log",
    "security": "security.log",
    "audit": "audit.log",
}

HEARTBEAT_FILE = LOG_DIR / "heartbeat.json"
STATE_BOT = LOG_DIR / "state_bot.json"
STATE_GUILDS = LOG_DIR / "state_guilds.json"
COMMANDS_FILE = LOG_DIR / "commands.json"
COMMAND_TTL = 600  # seconds a queued command stays valid
MAX_PENDING = 50

LOG_DIR.mkdir(parents=True, exist_ok=True)
# NOTE: this lock is per-process. Run gunicorn with ONE worker (threads are fine):
#   gunicorn app:app --workers 1 --threads 4 --bind 0.0.0.0:$PORT
LOG_LOCK = Lock()
STATE_LOCK = RLock()

# ---------------------------------------------------------------- login throttle
_fail_lock = Lock()
_fails_by_ip: dict[str, list[float]] = {}
_fails_global: list[float] = []
IP_MAX, IP_WINDOW = 5, 900          # 5 failures / 15 min per IP
GLOBAL_MAX, GLOBAL_WINDOW = 30, 900  # 30 failures / 15 min overall (IP rotation)


def _prune(items: list[float], window: int, now: float) -> None:
    while items and now - items[0] > window:
        items.pop(0)


def login_blocked(ip: str) -> bool:
    now = time.time()
    with _fail_lock:
        mine = _fails_by_ip.setdefault(ip, [])
        _prune(mine, IP_WINDOW, now)
        _prune(_fails_global, GLOBAL_WINDOW, now)
        if len(_fails_by_ip) > 5000:  # bound memory
            _fails_by_ip.clear()
        return len(mine) >= IP_MAX or len(_fails_global) >= GLOBAL_MAX


def record_failure(ip: str) -> None:
    now = time.time()
    with _fail_lock:
        _fails_by_ip.setdefault(ip, []).append(now)
        _fails_global.append(now)


def _eq(a: str, b: str) -> bool:
    """Constant-time compare that also accepts non-ASCII text.

    hmac.compare_digest() on two *str* raises TypeError for non-ASCII input,
    which turned a login attempt with e.g. "é" into a 500 error.
    """
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def password_ok(candidate: str) -> bool:
    if PASSWORD.startswith(("scrypt:", "pbkdf2:")):
        return check_password_hash(PASSWORD, candidate)
    return _eq(candidate, PASSWORD)


# ---------------------------------------------------------------------- CSRF
def csrf_token() -> str:
    token = session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf"] = token
    return token


def csrf_valid() -> bool:
    sent = request.form.get("csrf", "")
    expected = session.get("csrf", "")
    return bool(expected) and _eq(sent, expected)


app.jinja_env.globals["csrf_token"] = csrf_token


@app.after_request
def security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
        "base-uri 'none'; frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Robots-Tag"] = "noindex, nofollow"
    response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Sentinel Guard Login</title>
<style>
body {
    background: #0b1020; color: white; font-family: Arial;
    display: flex; align-items: center; justify-content: center;
    min-height: 90vh; margin: 0;
}
.box {
    background: #171f33; padding: 25px; border-radius: 15px;
    width: 85%; max-width: 360px;
}
input, button {
    width: 100%; padding: 13px; margin-top: 12px;
    box-sizing: border-box; border-radius: 8px;
}
input { background: #0b1020; color: white; border: 1px solid #445; }
button { background: #625bff; color: white; border: 0; font-weight: bold; }
.error { color: #ff7777; }
</style>
</head>
<body>
<div class="box">
<h2>🛡️ Sentinel Guard</h2>
<p>Secure Dashboard Login</p>
{% if error %}<p class="error">{{ error }}</p>{% endif %}
<form method="post">
<input type="hidden" name="csrf" value="{{ csrf_token() }}">
<input name="username" placeholder="Username" required autocomplete="username">
<input name="password" type="password" placeholder="Password"
required autocomplete="current-password">
<button type="submit">Login</button>
</form>
</div>
</body>
</html>
"""

# ------------------------------------------------------------------ templates
BASE_CSS = """
body{margin:0;padding:18px;background:#0b1020;color:#edf2ff;font-family:Arial,sans-serif}
header,.card{background:#171f33;padding:16px;border-radius:12px;margin-bottom:15px}
h1{font-size:23px;margin:0}h2{font-size:18px;margin-top:0}h3{font-size:15px;margin:14px 0 6px}
a{color:#aaa5ff}.status{color:#71e6a0}.bad{color:#ff7777}.warn{color:#ffcc66}.muted{color:#8f9ac0;font-size:13px}
nav{display:flex;gap:14px;flex-wrap:wrap;align-items:center;margin-top:10px}
input,button,select{padding:10px;border-radius:7px;border:1px solid #445;box-sizing:border-box;font-size:14px}
input{background:#0b1020;color:#fff}button{background:#625bff;color:#fff;cursor:pointer;border:0}
button.danger{background:#c0392b}button.small{padding:6px 10px;font-size:12px}
.linkbtn{background:none;border:0;color:#aaa5ff;text-decoration:underline;cursor:pointer;padding:0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.stat{background:#0f1730;border-radius:10px;padding:12px}.stat b{display:block;font-size:20px;margin-top:4px}
.bar{height:8px;background:#0b1020;border-radius:6px;margin-top:8px;overflow:hidden}.bar i{display:block;height:100%;background:#625bff}
.bar i.hot{background:#ff7777}
.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:8px;border-bottom:1px solid #26304d;vertical-align:top;white-space:nowrap}
td.wrap{white-space:normal;overflow-wrap:anywhere}
pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:420px;overflow-y:auto;background:#090d18;padding:12px;border-radius:8px;font-size:12px}
form.inline{display:inline;margin:0}.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:8px}
.danger-zone{border:1px solid #6b2a2a}.pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px;background:#26304d}
.pill.ok{background:#1d4d33}.pill.bad{background:#5a2020}.pill.warn{background:#5a4a1d}
"""

TEMPLATES = {
"base.html": """<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex,nofollow">
{% if refresh %}<meta http-equiv="refresh" content="10">{% endif %}
<title>Sentinel Guard Dashboard</title><style>""" + BASE_CSS + """</style></head><body>
<header><div style="display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap">
<h1>🛡️ Sentinel Guard</h1>
<form class="inline" method="post" action="{{ url_for('logout') }}"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><button class="linkbtn" type="submit">Logout</button></form></div>
<nav><a href="{{ url_for('index') }}">Overview</a><a href="{{ url_for('logs_page') }}">Logs</a><a href="{{ url_for('commands_page') }}">Commands</a></nav>
{% if bot_hb.state == 'online' %}<p class="status">● Discord bot online — heartbeat {{ bot_hb.age }}s ago</p>
{% elif bot_hb.state == 'stale' %}<p class="bad">● Bot OFFLINE? Last heartbeat {{ bot_hb.age }}s ago. Anti-nuke may not be running.</p>
{% else %}<p class="bad">● No bot heartbeat received yet.</p>{% endif %}
</header>
{% block body %}{% endblock %}
</body></html>""",

"overview.html": """{% extends "base.html" %}{% block body %}
{% if msg %}<div class="card"><p class="status">{{ msg }}</p></div>{% endif %}
<div class="card"><h2>🖥️ Bot &amp; host</h2>
{% if bot %}
<p class="muted">Data from {{ bot_seen|ago }} ago · Python {{ bot.python }} · discord.py {{ bot.discord_py }} · {{ bot.platform }}</p>
<div class="grid">
<div class="stat">Uptime<b>{{ bot.uptime_s|uptime }}</b></div>
<div class="stat">Latency<b>{{ bot.latency_ms if bot.latency_ms is not none else '—' }} ms</b></div>
<div class="stat">Servers<b>{{ bot.guilds }}</b></div>
<div class="stat">Members seen<b>{{ bot.members }}</b></div>
<div class="stat">Host CPU ({{ bot.cpu_cores }} cores)<b>{{ bot.cpu_percent }}%</b><div class="bar"><i class="{{ 'hot' if bot.cpu_percent > 85 }}" style="width:{{ bot.cpu_percent|pct }}%"></i></div><span class="muted">Bot process: {{ bot.process_cpu_percent if bot.process_cpu_percent is not none else '—' }}%</span></div>
<div class="stat">RAM<b>{{ bot.ram_used|hbytes }} / {{ bot.ram_total|hbytes }}</b><div class="bar"><i class="{{ 'hot' if bot.ram_percent > 85 }}" style="width:{{ bot.ram_percent|pct }}%"></i></div><span class="muted">Bot process: {{ bot.process_rss|hbytes }}</span></div>
<div class="stat">Disk<b>{{ bot.disk_used|hbytes }} / {{ bot.disk_total|hbytes }}</b><div class="bar"><i class="{{ 'hot' if bot.disk_percent and bot.disk_percent > 85 }}" style="width:{{ bot.disk_percent|pct }}%"></i></div><span class="muted">Database: {{ bot.db_size|hbytes }}</span></div>
</div>
{% else %}<p class="bad">No state received from the bot yet. Check DASHBOARD_URL and LOG_INGEST_TOKEN on the bot.</p>{% endif %}
</div>

<div class="card"><h2>🌐 Servers ({{ guilds|length }})</h2>
<div class="scroll"><table><tr><th>Server</th><th>Members</th><th>Owner</th><th>Health</th><th>Whitelist</th><th>Extra owners</th><th>Incidents</th><th>Updated</th></tr>
{% for g in guilds %}<tr>
<td><a href="{{ url_for('server', gid=g.id) }}">{{ g.name }}</a></td><td>{{ g.member_count }}</td>
<td>{{ g.owner.name or '?' }} <span class="muted">{{ g.owner.id }}</span></td>
<td>{% if g.missing_perms %}<span class="pill bad">missing {{ g.missing_perms|join(', ') }}</span>{% elif g.roles_above_bot %}<span class="pill warn">{{ g.roles_above_bot }} role(s) above bot</span>{% else %}<span class="pill ok">OK</span>{% endif %}</td>
<td>{{ g.whitelist|length }}</td><td>{{ g.extra_owners|length }}</td><td>{{ g.incident_total }}</td><td class="muted">{{ g.seen|ago }}</td></tr>
{% else %}<tr><td colspan="8" class="muted">No servers reported yet.</td></tr>{% endfor %}
</table></div></div>
{% endblock %}""",

"server.html": """{% extends "base.html" %}{% macro person(p) %}{{ p.name or '?' }} <span class="muted">{{ p.id }}</span>{% endmacro %}
{% macro act(action, gid, uid, label, cls='') %}<form class="inline" method="post" action="{{ url_for('action') }}"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><input type="hidden" name="action" value="{{ action }}"><input type="hidden" name="guild_id" value="{{ gid }}"><input type="hidden" name="user_id" value="{{ uid }}">{% if action in confirm_text %}<input name="confirm" placeholder="type {{ confirm_text[action] }}" required size="10">{% endif %}<button class="small {{ cls }}" type="submit">{{ label }}</button></form>{% endmacro %}
{% block body %}
<div class="card"><h2>{{ g.name }}</h2><p class="muted">Server ID {{ g.id }} · updated {{ g.seen|ago }} ago · bot joined {{ g.bot_joined or '?' }}</p>
<div class="grid"><div class="stat">Members<b>{{ g.member_count }}</b></div>
<div class="stat">Owner<b style="font-size:15px">{{ person(g.owner) }}</b></div>
<div class="stat">Anti-nuke incidents<b>{{ g.incident_total }}</b></div>
<div class="stat">Health<b style="font-size:15px">{% if g.missing_perms %}<span class="bad">Missing: {{ g.missing_perms|join(', ') }}</span>{% elif g.roles_above_bot %}<span class="warn">{{ g.roles_above_bot }} role(s) above the bot</span>{% else %}<span class="status">OK</span>{% endif %}</b></div></div></div>

<div class="card"><h2>👑 Extra owners ({{ g.extra_owners|length }})</h2>
<div class="scroll"><table>{% for p in g.extra_owners %}<tr><td>{{ person(p) }}</td><td>{{ act('extra_owner_remove', g.id, p.id, 'Remove') }}</td></tr>{% else %}<tr><td class="muted">None</td></tr>{% endfor %}</table></div>
<form method="post" action="{{ url_for('action') }}" class="row"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><input type="hidden" name="action" value="extra_owner_add"><input type="hidden" name="guild_id" value="{{ g.id }}">
<input name="user_id" placeholder="User ID" pattern="[0-9]{5,20}" required><input name="confirm" placeholder="type {{ confirm_text['extra_owner_add'] }}" required size="10"><button class="small" type="submit">Add extra owner</button></form>
<p class="muted">Extra owners are fully trusted (never banned by anti-nuke) and can manage the whitelist.</p></div>

<div class="card"><h2>✅ Whitelist ({{ g.whitelist|length }})</h2>
<div class="scroll"><table>{% for p in g.whitelist %}<tr><td>{{ person(p) }}</td><td>{{ act('whitelist_remove', g.id, p.id, 'Remove') }}</td></tr>{% else %}<tr><td class="muted">Nobody (besides the owner, extra owners and global whitelist)</td></tr>{% endfor %}</table></div>
<form method="post" action="{{ url_for('action') }}" class="row"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><input type="hidden" name="action" value="whitelist_add"><input type="hidden" name="guild_id" value="{{ g.id }}">
<input name="user_id" placeholder="User ID" pattern="[0-9]{5,20}" required><input name="confirm" placeholder="type {{ confirm_text['whitelist_add'] }}" required size="10"><button class="small" type="submit">Add to whitelist</button></form></div>

<div class="card"><h2>🔨 Ban / unban history</h2>
<div class="scroll"><table><tr><th>When (UTC)</th><th>Event</th><th>User</th><th>By</th><th>Reason</th><th></th></tr>
{% for e in g.events %}<tr><td>{{ e.at }}</td><td><span class="pill {{ 'bad' if e.kind == 'ban' else 'ok' }}">{{ e.kind }}</span></td><td>{{ person(e.target) }}</td><td>{{ person(e.actor) }}</td><td class="wrap">{{ e.reason }}</td>
<td>{% if e.kind == 'ban' %}{{ act('unban', g.id, e.target.id, 'Unban') }}{% endif %}</td></tr>
{% else %}<tr><td colspan="6" class="muted">No bans or unbans recorded yet (recording starts when this version of the bot is running).</td></tr>{% endfor %}</table></div></div>

<div class="card"><h2>🚨 Anti-nuke incidents</h2>
<div class="scroll"><table><tr><th>When (UTC)</th><th>Actor</th><th>Action</th><th>Details</th></tr>
{% for i in g.incidents %}<tr><td>{{ i.at }}</td><td>{{ person(i.actor) }}</td><td>{{ i.action }}</td><td class="wrap">{{ i.details }}</td></tr>
{% else %}<tr><td colspan="4" class="muted">None</td></tr>{% endfor %}</table></div></div>

<div class="card danger-zone"><h2>⚠️ Danger zone</h2>
<h3>Ban a user by ID</h3>
<form method="post" action="{{ url_for('action') }}" class="row"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><input type="hidden" name="action" value="ban"><input type="hidden" name="guild_id" value="{{ g.id }}">
<input name="user_id" placeholder="User ID" pattern="[0-9]{5,20}" required><input name="confirm" placeholder="type BAN" required size="8"><button class="danger small" type="submit">Ban</button></form>
<h3>Unban a user by ID</h3>
<form method="post" action="{{ url_for('action') }}" class="row"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><input type="hidden" name="action" value="unban"><input type="hidden" name="guild_id" value="{{ g.id }}">
<input name="user_id" placeholder="User ID" pattern="[0-9]{5,20}" required><button class="small" type="submit">Unban</button></form>
<h3>Remove the bot from this server</h3>
<p class="muted">The bot leaves immediately and all protection for this server stops. Type the exact server name to confirm.</p>
<form method="post" action="{{ url_for('action') }}" class="row"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><input type="hidden" name="action" value="leave_guild"><input type="hidden" name="guild_id" value="{{ g.id }}">
<input name="confirm" placeholder="{{ g.name }}" required><button class="danger small" type="submit">Remove bot from server</button></form></div>
{% endblock %}""",

"logs.html": """{% extends "base.html" %}{% block body %}
<div class="card"><h2>🔎 Search Logs</h2><form method="get"><input name="q" value="{{ query }}" placeholder="Search log text..." style="width:100%"><div class="row"><button type="submit">Search</button></div></form></div>
{% for filename, title in logs.items() %}<div class="card"><h2>📄 {{ title }}</h2><p class="muted">File: {{ filename }}</p><pre>{{ contents[filename] }}</pre></div>{% endfor %}
{% endblock %}""",

"commands.html": """{% extends "base.html" %}{% block body %}
{% if msg %}<div class="card"><p class="status">{{ msg }}</p></div>{% endif %}
<div class="card"><h2>📬 Commands sent to the bot</h2>
<p class="muted">The bot picks these up within about 5 seconds. Commands expire after {{ ttl // 60 }} minutes if the bot is offline.</p>
<form class="row" method="post" action="{{ url_for('action') }}"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><input type="hidden" name="action" value="backup_now"><input type="hidden" name="guild_id" value="0"><button class="small" type="submit">Create database backup now</button></form>
<div class="scroll"><table><tr><th>When</th><th>Action</th><th>Server</th><th>User</th><th>Status</th><th>Result</th></tr>
{% for c in cmds %}<tr><td class="muted">{{ c.created|ago }} ago</td><td>{{ c.action }}</td><td>{{ c.guild_name or c.guild_id }}</td><td>{{ c.user_id or '' }}</td>
<td><span class="pill {{ 'ok' if c.status == 'done' else 'bad' if c.status in ('failed','expired') else 'warn' }}">{{ c.status }}</span></td><td class="wrap">{{ c.message or '' }}</td></tr>
{% else %}<tr><td colspan="6" class="muted">No commands yet.</td></tr>{% endfor %}</table></div></div>
{% endblock %}""",
}


# ------------------------------------------------------------ state storage
def _load(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _save(path: Path, data) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data), encoding="utf-8")
    temporary.replace(path)


def _s(value, limit=100) -> str:
    """Short single-line text (Jinja escapes it on output)."""
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return ""
    return " ".join(str(value).split())[:limit]


def _i(value, hi=2**63):
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= hi else None


def _n(value, hi=1e18):
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= hi else None


def _person(value) -> dict:
    if not isinstance(value, dict):
        return {"id": None, "name": None}
    return {"id": _i(value.get("id")), "name": _s(value.get("name"), 40) or None}


def _people(value, limit) -> list:
    return [_person(p) for p in value[:limit]] if isinstance(value, list) else []


def clean_bot(p: dict) -> dict:
    out = {k: _i(p.get(k)) for k in (
        "uptime_s", "latency_ms", "guilds", "members", "cpu_cores",
        "ram_used", "ram_total", "process_rss", "disk_used", "disk_total", "db_size")}
    for key in ("cpu_percent", "process_cpu_percent", "ram_percent", "disk_percent"):
        out[key] = _n(p.get(key), 100000)
    for key in ("cpu_percent", "ram_percent"):
        out[key] = out[key] or 0.0  # the template compares these numerically
    out["python"] = _s(p.get("python"), 20)
    out["discord_py"] = _s(p.get("discord_py"), 20)
    out["platform"] = _s(p.get("platform"), 80)
    ids = p.get("guild_ids")
    out["guild_ids"] = [i for i in (_i(x) for x in ids[:1000]) if i] if isinstance(ids, list) else []
    return out


def clean_guild(p: dict) -> dict | None:
    gid = _i(p.get("id"))
    if not gid:
        return None
    events = []
    for e in (p.get("events") or [])[:40] if isinstance(p.get("events"), list) else []:
        if isinstance(e, dict):
            events.append({"kind": "ban" if e.get("kind") == "ban" else "unban", "target": _person(e.get("target")),
                           "actor": _person(e.get("actor")), "reason": _s(e.get("reason"), 150), "at": _s(e.get("at"), 30)})
    incidents = []
    for e in (p.get("incidents") or [])[:30] if isinstance(p.get("incidents"), list) else []:
        if isinstance(e, dict):
            incidents.append({"actor": _person(e.get("actor")), "action": _s(e.get("action"), 60),
                              "details": _s(e.get("details"), 150), "at": _s(e.get("at"), 30)})
    return {
        "id": gid, "name": _s(p.get("name"), 100) or str(gid),
        "member_count": _i(p.get("member_count"), 10**9) or 0,
        "owner": _person(p.get("owner")), "bot_joined": _s(p.get("bot_joined"), 30),
        "missing_perms": [_s(x, 30) for x in (p.get("missing_perms") or [])[:10]] if isinstance(p.get("missing_perms"), list) else [],
        "roles_above_bot": _i(p.get("roles_above_bot"), 10**6) or 0,
        "whitelist": _people(p.get("whitelist"), 100), "extra_owners": _people(p.get("extra_owners"), 50),
        "events": events, "incidents": incidents, "incident_total": _i(p.get("incident_total"), 10**9) or 0,
        "seen": time.time(),
    }


# ------------------------------------------------------------ template filters
def _hbytes(value) -> str:
    if value is None:
        return "—"
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}"
        size /= 1024


def _uptime(seconds) -> str:
    seconds = max(0, int(seconds or 0))
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, _ = divmod(seconds, 60)
    return f"{days}d {hours}h {minutes}m"


def _ago(epoch) -> str:
    seconds = max(0, int(time.time() - float(epoch or 0)))
    if seconds < 90:
        return f"{seconds}s"
    if seconds < 5400:
        return f"{seconds // 60}m"
    if seconds < 172800:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


app.jinja_env.filters.update(hbytes=_hbytes, uptime=_uptime, ago=_ago, pct=lambda v: max(0, min(100, float(v or 0))))
app.jinja_env.loader = DictLoader(TEMPLATES)


def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login"))
        return function(*args, **kwargs)
    return wrapper


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr or "unknown"

        if login_blocked(ip):
            return render_template_string(
                LOGIN_PAGE, error="Too many failed attempts. Try again in 15 minutes."
            ), 429

        if not csrf_valid():
            return render_template_string(
                LOGIN_PAGE, error="Session expired. Reload the page and try again."
            ), 400

        username = request.form.get("username", "")[:200]
        password = request.form.get("password", "")[:200]

        # Evaluate both so timing doesn't reveal which field was wrong.
        valid_user = _eq(username, USERNAME)
        valid_password = password_ok(password)

        if valid_user and valid_password:
            session.clear()
            session["authenticated"] = True
            session.permanent = True
            return redirect(url_for("index"))

        record_failure(ip)
        return render_template_string(
            LOGIN_PAGE, error="Invalid username or password."
        ), 401

    return render_template_string(LOGIN_PAGE, error=None)


def read_heartbeat() -> dict:
    try:
        data = json.loads(HEARTBEAT_FILE.read_text(encoding="utf-8"))
        ts = float(data["ts"])
    except (OSError, ValueError, KeyError, TypeError):
        return {"state": "none", "age": None, "guilds": None, "latency": None}
    age = max(0, int(time.time() - ts))
    return {
        "state": "online" if age <= HEARTBEAT_STALE_SECONDS else "stale",
        "age": age,
        "guilds": data.get("guilds"),
        "latency": data.get("latency_ms"),
    }


@app.context_processor
def inject_heartbeat():
    return {"bot_hb": read_heartbeat()}


MESSAGES = {
    "queued": "Command sent. The bot will run it within a few seconds; see the result below.",
    "confirm": "Confirmation text did not match. Nothing was sent.",
    "full": "Too many commands are still waiting. Check that the bot is online.",
}


@app.route("/")
@login_required
def index():
    bot = _load(STATE_BOT, None)
    guilds = sorted(_load(STATE_GUILDS, {}).values(), key=lambda g: g["name"].lower())
    return render_template(
        "overview.html", bot=bot, bot_seen=(bot or {}).get("_seen", 0), guilds=guilds,
        refresh=True, msg=None,
    )


@app.route("/servers/<int:gid>")
@login_required
def server(gid):
    guild = _load(STATE_GUILDS, {}).get(str(gid))
    if not guild:
        abort(404)
    return render_template("server.html", g=guild, confirm_text=CONFIRM_TEXT, refresh=False)


@app.route("/logs")
@login_required
def logs_page():
    query = request.args.get("q", "").strip().lower()[:200]
    contents = {}

    for filename in LOG_FILES:
        path = LOG_DIR / filename

        try:
            if path.is_file():
                with path.open("rb") as file:
                    file.seek(0, os.SEEK_END)
                    size = file.tell()
                    file.seek(max(0, size - 200_000))
                    raw = file.read().decode("utf-8", errors="replace")

                lines = raw.splitlines()[-500:]
            else:
                lines = ["No logs received yet."]

            if query:
                lines = [line for line in lines if query in line.lower()]

            contents[filename] = "\n".join(lines) or "No matching log entries."

        except OSError:
            contents[filename] = "Unable to read this log file."

    return render_template("logs.html", logs=LOG_FILES, contents=contents, query=query, refresh=not query)


def _expire_commands(commands: list) -> bool:
    changed = False
    now = time.time()
    for c in commands:
        if c["status"] == "pending" and now - c["created"] > COMMAND_TTL:
            c["status"], c["message"] = "expired", "Bot did not pick this up in time"
            changed = True
    return changed


@app.route("/commands")
@login_required
def commands_page():
    with STATE_LOCK:
        commands = _load(COMMANDS_FILE, [])
        if _expire_commands(commands):
            _save(COMMANDS_FILE, commands)
    return render_template(
        "commands.html", cmds=list(reversed(commands))[:100], ttl=COMMAND_TTL,
        msg=MESSAGES.get(request.args.get("m", "")), refresh=True,
    )


# Typed confirmation required for these (leave_guild must match the server name).
CONFIRM_TEXT = {"ban": "BAN", "whitelist_add": "CONFIRM", "extra_owner_add": "CONFIRM"}
USER_ACTIONS = {"ban", "unban", "whitelist_add", "whitelist_remove", "extra_owner_add", "extra_owner_remove"}
ALL_ACTIONS = USER_ACTIONS | {"leave_guild", "backup_now"}


@app.route("/action", methods=["POST"])
@login_required
def action():
    if not csrf_valid():
        abort(400)
    name = request.form.get("action", "")
    if name not in ALL_ACTIONS:
        abort(400)

    guild_id, guild_name = 0, None
    if name != "backup_now":
        raw = request.form.get("guild_id", "").strip()
        guild = _load(STATE_GUILDS, {}).get(raw) if re.fullmatch(r"\d{1,20}", raw) else None
        if not guild:
            abort(404)
        guild_id, guild_name = guild["id"], guild["name"]

    user_id = None
    if name in USER_ACTIONS:
        raw = request.form.get("user_id", "").strip()
        if not re.fullmatch(r"\d{5,20}", raw):
            abort(400)
        user_id = int(raw)

    confirm = request.form.get("confirm", "")
    needed = guild_name if name == "leave_guild" else CONFIRM_TEXT.get(name)
    if needed is not None and not _eq(confirm, needed):
        return redirect(url_for("commands_page", m="confirm"))

    with STATE_LOCK:
        commands = _load(COMMANDS_FILE, [])
        _expire_commands(commands)
        if sum(1 for c in commands if c["status"] == "pending") >= MAX_PENDING:
            return redirect(url_for("commands_page", m="full"))
        commands.append({
            "id": uuid.uuid4().hex, "action": name, "guild_id": guild_id, "guild_name": guild_name,
            "user_id": user_id, "created": time.time(), "status": "pending", "message": "",
        })
        _save(COMMANDS_FILE, commands[-200:])
    app.logger.warning("DASHBOARD_ACTION action=%s guild=%s user=%s ip=%s", name, guild_id, user_id, request.remote_addr)
    return redirect(url_for("commands_page", m="queued"))


def _token_ok(header: str) -> bool:
    return _eq(header, f"Bearer {LOG_INGEST_TOKEN}")


def _rotate(path: Path) -> None:
    """Keep each log bounded (~1 MB), cutting at a line boundary."""
    try:
        if path.stat().st_size <= 2_000_000:
            return
        with path.open("rb") as source:
            source.seek(-1_000_000, os.SEEK_END)
            retained = source.read()
        newline = retained.find(b"\n")
        if newline != -1:
            retained = retained[newline + 1:]
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_bytes(retained)
        temporary.replace(path)
    except OSError:
        app.logger.exception("Log rotation failed")


@app.route("/api/logs", methods=["POST"])
def ingest_logs():
    # Fail closed if no ingestion token is configured.
    if not LOG_INGEST_TOKEN:
        abort(503)

    if not _token_ok(request.headers.get("Authorization", "")):
        abort(401)

    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return jsonify({"error": "Invalid JSON object"}), 400

    log_type = payload.get("type")

    if log_type == "heartbeat":
        def _small_int(value):
            return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 10_000_000 else None

        beat = {
            "ts": time.time(),
            "guilds": _small_int(payload.get("guilds")),
            "latency_ms": _small_int(payload.get("latency_ms")),
        }
        try:
            temporary = HEARTBEAT_FILE.with_suffix(".tmp")
            with LOG_LOCK:
                temporary.write_text(json.dumps(beat), encoding="utf-8")
                temporary.replace(HEARTBEAT_FILE)
        except OSError:
            app.logger.exception("Unable to save heartbeat")
            return jsonify({"error": "Unable to save heartbeat"}), 500
        return jsonify({"status": "accepted", "type": "heartbeat"}), 200

    lines = payload.get("lines")

    if log_type not in INGEST_TYPES:
        return jsonify({"error": "Invalid log type"}), 400

    if not isinstance(lines, list) or not lines or len(lines) > 100:
        return jsonify({"error": "Expected 1 to 100 log lines"}), 400

    clean_lines = []

    for line in lines:
        if not isinstance(line, str):
            return jsonify({"error": "Each log line must be text"}), 400

        # Reject embedded line breaks (and Unicode line separators) to prevent forged log entries.
        if any(ch in line for ch in ("\n", "\r", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", " ", " ")):
            return jsonify({"error": "Multiline entries are not allowed"}), 400

        clean_lines.append(line[:2000])

    filename = INGEST_TYPES[log_type]
    path = LOG_DIR / filename

    try:
        with LOG_LOCK:
            with path.open("a", encoding="utf-8") as file:
                for line in clean_lines:
                    file.write(line + "\n")
            # Rotate AFTER the append handle is closed.
            _rotate(path)

    except OSError:
        app.logger.exception("Unable to save incoming logs")
        return jsonify({"error": "Unable to save logs"}), 500

    return jsonify({
        "status": "accepted",
        "type": log_type,
        "count": len(clean_lines),
    }), 200


def _require_token() -> None:
    if not LOG_INGEST_TOKEN:
        abort(503)
    if not _token_ok(request.headers.get("Authorization", "")):
        abort(401)


def _write_heartbeat(guilds, latency) -> None:
    beat = {"ts": time.time(), "guilds": _i(guilds, 10_000_000), "latency_ms": _i(latency, 10_000_000)}
    with LOG_LOCK:
        temporary = HEARTBEAT_FILE.with_suffix(".tmp")
        temporary.write_text(json.dumps(beat), encoding="utf-8")
        temporary.replace(HEARTBEAT_FILE)


@app.route("/api/state", methods=["POST"])
def ingest_state():
    _require_token()
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Invalid JSON object"}), 400
    kind = payload.get("type")
    try:
        with STATE_LOCK:
            if kind == "bot":
                bot = clean_bot(payload)
                bot["_seen"] = time.time()
                _save(STATE_BOT, bot)
                _write_heartbeat(bot["guilds"], bot["latency_ms"])
                if isinstance(payload.get("guild_ids"), list):  # forget servers the bot has left
                    keep = {str(i) for i in bot["guild_ids"]}
                    current = _load(STATE_GUILDS, {})
                    pruned = {k: v for k, v in current.items() if k in keep}
                    if len(pruned) != len(current):
                        _save(STATE_GUILDS, pruned)
            elif kind == "guild":
                guild = clean_guild(payload)
                if guild is None:
                    return jsonify({"error": "Invalid guild"}), 400
                current = _load(STATE_GUILDS, {})
                if len(current) >= 1000 and str(guild["id"]) not in current:
                    return jsonify({"error": "Too many guilds"}), 400
                current[str(guild["id"])] = guild
                _save(STATE_GUILDS, current)
            else:
                return jsonify({"error": "Invalid state type"}), 400
    except OSError:
        app.logger.exception("Unable to save state")
        return jsonify({"error": "Unable to save state"}), 500
    return jsonify({"status": "accepted"}), 200


@app.route("/api/commands", methods=["GET"])
def fetch_commands():
    _require_token()
    with STATE_LOCK:
        commands = _load(COMMANDS_FILE, [])
        if _expire_commands(commands):
            _save(COMMANDS_FILE, commands)
    pending = [
        {k: c[k] for k in ("id", "action", "guild_id", "user_id")}
        for c in commands if c["status"] == "pending"
    ]
    return jsonify({"commands": pending[:20]})


@app.route("/api/commands/<cid>/result", methods=["POST"])
def command_result(cid):
    _require_token()
    if not re.fullmatch(r"[0-9a-f]{32}", cid):
        abort(400)
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Invalid JSON object"}), 400
    with STATE_LOCK:
        commands = _load(COMMANDS_FILE, [])
        for c in commands:
            if c["id"] == cid and c["status"] == "pending":
                c["status"] = "done" if payload.get("ok") is True else "failed"
                c["message"] = _s(payload.get("message"), 300)
                c["finished"] = time.time()
                _save(COMMANDS_FILE, commands)
                break
        else:
            return jsonify({"error": "Unknown or already finished command"}), 404
    return jsonify({"status": "ok"}), 200


@app.route("/logout", methods=["POST"])
def logout():
    # POST + CSRF so a third-party page can't log you out by embedding an image.
    if session.get("authenticated") and not csrf_valid():
        abort(400)
    session.clear()
    return redirect(url_for("login"))


@app.route("/health")
def health():
    return {"status": "ok"}


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify({"error": "Request too large"}), 413


if __name__ == "__main__":
    # Local testing only. On Render use gunicorn (see README).
    app.run(host="127.0.0.1", port=PORT, debug=False)
