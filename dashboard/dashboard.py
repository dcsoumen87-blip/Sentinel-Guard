import os
import hmac
from pathlib import Path
from functools import wraps

from flask import (
    Flask,
    request,
    session,
    redirect,
    url_for,
    render_template_string,
    abort,
)

app = Flask(__name__)

app.secret_key = os.environ.get("DASHBOARD_SECRET", "")
USERNAME = os.environ.get("DASHBOARD_USER", "")
PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")

# Render uses PORT; local testing defaults to 8080.
PORT = int(os.environ.get("PORT", "8080"))

# Log directory can be configured through an environment variable.
LOG_DIR = Path(os.environ.get("LOG_DIR", "data/logs"))

if not app.secret_key or not USERNAME or not PASSWORD:
    raise RuntimeError(
        "Set DASHBOARD_SECRET, DASHBOARD_USER and DASHBOARD_PASSWORD."
    )

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,
    PERMANENT_SESSION_LIFETIME=1800,
)

LOG_FILES = {
    "sentinel.log": "Application Logs",
    "security.log": "Security Logs",
    "audit.log": "Audit Logs",
}

LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
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
<input name="username" placeholder="Username" required autocomplete="username">
<input name="password" type="password" placeholder="Password"
required autocomplete="current-password">
<button type="submit">Login</button>
</form>
</div>
</body>
</html>
"""

DASHBOARD_PAGE = """
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="10">
<title>Sentinel Guard Dashboard</title>
<style>
body {
    margin: 0; padding: 18px; background: #0b1020;
    color: #edf2ff; font-family: Arial, sans-serif;
}
header, .card {
    background: #171f33; padding: 16px;
    border-radius: 12px; margin-bottom: 15px;
}
h1 { font-size: 23px; }
h2 { font-size: 18px; }
a { color: #aaa5ff; }
.status { color: #71e6a0; }
input, button {
    padding: 11px; border-radius: 7px;
    border: 1px solid #445; box-sizing: border-box;
}
input { background: #0b1020; color: white; width: 100%; }
button { background: #625bff; color: white; margin-top: 8px; }
pre {
    white-space: pre-wrap; overflow-wrap: anywhere;
    max-height: 420px; overflow-y: auto;
    background: #090d18; padding: 12px; border-radius: 8px;
    font-size: 12px;
}
.top { display: flex; justify-content: space-between; gap: 10px; }
</style>
</head>
<body>
<header>
<div class="top">
<h1>🛡️ Sentinel Guard</h1>
<a href="{{ url_for('logout') }}">Logout</a>
</div>
<p class="status">● Dashboard Online</p>
<p>Auto-refresh: 10 seconds</p>
<p>Note: Dashboard status does not confirm the Discord bot is online.</p>
</header>

<div class="card">
<h2>🔎 Search Logs</h2>
<form method="get">
<input name="q" value="{{ query }}" placeholder="Search log text...">
<button type="submit">Search</button>
</form>
</div>

{% for filename, title in logs.items() %}
<div class="card">
<h2>📄 {{ title }}</h2>
<p>File: {{ filename }}</p>
<pre>{{ contents[filename] }}</pre>
</div>
{% endfor %}
</body>
</html>
"""


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
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        valid_user = hmac.compare_digest(username, USERNAME)
        valid_password = hmac.compare_digest(password, PASSWORD)

        if valid_user and valid_password:
            session.clear()
            session["authenticated"] = True
            session.permanent = True
            return redirect(url_for("index"))

        return render_template_string(
            LOGIN_PAGE, error="Invalid username or password."
        ), 401

    return render_template_string(LOGIN_PAGE, error=None)


@app.route("/")
@login_required
def index():
    query = request.args.get("q", "").strip().lower()[:200]
    contents = {}

    for filename in LOG_FILES:
        path = LOG_DIR / filename

        try:
            # Read only the last 200 KB from each log.
            if path.is_file():
                with path.open("rb") as file:
                    file.seek(0, os.SEEK_END)
                    size = file.tell()
                    file.seek(max(0, size - 200_000))
                    raw = file.read().decode("utf-8", errors="replace")
                lines = raw.splitlines()[-500:]
            else:
                lines = ["Log file not found on this host."]

            if query:
                lines = [line for line in lines if query in line.lower()]

            contents[filename] = "\n".join(lines) or "No matching log entries."

        except OSError:
            contents[filename] = "Unable to read this log file."

    return render_template_string(
        DASHBOARD_PAGE,
        logs=LOG_FILES,
        contents=contents,
        query=query,
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/health")
def health():
    # Only a basic service health check; no secrets or log contents.
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False)
