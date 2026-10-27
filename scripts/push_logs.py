import os
import time
import json
import hashlib
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from dotenv import load_dotenv

load_dotenv()

LOG_DIR = Path(
    os.getenv("LOG_DIR", "/home/ubuntu/app/data/logs")
)

RENDER_LOG_URL = os.getenv("RENDER_LOG_URL", "").rstrip("/")
LOG_INGEST_TOKEN = os.getenv("LOG_INGEST_TOKEN", "")

LOG_FILES = {
    "application": LOG_DIR / "sentinel.log",
    "security": LOG_DIR / "security.log",
    "audit": LOG_DIR / "audit.log",
}

POLL_SECONDS = 10
MAX_LINES = 100
MAX_BYTES = 48_000


def read_new_lines(path, offset):
    if not path.exists():
        return [], offset

    size = path.stat().st_size

    # Handle log rotation or truncation.
    if size < offset:
        offset = 0

    with path.open("rb") as file:
        file.seek(offset)
        data = file.read(MAX_BYTES)
        new_offset = file.tell()

    lines = data.decode("utf-8", errors="replace").splitlines()

    return lines[-MAX_LINES:], new_offset


def send_logs(log_type, lines):
    if not lines:
        return True

    if not RENDER_LOG_URL or not LOG_INGEST_TOKEN:
        print("Missing RENDER_LOG_URL or LOG_INGEST_TOKEN.")
        return False

    payload = json.dumps({
        "type": log_type,
        "lines": lines,
    }).encode("utf-8")

    request = Request(
        RENDER_LOG_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {LOG_INGEST_TOKEN}",
        },
        method="POST",
    )

    try:
        with urlopen(request, timeout=15) as response:
            return 200 <= response.status < 300
    except (HTTPError, URLError, TimeoutError) as exc:
        print(f"Log transfer failed ({log_type}): {type(exc).__name__}")
        return False


def main():
    offsets = {
        name: 0
        for name in LOG_FILES
    }

    print("Sentinel Guard log forwarder started.")

    while True:
        for log_type, path in LOG_FILES.items():
            lines, next_offset = read_new_lines(
                path,
                offsets[log_type],
            )

            if not lines:
                continue

            if send_logs(log_type, lines):
                offsets[log_type] = next_offset

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
