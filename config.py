import os
from dotenv import load_dotenv
load_dotenv()
BOT_TOKEN = os.getenv("DISCORD_TOKEN", "").strip()
DEFAULT_PREFIX = os.getenv("DEFAULT_PREFIX", "!").strip() or "!"
try:
    DEVELOPER_ID = int(os.getenv("DEVELOPER_ID", "0").strip() or "0")
except ValueError:
    DEVELOPER_ID = 0
DATA_DIR = os.path.abspath(os.getenv("DATA_DIR", "./data"))
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "sentinel_guard.sqlite3")
