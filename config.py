import os
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("DISCORD_TOKEN", "").strip()
DEVELOPER_ID = int(os.getenv("DEVELOPER_ID", "0") or "0")
DEFAULT_PREFIX = os.getenv("DEFAULT_PREFIX", "!")
DATABASE_PATH = os.getenv("DATABASE_PATH", "data/sentinel.db")
BOT_NAME = "Sentinel Guard"
BOT_VERSION = "1.0.0"
