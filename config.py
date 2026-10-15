import os
from dotenv import load_dotenv

load_dotenv()


# ==========================================
# SENTINEL GUARD CONFIGURATION
# ==========================================

BOT_NAME = "Sentinel Guard"
BOT_VERSION = "1.0.0"

DEFAULT_PREFIX = os.getenv("DEFAULT_PREFIX", "!").strip() or "!"

DATABASE_PATH = os.getenv(
    "DATABASE_PATH",
    "data/sentinel.db"
).strip() or "data/sentinel.db"


# ==========================================
# ENVIRONMENT VARIABLES
# ==========================================

BOT_TOKEN = os.getenv(
    "DISCORD_TOKEN",
    ""
).strip()


def load_developer_id():
    """
    Load the configured Discord Developer ID.

    Invalid or placeholder values return 0,
    disabling Developer-only access safely.
    """

    value = os.getenv(
        "DEVELOPER_ID",
        "0"
    ).strip()

    if not value.isdigit():
        return 0

    user_id = int(value)

    if user_id <= 0:
        return 0

    return user_id


DEVELOPER_ID = load_developer_id()


# ==========================================
# SECURITY SETTINGS
# ==========================================

MAX_PREFIX_LENGTH = 5

MAX_WARNINGS_DISPLAY = 10

MAX_PURGE_MESSAGES = 100

SETUP_MODE_DEFAULT = "maximum"

# Safety: automated destructive actions are disabled
# unless a separately reviewed feature implements them.
ENABLE_AUTOMATIC_MASS_BAN = False

ENABLE_UNSOLICITED_BULK_DMS = False
