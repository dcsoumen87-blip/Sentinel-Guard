import logging
from pathlib import Path

import aiosqlite

from config import DB_PATH, DATA_DIR


LOG_DIR = Path(DATA_DIR) / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

security_logger = logging.getLogger("sentinel.security")
security_logger.setLevel(logging.INFO)
security_logger.propagate = False

if not security_logger.handlers:
    handler = logging.FileHandler(
        LOG_DIR / "security.log",
        encoding="utf-8"
    )
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s | %(levelname)s | %(message)s"
        )
    )
    security_logger.addHandler(handler)


audit_logger = logging.getLogger("sentinel.audit")
audit_logger.setLevel(logging.INFO)
audit_logger.propagate = False

if not audit_logger.handlers:
    handler = logging.FileHandler(
        LOG_DIR / "audit.log",
        encoding="utf-8"
    )
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s | %(levelname)s | %(message)s"
        )
    )
    audit_logger.addHandler(handler)


SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS guild_settings (
        guild_id INTEGER PRIMARY KEY,
        prefix TEXT NOT NULL DEFAULT '!',
        log_channel_id INTEGER,
        raid_mode INTEGER NOT NULL DEFAULT 0,
        automod_enabled INTEGER NOT NULL DEFAULT 1
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS security_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        details TEXT NOT NULL DEFAULT '',
        actor_id INTEGER,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS antinuke_config (
        guild_id INTEGER PRIMARY KEY,
        enabled INTEGER NOT NULL DEFAULT 1,
        threshold INTEGER NOT NULL DEFAULT 4,
        window_seconds INTEGER NOT NULL DEFAULT 10,
        alert_channel_id INTEGER,
        mode TEXT NOT NULL DEFAULT 'alert'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS antinuke_whitelist (
        guild_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        PRIMARY KEY (guild_id, user_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS server_extra_owners (
        guild_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (guild_id, user_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS antinuke_incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id INTEGER NOT NULL,
        actor_id INTEGER,
        action TEXT NOT NULL,
        event_count INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        details TEXT NOT NULL DEFAULT ''
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS warnings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        moderator_id INTEGER NOT NULL,
        reason TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """
]


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA foreign_keys=ON")

        for sql in SCHEMA:
            await db.execute(sql)

        await db.commit()


async def get_prefix(guild_id, default="!"):
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "SELECT prefix FROM guild_settings WHERE guild_id = ?",
            (guild_id,)
        )
        row = await cursor.fetchone()

        return row[0] if row and row[0] else default


async def set_prefix(guild_id, prefix):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO guild_settings (guild_id, prefix)
            VALUES (?, ?)
            ON CONFLICT(guild_id)
            DO UPDATE SET prefix = excluded.prefix
            """,
            (guild_id, prefix)
        )
        await db.commit()


async def get_log_channel(guild_id):
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "SELECT log_channel_id FROM guild_settings WHERE guild_id = ?",
            (guild_id,)
        )
        row = await cursor.fetchone()

        return row[0] if row else None


async def set_log_channel(guild_id, channel_id):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO guild_settings (guild_id, log_channel_id)
            VALUES (?, ?)
            ON CONFLICT(guild_id)
            DO UPDATE SET log_channel_id = excluded.log_channel_id
            """,
            (guild_id, channel_id)
        )
        await db.commit()


async def add_security_log(
    guild_id,
    action,
    details="",
    actor_id=None
):
    safe_details = str(details)[:1500]
    safe_action = str(action)[:200]

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO security_logs
            (guild_id, action, details, actor_id)
            VALUES (?, ?, ?, ?)
            """,
            (guild_id, safe_action, safe_details, actor_id)
        )
        await db.commit()

    security_logger.info(
        "guild_id=%s | action=%s | actor_id=%s | details=%s",
        guild_id,
        safe_action,
        actor_id,
        safe_details.replace("\n", " ")
    )


async def add_audit_log(
    guild_id,
    action,
    details="",
    actor_id=None
):
    audit_logger.info(
        "guild_id=%s | action=%s | actor_id=%s | details=%s",
        guild_id,
        str(action)[:200],
        actor_id,
        str(details)[:1500].replace("\n", " ")
    )
