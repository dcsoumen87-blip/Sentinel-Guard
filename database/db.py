import logging
import sqlite3

from contextlib import asynccontextmanager
from pathlib import Path

import aiosqlite

from config import DB_PATH, DATA_DIR


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

DATABASE_PATH = Path(DB_PATH)
DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

LOG_DIR = Path(DATA_DIR) / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_TIMEOUT = 30
DATABASE_BUSY_TIMEOUT = 30000

SCHEMA_VERSION = 1


# ============================================================
# LOGGING
# ============================================================

def configure_file_logger(name: str, filename: str):

    logger = logging.getLogger(name)

    logger.setLevel(logging.INFO)
    logger.propagate = False

    expected_path = (LOG_DIR / filename).resolve()

    exists = any(
        isinstance(handler, logging.FileHandler)
        and Path(handler.baseFilename).resolve() == expected_path
        for handler in logger.handlers
    )

    if not exists:

        handler = logging.FileHandler(
            expected_path,
            encoding="utf-8",
        )

        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s | %(levelname)s | %(message)s"
            )
        )

        logger.addHandler(handler)

    return logger


security_logger = configure_file_logger(
    "sentinel.security",
    "security.log",
)

audit_logger = configure_file_logger(
    "sentinel.audit",
    "audit.log",
)


# ============================================================
# DATABASE SCHEMA
# ============================================================

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

        mode TEXT NOT NULL DEFAULT 'ban'

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
    """,

    """
    CREATE TABLE IF NOT EXISTS automod_config (

        guild_id INTEGER PRIMARY KEY,

        enabled INTEGER NOT NULL DEFAULT 1,

        log_actions INTEGER NOT NULL DEFAULT 1

    )
    """,

    """
    CREATE TABLE IF NOT EXISTS antiraid_config (

        guild_id INTEGER PRIMARY KEY,

        enabled INTEGER NOT NULL DEFAULT 1,

        threshold INTEGER NOT NULL DEFAULT 8,

        window_seconds INTEGER NOT NULL DEFAULT 20,

        alert_channel_id INTEGER

    )
    """,

    # --------------------------------------------------------
    # WHITELIST PERMISSIONS
    # --------------------------------------------------------

    """
    CREATE TABLE IF NOT EXISTS whitelist_permissions (

        guild_id INTEGER NOT NULL,

        user_id INTEGER NOT NULL,

        permission TEXT NOT NULL,

        PRIMARY KEY (
            guild_id,
            user_id,
            permission
        )

    )
    """,

    # --------------------------------------------------------
    # ANTINUKE REJOIN CONFIGURATION
    # --------------------------------------------------------

    """
    CREATE TABLE IF NOT EXISTS antinuke_rejoin (

        guild_id INTEGER PRIMARY KEY,

        enabled INTEGER NOT NULL DEFAULT 0

    )
    """,

    # --------------------------------------------------------
    # LOCKDOWN STATE
    # --------------------------------------------------------

    """
    CREATE TABLE IF NOT EXISTS lockdown_state (

        guild_id INTEGER PRIMARY KEY,

        enabled INTEGER NOT NULL DEFAULT 0,

        activated_by INTEGER,

        reason TEXT NOT NULL DEFAULT '',

        activated_at TEXT,

        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP

    )
    """,

    # --------------------------------------------------------
    # LOCKDOWN PERMISSION BACKUPS
    # --------------------------------------------------------

    """
    CREATE TABLE IF NOT EXISTS lockdown_overwrites (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        guild_id INTEGER NOT NULL,

        channel_id INTEGER NOT NULL,

        target_id INTEGER NOT NULL,

        target_type TEXT NOT NULL,

        overwrite_data TEXT NOT NULL,

        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

        UNIQUE (
            guild_id,
            channel_id,
            target_id,
            target_type
        )

    )
    """,

    # --------------------------------------------------------
    # RECOVERY SNAPSHOTS
    # --------------------------------------------------------

    """
    CREATE TABLE IF NOT EXISTS recovery_snapshots (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        guild_id INTEGER NOT NULL,

        snapshot_type TEXT NOT NULL,

        resource_id INTEGER,

        snapshot_data TEXT NOT NULL,

        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP

    )
    """,

    # --------------------------------------------------------
    # RECOVERY OPERATION TRACKING
    # --------------------------------------------------------

    """
    CREATE TABLE IF NOT EXISTS recovery_operations (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        guild_id INTEGER NOT NULL,

        resource_id INTEGER,

        operation TEXT NOT NULL,

        status TEXT NOT NULL DEFAULT 'pending',

        details TEXT NOT NULL DEFAULT '',

        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

        completed_at TEXT

    )
    """,

]


# ============================================================
# DATABASE INDEXES
# ============================================================

INDEXES = [

    """
    CREATE INDEX IF NOT EXISTS idx_security_logs_guild
    ON security_logs(guild_id)
    """,

    """
    CREATE INDEX IF NOT EXISTS idx_security_logs_created
    ON security_logs(created_at)
    """,

    """
    CREATE INDEX IF NOT EXISTS idx_antinue_incidents_guild
    ON antinuke_incidents(guild_id)
    """,

    """
    CREATE INDEX IF NOT EXISTS idx_warnings_user
    ON warnings(guild_id, user_id)
    """,

    """
    CREATE INDEX IF NOT EXISTS idx_recovery_guild
    ON recovery_snapshots(guild_id)
    """,

    """
    CREATE INDEX IF NOT EXISTS idx_recovery_operations_guild
    ON recovery_operations(guild_id)
    """,

]


# ============================================================
# SAFE DATABASE CONNECTION
# ============================================================

@asynccontextmanager
async def get_db():

    db = await aiosqlite.connect(
        DATABASE_PATH,
        timeout=DATABASE_TIMEOUT,
    )

    try:

        await db.execute(
            f"PRAGMA busy_timeout={DATABASE_BUSY_TIMEOUT}"
        )

        await db.execute(
            "PRAGMA foreign_keys=ON"
        )

        db.row_factory = aiosqlite.Row

        yield db

    finally:

        await db.close()


# ============================================================
# COLUMN INSPECTION
# ============================================================

async def get_table_columns(db, table_name: str):

    cursor = await db.execute(
        f"PRAGMA table_info({table_name})"
    )

    rows = await cursor.fetchall()

    return {
        row["name"]
        for row in rows
    }


# ============================================================
# SAFE COLUMN MIGRATION
# ============================================================

async def ensure_column(
    db,
    table_name: str,
    column_name: str,
    column_definition: str,
):

    columns = await get_table_columns(
        db,
        table_name,
    )

    if column_name in columns:
        return False

    # Identifiers are internal hard-coded migration values.
    allowed_tables = {
        "guild_settings",
        "security_logs",
        "antinuke_config",
        "automod_config",
        "antiraid_config",
        "server_extra_owners",
    }

    if table_name not in allowed_tables:
        raise ValueError(
            f"Unknown migration table: {table_name}"
        )

    if not column_name.replace("_", "").isalnum():
        raise ValueError("Invalid column name")

    await db.execute(
        f"""
        ALTER TABLE {table_name}
        ADD COLUMN {column_name} {column_definition}
        """
    )

    return True


# ============================================================
# MIGRATIONS
# ============================================================

async def run_migrations(db):

    # Existing tables are preserved.
    # Missing tables are created with IF NOT EXISTS.

    for statement in SCHEMA:

        await db.execute(statement)

    # Future-compatible schema checks.
    # These additions are safe for existing installations.

    migrations = [

        (
            "guild_settings",
            "raid_mode",
            "INTEGER NOT NULL DEFAULT 0",
        ),

        (
            "guild_settings",
            "automod_enabled",
            "INTEGER NOT NULL DEFAULT 1",
        ),

        (
            "antinuke_config",
            "enabled",
            "INTEGER NOT NULL DEFAULT 1",
        ),

        (
            "antinuke_config",
            "threshold",
            "INTEGER NOT NULL DEFAULT 4",
        ),

        (
            "antinuke_config",
            "window_seconds",
            "INTEGER NOT NULL DEFAULT 10",
        ),

        (
            "automod_config",
            "enabled",
            "INTEGER NOT NULL DEFAULT 1",
        ),

        (
            "automod_config",
            "log_actions",
            "INTEGER NOT NULL DEFAULT 1",
        ),

    ]

    for table, column, definition in migrations:

        await ensure_column(
            db,
            table,
            column,
            definition,
        )

    for statement in INDEXES:

        await db.execute(statement)

    await db.execute(
        f"PRAGMA user_version={SCHEMA_VERSION}"
    )


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

_db_init_lock = None


async def init_db():

    global _db_init_lock

    import asyncio

    if _db_init_lock is None:
        _db_init_lock = asyncio.Lock()

    async with _db_init_lock:

        async with aiosqlite.connect(
            DATABASE_PATH,
            timeout=DATABASE_TIMEOUT,
        ) as db:

            await db.execute(
                f"PRAGMA busy_timeout={DATABASE_BUSY_TIMEOUT}"
            )

            await db.execute(
                "PRAGMA journal_mode=WAL"
            )

            await db.execute(
                "PRAGMA foreign_keys=ON"
            )

            await db.execute(
                "PRAGMA synchronous=NORMAL"
            )

            try:

                await db.execute("BEGIN IMMEDIATE")

                await run_migrations(db)

                await db.commit()

                security_logger.info(
                    "Database initialization completed. Schema version=%s",
                    SCHEMA_VERSION,
                )

            except Exception:

                await db.rollback()

                security_logger.exception(
                    "Database initialization failed"
                )

                raise


# ============================================================
# PREFIX MANAGEMENT
# ============================================================

async def get_prefix(guild_id: int, default: str = "!"):

    async with get_db() as db:

        cursor = await db.execute(
            """
            SELECT prefix
            FROM guild_settings
            WHERE guild_id = ?
            """,
            (guild_id,),
        )

        row = await cursor.fetchone()

        return row["prefix"] if row and row["prefix"] else default


async def set_prefix(guild_id: int, prefix: str):

    if not prefix or len(prefix) > 10:
        raise ValueError("Invalid prefix")

    async with get_db() as db:

        await db.execute(
            """
            INSERT INTO guild_settings (
                guild_id,
                prefix
            )
            VALUES (?, ?)

            ON CONFLICT(guild_id)
            DO UPDATE SET prefix = excluded.prefix
            """,
            (guild_id, prefix),
        )

        await db.commit()


# ============================================================
# LOG CHANNEL MANAGEMENT
# ============================================================

async def get_log_channel(guild_id: int):

    async with get_db() as db:

        cursor = await db.execute(
            """
            SELECT log_channel_id
            FROM guild_settings
            WHERE guild_id = ?
            """,
            (guild_id,),
        )

        row = await cursor.fetchone()

        return row["log_channel_id"] if row else None


async def set_log_channel(
    guild_id: int,
    channel_id: int | None,
):

    async with get_db() as db:

        await db.execute(
            """
            INSERT INTO guild_settings (
                guild_id,
                log_channel_id
            )
            VALUES (?, ?)

            ON CONFLICT(guild_id)
            DO UPDATE SET
                log_channel_id = excluded.log_channel_id
            """,
            (guild_id, channel_id),
        )

        await db.commit()


# ============================================================
# SECURITY LOGGING
# ============================================================

async def add_security_log(
    guild_id: int,
    action: str,
    details: str = "",
    actor_id: int | None = None,
):

    safe_action = str(action)[:200].replace("\n", " ")

    safe_details = str(details)[:1500].replace("\n", " ")

    async with get_db() as db:

        await db.execute(
            """
            INSERT INTO security_logs (
                guild_id,
                action,
                details,
                actor_id
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                guild_id,
                safe_action,
                safe_details,
                actor_id,
            ),
        )

        await db.commit()

    security_logger.info(
        "guild_id=%s | action=%s | actor_id=%s | details=%s",
        guild_id,
        safe_action,
        actor_id,
        safe_details,
    )


# ============================================================
# AUDIT LOGGING
# ============================================================

async def add_audit_log(
    guild_id: int,
    action: str,
    details: str = "",
    actor_id: int | None = None,
):

    safe_action = str(action)[:200].replace("\n", " ")

    safe_details = str(details)[:1500].replace("\n", " ")

    audit_logger.info(
        "guild_id=%s | action=%s | actor_id=%s | details=%s",
        guild_id,
        safe_action,
        actor_id,
        safe_details,
    )
