import os
import aiosqlite
from config import DATABASE_PATH, DEFAULT_PREFIX


async def init_db():
    folder = os.path.dirname(DATABASE_PATH)
    if folder:
        os.makedirs(folder, exist_ok=True)
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS guild_settings (
                guild_id INTEGER PRIMARY KEY,
                prefix TEXT NOT NULL DEFAULT '!'
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                actor_id INTEGER,
                action TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS warnings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                member_id INTEGER NOT NULL,
                moderator_id INTEGER NOT NULL,
                reason TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS setup_state (
                guild_id INTEGER PRIMARY KEY,
                status TEXT NOT NULL DEFAULT 'not_started',
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.commit()


async def get_prefix(guild_id, default=None):
    if guild_id is None:
        return default or DEFAULT_PREFIX
    async with aiosqlite.connect(DATABASE_PATH) as db:
        async with db.execute(
            "SELECT prefix FROM guild_settings WHERE guild_id = ?", (guild_id,)
        ) as cursor:
            row = await cursor.fetchone()
    return row[0] if row else (default or DEFAULT_PREFIX)


async def set_prefix(guild_id, prefix):
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            INSERT INTO guild_settings (guild_id, prefix) VALUES (?, ?)
            ON CONFLICT(guild_id) DO UPDATE SET prefix = excluded.prefix
        """, (guild_id, prefix))
        await db.commit()


async def add_security_log(guild_id, action, details="", actor_id=None):
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            INSERT INTO security_logs (guild_id, actor_id, action, details)
            VALUES (?, ?, ?, ?)
        """, (guild_id, actor_id, action, details[:1500]))
        await db.commit()


async def add_warning(guild_id, member_id, moderator_id, reason):
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            INSERT INTO warnings (guild_id, member_id, moderator_id, reason)
            VALUES (?, ?, ?, ?)
        """, (guild_id, member_id, moderator_id, reason[:1000]))
        await db.commit()


async def get_warnings(guild_id, member_id, limit=10):
    async with aiosqlite.connect(DATABASE_PATH) as db:
        async with db.execute("""
            SELECT id, moderator_id, reason, created_at
            FROM warnings
            WHERE guild_id = ? AND member_id = ?
            ORDER BY id DESC LIMIT ?
        """, (guild_id, member_id, limit)) as cursor:
            return await cursor.fetchall()


async def clear_warnings(guild_id, member_id):
    async with aiosqlite.connect(DATABASE_PATH) as db:
        cursor = await db.execute(
            "DELETE FROM warnings WHERE guild_id = ? AND member_id = ?",
            (guild_id, member_id)
        )
        await db.commit()
        return cursor.rowcount


async def set_setup_status(guild_id, status):
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            INSERT INTO setup_state (guild_id, status, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(guild_id) DO UPDATE SET
                status = excluded.status, updated_at = CURRENT_TIMESTAMP
        """, (guild_id, status))
        await db.commit()
