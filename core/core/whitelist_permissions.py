"""Whitelist permission management for Sentinel Guard."""

import aiosqlite

from config import DB_PATH


VALID_PERMISSIONS = {
    "channel_create",
    "channel_delete",
    "member_kick",
    "member_ban",
    "admin_grant",
}


async def init_whitelist_permissions():
    """Create the whitelist permissions table."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS whitelist_permissions (
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                permission TEXT NOT NULL,
                PRIMARY KEY (guild_id, user_id, permission)
            )
            """
        )
        await db.commit()


async def grant_permission(
    guild_id: int,
    user_id: int,
    permission: str,
) -> bool:
    """Grant one supported permission to a whitelisted user."""
    if permission not in VALID_PERMISSIONS:
        return False

    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """
            SELECT 1 FROM antinuke_whitelist
            WHERE guild_id = ? AND user_id = ?
            """,
            (guild_id, user_id),
        )
        if await cursor.fetchone() is None:
            return False

        await db.execute(
            """
            INSERT OR IGNORE INTO whitelist_permissions
            (guild_id, user_id, permission)
            VALUES (?, ?, ?)
            """,
            (guild_id, user_id, permission),
        )
        await db.commit()

    return True


async def revoke_permission(
    guild_id: int,
    user_id: int,
    permission: str,
) -> bool:
    """Revoke one supported permission."""
    if permission not in VALID_PERMISSIONS:
        return False

    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """
            DELETE FROM whitelist_permissions
            WHERE guild_id = ? AND user_id = ? AND permission = ?
            """,
            (guild_id, user_id, permission),
        )
        await db.commit()
        return cursor.rowcount > 0


async def has_permission(
    guild_id: int,
    user_id: int,
    permission: str,
) -> bool:
    """Check whether a whitelisted user has a specific permission."""
    if permission not in VALID_PERMISSIONS:
        return False

    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """
            SELECT 1 FROM antinuke_whitelist
            WHERE guild_id = ? AND user_id = ?
            """,
            (guild_id, user_id),
        )
        if await cursor.fetchone() is None:
            return False

        cursor = await db.execute(
            """
            SELECT 1 FROM whitelist_permissions
            WHERE guild_id = ? AND user_id = ? AND permission = ?
            """,
            (guild_id, user_id, permission),
        )
        return await cursor.fetchone() is not None
