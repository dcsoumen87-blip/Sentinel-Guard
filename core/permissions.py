"""Permission checks for Sentinel Guard."""

import aiosqlite

from config import DB_PATH


async def is_server_owner(guild, user_id: int) -> bool:
    """Check whether the user owns the Discord server."""
    return guild.owner_id == user_id


async def is_extra_owner(guild_id: int, user_id: int) -> bool:
    """Check whether the user is an Extra Owner."""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """
            SELECT 1
            FROM server_extra_owners
            WHERE guild_id = ? AND user_id = ?
            """,
            (guild_id, user_id),
        )
        return await cursor.fetchone() is not None


async def is_whitelisted(guild_id: int, user_id: int) -> bool:
    """Check whether the user is on the AntiNuke whitelist."""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """
            SELECT 1
            FROM antinuke_whitelist
            WHERE guild_id = ? AND user_id = ?
            """,
            (guild_id, user_id),
        )
        return await cursor.fetchone() is not None


async def get_access_level(guild, user_id: int) -> str:
    """Return the user's highest recognized access level."""
    if await is_server_owner(guild, user_id):
        return "server_owner"

    if await is_extra_owner(guild.id, user_id):
        return "extra_owner"

    if await is_whitelisted(guild.id, user_id):
        return "whitelist"

    return "member"


async def can_manage_extra_owners(guild, user_id: int) -> bool:
    """Only the actual Discord Server Owner can manage Extra Owners."""
    return await is_server_owner(guild, user_id)


async def can_manage_security(guild, user_id: int) -> bool:
    """Server Owner and Extra Owners can manage security settings."""
    level = await get_access_level(guild, user_id)
    return level in {"server_owner", "extra_owner"}
