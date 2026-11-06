# core/permissions.py

"""
Sentinel Guard - Central Authorization Engine

Responsibilities:
- Server Owner verification
- Extra Owner verification
- Whitelist verification
- Whitelist permission verification
- Central security authorization
- Fail-closed database handling

IMPORTANT:
Discord Administrator permission does not automatically
grant Sentinel Guard security privileges.
"""

import logging
import aiosqlite

from config import DB_PATH


logger = logging.getLogger("sentinel.permissions")


# ============================================================
# ACCESS LEVELS
# ============================================================

ACCESS_SERVER_OWNER = "server_owner"
ACCESS_EXTRA_OWNER = "extra_owner"
ACCESS_WHITELIST = "whitelist"
ACCESS_MEMBER = "member"


# ============================================================
# VALIDATION
# ============================================================

def _valid_id(value: int) -> bool:

    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value > 0
    )


def _validate_guild(guild) -> bool:

    return (
        guild is not None
        and _valid_id(getattr(guild, "id", None))
        and _valid_id(getattr(guild, "owner_id", None))
    )


# ============================================================
# SERVER OWNER
# ============================================================

async def is_server_owner(guild, user_id: int) -> bool:

    if not _validate_guild(guild):
        return False

    if not _valid_id(user_id):
        return False

    return guild.owner_id == user_id


# ============================================================
# EXTRA OWNER
# ============================================================

async def is_extra_owner(
    guild_id: int,
    user_id: int,
) -> bool:

    if not _valid_id(guild_id) or not _valid_id(user_id):
        return False

    try:

        async with aiosqlite.connect(
            DB_PATH,
            timeout=30,
        ) as db:

            cursor = await db.execute(
                """
                SELECT 1

                FROM server_extra_owners

                WHERE guild_id = ?
                  AND user_id = ?

                LIMIT 1
                """,
                (guild_id, user_id),
            )

            return await cursor.fetchone() is not None

    except aiosqlite.Error:

        logger.exception(
            "Extra Owner verification failed."
        )

        return False


# ============================================================
# WHITELIST
# ============================================================

async def is_whitelisted(
    guild_id: int,
    user_id: int,
) -> bool:

    if not _valid_id(guild_id) or not _valid_id(user_id):
        return False

    try:

        async with aiosqlite.connect(
            DB_PATH,
            timeout=30,
        ) as db:

            cursor = await db.execute(
                """
                SELECT 1

                FROM antinuke_whitelist

                WHERE guild_id = ?
                  AND user_id = ?

                LIMIT 1
                """,
                (guild_id, user_id),
            )

            return await cursor.fetchone() is not None

    except aiosqlite.Error:

        logger.exception(
            "Whitelist verification failed."
        )

        return False


# ============================================================
# WHITELIST PERMISSION
# ============================================================

async def has_whitelist_permission(
    guild_id: int,
    user_id: int,
    permission: str,
) -> bool:

    if not _valid_id(guild_id) or not _valid_id(user_id):
        return False

    try:

        from core.whitelist_permissions import (
            has_permission,
        )

        return await has_permission(
            guild_id,
            user_id,
            permission,
        )

    except (ValueError, TypeError, aiosqlite.Error):

        logger.exception(
            "Whitelist permission verification failed."
        )

        return False


# ============================================================
# ACCESS LEVEL
# ============================================================

async def get_access_level(
    guild,
    user_id: int,
) -> str:

    if not _validate_guild(guild):
        return ACCESS_MEMBER

    if not _valid_id(user_id):
        return ACCESS_MEMBER

    if await is_server_owner(guild, user_id):
        return ACCESS_SERVER_OWNER

    if await is_extra_owner(guild.id, user_id):
        return ACCESS_EXTRA_OWNER

    if await is_whitelisted(guild.id, user_id):
        return ACCESS_WHITELIST

    return ACCESS_MEMBER


# ============================================================
# EXTRA OWNER MANAGEMENT
# ============================================================

async def can_manage_extra_owners(
    guild,
    user_id: int,
) -> bool:

    """
    Only the actual Discord Server Owner can
    add or remove Extra Owners.
    """

    return await is_server_owner(
        guild,
        user_id,
    )


# ============================================================
# SECURITY CONFIGURATION
# ============================================================

async def can_manage_security(
    guild,
    user_id: int,
) -> bool:

    """
    Server Owner and Extra Owners can manage
    security configuration.

    Whitelisted members do not automatically
    receive configuration management access.
    """

    access = await get_access_level(
        guild,
        user_id,
    )

    return access in {
        ACCESS_SERVER_OWNER,
        ACCESS_EXTRA_OWNER,
    }


# ============================================================
# ANTINUKE EXEMPTION
# ============================================================

async def is_security_exempt(
    guild,
    user_id: int,
) -> bool:

    """
    Check whether a user should be exempt
    from AntiNuke punishment.

    This is NOT equivalent to granting
    administrative command permissions.
    """

    if not _validate_guild(guild):
        return False

    if not _valid_id(user_id):
        return False

    if await is_server_owner(guild, user_id):
        return True

    if await is_extra_owner(guild.id, user_id):
        return True

    return await is_whitelisted(
        guild.id,
        user_id,
    )


# ============================================================
# SPECIFIC WHITELIST AUTHORIZATION
# ============================================================

async def can_execute_whitelist_action(
    guild,
    user_id: int,
    permission: str,
) -> bool:

    """
    Check explicit whitelist permission.

    Server Owner and Extra Owner are handled
    separately through their own authorization.

    Normal members cannot inherit permissions
    from Discord Administrator status.
    """

    if not _validate_guild(guild):
        return False

    if not _valid_id(user_id):
        return False

    if await is_server_owner(guild, user_id):
        return True

    if await is_extra_owner(guild.id, user_id):
        return True

    if not await is_whitelisted(guild.id, user_id):
        return False

    return await has_whitelist_permission(
        guild.id,
        user_id,
        permission,
    )


# ============================================================
# GENERAL SECURITY AUTHORIZATION
# ============================================================

async def authorize_security_action(
    guild,
    user_id: int,
    permission: str,
) -> bool:

    """
    Central authorization entry point.

    Returns False by default when authorization
    cannot be established.
    """

    try:

        return await can_execute_whitelist_action(
            guild,
            user_id,
            permission,
        )

    except Exception:

        logger.exception(
            "Unexpected authorization failure."
        )

        return False
