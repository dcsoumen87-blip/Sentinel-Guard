# File: core/whitelist_permissions.py

"""Secure whitelist permission management for Sentinel Guard."""

import logging
import aiosqlite

from config import DB_PATH


logger = logging.getLogger("sentinel.permissions")


# ============================================================
# VALID PERMISSIONS
# ============================================================

VALID_PERMISSIONS = frozenset({
    "channel_create",
    "channel_delete",
    "member_kick",
    "member_ban",
    "admin_grant",
})


# ============================================================
# VALIDATION
# ============================================================

def validate_ids(guild_id: int, user_id: int):

    if isinstance(guild_id, bool) or not isinstance(guild_id, int):
        raise ValueError("Invalid guild ID.")

    if isinstance(user_id, bool) or not isinstance(user_id, int):
        raise ValueError("Invalid user ID.")

    if guild_id <= 0 or user_id <= 0:
        raise ValueError("IDs must be positive integers.")


def validate_permission(permission: str):

    if not isinstance(permission, str):
        return False

    return permission in VALID_PERMISSIONS


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

async def init_whitelist_permissions():

    async with aiosqlite.connect(DB_PATH) as db:

        await db.execute(
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
            """
        )

        await db.commit()

    logger.info("Whitelist permission system initialized.")


# ============================================================
# WHITELIST STATUS
# ============================================================

async def is_whitelisted(
    guild_id: int,
    user_id: int,
) -> bool:

    validate_ids(guild_id, user_id)

    async with aiosqlite.connect(DB_PATH) as db:

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


# ============================================================
# GRANT PERMISSION
# ============================================================

async def grant_permission(
    guild_id: int,
    user_id: int,
    permission: str,
) -> bool:

    validate_ids(guild_id, user_id)

    if not validate_permission(permission):
        return False

    try:

        async with aiosqlite.connect(DB_PATH) as db:

            await db.execute("BEGIN IMMEDIATE")

            # Only explicitly whitelisted members
            # can receive additional permissions.

            cursor = await db.execute(
                """
                INSERT OR IGNORE INTO whitelist_permissions
                (
                    guild_id,
                    user_id,
                    permission
                )

                SELECT
                    guild_id,
                    user_id,
                    ?

                FROM antinuke_whitelist

                WHERE guild_id = ?
                  AND user_id = ?
                """,
                (
                    permission,
                    guild_id,
                    user_id,
                ),
            )

            granted = cursor.rowcount > 0

            await db.commit()

            if granted:

                logger.info(
                    "Permission granted: guild=%s user=%s permission=%s",
                    guild_id,
                    user_id,
                    permission,
                )

            return granted

    except aiosqlite.Error:

        logger.exception(
            "Permission grant failed: guild=%s user=%s",
            guild_id,
            user_id,
        )

        return False


# ============================================================
# REVOKE PERMISSION
# ============================================================

async def revoke_permission(
    guild_id: int,
    user_id: int,
    permission: str,
) -> bool:

    validate_ids(guild_id, user_id)

    if not validate_permission(permission):
        return False

    try:

        async with aiosqlite.connect(DB_PATH) as db:

            cursor = await db.execute(
                """
                DELETE FROM whitelist_permissions

                WHERE guild_id = ?
                  AND user_id = ?
                  AND permission = ?
                """,
                (
                    guild_id,
                    user_id,
                    permission,
                ),
            )

            await db.commit()

            revoked = cursor.rowcount > 0

            if revoked:

                logger.info(
                    "Permission revoked: guild=%s user=%s permission=%s",
                    guild_id,
                    user_id,
                    permission,
                )

            return revoked

    except aiosqlite.Error:

        logger.exception("Permission revocation failed.")

        return False


# ============================================================
# CHECK PERMISSION
# ============================================================

async def has_permission(
    guild_id: int,
    user_id: int,
    permission: str,
) -> bool:

    validate_ids(guild_id, user_id)

    if not validate_permission(permission):
        return False

    async with aiosqlite.connect(DB_PATH) as db:

        cursor = await db.execute(
            """
            SELECT 1

            FROM whitelist_permissions AS wp

            INNER JOIN antinuke_whitelist AS wl

                ON wl.guild_id = wp.guild_id
                AND wl.user_id = wp.user_id

            WHERE wp.guild_id = ?
              AND wp.user_id = ?
              AND wp.permission = ?

            LIMIT 1
            """,
            (
                guild_id,
                user_id,
                permission,
            ),
        )

        return await cursor.fetchone() is not None


# ============================================================
# LIST USER PERMISSIONS
# ============================================================

async def get_user_permissions(
    guild_id: int,
    user_id: int,
) -> list[str]:

    validate_ids(guild_id, user_id)

    async with aiosqlite.connect(DB_PATH) as db:

        cursor = await db.execute(
            """
            SELECT wp.permission

            FROM whitelist_permissions AS wp

            INNER JOIN antinuke_whitelist AS wl

                ON wl.guild_id = wp.guild_id
                AND wl.user_id = wp.user_id

            WHERE wp.guild_id = ?
              AND wp.user_id = ?

            ORDER BY wp.permission
            """,
            (
                guild_id,
                user_id,
            ),
        )

        rows = await cursor.fetchall()

        return [row[0] for row in rows]


# ============================================================
# REMOVE ALL USER PERMISSIONS
# ============================================================

async def revoke_all_permissions(
    guild_id: int,
    user_id: int,
) -> int:

    validate_ids(guild_id, user_id)

    async with aiosqlite.connect(DB_PATH) as db:

        cursor = await db.execute(
            """
            DELETE FROM whitelist_permissions

            WHERE guild_id = ?
              AND user_id = ?
            """,
            (
                guild_id,
                user_id,
            ),
        )

        await db.commit()

        return cursor.rowcount


# ============================================================
# LIST VALID PERMISSIONS
# ============================================================

def get_available_permissions() -> list[str]:

    return sorted(VALID_PERMISSIONS)
