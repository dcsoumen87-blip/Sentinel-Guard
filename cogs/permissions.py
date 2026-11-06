# cogs/permissions.py

import logging

import discord
import aiosqlite

from discord import app_commands
from discord.ext import commands

from config import DB_PATH

from core.permissions import is_server_owner

from core.whitelist_permissions import (
    VALID_PERMISSIONS,
    grant_permission,
    revoke_permission,
    has_permission,
)


logger = logging.getLogger("sentinel.permissions")


class Permissions(commands.Cog):
    """Server Owner, Extra Owner and Whitelist management."""

    def __init__(self, bot: commands.Bot):
        self.bot = bot

    # ========================================================
    # AUTHORIZATION
    # ========================================================

    async def can_manage(
        self,
        guild: discord.Guild,
        user_id: int,
    ) -> bool:

        if guild is None:
            return False

        try:
            return await is_server_owner(
                guild,
                user_id,
            )

        except Exception:

            logger.exception(
                "Authorization verification failed."
            )

            return False

    # ========================================================
    # RESPONSE HELPER
    # ========================================================

    async def respond(
        self,
        interaction: discord.Interaction,
        message: str,
        *,
        success: bool = True,
    ):

        embed = discord.Embed(
            description=message,
            color=(
                discord.Color.green()
                if success
                else discord.Color.red()
            ),
            timestamp=discord.utils.utcnow(),
        )

        if interaction.response.is_done():

            await interaction.followup.send(
                embed=embed,
                ephemeral=True,
            )

        else:

            await interaction.response.send_message(
                embed=embed,
                ephemeral=True,
            )

    # ========================================================
    # EXTRA OWNER ADD
    # ========================================================

    @app_commands.command(
        name="extraowner_add",
        description="Add a server-specific Extra Owner.",
    )
    @app_commands.guild_only()
    async def extraowner_add(
        self,
        interaction: discord.Interaction,
        member: discord.Member,
    ):

        guild = interaction.guild

        if not await self.can_manage(
            guild,
            interaction.user.id,
        ):

            await self.respond(
                interaction,
                "❌ Only the Server Owner can add Extra Owners.",
                success=False,
            )
            return

        if member.id == guild.owner_id or member.bot:

            await self.respond(
                interaction,
                "❌ This member cannot be assigned as an Extra Owner.",
                success=False,
            )
            return

        try:

            async with aiosqlite.connect(DB_PATH) as db:

                cursor = await db.execute(
                    """
                    INSERT OR IGNORE INTO server_extra_owners
                    (guild_id, user_id)
                    VALUES (?, ?)
                    """,
                    (guild.id, member.id),
                )

                await db.commit()

                added = cursor.rowcount > 0

            if added:

                await self.respond(
                    interaction,
                    f"✅ {member.mention} is now an Extra Owner.",
                )

            else:

                await self.respond(
                    interaction,
                    f"ℹ️ {member.mention} is already an Extra Owner.",
                    success=False,
                )

        except aiosqlite.Error:

            logger.exception("Extra Owner addition failed.")

            await self.respond(
                interaction,
                "❌ Database error while adding Extra Owner.",
                success=False,
            )

    # ========================================================
    # EXTRA OWNER REMOVE
    # ========================================================

    @app_commands.command(
        name="extraowner_remove",
        description="Remove a server-specific Extra Owner.",
    )
    @app_commands.guild_only()
    async def extraowner_remove(
        self,
        interaction: discord.Interaction,
        member: discord.Member,
    ):

        guild = interaction.guild

        if not await self.can_manage(
            guild,
            interaction.user.id,
        ):

            await self.respond(
                interaction,
                "❌ Only the Server Owner can remove Extra Owners.",
                success=False,
            )
            return

        try:

            async with aiosqlite.connect(DB_PATH) as db:

                cursor = await db.execute(
                    """
                    DELETE FROM server_extra_owners
                    WHERE guild_id = ?
                    AND user_id = ?
                    """,
                    (guild.id, member.id),
                )

                await db.commit()

                removed = cursor.rowcount > 0

            if removed:

                await self.respond(
                    interaction,
                    f"✅ Removed {member.mention} from Extra Owners.",
                )

            else:

                await self.respond(
                    interaction,
                    "ℹ️ This member is not an Extra Owner.",
                    success=False,
                )

        except aiosqlite.Error:

            logger.exception("Extra Owner removal failed.")

            await self.respond(
                interaction,
                "❌ Database error while removing Extra Owner.",
                success=False,
            )

    # ========================================================
    # EXTRA OWNER LIST
    # ========================================================

    @app_commands.command(
        name="extraowner_list",
        description="List this server's Extra Owners.",
    )
    @app_commands.guild_only()
    async def extraowner_list(
        self,
        interaction: discord.Interaction,
    ):

        guild = interaction.guild

        if not await self.can_manage(
            guild,
            interaction.user.id,
        ):

            await self.respond(
                interaction,
                "❌ Only the Server Owner can view this list.",
                success=False,
            )
            return

        try:

            async with aiosqlite.connect(DB_PATH) as db:

                cursor = await db.execute(
                    """
                    SELECT user_id
                    FROM server_extra_owners
                    WHERE guild_id = ?
                    ORDER BY created_at
                    """,
                    (guild.id,),
                )

                rows = await cursor.fetchall()

            description = (
                "\n".join(
                    f"• <@{row[0]}> (`{row[0]}`)"
                    for row in rows
                )
                if rows
                else "No Extra Owners are configured."
            )

            embed = discord.Embed(
                title="👑 Server Extra Owners",
                description=description,
                color=discord.Color.gold(),
                timestamp=discord.utils.utcnow(),
            )

            await interaction.response.send_message(
                embed=embed,
                ephemeral=True,
            )

        except aiosqlite.Error:

            logger.exception("Extra Owner listing failed.")

            await self.respond(
                interaction,
                "❌ Unable to retrieve Extra Owners.",
                success=False,
            )

    # ========================================================
    # WHITELIST ADD
    # ========================================================

    @app_commands.command(
        name="whitelist_add",
        description="Add a member to the AntiNuke whitelist.",
    )
    @app_commands.guild_only()
    async def whitelist_add(
        self,
        interaction: discord.Interaction,
        member: discord.Member,
    ):

        guild = interaction.guild

        if not await self.can_manage(
            guild,
            interaction.user.id,
        ):

            await self.respond(
                interaction,
                "❌ Only the Server Owner can manage the whitelist.",
                success=False,
            )
            return

        if member.id == guild.owner_id or member.bot:

            await self.respond(
                interaction,
                "❌ This member cannot be added to the whitelist.",
                success=False,
            )
            return

        try:

            async with aiosqlite.connect(DB_PATH) as db:

                cursor = await db.execute(
                    """
                    INSERT OR IGNORE INTO antinuke_whitelist
                    (guild_id, user_id)
                    VALUES (?, ?)
                    """,
                    (guild.id, member.id),
                )

                await db.commit()

                added = cursor.rowcount > 0

            if added:

                message = (
                    f"✅ Added {member.mention} to the whitelist."
                )

            else:

                message = (
                    f"ℹ️ {member.mention} is already whitelisted."
                )

            await self.respond(
                interaction,
                message,
                success=added,
            )

        except aiosqlite.Error:

            logger.exception("Whitelist addition failed.")

            await self.respond(
                interaction,
                "❌ Database error while updating whitelist.",
                success=False,
            )

    # ========================================================
    # WHITELIST REMOVE
    # ========================================================

    @app_commands.command(
        name="whitelist_remove",
        description="Remove a member from the AntiNuke whitelist.",
    )
    @app_commands.guild_only()
    async def whitelist_remove(
        self,
        interaction: discord.Interaction,
        member: discord.Member,
    ):

        guild = interaction.guild

        if not await self.can_manage(
            guild,
            interaction.user.id,
        ):

            await self.respond(
                interaction,
                "❌ Only the Server Owner can manage the whitelist.",
                success=False,
            )
            return

        try:

            async with aiosqlite.connect(DB_PATH) as db:

                await db.execute("BEGIN IMMEDIATE")

                cursor = await db.execute(
                    """
                    DELETE FROM antinuke_whitelist
                    WHERE guild_id = ?
                    AND user_id = ?
                    """,
                    (guild.id, member.id),
                )

                removed = cursor.rowcount > 0

                await db.execute(
                    """
                    DELETE FROM whitelist_permissions
                    WHERE guild_id = ?
                    AND user_id = ?
                    """,
                    (guild.id, member.id),
                )

                await db.commit()

            if removed:

                message = (
                    f"✅ Removed {member.mention} and revoked "
                    "their whitelist permissions."
                )

            else:

                message = (
                    "ℹ️ This member is not whitelisted."
                )

            await self.respond(
                interaction,
                message,
                success=removed,
            )

        except aiosqlite.Error:

            logger.exception("Whitelist removal failed.")

            await self.respond(
                interaction,
                "❌ Database error while removing whitelist entry.",
                success=False,
            )

    # ========================================================
    # WHITELIST PERMISSION
    # ========================================================

    @app_commands.command(
        name="whitelist_permission",
        description="Manage specific whitelist permissions.",
    )
    @app_commands.guild_only()
    @app_commands.choices(
        action=[
            app_commands.Choice(name="Grant", value="grant"),
            app_commands.Choice(name="Revoke", value="revoke"),
            app_commands.Choice(name="Check", value="check"),
        ],
        permission=[
            app_commands.Choice(
                name="Create Channels",
                value="channel_create",
            ),
            app_commands.Choice(
                name="Delete Channels",
                value="channel_delete",
            ),
            app_commands.Choice(
                name="Kick Members",
                value="member_kick",
            ),
            app_commands.Choice(
                name="Ban Members",
                value="member_ban",
            ),
            app_commands.Choice(
                name="Grant Administrator",
                value="admin_grant",
            ),
        ],
    )
    async def whitelist_permission(
        self,
        interaction: discord.Interaction,
        member: discord.Member,
        action: app_commands.Choice[str],
        permission: app_commands.Choice[str],
    ):

        guild = interaction.guild

        if not await self.can_manage(
            guild,
            interaction.user.id,
        ):

            await self.respond(
                interaction,
                "❌ Only the Server Owner can change whitelist permissions.",
                success=False,
            )
            return

        if permission.value not in VALID_PERMISSIONS:

            await self.respond(
                interaction,
                "❌ Invalid permission selected.",
                success=False,
            )
            return

        if member.bot or member.id == guild.owner_id:

            await self.respond(
                interaction,
                "❌ This member cannot receive whitelist permissions.",
                success=False,
            )
            return

        try:

            if action.value == "grant":

                success = await grant_permission(
                    guild.id,
                    member.id,
                    permission.value,
                )

                if success:

                    result = (
                        f"✅ Granted `{permission.value}` "
                        f"to {member.mention}."
                    )

                else:

                    result = (
                        "❌ Add this member to the whitelist first."
                    )

            elif action.value == "revoke":

                success = await revoke_permission(
                    guild.id,
                    member.id,
                    permission.value,
                )

                result = (
                    f"✅ Revoked `{permission.value}` "
                    f"from {member.mention}."
                    if success
                    else "ℹ️ This permission was not assigned."
                )

            elif action.value == "check":

                success = await has_permission(
                    guild.id,
                    member.id,
                    permission.value,
                )

                result = (
                    f"✅ {member.mention} has `{permission.value}`."
                    if success
                    else f"❌ {member.mention} does not have "
                         f"`{permission.value}`."
                )

            else:

                await self.respond(
                    interaction,
                    "❌ Invalid action.",
                    success=False,
                )
                return

            await self.respond(
                interaction,
                result,
                success=success,
            )

        except (aiosqlite.Error, ValueError):

            logger.exception(
                "Whitelist permission operation failed."
            )

            await self.respond(
                interaction,
                "❌ Unable to process whitelist permission.",
                success=False,
            )


async def setup(bot: commands.Bot):

    await bot.add_cog(
        Permissions(bot)
    )
