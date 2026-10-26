"""Server Owner, Extra Owner and Whitelist permission management."""

import discord
import aiosqlite

from discord import app_commands
from discord.ext import commands

from config import DB_PATH
from core.permissions import is_server_owner, is_extra_owner
from core.whitelist_permissions import (
    VALID_PERMISSIONS,
    grant_permission,
    revoke_permission,
    has_permission,
)


class Permissions(commands.Cog):
    """Manage server-specific security permissions."""

    def __init__(self, bot: commands.Bot):
        self.bot = bot

    async def can_manage(self, guild: discord.Guild, user_id: int) -> bool:
        """Only the actual Server Owner can manage these assignments."""
        return await is_server_owner(guild, user_id)

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

        if guild is None:
            return

        if not await self.can_manage(guild, interaction.user.id):
            await interaction.response.send_message(
                "❌ Only the Server Owner can add Extra Owners.",
                ephemeral=True,
            )
            return

        if member.id == guild.owner_id or member.bot:
            await interaction.response.send_message(
                "❌ This member cannot be assigned as an Extra Owner.",
                ephemeral=True,
            )
            return

        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                """
                INSERT OR IGNORE INTO server_extra_owners
                (guild_id, user_id)
                VALUES (?, ?)
                """,
                (guild.id, member.id),
            )
            await db.commit()

        await interaction.response.send_message(
            f"✅ {member.mention} is now an Extra Owner.",
            ephemeral=True,
        )

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

        if guild is None:
            return

        if not await self.can_manage(guild, interaction.user.id):
            await interaction.response.send_message(
                "❌ Only the Server Owner can remove Extra Owners.",
                ephemeral=True,
            )
            return

        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute(
                """
                DELETE FROM server_extra_owners
                WHERE guild_id = ? AND user_id = ?
                """,
                (guild.id, member.id),
            )
            await db.commit()

        if cursor.rowcount:
            message = f"✅ Removed {member.mention} from Extra Owners."
        else:
            message = "ℹ️ This member is not an Extra Owner."

        await interaction.response.send_message(
            message,
            ephemeral=True,
        )

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

        if guild is None:
            return

        if not await self.can_manage(guild, interaction.user.id):
            await interaction.response.send_message(
                "❌ Only the Server Owner can view this list.",
                ephemeral=True,
            )
            return

        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute(
                """
                SELECT user_id FROM server_extra_owners
                WHERE guild_id = ?
                ORDER BY created_at
                """,
                (guild.id,),
            )
            rows = await cursor.fetchall()

        if not rows:
            description = "No Extra Owners are configured."
        else:
            description = "\n".join(
                f"• <@{row[0]}> (`{row[0]}`)"
                for row in rows
            )

        embed = discord.Embed(
            title="👑 Server Extra Owners",
            description=description,
            color=discord.Color.gold(),
        )

        await interaction.response.send_message(
            embed=embed,
            ephemeral=True,
        )

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

        if guild is None:
            return

        if not await self.can_manage(guild, interaction.user.id):
            await interaction.response.send_message(
                "❌ Only the Server Owner can manage the whitelist.",
                ephemeral=True,
            )
            return

        if member.id == guild.owner_id or member.bot:
            await interaction.response.send_message(
                "❌ This member cannot be added to the whitelist.",
                ephemeral=True,
            )
            return

        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                """
                INSERT OR IGNORE INTO antinuke_whitelist
                (guild_id, user_id)
                VALUES (?, ?)
                """,
                (guild.id, member.id),
            )
            await db.commit()

        await interaction.response.send_message(
            f"✅ Added {member.mention} to the whitelist.",
            ephemeral=True,
        )

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

        if guild is None:
            return

        if not await self.can_manage(guild, interaction.user.id):
            await interaction.response.send_message(
                "❌ Only the Server Owner can manage the whitelist.",
                ephemeral=True,
            )
            return

        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                """
                DELETE FROM antinuke_whitelist
                WHERE guild_id = ? AND user_id = ?
                """,
                (guild.id, member.id),
            )
            await db.execute(
                """
                DELETE FROM whitelist_permissions
                WHERE guild_id = ? AND user_id = ?
                """,
                (guild.id, member.id),
            )
            await db.commit()

        await interaction.response.send_message(
            f"✅ Removed {member.mention} and their whitelist permissions.",
            ephemeral=True,
        )

    @app_commands.command(
        name="whitelist_permission",
        description="Grant or revoke a specific whitelist permission.",
    )
    @app_commands.guild_only()
    @app_commands.choices(
        action=[
            app_commands.Choice(name="Grant", value="grant"),
            app_commands.Choice(name="Revoke", value="revoke"),
            app_commands.Choice(name="Check", value="check"),
        ],
        permission=[
            app_commands.Choice(name="Create Channels", value="channel_create"),
            app_commands.Choice(name="Delete Channels", value="channel_delete"),
            app_commands.Choice(name="Kick Members", value="member_kick"),
            app_commands.Choice(name="Ban Members", value="member_ban"),
            app_commands.Choice(name="Grant Administrator", value="admin_grant"),
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

        if guild is None:
            return

        if not await self.can_manage(guild, interaction.user.id):
            await interaction.response.send_message(
                "❌ Only the Server Owner can change whitelist permissions.",
                ephemeral=True,
            )
            return

        if permission.value not in VALID_PERMISSIONS:
            await interaction.response.send_message(
                "❌ Invalid permission.",
                ephemeral=True,
            )
            return

        if action.value == "grant":
            success = await grant_permission(
                guild.id, member.id, permission.value
            )
            result = (
                f"✅ Granted `{permission.value}` to {member.mention}."
                if success
                else "❌ Add this member to the whitelist first."
            )

        elif action.value == "revoke":
            success = await revoke_permission(
                guild.id, member.id, permission.value
            )
            result = (
                f"✅ Revoked `{permission.value}` from {member.mention}."
                if success
                else "ℹ️ This permission was not assigned."
            )

        else:
            success = await has_permission(
                guild.id, member.id, permission.value
            )
            result = (
                f"✅ {member.mention} has `{permission.value}`."
                if success
                else f"❌ {member.mention} does not have `{permission.value}`."
            )

        await interaction.response.send_message(
            result,
            ephemeral=True,
        )


async def setup(bot: commands.Bot):
    await bot.add_cog(Permissions(bot))
