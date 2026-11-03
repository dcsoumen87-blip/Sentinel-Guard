"""Lockdown / Panic Mode for Sentinel Guard."""

import asyncio
import discord
from discord import app_commands
from discord.ext import commands

from config import DB_PATH
from database.db import add_security_log, get_log_channel
from core.permissions import is_server_owner, is_extra_owner


class Lockdown(commands.Cog):
    """Server lockdown and panic mode commands."""

    def __init__(self, bot: commands.Bot):
        self.bot = bot
        self._lockdown_locks = {}

    async def _can_manage_lockdown(self, guild: discord.Guild, user_id: int) -> bool:
        """Check if user can manage lockdown (Server Owner or Extra Owner)."""
        return await is_server_owner(guild, user_id) or await is_extra_owner(guild, user_id)

    async def _get_raid_mode(self, guild_id: int) -> bool:
        """Get current raid/lockdown mode from database."""
        import aiosqlite
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute(
                "SELECT raid_mode FROM guild_settings WHERE guild_id = ?",
                (guild_id,),
            )
            row = await cursor.fetchone()
            return bool(row[0]) if row else False

    async def _set_raid_mode(self, guild_id: int, enabled: bool):
        """Set raid/lockdown mode in database."""
        import aiosqlite
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                """
                INSERT INTO guild_settings (guild_id, raid_mode)
                VALUES (?, ?)
                ON CONFLICT(guild_id) DO UPDATE SET raid_mode = excluded.raid_mode
                """,
                (guild_id, int(enabled)),
            )
            await db.commit()

    @app_commands.command(name="lockdown", description="Enable or disable server lockdown (panic mode)")
    @app_commands.guild_only()
    @app_commands.describe(
        state="Enable or disable lockdown mode",
        reason="Reason for lockdown (optional)"
    )
    @app_commands.choices(state=[
        app_commands.Choice(name="Enable", value="enable"),
        app_commands.Choice(name="Disable", value="disable"),
    ])
    async def lockdown(
        self,
        interaction: discord.Interaction,
        state: app_commands.Choice[str],
        reason: str = "No reason provided",
    ):
        """Enable/disable server lockdown (panic mode)."""
        guild = interaction.guild
        if guild is None:
            return

        # Permission check
        if not await self._can_manage_lockdown(guild, interaction.user.id):
            await interaction.response.send_message(
                "Only the Server Owner or Extra Owners can manage lockdown.",
                ephemeral=True,
            )
            return

        # Prevent concurrent lockdown operations
        lock = self._lockdown_locks.setdefault(guild.id, asyncio.Lock())
        async with lock:
            await interaction.response.defer(ephemeral=True, thinking=True)

            try:
                if state.value == "enable":
                    await self._enable_lockdown(guild, interaction.user, reason)
                else:
                    await self._disable_lockdown(guild, interaction.user, reason)

            except Exception as exc:
                await add_security_log(
                    guild.id, "lockdown_error", f"{type(exc).__name__}: {exc}", interaction.user.id
                )
                await interaction.followup.send(
                    f"Lockdown failed: `{type(exc).__name__}`. Check logs.",
                    ephemeral=True,
                )

    async def _enable_lockdown(self, guild: discord.Guild, actor: discord.Member, reason: str):
        """Enable lockdown: deny @everyone Send Messages in all text channels."""
        me = guild.me
        if me is None:
            raise RuntimeError("Bot member unavailable")

        everyone_role = guild.default_role
        affected_channels = []
        failed_channels = []

        # Lock all text channels where @everyone can currently send messages
        for channel in guild.text_channels:
            perms = channel.permissions_for(everyone_role)
            if perms.send_messages:
                try:
                    await channel.set_permissions(
                        everyone_role,
                        send_messages=False,
                        reason=f"Lockdown enabled by {actor} ({actor.id}): {reason}",
                    )
                    affected_channels.append(channel)
                except discord.Forbidden:
                    failed_channels.append(channel)
                except discord.HTTPException:
                    failed_channels.append(channel)

        # Save lockdown state
        await self._set_raid_mode(guild.id, True)
        await add_security_log(
            guild.id,
            "lockdown_enabled",
            f"Locked {len(affected_channels)} channels. Failed: {len(failed_channels)}. Reason: {reason}",
            actor.id,
        )

        embed = discord.Embed(
            title="SERVER LOCKDOWN ENABLED",
            description=(
                f"**Actor:** {actor.mention} (`{actor.id}`)\n"
                f"**Reason:** {reason}\n"
                f"**Channels locked:** {len(affected_channels)}\n"
                f"**Channels failed:** {len(failed_channels)}"
            ),
            color=discord.Color.red(),
            timestamp=discord.utils.utcnow(),
        )
        embed.set_footer(text="Panic mode active - Use /lockdown disable to restore")

        await interaction.followup.send(embed=embed, ephemeral=True)

        # Also send to log channel if configured
        log_channel_id = await get_log_channel(guild.id)
        if log_channel_id:
            log_channel = guild.get_channel(log_channel_id)
            if isinstance(log_channel, discord.TextChannel):
                try:
                    await log_channel.send(embed=embed)
                except discord.HTTPException:
                    pass

    async def _disable_lockdown(self, guild: discord.Guild, actor: discord.Member, reason: str):
        """Disable lockdown: restore @everyone Send Messages in text channels."""
        me = guild.me
        if me is None:
            raise RuntimeError("Bot member unavailable")

        everyone_role = guild.default_role
        affected_channels = []
        failed_channels = []

        # Restore permissions in text channels where @everyone is denied Send Messages
        for channel in guild.text_channels:
            perms = channel.permissions_for(everyone_role)
            # Check if send_messages is explicitly False (not None/inherited)
            if perms.send_messages is False:
                try:
                    # Remove the overwrite to restore default/inherited permissions
                    await channel.set_permissions(
                        everyone_role,
                        send_messages=None,
                        reason=f"Lockdown disabled by {actor} ({actor.id}): {reason}",
                    )
                    affected_channels.append(channel)
                except discord.Forbidden:
                    failed_channels.append(channel)
                except discord.HTTPException:
                    failed_channels.append(channel)

        # Save lockdown state
        await self._set_raid_mode(guild.id, False)
        await add_security_log(
            guild.id,
            "lockdown_disabled",
            f"Unlocked {len(affected_channels)} channels. Failed: {len(failed_channels)}. Reason: {reason}",
            actor.id,
        )

        embed = discord.Embed(
            title="SERVER LOCKDOWN DISABLED",
            description=(
                f"**Actor:** {actor.mention} (`{actor.id}`)\n"
                f"**Reason:** {reason}\n"
                f"**Channels restored:** {len(affected_channels)}\n"
                f"**Channels failed:** {len(failed_channels)}"
            ),
            color=discord.Color.green(),
            timestamp=discord.utils.utcnow(),
        )
        embed.set_footer(text="Normal operations restored")

        await interaction.followup.send(embed=embed, ephemeral=True)

        # Also send to log channel
        log_channel_id = await get_log_channel(guild.id)
        if log_channel_id:
            log_channel = guild.get_channel(log_channel_id)
            if isinstance(log_channel, discord.TextChannel):
                try:
                    await log_channel.send(embed=embed)
                except discord.HTTPException:
                    pass

    @app_commands.command(name="lockdown_status", description="Check current lockdown status")
    @app_commands.guild_only()
    async def lockdown_status(self, interaction: discord.Interaction):
        """Check if lockdown is active."""
        guild = interaction.guild
        if guild is None:
            return

        is_locked = await self._get_raid_mode(guild.id)

        # Count channels with explicit deny
        everyone_role = guild.default_role
        locked_count = sum(
            1 for ch in guild.text_channels
            if ch.permissions_for(everyone_role).send_messages is False
        )

        embed = discord.Embed(
            title="Lockdown Status",
            color=discord.Color.red() if is_locked else discord.Color.green(),
            timestamp=discord.utils.utcnow(),
        )
        embed.add_field(name="Database State", value="Locked" if is_locked else "Unlocked", inline=True)
        embed.add_field(name="Channels with @everyone denied Send Messages", value=str(locked_count), inline=True)
        embed.add_field(name="Total Text Channels", value=str(len(guild.text_channels)), inline=True)

        await interaction.response.send_message(embed=embed, ephemeral=True)

    @commands.hybrid_command(name="panic", description="Quick panic mode toggle (alias for lockdown)")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def panic(self, ctx: commands.Context, state: str = "toggle"):
        """Quick panic mode command. Usage: /panic enable|disable|toggle"""
        state = state.lower()

        if state not in ("enable", "disable", "toggle"):
            await ctx.send("Usage: `/panic enable|disable|toggle`", ephemeral=ctx.interaction is not None)
            return

        guild = ctx.guild
        if guild is None:
            return

        # Same rule as /lockdown: only the Server Owner or Extra Owners.
        if not await self._can_manage_lockdown(guild, ctx.author.id):
            await ctx.send(
                "Only the Server Owner or Extra Owners can manage lockdown.",
                ephemeral=ctx.interaction is not None,
            )
            return

        await ctx.defer(ephemeral=ctx.interaction is not None)

        current = await self._get_raid_mode(guild.id)

        if state == "toggle":
            state = "disable" if current else "enable"

        # Reuse the slash command logic
        if state == "enable":
            await self._enable_lockdown(guild, ctx.author, "Panic mode via command")
        else:
            await self._disable_lockdown(guild, ctx.author, "Panic mode via command")

        action = "enabled" if state == "enable" else "disabled"
        await ctx.send(f"Lockdown **{action}**.", ephemeral=ctx.interaction is not None)


async def setup(bot: commands.Bot):
    await bot.add_cog(Lockdown(bot))
