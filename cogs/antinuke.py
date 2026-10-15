from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

import aiosqlite
import discord
from discord.ext import commands


DB_PATH = "sentinel_guard.db"

DEFAULT_THRESHOLD = 4
DEFAULT_WINDOW = 10
ALERT_COOLDOWN = 30


class AntiNuke(commands.Cog):
    """Defensive channel Anti-Nuke monitoring."""

    def __init__(self, bot: commands.Bot):
        self.bot = bot

        # (guild_id, actor_id) -> recent events
        self.events = defaultdict(deque)

        # Prevent repeated alerts/actions for the same incident.
        self.cooldowns = {}

        # Prevent duplicate processing of audit-log entries.
        self.processed_entries = {}

    async def cog_load(self):
        await self.ensure_tables()

    async def ensure_tables(self):
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS antinuke_config (
                    guild_id INTEGER PRIMARY KEY,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    threshold INTEGER NOT NULL DEFAULT 4,
                    window_seconds INTEGER NOT NULL DEFAULT 10,
                    alert_channel_id INTEGER,
                    mode TEXT NOT NULL DEFAULT 'alert'
                )
            """)

            await db.execute("""
                CREATE TABLE IF NOT EXISTS antinuke_whitelist (
                    guild_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    PRIMARY KEY (guild_id, user_id)
                )
            """)

            await db.execute("""
                CREATE TABLE IF NOT EXISTS antinuke_incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id INTEGER NOT NULL,
                    actor_id INTEGER,
                    action TEXT NOT NULL,
                    event_count INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    details TEXT
                )
            """)

            await db.commit()

    async def get_config(self, guild_id: int):
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("""
                SELECT enabled, threshold, window_seconds,
                       alert_channel_id, mode
                FROM antinuke_config
                WHERE guild_id = ?
            """, (guild_id,))

            row = await cursor.fetchone()

            if row:
                return {
                    "enabled": bool(row[0]),
                    "threshold": row[1],
                    "window": row[2],
                    "alert_channel_id": row[3],
                    "mode": row[4],
                }

            await db.execute("""
                INSERT OR IGNORE INTO antinuke_config
                (guild_id, enabled, threshold, window_seconds, mode)
                VALUES (?, 1, ?, ?, 'alert')
            """, (guild_id, DEFAULT_THRESHOLD, DEFAULT_WINDOW))

            await db.commit()

        return {
            "enabled": True,
            "threshold": DEFAULT_THRESHOLD,
            "window": DEFAULT_WINDOW,
            "alert_channel_id": None,
            "mode": "alert",
        }

    async def is_whitelisted(self, guild_id: int, user_id: int) -> bool:
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("""
                SELECT 1 FROM antinuke_whitelist
                WHERE guild_id = ? AND user_id = ?
            """, (guild_id, user_id))

            return await cursor.fetchone() is not None

    async def save_incident(
        self,
        guild_id: int,
        actor_id: int | None,
        action: str,
        event_count: int,
        details: str,
    ):
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("""
                INSERT INTO antinuke_incidents
                (guild_id, actor_id, action, event_count,
                 created_at, details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                guild_id,
                actor_id,
                action,
                event_count,
                datetime.now(timezone.utc).isoformat(),
                details[:1000],
            ))

            await db.commit()

        # Integrate with the existing security log system if available.
        try:
            from database.db import add_security_log

            result = add_security_log(
                guild_id,
                action,
                details,
                actor_id,
            )

            if asyncio.iscoroutine(result):
                await result

        except Exception:
            # The dedicated antinuke_incidents table remains available.
            pass

    async def find_audit_actor(
        self,
        guild: discord.Guild,
        channel_id: int,
        action: discord.AuditLogAction,
    ):
        """
        Match the channel event to a recent Discord audit-log entry.
        Return the actor and audit entry, or (None, None).
        """

        for attempt in range(4):
            try:
                async for entry in guild.audit_logs(
                    limit=10,
                    action=action,
                ):
                    if entry.target is None:
                        continue

                    if getattr(entry.target, "id", None) != channel_id:
                        continue

                    age = (
                        discord.utils.utcnow() - entry.created_at
                    ).total_seconds()

                    if age < -2 or age > 20:
                        continue

                    entry_key = (guild.id, entry.id)

                    if entry_key in self.processed_entries:
                        continue

                    self.processed_entries[entry_key] = time.monotonic()

                    return entry.user, entry

            except (discord.Forbidden, discord.HTTPException):
                return None, None

            if attempt < 3:
                await asyncio.sleep(1)

        return None, None

    async def send_alert(
        self,
        guild: discord.Guild,
        config: dict,
        actor: discord.abc.User,
        action: str,
        event_count: int,
        channel_name: str,
    ):
        channel_id = config["alert_channel_id"]

        if not channel_id:
            return

        channel = guild.get_channel(channel_id)

        if not isinstance(channel, discord.TextChannel):
            return

        embed = discord.Embed(
            title="🚨 Sentinel Guard | Anti-Nuke Alert",
            description=(
                "Suspicious channel activity has reached "
                "the configured threshold."
            ),
            color=discord.Color.red(),
            timestamp=discord.utils.utcnow(),
        )

        embed.add_field(
            name="👤 Actor",
            value=f"{actor.mention}\n`{actor.id}`",
            inline=False,
        )

        embed.add_field(
            name="⚠️ Activity",
            value=action,
            inline=True,
        )

        embed.add_field(
            name="📊 Events",
            value=(
                f"`{event_count}` events in "
                f"`{config['window']}` seconds"
            ),
            inline=True,
        )

        embed.add_field(
            name="📁 Channel",
            value=f"`{channel_name[:100]}`",
            inline=False,
        )

        embed.add_field(
            name="🛡️ Response Mode",
            value=config["mode"].upper(),
            inline=True,
        )

        embed.set_footer(
            text="Sentinel Guard • Security Monitoring"
        )

        try:
            await channel.send(embed=embed)
        except (discord.Forbidden, discord.HTTPException):
            pass

    async def process_channel_event(
        self,
        channel: discord.abc.GuildChannel,
        action: str,
        audit_action: discord.AuditLogAction,
    ):
        guild = channel.guild

        config = await self.get_config(guild.id)

        if not config["enabled"]:
            return

        actor, entry = await self.find_audit_actor(
            guild,
            channel.id,
            audit_action,
        )

        # Without audit-log evidence, do not punish anyone.
        if actor is None or entry is None:
            await self.save_incident(
                guild.id,
                None,
                f"{action}_actor_unverified",
                1,
                f"Could not verify actor for channel ID {channel.id}.",
            )
            return

        if actor.bot and actor.id == self.bot.user.id:
            return

        if await self.is_whitelisted(guild.id, actor.id):
            return

        now = time.monotonic()
        key = (guild.id, actor.id)

        history = self.events[key]
        history.append((now, action))

        # Keep only events inside the configured time window.
        while history and now - history[0][0] > config["window"]:
            history.popleft()

        # Count both channel creations and deletions.
        event_count = len(history)

        if event_count < config["threshold"]:
            return

        cooldown_key = (guild.id, actor.id)
        last_alert = self.cooldowns.get(cooldown_key, 0)

        if now - last_alert < ALERT_COOLDOWN:
            return

        self.cooldowns[cooldown_key] = now

        await self.save_incident(
            guild.id,
            actor.id,
            "channel_activity_threshold",
            event_count,
            (
                f"Actor {actor.id} reached {event_count} channel "
                f"events in {config['window']} seconds."
            ),
        )

        await self.send_alert(
            guild,
            config,
            actor,
            action,
            event_count,
            channel.name,
        )

        # Optional, conservative mitigation:
        # kick only a verified bot when explicitly configured.
        # Never mass-ban or automatically punish human administrators.
        if config["mode"] == "kick":
            await self.kick_verified_bot(
                guild,
                actor,
                event_count,
            )

    async def kick_verified_bot(
        self,
        guild: discord.Guild,
        actor: discord.abc.User,
        event_count: int,
    ):
        if not isinstance(actor, discord.Member):
            return

        if not actor.bot:
            return

        if actor.id == guild.owner_id:
            return

        if actor.guild_permissions.administrator:
            return

        bot_member = guild.me

        if bot_member is None:
            return

        if not bot_member.guild_permissions.kick_members:
            return

        if actor.top_role >= bot_member.top_role:
            return

        try:
            await actor.kick(
                reason=(
                    "Sentinel Guard: verified channel activity "
                    f"threshold exceeded ({event_count} events)."
                )
            )

            await self.save_incident(
                guild.id,
                actor.id,
                "verified_bot_kicked",
                event_count,
                "A verified bot actor was kicked after threshold detection.",
            )

        except (discord.Forbidden, discord.HTTPException):
            pass

    @commands.Cog.listener()
    async def on_guild_channel_create(
        self,
        channel: discord.abc.GuildChannel,
    ):
        await self.process_channel_event(
            channel,
            "channel_create",
            discord.AuditLogAction.channel_create,
        )

    @commands.Cog.listener()
    async def on_guild_channel_delete(
        self,
        channel: discord.abc.GuildChannel,
    ):
        await self.process_channel_event(
            channel,
            "channel_delete",
            discord.AuditLogAction.channel_delete,
        )

    # -------------------------
    # Commands
    # -------------------------

    @commands.hybrid_group(
        name="antinuke",
        invoke_without_command=True,
    )
    @commands.guild_only()
    async def antinuke(self, ctx: commands.Context):
        await ctx.send(
            "🛡️ Use `/antinuke status` to view protection status.",
            ephemeral=ctx.interaction is not None,
        )

    @antinuke.command(name="status")
    @commands.guild_only()
    async def status(self, ctx: commands.Context):
        config = await self.get_config(ctx.guild.id)

        embed = discord.Embed(
            title="🛡️ Sentinel Guard | Anti-Nuke",
            color=discord.Color.green(),
        )

        embed.add_field(
            name="Status",
            value="Enabled" if config["enabled"] else "Disabled",
            inline=True,
        )

        embed.add_field(
            name="Threshold",
            value=str(config["threshold"]),
            inline=True,
        )

        embed.add_field(
            name="Time Window",
            value=f"{config['window']} seconds",
            inline=True,
        )

        embed.add_field(
            name="Mode",
            value=config["mode"].upper(),
            inline=True,
        )

        embed.add_field(
            name="Alert Channel",
            value=(
                f"<#{config['alert_channel_id']}>"
                if config["alert_channel_id"]
                else "Not configured"
            ),
            inline=True,
        )

        await ctx.send(
            embed=embed,
            ephemeral=ctx.interaction is not None,
        )

    @antinuke.command(name="setup")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def setup(self, ctx: commands.Context):
        await self.get_config(ctx.guild.id)

        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("""
                UPDATE antinuke_config
                SET enabled = 1
                WHERE guild_id = ?
            """, (ctx.guild.id,))
            await db.commit()

        await ctx.send(
            "✅ Anti-Nuke monitoring enabled.\n"
            "⚠️ Default response mode: ALERT.\n"
            "Use `/antinuke alertchannel` to configure alerts.",
            ephemeral=ctx.interaction is not None,
        )

    @antinuke.command(name="threshold")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def threshold(
        self,
        ctx: commands.Context,
        count: int,
        window_seconds: int,
    ):
        if not 2 <= count <= 20:
            await ctx.send(
                "❌ Threshold must be between 2 and 20.",
                ephemeral=ctx.interaction is not None,
            )
            return

        if not 3 <= window_seconds <= 60:
            await ctx.send(
                "❌ Window must be between 3 and 60 seconds.",
                ephemeral=ctx.interaction is not None,
            )
            return

        await self.get_config(ctx.guild.id)

        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("""
                UPDATE antinuke_config
                SET threshold = ?, window_seconds = ?
                WHERE guild_id = ?
            """, (count, window_seconds, ctx.guild.id))
            await db.commit()

        await ctx.send(
            f"✅ Threshold updated: **{count} events** "
            f"in **{window_seconds} seconds**.",
            ephemeral=ctx.interaction is not None,
        )

    @antinuke.command(name="alertchannel")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def alertchannel(
        self,
        ctx: commands.Context,
        channel: discord.TextChannel = None,
    ):
        channel = channel or ctx.channel

        if not isinstance(channel, discord.TextChannel):
            await ctx.send(
                "❌ Select a text channel.",
                ephemeral=ctx.interaction is not None,
            )
            return

        permissions = channel.permissions_for(ctx.guild.me)

        if not permissions.send_messages or not permissions.embed_links:
            await ctx.send(
                "❌ Bot needs Send Messages and Embed Links permissions "
                "in that channel.",
                ephemeral=ctx.interaction is not None,
            )
            return

        await self.get_config(ctx.guild.id)

        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("""
                UPDATE antinuke_config
                SET alert_channel_id = ?
                WHERE guild_id = ?
            """, (channel.id, ctx.guild.id))
            await db.commit()

        await ctx.send(
            f"✅ Anti-Nuke alerts will be sent to {channel.mention}.",
            ephemeral=ctx.interaction is not None,
        )

    @antinuke.command(name="whitelist-add")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def whitelist_add(
        self,
        ctx: commands.Context,
        member: discord.Member,
    ):
        await self.get_config(ctx.guild.id)

        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("""
                INSERT OR IGNORE INTO antinuke_whitelist
                (guild_id, user_id)
                VALUES (?, ?)
            """, (ctx.guild.id, member.id))
            await db.commit()

        await ctx.send(
            f"✅ {member.mention} added to the Anti-Nuke whitelist.",
            ephemeral=ctx.interaction is not None,
        )

    @antinuke.command(name="whitelist-remove")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def whitelist_remove(
        self,
        ctx: commands.Context,
        member: discord.Member,
    ):
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("""
                DELETE FROM antinuke_whitelist
                WHERE guild_id = ? AND user_id = ?
            """, (ctx.guild.id, member.id))
            await db.commit()

        await ctx.send(
            f"✅ {member.mention} removed from the whitelist.",
            ephemeral=ctx.interaction is not None,
        )

    @antinuke.command(name="whitelist-list")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def whitelist_list(self, ctx: commands.Context):
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("""
                SELECT user_id FROM antinuke_whitelist
                WHERE guild_id = ?
                ORDER BY user_id
            """, (ctx.guild.id,))

            rows = await cursor.fetchall()

        if not rows:
            description = "No whitelisted users or bots."
        else:
            description = "\n".join(
                f"• <@{row[0]}> (`{row[0]}`)"
                for row in rows[:40]
            )

        embed = discord.Embed(
            title="🛡️ Anti-Nuke Whitelist",
            description=description,
            color=discord.Color.blurple(),
        )

        await ctx.send(
            embed=embed,
            ephemeral=ctx.interaction is not None,
        )

    @antinuke.command(name="mode")
    @commands.guild_only()
    @commands.has_guild_permissions(administrator=True)
    async def mode(
        self,
        ctx: commands.Context,
        mode: str,
    ):
        mode = mode.lower().strip()

        if mode not in ("alert", "kick"):
            await ctx.send(
                "❌ Available modes: `alert`, `kick`.\n"
                "`kick` only attempts to kick a verified bot actor "
                "after the configured threshold is reached.",
                ephemeral=ctx.interaction is not None,
            )
            return

        await self.get_config(ctx.guild.id)

        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("""
                UPDATE antinuke_config
                SET mode = ?
                WHERE guild_id = ?
            """, (mode, ctx.guild.id))
            await db.commit()

        await ctx.send(
            f"✅ Anti-Nuke mode set to **{mode.upper()}**.\n"
            + (
                "No automatic punishment is enabled."
                if mode == "alert"
                else
                "⚠️ Verified bot actors may be kicked after "
                "threshold detection. Human users are not auto-kicked."
            ),
            ephemeral=ctx.interaction is not None,
        )

    @commands.Cog.listener()
    async def on_ready(self):
        # Keep the in-memory cache bounded.
        now = time.monotonic()

        self.processed_entries = {
            key: timestamp
            for key, timestamp in self.processed_entries.items()
            if now - timestamp < 120
        }

        self.cooldowns = {
            key: timestamp
            for key, timestamp in self.cooldowns.items()
            if now - timestamp < 300
        }


async def setup(bot: commands.Bot):
    await bot.add_cog(AntiNuke(bot))
