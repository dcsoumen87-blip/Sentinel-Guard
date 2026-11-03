import time
from collections import defaultdict, deque
import discord
from discord.ext import commands
from config import DB_PATH
from database.db import add_security_log, get_log_channel

INVITE_MARKERS = ("discord.gg/", "discord.com/invite/")
PHISHING_MARKERS = ("free nitro", "claim nitro", "steamcommunitiy", "discord-gift")


class AutoMod(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.recent = defaultdict(deque)
        self.last_warn = {}

    async def _get_config(self, guild_id):
        import aiosqlite
        async with aiosqlite.connect(DB_PATH) as db:
            cur = await db.execute(
                "SELECT enabled, log_actions FROM automod_config WHERE guild_id=?", (guild_id,)
            )
            row = await cur.fetchone()
            if row:
                return {"enabled": bool(row[0]), "log_actions": bool(row[1])}
            # Create default config
            await db.execute(
                "INSERT OR IGNORE INTO automod_config(guild_id, enabled, log_actions) VALUES(?, 1, 1)",
                (guild_id,),
            )
            await db.commit()
        return {"enabled": True, "log_actions": True}

    async def _set_config(self, guild_id, enabled=None, log_actions=None):
        import aiosqlite
        async with aiosqlite.connect(DB_PATH) as db:
            if enabled is not None:
                await db.execute(
                    "UPDATE automod_config SET enabled=? WHERE guild_id=?", (int(enabled), guild_id)
                )
            if log_actions is not None:
                await db.execute(
                    "UPDATE automod_config SET log_actions=? WHERE guild_id=?", (int(log_actions), guild_id)
                )
            await db.commit()

    @commands.Cog.listener()
    async def on_message(self, message):
        if message.author.bot or not message.guild or not isinstance(message.channel, discord.TextChannel):
            return
        if message.author.guild_permissions.manage_messages:
            return

        cfg = await self._get_config(message.guild.id)
        if not cfg["enabled"]:
            return

        text = message.content.lower()
        now = time.monotonic()
        key = (message.guild.id, message.author.id)
        q = self.recent[key]
        q.append((now, text))
        while q and now - q[0][0] > 8:
            q.popleft()

        reason = None
        if len(q) >= 6:
            reason = "message_flood"
        elif message.mention_everyone:
            reason = "mass_mention"
        elif any(x in text for x in PHISHING_MARKERS):
            reason = "suspicious_phishing_text"
        elif any(x in text for x in INVITE_MARKERS) and not message.author.guild_permissions.manage_guild:
            reason = "discord_invite"
        elif len(q) >= 3 and len({t for _, t in q}) == 1:
            reason = "duplicate_messages"

        if not reason:
            return

        try:
            await message.delete()
        except discord.HTTPException:
            pass

        if cfg["log_actions"]:
            await add_security_log(
                message.guild.id,
                "automod_" + reason,
                f"Message by {message.author.id} in channel {message.channel.id}",
                message.author.id,
            )

        if now - self.last_warn.get(key, 0) > 15:
            self.last_warn[key] = now
            try:
                await message.channel.send(
                    f"âš ï¸ {message.author.mention}, message removed by AutoMod ({reason.replace('_', ' ')}).",
                    delete_after=8,
                    allowed_mentions=discord.AllowedMentions(users=True),
                )
            except discord.HTTPException:
                pass

    @commands.hybrid_group(name="automod", invoke_without_command=True)
    @commands.guild_only()
    async def automod(self, ctx):
        await ctx.send("Use `/automod enable|disable|status|config`", ephemeral=ctx.interaction is not None)

    @automod.command(name="status")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def status(self, ctx):
        cfg = await self._get_config(ctx.guild.id)
        e = discord.Embed(title="ðŸ›¡ï¸ AutoMod Status", color=discord.Color.blue())
        e.add_field(name="Enabled", value="âœ… Yes" if cfg["enabled"] else "âŒ No", inline=True)
        e.add_field(name="Log Actions", value="âœ… Yes" if cfg["log_actions"] else "âŒ No", inline=True)
        e.add_field(
            name="Filters Active",
            value=(
                "â€¢ Message flood (6 msgs/8s)\n"
                "â€¢ Mass mentions (@everyone/@here)\n"
                "â€¢ Suspicious phishing text\n"
                "â€¢ Discord invites (non-managers)\n"
                "â€¢ Duplicate messages (3x same)"
            ),
            inline=False,
        )
        await ctx.send(embed=e, ephemeral=ctx.interaction is not None)

    @automod.command(name="enable")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def enable(self, ctx):
        """Enable AutoMod."""
        await self._set_config(ctx.guild.id, enabled=True)
        await add_security_log(ctx.guild.id, "automod_enabled", "AutoMod enabled", ctx.author.id)
        await ctx.send("âœ… AutoMod **enabled**.", ephemeral=ctx.interaction is not None)

    @automod.command(name="disable")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def disable(self, ctx):
        """Disable AutoMod."""
        await self._set_config(ctx.guild.id, enabled=False)
        await add_security_log(ctx.guild.id, "automod_disabled", "AutoMod disabled", ctx.author.id)
        await ctx.send("âŒ AutoMod **disabled**.", ephemeral=ctx.interaction is not None)

    @automod.command(name="toggle")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def toggle(self, ctx):
        """Toggle AutoMod on/off."""
        cfg = await self._get_config(ctx.guild.id)
        new_state = not cfg["enabled"]
        await self._set_config(ctx.guild.id, enabled=new_state)
        action = "enabled" if new_state else "disabled"
        await add_security_log(ctx.guild.id, f"automod_{action}", f"AutoMod {action} via toggle", ctx.author.id)
        await ctx.send(f"ðŸ”„ AutoMod **{action}**.", ephemeral=ctx.interaction is not None)

    @automod.command(name="logging")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def logging(self, ctx, state: str):
        """Enable/disable AutoMod action logging to security logs. Usage: /automod logging on|off"""
        state = state.lower()
        if state not in ("on", "off", "enable", "disable", "true", "false", "yes", "no"):
            await ctx.send("Usage: `/automod logging on|off`", ephemeral=ctx.interaction is not None)
            return
        enabled = state in ("on", "enable", "true", "yes")
        await self._set_config(ctx.guild.id, log_actions=enabled)
        await add_security_log(ctx.guild.id, "automod_logging", f"Logging {'enabled' if enabled else 'disabled'}", ctx.author.id)
        await ctx.send(f"ðŸ“ AutoMod action logging **{'enabled' if enabled else 'disabled'}**.", ephemeral=ctx.interaction is not None)


async def setup(bot):
    await bot.add_cog(AutoMod(bot))
