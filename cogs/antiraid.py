import time
from collections import defaultdict, deque
import discord
from discord.ext import commands
from config import DB_PATH
from database.db import get_log_channel, add_security_log


class AntiRaid(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.joins = defaultdict(deque)

    async def _get_config(self, guild_id):
        import aiosqlite
        async with aiosqlite.connect(DB_PATH) as db:
            cur = await db.execute(
                "SELECT enabled, threshold, window_seconds, alert_channel_id FROM antiraid_config WHERE guild_id=?",
                (guild_id,),
            )
            row = await cur.fetchone()
            if row:
                return {"enabled": bool(row[0]), "threshold": row[1], "window": row[2], "alert": row[3]}
            await db.execute(
                "INSERT OR IGNORE INTO antiraid_config(guild_id, enabled, threshold, window_seconds) VALUES(?, 1, 8, 20)",
                (guild_id,),
            )
            await db.commit()
        return {"enabled": True, "threshold": 8, "window": 20, "alert": None}

    async def _set_config(self, guild_id, enabled=None, threshold=None, window=None, alert=None):
        import aiosqlite
        async with aiosqlite.connect(DB_PATH) as db:
            if enabled is not None:
                await db.execute(
                    "UPDATE antiraid_config SET enabled=? WHERE guild_id=?", (int(enabled), guild_id)
                )
            if threshold is not None:
                await db.execute(
                    "UPDATE antiraid_config SET threshold=? WHERE guild_id=?", (threshold, guild_id)
                )
            if window is not None:
                await db.execute(
                    "UPDATE antiraid_config SET window_seconds=? WHERE guild_id=?", (window, guild_id)
                )
            if alert is not None:
                await db.execute(
                    "UPDATE antiraid_config SET alert_channel_id=? WHERE guild_id=?", (alert, guild_id)
                )
            await db.commit()

    @commands.Cog.listener()
    async def on_member_join(self, member):
        cfg = await self._get_config(member.guild.id)
        if not cfg["enabled"]:
            return

        q = self.joins[member.guild.id]
        now = time.monotonic()
        q.append(now)
        while q and now - q[0] > cfg["window"]:
            q.popleft()

        if len(q) >= cfg["threshold"]:
            await add_security_log(
                member.guild.id,
                "raid_join_spike",
                f"{len(q)} joins in {cfg['window']} seconds (threshold: {cfg['threshold']})",
                None,
            )
            cid = await get_log_channel(member.guild.id)
            ch = member.guild.get_channel(cid) if cid else None
            if isinstance(ch, discord.TextChannel):
                try:
                    await ch.send(
                        f"ðŸš¨ **Possible raid:** {len(q)} joins within {cfg['window']} seconds. "
                        f"Review new accounts; no automatic punishment applied."
                    )
                except discord.HTTPException:
                    pass

    @commands.hybrid_group(name="raidmode", invoke_without_command=True)
    @commands.guild_only()
    async def raidmode(self, ctx):
        await ctx.send("Use `/raidmode status`, `/raidmode enable|disable|toggle`, or `/raidmode config`.", ephemeral=ctx.interaction is not None)

    @raidmode.command(name="status")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def status(self, ctx):
        cfg = await self._get_config(ctx.guild.id)
        e = discord.Embed(title="ðŸ›¡ï¸ Anti-Raid Status", color=discord.Color.blue())
        e.add_field(name="Enabled", value="âœ… Yes" if cfg["enabled"] else "âŒ No", inline=True)
        e.add_field(name="Threshold", value=f"{cfg['threshold']} joins", inline=True)
        e.add_field(name="Window", value=f"{cfg['window']} seconds", inline=True)
        e.add_field(name="Alert Channel", value=f"<#{cfg['alert']}>" if cfg["alert"] else "Not configured", inline=False)
        e.add_field(name="Recent Joins (in window)", value=str(len(self.joins[ctx.guild.id])), inline=True)
        await ctx.send(embed=e, ephemeral=ctx.interaction is not None)

    @raidmode.command(name="enable")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def enable(self, ctx):
        await self._set_config(ctx.guild.id, enabled=True)
        await add_security_log(ctx.guild.id, "raidmode_enabled", "AntiRaid monitoring enabled", ctx.author.id)
        await ctx.send("âœ… AntiRaid **enabled**. Monitoring join spikes.", ephemeral=ctx.interaction is not None)

    @raidmode.command(name="disable")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def disable(self, ctx):
        await self._set_config(ctx.guild.id, enabled=False)
        await add_security_log(ctx.guild.id, "raidmode_disabled", "AntiRaid monitoring disabled", ctx.author.id)
        await ctx.send("âŒ AntiRaid **disabled**.", ephemeral=ctx.interaction is not None)

    @raidmode.command(name="toggle")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def toggle(self, ctx):
        cfg = await self._get_config(ctx.guild.id)
        new_state = not cfg["enabled"]
        await self._set_config(ctx.guild.id, enabled=new_state)
        action = "enabled" if new_state else "disabled"
        await add_security_log(ctx.guild.id, f"raidmode_{action}", f"AntiRaid {action} via toggle", ctx.author.id)
        await ctx.send(f"ðŸ”„ AntiRaid **{action}**.", ephemeral=ctx.interaction is not None)

    @raidmode.command(name="config")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def config_cmd(self, ctx, threshold: int = None, window_seconds: int = None, alert_channel: discord.TextChannel = None):
        if threshold is not None and not 3 <= threshold <= 50:
            await ctx.send("Threshold must be 3â€“50.", ephemeral=ctx.interaction is not None)
            return
        if window_seconds is not None and not 10 <= window_seconds <= 120:
            await ctx.send("Window must be 10â€“120 seconds.", ephemeral=ctx.interaction is not None)
            return
        if alert_channel is not None:
            p = alert_channel.permissions_for(ctx.guild.me)
            if not p.send_messages or not p.embed_links:
                await ctx.send("Bot needs Send Messages and Embed Links in that channel.", ephemeral=ctx.interaction is not None)
                return

        await self._set_config(
            ctx.guild.id,
            threshold=threshold,
            window=window_seconds,
            alert=alert_channel.id if alert_channel else None,
        )
        await add_security_log(ctx.guild.id, "raidmode_config", f"Config updated: threshold={threshold}, window={window_seconds}, alert={alert_channel.id if alert_channel else 'unchanged'}", ctx.author.id)
        await ctx.send("âœ… AntiRaid configuration updated.", ephemeral=ctx.interaction is not None)

    # Legacy command alias
    @commands.hybrid_command(name="raidstatus")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def raidstatus(self, ctx):
        cfg = await self._get_config(ctx.guild.id)
        await ctx.send(
            f"ðŸ›¡ï¸ Anti-Raid: {'Active' if cfg['enabled'] else 'Disabled'} â€¢ "
            f"Threshold: {cfg['threshold']} joins / {cfg['window']}s â€¢ "
            f"Recent: {len(self.joins[ctx.guild.id])} â€¢ "
            f"Alert: <#{cfg['alert']}>" if cfg['alert'] else "No alert channel",
            ephemeral=ctx.interaction is not None,
        )


async def setup(bot):
    await bot.add_cog(AntiRaid(bot))
