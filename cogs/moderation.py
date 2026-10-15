import discord
from discord.ext import commands
from database.db import add_security_log, add_warning, get_warnings, clear_warnings
from utils.security import can_moderate_target, embed_ok, embed_error


class Moderation(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    async def check_target(self, ctx, member):
        if not isinstance(ctx.author, discord.Member):
            await ctx.send(embed=embed_error("Unavailable", "This command must be used in a server."))
            return False
        allowed, reason = can_moderate_target(ctx.author, member)
        if not allowed:
            await ctx.send(embed=embed_error("Action blocked", reason))
            return False
        return True

    @commands.hybrid_command(name="ban")
    @commands.has_permissions(ban_members=True)
    @commands.bot_has_permissions(ban_members=True)
    @commands.guild_only()
    async def ban(self, ctx, member: discord.Member, *, reason="No reason provided"):
        if not await self.check_target(ctx, member): return
        await member.ban(reason=f"{ctx.author} ({ctx.author.id}): {reason}", delete_message_seconds=0)
        await add_security_log(ctx.guild.id, "BAN", f"{member} ({member.id}): {reason}", ctx.author.id)
        await ctx.send(embed=embed_ok("Member banned", f"{member.mention} was banned.\nReason: {reason}"))

    @commands.hybrid_command(name="kick")
    @commands.has_permissions(kick_members=True)
    @commands.bot_has_permissions(kick_members=True)
    @commands.guild_only()
    async def kick(self, ctx, member: discord.Member, *, reason="No reason provided"):
        if not await self.check_target(ctx, member): return
        await member.kick(reason=f"{ctx.author} ({ctx.author.id}): {reason}")
        await add_security_log(ctx.guild.id, "KICK", f"{member} ({member.id}): {reason}", ctx.author.id)
        await ctx.send(embed=embed_ok("Member kicked", f"{member.mention} was kicked.\nReason: {reason}"))

    @commands.hybrid_command(name="timeout")
    @commands.has_permissions(moderate_members=True)
    @commands.bot_has_permissions(moderate_members=True)
    @commands.guild_only()
    async def timeout(self, ctx, member: discord.Member, minutes: commands.Range[int, 1, 40320], *, reason="No reason provided"):
        if not await self.check_target(ctx, member): return
        until = discord.utils.utcnow() + discord.timedelta(minutes=minutes) if hasattr(discord, "timedelta") else None
        from datetime import timedelta
        await member.timeout(timedelta(minutes=minutes), reason=f"{ctx.author} ({ctx.author.id}): {reason}")
        await add_security_log(ctx.guild.id, "TIMEOUT", f"{member} for {minutes} minutes: {reason}", ctx.author.id)
        await ctx.send(embed=embed_ok("Member timed out", f"{member.mention} for `{minutes}` minute(s).\nReason: {reason}"))

    @commands.hybrid_command(name="untimeout")
    @commands.has_permissions(moderate_members=True)
    @commands.bot_has_permissions(moderate_members=True)
    @commands.guild_only()
    async def untimeout(self, ctx, member: discord.Member, *, reason="No reason provided"):
        if not await self.check_target(ctx, member): return
        await member.timeout(None, reason=f"{ctx.author} ({ctx.author.id}): {reason}")
        await add_security_log(ctx.guild.id, "UNTIMEOUT", f"{member}: {reason}", ctx.author.id)
        await ctx.send(embed=embed_ok("Timeout removed", f"Removed timeout from {member.mention}."))

    @commands.hybrid_command(name="mute")
    @commands.has_permissions(manage_roles=True)
    @commands.bot_has_permissions(manage_roles=True)
    @commands.guild_only()
    async def mute(self, ctx, member: discord.Member, *, reason="No reason provided"):
        if not await self.check_target(ctx, member): return
        role = discord.utils.get(ctx.guild.roles, name="Sentinel Muted")
        if role is None:
            role = await ctx.guild.create_role(name="Sentinel Muted", reason="Sentinel Guard mute role")
            for channel in ctx.guild.channels:
                try:
                    await channel.set_permissions(role, send_messages=False, add_reactions=False, speak=False)
                except discord.HTTPException:
                    pass
        if role >= ctx.guild.me.top_role:
            return await ctx.send(embed=embed_error("Role hierarchy", "Move my bot role above Sentinel Muted."))
        await member.add_roles(role, reason=reason)
        await add_security_log(ctx.guild.id, "MUTE", f"{member}: {reason}", ctx.author.id)
        await ctx.send(embed=embed_ok("Member muted", f"{member.mention} received {role.mention}."))

    @commands.hybrid_command(name="unmute")
    @commands.has_permissions(manage_roles=True)
    @commands.bot_has_permissions(manage_roles=True)
    @commands.guild_only()
    async def unmute(self, ctx, member: discord.Member, *, reason="No reason provided"):
        if not await self.check_target(ctx, member): return
        role = discord.utils.get(ctx.guild.roles, name="Sentinel Muted")
        if role is None or role not in member.roles:
            return await ctx.send(embed=embed_error("Not muted", "That member does not have Sentinel Muted."))
        await member.remove_roles(role, reason=reason)
        await add_security_log(ctx.guild.id, "UNMUTE", f"{member}: {reason}", ctx.author.id)
        await ctx.send(embed=embed_ok("Member unmuted", f"Removed mute role from {member.mention}."))

    @commands.hybrid_command(name="warn")
    @commands.has_permissions(moderate_members=True)
    @commands.guild_only()
    async def warn(self, ctx, member: discord.Member, *, reason="No reason provided"):
        if not await self.check_target(ctx, member): return
        await add_warning(ctx.guild.id, member.id, ctx.author.id, reason)
        await add_security_log(ctx.guild.id, "WARN", f"{member}: {reason}", ctx.author.id)
        await ctx.send(embed=embed_ok("Warning recorded", f"{member.mention}: {reason}"))

    @commands.hybrid_command(name="warnings")
    @commands.has_permissions(moderate_members=True)
    @commands.guild_only()
    async def warnings(self, ctx, member: discord.Member):
        rows = await get_warnings(ctx.guild.id, member.id)
        description = "\n".join(f"`#{r[0]}` <@{r[1]}> — {r[2]} ({r[3]})" for r in rows) or "No warnings found."
        await ctx.send(embed=discord.Embed(title=f"📋 Warnings: {member}", description=description[:4000], color=discord.Color.orange()))

    @commands.hybrid_command(name="clearwarnings")
    @commands.has_permissions(moderate_members=True)
    @commands.guild_only()
    async def clearwarnings(self, ctx, member: discord.Member):
        count = await clear_warnings(ctx.guild.id, member.id)
        await add_security_log(ctx.guild.id, "CLEAR_WARNINGS", f"{member}: removed {count}", ctx.author.id)
        await ctx.send(embed=embed_ok("Warnings cleared", f"Removed `{count}` warning(s) for {member.mention}."))

    @commands.hybrid_command(name="purge")
    @commands.has_permissions(manage_messages=True)
    @commands.bot_has_permissions(manage_messages=True, read_message_history=True)
    @commands.guild_only()
    async def purge(self, ctx, amount: commands.Range[int, 1, 100]):
        if isinstance(ctx, commands.Context) and ctx.interaction is None:
            deleted = await ctx.channel.purge(limit=amount + 1)
            return await ctx.send(embed=embed_ok("Messages removed", f"Deleted `{len(deleted)-1}` message(s)."), delete_after=5)
        await ctx.defer(ephemeral=True)
        deleted = await ctx.channel.purge(limit=amount)
        await ctx.send(embed=embed_ok("Messages removed", f"Deleted `{len(deleted)}` message(s)."), ephemeral=True)

    @commands.hybrid_command(name="unban")
    @commands.has_permissions(ban_members=True)
    @commands.bot_has_permissions(ban_members=True)
    @commands.guild_only()
    async def unban(self, ctx, user_id: str, *, reason="No reason provided"):
        try:
            uid = int(user_id)
            user = await self.bot.fetch_user(uid)
            await ctx.guild.unban(user, reason=f"{ctx.author}: {reason}")
            await add_security_log(ctx.guild.id, "UNBAN", f"{uid}: {reason}", ctx.author.id)
            await ctx.send(embed=embed_ok("User unbanned", f"{user} (`{uid}`) was unbanned."))
        except (ValueError, discord.NotFound, discord.Forbidden, discord.HTTPException) as exc:
            await ctx.send(embed=embed_error("Unban failed", f"{type(exc).__name__}: {exc}"))

    @commands.hybrid_command(name="modlogs")
    @commands.has_permissions(view_audit_log=True)
    @commands.guild_only()
    async def modlogs(self, ctx, member: discord.Member = None):
        import aiosqlite
        from config import DATABASE_PATH
        async with aiosqlite.connect(DATABASE_PATH) as db:
            if member:
                cursor = await db.execute("SELECT action, details, created_at FROM security_logs WHERE guild_id=? AND details LIKE ? ORDER BY id DESC LIMIT 10", (ctx.guild.id, f"%{member.id}%"))
            else:
                cursor = await db.execute("SELECT action, details, created_at FROM security_logs WHERE guild_id=? ORDER BY id DESC LIMIT 10", (ctx.guild.id,))
            rows = await cursor.fetchall()
        desc = "\n".join(f"`{r[2]}` **{r[0]}** — {r[1]}" for r in rows) or "No logs found."
        await ctx.send(embed=discord.Embed(title="📜 Moderation Logs", description=desc[:4000], color=discord.Color.blurple()))


async def setup(bot):
    await bot.add_cog(Moderation(bot))
