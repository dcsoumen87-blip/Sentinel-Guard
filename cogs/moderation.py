from datetime import timedelta
import discord
from discord.ext import commands
from database.db import add_security_log

class Moderation(commands.Cog):
    def __init__(self,bot): self.bot=bot
    async def check(self,ctx,m):
        if m.id in (ctx.author.id,ctx.guild.owner_id):
            await ctx.send("Cannot target yourself or server owner.",ephemeral=ctx.interaction is not None); return False
        if ctx.author.id!=ctx.guild.owner_id and m.top_role>=ctx.author.top_role:
            await ctx.send("Your top role must be higher than target.",ephemeral=ctx.interaction is not None); return False
        if m.top_role>=ctx.guild.me.top_role:
            await ctx.send("Bot's top role must be higher than target.",ephemeral=ctx.interaction is not None); return False
        return True
    @commands.hybrid_command(name="kick")
    @commands.guild_only()
    @commands.has_guild_permissions(kick_members=True)
    @commands.bot_has_guild_permissions(kick_members=True)
    async def kick(self,ctx,member:discord.Member,*,reason="No reason provided"):
        if not await self.check(ctx,member):return
        await member.kick(reason=reason); await add_security_log(ctx.guild.id,"kick",reason,ctx.author.id)
        await ctx.send(f"👢 Kicked {member.mention}.",ephemeral=ctx.interaction is not None)
    @commands.hybrid_command(name="ban")
    @commands.guild_only()
    @commands.has_guild_permissions(ban_members=True)
    @commands.bot_has_guild_permissions(ban_members=True)
    async def ban(self,ctx,member:discord.Member,*,reason="No reason provided"):
        if not await self.check(ctx,member):return
        await member.ban(reason=reason,delete_message_seconds=0); await add_security_log(ctx.guild.id,"ban",reason,ctx.author.id)
        await ctx.send(f"🔨 Banned {member.mention}.",ephemeral=ctx.interaction is not None)
    @commands.hybrid_command(name="timeout")
    @commands.guild_only()
    @commands.has_guild_permissions(moderate_members=True)
    @commands.bot_has_guild_permissions(moderate_members=True)
    async def timeout(self,ctx,member:discord.Member,minutes:int,*,reason="No reason provided"):
        if not 1<=minutes<=40320:
            await ctx.send("Minutes must be 1–40320.",ephemeral=ctx.interaction is not None);return
        if not await self.check(ctx,member):return
        await member.timeout(timedelta(minutes=minutes),reason=reason); await add_security_log(ctx.guild.id,"timeout",reason,ctx.author.id)
        await ctx.send(f"⏳ Timed out {member.mention} for {minutes} minutes.",ephemeral=ctx.interaction is not None)
    @commands.hybrid_command(name="purge")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_messages=True)
    @commands.bot_has_guild_permissions(manage_messages=True,read_message_history=True)
    async def purge(self,ctx,amount:int):
        if not 1<=amount<=100:
            await ctx.send("Amount must be 1–100.",ephemeral=ctx.interaction is not None);return
        deleted=await ctx.channel.purge(limit=amount+1)
        await add_security_log(ctx.guild.id,"purge",f"Deleted {max(0,len(deleted)-1)} messages",ctx.author.id)
        await ctx.send(f"🧹 Deleted {max(0,len(deleted)-1)} messages.",ephemeral=ctx.interaction is not None)
    @commands.hybrid_command(name="warn")
    @commands.guild_only()
    @commands.has_guild_permissions(moderate_members=True)
    async def warn(self,ctx,member:discord.Member,*,reason="No reason provided"):
        await add_security_log(ctx.guild.id,"warn",f"Target {member.id}: {reason}",ctx.author.id)
        import aiosqlite
        from config import DB_PATH
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("INSERT INTO warnings(guild_id,user_id,moderator_id,reason) VALUES(?,?,?,?)",(ctx.guild.id,member.id,ctx.author.id,reason)); await db.commit()
        await ctx.send(f"⚠️ Warned {member.mention}: {reason}",ephemeral=ctx.interaction is not None)

async def setup(bot): await bot.add_cog(Moderation(bot))
