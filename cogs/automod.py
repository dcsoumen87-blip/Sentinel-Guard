import time
from collections import defaultdict, deque
import discord
from discord.ext import commands
from database.db import add_security_log, get_log_channel

INVITE_MARKERS=("discord.gg/","discord.com/invite/")
PHISHING_MARKERS=("free nitro","claim nitro","steamcommunitiy","discord-gift")
class AutoMod(commands.Cog):
    def __init__(self,bot):
        self.bot=bot; self.recent=defaultdict(deque); self.last_warn={}

    @commands.Cog.listener()
    async def on_message(self,message):
        if message.author.bot or not message.guild or not isinstance(message.channel,discord.TextChannel): return
        if message.author.guild_permissions.manage_messages: return
        text=message.content.lower(); now=time.monotonic(); key=(message.guild.id,message.author.id)
        q=self.recent[key]; q.append((now,text))
        while q and now-q[0][0]>8:q.popleft()
        reason=None
        if len(q)>=6: reason="message_flood"
        elif message.mention_everyone: reason="mass_mention"
        elif any(x in text for x in PHISHING_MARKERS): reason="suspicious_phishing_text"
        elif any(x in text for x in INVITE_MARKERS) and not message.author.guild_permissions.manage_guild: reason="discord_invite"
        elif len(q)>=3 and len({t for _,t in q})==1: reason="duplicate_messages"
        if not reason:return
        try:
            await message.delete()
        except discord.HTTPException: pass
        await add_security_log(message.guild.id,"automod_"+reason,f"Message by {message.author.id} in channel {message.channel.id}",message.author.id)
        if now-self.last_warn.get(key,0)>15:
            self.last_warn[key]=now
            try: await message.channel.send(f"⚠️ {message.author.mention}, message removed by AutoMod ({reason.replace('_',' ')}).",delete_after=8,allowed_mentions=discord.AllowedMentions(users=True))
            except discord.HTTPException: pass

    @commands.hybrid_command(name="automodstatus")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def automodstatus(self,ctx):
        await ctx.send("🛡️ AutoMod active: flood, duplicate messages, mass mentions, common invite and suspicious-text indicators. Heuristics can produce false positives; test in a private server.")

async def setup(bot): await bot.add_cog(AutoMod(bot))
