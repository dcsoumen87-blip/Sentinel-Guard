import time
from collections import defaultdict, deque
import discord
from discord.ext import commands
from database.db import get_log_channel, add_security_log

class AntiRaid(commands.Cog):
    def __init__(self,bot):
        self.bot=bot; self.joins=defaultdict(deque)

    @commands.Cog.listener()
    async def on_member_join(self,member):
        q=self.joins[member.guild.id]; now=time.monotonic(); q.append(now)
        while q and now-q[0]>20:q.popleft()
        if len(q)>=8:
            await add_security_log(member.guild.id,"raid_join_spike",f"{len(q)} joins in 20 seconds",None)
            cid=await get_log_channel(member.guild.id); ch=member.guild.get_channel(cid) if cid else None
            if isinstance(ch,discord.TextChannel):
                try:
                    await ch.send(f"🚨 **Possible raid:** {len(q)} joins within 20 seconds. Review new accounts; no automatic punishment applied.")
                except discord.HTTPException: pass

    @commands.hybrid_command(name="raidstatus")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def raidstatus(self,ctx):
        await ctx.send(f"🛡️ Anti-Raid join monitor active. Recent joins in 20s: {len(self.joins[ctx.guild.id])}. Threshold: 8. Alert-only.")

async def setup(bot): await bot.add_cog(AntiRaid(bot))
