import discord
from discord.ext import commands
from utils.security import embed_info


class AntiRaid(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.join_times = {}

    @commands.Cog.listener()
    async def on_member_join(self, member):
        # Safe baseline: record joins in memory only; no automatic punishment.
        from collections import deque
        from datetime import datetime, timezone
        queue = self.join_times.setdefault(member.guild.id, deque(maxlen=100))
        queue.append(datetime.now(timezone.utc))

    @commands.hybrid_command(name="raidmode")
    @commands.has_guild_permissions(manage_guild=True)
    @commands.guild_only()
    async def raidmode(self, ctx, enabled: bool = None):
        await ctx.send(embed=embed_info(
            "Raid Mode",
            "Raid Mode configuration storage and enforcement are not yet implemented."
            if enabled is not None else
            "Raid detection framework loaded; automatic restrictions are not enabled in this starter module."
        ))

async def setup(bot):
    await bot.add_cog(AntiRaid(bot))
