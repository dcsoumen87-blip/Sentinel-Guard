import discord
from discord.ext import commands
from utils.security import embed_info


class AutoMod(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.hybrid_command(name="automod")
    @commands.has_guild_permissions(manage_guild=True)
    @commands.guild_only()
    async def automod(self, ctx):
        await ctx.send(embed=embed_info(
            "AutoMod",
            "AutoMod module loaded. Spam, invite, phishing and mention thresholds still need configuration before enforcement."
        ))

async def setup(bot):
    await bot.add_cog(AutoMod(bot))
