import discord
from discord.ext import commands
from utils.security import embed_info


class AntiNuke(commands.Cog):
    """Baseline monitoring status. Automated punitive mitigation is intentionally not enabled by default."""
    def __init__(self, bot):
        self.bot = bot

    @commands.hybrid_group(name="antinuke", invoke_without_command=True)
    @commands.guild_only()
    async def antinuke(self, ctx):
        await ctx.send(embed=embed_info("Anti-Nuke", "Baseline module loaded. Use `/antinuke status` to inspect status. No automatic punitive action is enabled by this starter module."))

    @antinuke.command(name="status")
    async def status(self, ctx):
        await ctx.send(embed=embed_info("Anti-Nuke Status", "🟡 Monitoring framework loaded.\nAudit-log event correlation and configurable thresholds are not yet implemented."))

async def setup(bot):
    await bot.add_cog(AntiNuke(bot))
