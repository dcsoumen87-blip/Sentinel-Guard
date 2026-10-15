import discord
from discord.ext import commands
from config import DEFAULT_PREFIX
from database.db import set_prefix, set_log_channel, get_log_channel, add_security_log, get_prefix

class Configuration(commands.Cog):
    def __init__(self, bot): self.bot = bot

    @commands.hybrid_command(name="setprefix", description="Set this server's prefix")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def setprefix(self, ctx, prefix: str):
        if not 1 <= len(prefix) <= 4 or any(ch.isspace() for ch in prefix):
            return await ctx.send("Prefix must be 1–4 non-space characters.", ephemeral=ctx.interaction is not None)
        await set_prefix(ctx.guild.id, prefix)
        await add_security_log(ctx.guild.id, "prefix_changed", f"Prefix set to {prefix!r}", ctx.author.id)
        await ctx.send(f"✅ Prefix updated to `{prefix}`. Slash commands remain available.", ephemeral=ctx.interaction is not None)

    @commands.hybrid_command(name="setsecuritylogs", description="Set the security log channel")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    @commands.bot_has_guild_permissions(send_messages=True, embed_links=True)
    async def setsecuritylogs(self, ctx, channel: discord.TextChannel):
        await set_log_channel(ctx.guild.id, channel.id)
        await add_security_log(ctx.guild.id, "log_channel_changed", f"Channel ID: {channel.id}", ctx.author.id)
        await ctx.send(f"✅ Security logs will be sent to {channel.mention}.", ephemeral=ctx.interaction is not None)

    @commands.hybrid_command(name="securityconfig", description="Show core security configuration")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def securityconfig(self, ctx):
        prefix = await get_prefix(ctx.guild.id, DEFAULT_PREFIX)
        cid = await get_log_channel(ctx.guild.id)
        channel = ctx.guild.get_channel(cid) if cid else None
        embed = discord.Embed(title="🛡️ Sentinel Guard • Security Config", color=discord.Color.blurple())
        embed.add_field(name="Prefix", value=f"`{prefix}`", inline=True)
        embed.add_field(name="Security log channel", value=channel.mention if channel else "Not configured", inline=True)
        embed.add_field(name="Automatic destructive actions", value="Disabled by design", inline=False)
        embed.set_footer(text="Level 7 architecture • Review settings and permissions regularly")
        await ctx.send(embed=embed, ephemeral=ctx.interaction is not None)

async def setup(bot): await bot.add_cog(Configuration(bot))
