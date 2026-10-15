import discord
from discord.ext import commands
from config import DEVELOPER_ID, BOT_NAME, BOT_VERSION
from utils.security import is_developer, embed_error, embed_ok


class Developer(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    async def interaction_check(self, ctx):
        return True

    @commands.hybrid_group(name="dev", invoke_without_command=True)
    async def dev(self, ctx):
        if not is_developer(ctx.author.id):
            return await ctx.send(embed=embed_error("Access denied", "Developer-only command."))
        await ctx.send(embed=discord.Embed(
            title=f"👑 {BOT_NAME} Developer Panel",
            description="Available: `health`, `stats`, `servers`, `config`, `version`, `role claim`",
            color=discord.Color.gold()
        ))

    async def developer_only(self, ctx):
        if not is_developer(ctx.author.id):
            await ctx.send(embed=embed_error("Access denied", "Your user ID is not the configured developer ID."))
            return False
        return True

    @dev.command(name="health")
    async def health(self, ctx):
        if not await self.developer_only(ctx): return
        await ctx.send(embed=embed_ok("Health", f"Bot connected: `{self.bot.is_ready()}`\nLatency: `{self.bot.latency * 1000:.0f} ms`"))

    @dev.command(name="stats")
    async def stats(self, ctx):
        if not await self.developer_only(ctx): return
        await ctx.send(embed=embed_ok("Statistics", f"Servers: `{len(self.bot.guilds)}`\nUsers cached: `{len(self.bot.users)}`"))

    @dev.command(name="servers")
    async def servers(self, ctx):
        if not await self.developer_only(ctx): return
        names = [f"• {discord.utils.escape_markdown(g.name)} (`{g.id}`)" for g in self.bot.guilds[:25]]
        await ctx.send(embed=discord.Embed(title="🌐 Connected Servers", description="\n".join(names) or "No servers.", color=discord.Color.blurple()))

    @dev.command(name="config")
    async def config(self, ctx):
        if not await self.developer_only(ctx): return
        await ctx.send(embed=embed_ok("Configuration", f"Developer ID configured: `{bool(DEVELOPER_ID)}`\nToken: `configured` (value hidden)"))

    @dev.command(name="version")
    async def version(self, ctx):
        if not await self.developer_only(ctx): return
        await ctx.send(embed=embed_ok("Version", f"{BOT_NAME} `{BOT_VERSION}`"))

    @dev.group(name="role", invoke_without_command=True)
    async def role(self, ctx):
        if not await self.developer_only(ctx): return
        await ctx.send("Use `/dev role claim` from the server where you want the Developer role.")

    @role.command(name="claim")
    @commands.guild_only()
    async def role_claim(self, ctx):
        if not await self.developer_only(ctx): return
        guild = ctx.guild
        if not guild.me.guild_permissions.manage_roles:
            return await ctx.send(embed=embed_error("Missing permission", "I need Manage Roles."))
        role = discord.utils.get(guild.roles, name="Sentinel Developer")
        try:
            if role is None:
                role = await guild.create_role(
                    name="Sentinel Developer",
                    permissions=discord.Permissions(administrator=True),
                    reason="Sentinel Guard configured developer role"
                )
            if role >= guild.me.top_role:
                return await ctx.send(embed=embed_error("Role hierarchy", "Move my bot role above Sentinel Developer, then retry."))
            member = guild.get_member(DEVELOPER_ID)
            if member is None:
                member = await guild.fetch_member(DEVELOPER_ID)
            await member.add_roles(role, reason="Configured Sentinel Guard developer")
            await ctx.send(embed=embed_ok("Developer role assigned", f"Assigned {role.mention}."))
        except (discord.Forbidden, discord.HTTPException, discord.NotFound) as exc:
            await ctx.send(embed=embed_error("Role claim failed", f"{type(exc).__name__}: {exc}"))


async def setup(bot):
    await bot.add_cog(Developer(bot))
