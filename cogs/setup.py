import discord
from discord.ext import commands
from database.db import set_setup_status, add_security_log
from services.auto_role import ensure_member_role
from utils.security import embed_ok, embed_error


class Setup(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.hybrid_group(name="security", invoke_without_command=True)
    @commands.guild_only()
    async def security(self, ctx):
        await ctx.send(embed=discord.Embed(title="🛡️ Sentinel Guard Security", description="Use `/security setup` to configure baseline roles and settings.", color=discord.Color.blurple()))

    @security.command(name="setup")
    @commands.has_guild_permissions(manage_guild=True)
    @commands.bot_has_guild_permissions(manage_roles=True, manage_channels=True)
    async def setup_security(self, ctx, mode: str = "maximum"):
        if mode.lower() not in ("maximum", "basic"):
            return await ctx.send(embed=embed_error("Invalid mode", "Choose `basic` or `maximum`."))
        await ctx.defer()
        guild = ctx.guild
        status = discord.Embed(title="🛡️ Sentinel Guard Setup", description="Starting setup…", color=discord.Color.blurple())
        message = await ctx.send(embed=status)
        await set_setup_status(guild.id, "running")
        results = []
        try:
            role, assigned, failed = await ensure_member_role(guild)
            results.append(f"✅ Member role ready: {role.mention}")
            results.append(f"👥 Existing members processed: `{assigned}` assigned, `{failed}` failed")
            # Do not claim Anti-Nuke/Anti-Raid protections are active merely because the setup ran.
            await add_security_log(guild.id, "SECURITY_SETUP", f"Mode={mode}; role assigned={assigned}; failed={failed}", ctx.author.id)
            await set_setup_status(guild.id, "completed")
            status.title = "✅ Sentinel Guard Setup Complete"
            status.description = "\n".join(results) + "\n\nℹ️ Security monitoring modules require their own verified configuration."
            status.color = discord.Color.green()
        except Exception as exc:
            await set_setup_status(guild.id, "failed")
            status.title = "❌ Setup Failed"
            status.description = f"Setup stopped safely.\n`{type(exc).__name__}: {str(exc)[:500]}`"
            status.color = discord.Color.red()
        await message.edit(embed=status)


async def setup(bot):
    await bot.add_cog(Setup(bot))
