import asyncio
import logging
import discord
from discord.ext import commands
from database.db import set_log_channel, add_security_log
from config import DEVELOPER_ID

log = logging.getLogger("sentinel_guard.setup")
ROLE_DEFINITIONS = {
    "Sentinel Developer": discord.Permissions(administrator=True),
    "Sentinel Owner": discord.Permissions(manage_guild=True, manage_channels=True, manage_roles=True, view_audit_log=True),
    "Sentinel Admin": discord.Permissions(manage_messages=True, kick_members=True, ban_members=True, moderate_members=True, view_audit_log=True),
    "Sentinel Moderator": discord.Permissions(manage_messages=True, kick_members=True, moderate_members=True, view_audit_log=True),
    "Sentinel Trusted": discord.Permissions(view_channel=True, send_messages=True, read_message_history=True),
    "Sentinel Member": discord.Permissions(view_channel=True, send_messages=True, read_message_history=True),
}
# Developer role is created without Administrator by default. Claiming it is a separate explicit command.
ROLE_DEFINITIONS["Sentinel Developer"] = discord.Permissions.none()

class Setup(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.role_jobs = set()

    @commands.hybrid_command(name="security_setup")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    @commands.bot_has_guild_permissions(manage_roles=True, manage_channels=True, view_audit_log=True)
    async def security_setup(self, ctx):
        guild = ctx.guild
        status = []
        created_roles = []
        # Create every planned role, idempotently. Roles are non-admin by default.
        for name, permissions in ROLE_DEFINITIONS.items():
            role = discord.utils.get(guild.roles, name=name)
            if role is None:
                try:
                    role = await guild.create_role(name=name, permissions=permissions, reason="Sentinel Guard security setup")
                    created_roles.append(name)
                    status.append(f"✅ Created role: **{name}**")
                except discord.HTTPException as exc:
                    status.append(f"❌ Could not create **{name}**: {exc.__class__.__name__}")
            else:
                status.append(f"↪️ Role exists: **{name}**")
        category = discord.utils.get(guild.categories, name="Sentinel Security")
        if category is None:
            try:
                category = await guild.create_category("Sentinel Security", reason="Sentinel Guard setup")
                status.append("✅ Created category: **Sentinel Security**")
            except discord.HTTPException as exc:
                category = None
                status.append(f"❌ Category creation failed: {exc.__class__.__name__}")
        log_channel = discord.utils.get(guild.text_channels, name="sentinel-logs")
        if log_channel is None and category:
            try:
                log_channel = await guild.create_text_channel("sentinel-logs", category=category, reason="Sentinel Guard setup")
                status.append("✅ Created channel: **#sentinel-logs**")
            except discord.HTTPException as exc:
                status.append(f"❌ Log channel creation failed: {exc.__class__.__name__}")
        if log_channel:
            await set_log_channel(guild.id, log_channel.id)
        await add_security_log(guild.id, "security_setup", f"Roles created: {', '.join(created_roles) or 'none'}", ctx.author.id)
        # Assign basic member role to current members, in bounded batches; never grant elevated roles.
        member_role = discord.utils.get(guild.roles, name="Sentinel Member")
        assigned = failed = 0
        if member_role:
            try:
                members = [m async for m in guild.fetch_members(limit=None)]
                for start in range(0, len(members), 20):
                    batch = members[start:start+20]
                    for member in batch:
                        if member.bot or member.get_role(member_role.id):
                            continue
                        try:
                            await member.add_roles(member_role, reason="Sentinel Guard initial member role assignment")
                            assigned += 1
                        except (discord.Forbidden, discord.HTTPException):
                            failed += 1
                    await asyncio.sleep(1)
            except (discord.Forbidden, discord.HTTPException):
                status.append("⚠️ Could not fetch all members. Check Server Members Intent and permissions.")
        status.append(f"👥 Existing members assigned Sentinel Member: **{assigned}**; failures: **{failed}**")
        status.append("ℹ️ New members will receive Sentinel Member automatically if the bot can manage their role.")
        pages = "\n".join(status)
        embed = discord.Embed(title="🛡️ Sentinel Guard Setup Report", description=pages[:4000], color=discord.Color.blurple())
        await ctx.send(embed=embed, ephemeral=ctx.interaction is not None)

    @commands.hybrid_command(name="devroleclaim", description="Developer-only: create and claim the Sentinel Developer role")
    @commands.guild_only()
    @commands.bot_has_guild_permissions(manage_roles=True)
    async def devroleclaim(self, ctx):
        # This intentionally grants Administrator only after an explicit, ID-bound claim.
        if not DEVELOPER_ID or ctx.author.id != DEVELOPER_ID:
            return await ctx.send("🔒 This command is restricted to the configured developer ID.", ephemeral=ctx.interaction is not None)
        guild = ctx.guild
        role = discord.utils.get(guild.roles, name="Sentinel Developer")
        try:
            if role is None:
                role = await guild.create_role(name="Sentinel Developer", permissions=discord.Permissions.none(), reason="Sentinel developer claim")
            if role >= guild.me.top_role:
                return await ctx.send("❌ Move the bot's highest role above Sentinel Developer, then retry.", ephemeral=ctx.interaction is not None)
            await role.edit(permissions=discord.Permissions(administrator=True), reason="Explicit developer role claim by configured DEVELOPER_ID")
            await ctx.author.add_roles(role, reason="Configured Sentinel Guard developer claim")
            await add_security_log(guild.id, "developer_role_claimed", "Administrator-enabled Sentinel Developer role assigned to configured developer ID", ctx.author.id)
            embed = discord.Embed(title="👑 Developer Role Claimed", description="`Sentinel Developer` was created/updated and assigned to the verified developer account. This role has **Administrator** access.", color=discord.Color.gold())
            await ctx.send(embed=embed, ephemeral=ctx.interaction is not None)
        except discord.Forbidden:
            await ctx.send("❌ Discord denied this action. Check Manage Roles and role hierarchy.", ephemeral=ctx.interaction is not None)
        except discord.HTTPException as exc:
            await ctx.send(f"❌ Discord API error: `{type(exc).__name__}`", ephemeral=ctx.interaction is not None)

    @commands.Cog.listener()
    async def on_member_join(self, member):
        role = discord.utils.get(member.guild.roles, name="Sentinel Member")
        if role is None:
            return
        try:
            await member.add_roles(role, reason="Sentinel Guard automatic member role")
            log.info("AUTO_ROLE_ASSIGNED guild=%s member=%s", member.guild.id, member.id)
        except discord.Forbidden:
            log.error("AUTO_ROLE_FORBIDDEN guild=%s; move bot role above Sentinel Member", member.guild.id)
        except discord.HTTPException as exc:
            log.error("AUTO_ROLE_ERROR guild=%s member=%s error=%r", member.guild.id, member.id, exc)

async def setup(bot):
    await bot.add_cog(Setup(bot))
