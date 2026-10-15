import os
import platform
import discord

from datetime import datetime, timezone
from discord.ext import commands

from config import (
    BOT_NAME,
    BOT_VERSION,
    BOT_TOKEN,
    DEVELOPER_ID,
    DEFAULT_PREFIX,
    DATABASE_PATH,
)

from utils.security import is_developer


# ==========================================
# EMBED HELPERS
# ==========================================

def success_embed(title, description):
    return discord.Embed(
        title=f"✅ {title}",
        description=description,
        color=discord.Color.green(),
        timestamp=datetime.now(timezone.utc),
    )


def error_embed(title, description):
    return discord.Embed(
        title=f"❌ {title}",
        description=description,
        color=discord.Color.red(),
        timestamp=datetime.now(timezone.utc),
    )


def info_embed(title, description):
    return discord.Embed(
        title=f"🛡️ {title}",
        description=description,
        color=discord.Color.blurple(),
        timestamp=datetime.now(timezone.utc),
    )


# ==========================================
# DEVELOPER COG
# ==========================================

class Developer(commands.Cog):

    def __init__(self, bot):
        self.bot = bot

    # ======================================
    # ACCESS CONTROL
    # ======================================

    async def require_developer(self, ctx):
        """
        Only the exact configured Developer ID
        can use Developer commands.
        """

        if not is_developer(ctx.author.id):
            await ctx.send(
                embed=error_embed(
                    "Access Denied",
                    "🔒 This command is restricted to "
                    "the configured Sentinel Guard Developer."
                ),
                ephemeral=(
                    getattr(ctx, "interaction", None) is not None
                ),
            )
            return False

        return True

    # ======================================
    # MAIN DEVELOPER PANEL
    # ======================================

    @commands.hybrid_group(
        name="dev",
        invoke_without_command=True,
    )
    async def dev(self, ctx):
        """Open the Developer command panel."""

        if not await self.require_developer(ctx):
            return

        embed = info_embed(
            f"{BOT_NAME} Developer Panel",
            (
                "👑 **Developer Access Verified**\n\n"
                "Available commands:\n\n"
                "`/dev info`\n"
                "`/dev health`\n"
                "`/dev stats`\n"
                "`/dev servers`\n"
                "`/dev config`\n"
                "`/dev version`\n"
                "`/dev diagnostics`\n"
                "`/dev logs`\n"
                "`/dev maintenance`\n"
                "`/dev backup`\n"
                "`/dev role claim`"
            ),
        )

        embed.set_footer(
            text=f"{BOT_NAME} v{BOT_VERSION}"
        )

        await ctx.send(
            embed=embed,
            ephemeral=(
                getattr(ctx, "interaction", None) is not None
            ),
        )

    # ======================================
    # DEVELOPER INFO
    # ======================================

    @dev.command(name="info")
    async def developer_info(self, ctx):
        """Show configured developer information."""

        if not await self.require_developer(ctx):
            return

        embed = info_embed(
            "Developer Information",
            (
                f"👑 Developer: {ctx.author.mention}\n"
                f"🆔 Developer ID: `{DEVELOPER_ID}`\n"
                f"🤖 Bot: **{BOT_NAME}**\n"
                f"📦 Version: `{BOT_VERSION}`"
            ),
        )

        await ctx.send(
            embed=embed,
            ephemeral=(
                getattr(ctx, "interaction", None) is not None
            ),
        )

    # ======================================
    # HEALTH CHECK
    # ======================================

    @dev.command(name="health")
    async def health(self, ctx):
        """Check bot health and latency."""

        if not await self.require_developer(ctx):
            return

        latency = self.bot.latency * 1000

        embed = info_embed(
            "System Health",
            (
                f"🟢 Bot Ready: `{self.bot.is_ready()}`\n"
                f"🏓 Gateway Latency: `{latency:.0f} ms`\n"
                f"🌐 Connected Servers: `{len(self.bot.guilds)}`\n"
                f"🐍 Python: `{platform.python_version()}`\n"
                f"📦 discord.py: `{discord.__version__}`"
            ),
        )

        await ctx.send(
            embed=embed,
            ephemeral=(
                getattr(ctx, "interaction", None) is not None
            ),
        )

    # ======================================
    # BOT STATISTICS
    # ======================================

    @dev.command(name="stats")
    async def stats(self, ctx):
        """Show bot statistics."""

        if not await self.require_developer(ctx):
            return

        embed = info_embed(
            "Bot Statistics",
            (
                f"🌐 Servers: `{len(self.bot.guilds)}`\n"
                f"👥 Cached Users: `{len(self.bot.users)}`\n"
                f"⚙️ Loaded Extensions: "
                f"`{len(self.bot.extensions)}`\n"
                f"🏓 Latency: "
                f"`{self.bot.latency * 1000:.0f} ms`"
            ),
        )

        await ctx.send(
            embed=embed,
            ephemeral=(
                getattr(ctx, "interaction", None) is not None
            ),
        )

    # ======================================
    # SERVER LIST
    # ======================================

    @dev.command(name="servers")
    async def servers(self, ctx):
        """List connected Discord servers."""

        if not await self.require_developer(ctx):
            return

        guilds = list(self.bot.guilds)

        description = "\n".join(
            (
                f"• **{discord.utils.escape_markdown(guild.name)}** "
                f"`{guild.id}` — `{guild.member_count or 0}` members"
            )
            for guild in guilds[:20]
        )

        if len(guilds) > 20:
            description += (
                f"\n\n...and {len(guilds) - 20} more servers."
            )

        embed = info_embed(
            "Connected Servers",
            description or "The bot is not connected to any servers.",
        )

        await ctx.send(
            embed=embed,
            ephemeral=(
                getattr(ctx, "interaction", None) is not None
            ),
        )

    # ======================================
    # SAFE CONFIGURATION STATUS
    # ======================================

    @dev.command(name="config")
    async def config_status(self, ctx):
        """Show safe configuration information."""

        if not await self.require_developer(ctx):
            return

        embed = info_embed(
            "Configuration Status",
            (
                f"🤖 Bot Name: `{BOT_NAME}`\n"
                f"📦 Version: `{BOT_VERSION}`\n"
                f"👑 Developer ID Configured: "
                f"`{DEVELOPER_ID != 0}`\n"
                f"🔑 Bot Token Configured: "
                f"`{bool(BOT_TOKEN)}`\n"
                f"⌨️ Default Prefix: `{DEFAULT_PREFIX}`\n"
                f"💾 Database Path: `{DATABASE_PATH}`"
            ),
        )

        # Never print the actual bot token.

        await ctx.send(
            embed=embed,
            ephemeral=(
                getattr(ctx, "interaction", None) is not None
            ),
        )

    # ======================================
    # VERSION
    # ======================================

    @dev.command(name="version")
    async def version(self, ctx):
        """Show bot version."""

        if not await self.require_developer(ctx):
            return

        embed = success_embed(
            "Version Information",
            (
                f"🛡️ **{BOT_NAME}**\n"
                f"📦 Version: `{BOT_VERSION}`\n"
                f"🐍 Python: `{platform.python_version()}`\n"
                f"📚 discord.py: `{discord.__version__}`"
            ),
        )

        await ctx.send(
            embed=embed,
            ephemeral=(
                getattr(ctx, "interaction", None) is not None
            ),
        )

    # ======================================
    # DIAGNOSTICS
    # ======================================

    @dev.command(name="diagnostics")
    async def diagnostics(self, ctx):
        """Run basic runtime diagnostics."""

        if not await self.require_developer(ctx):
            return

        extension_names = sorted(self.bot.extensions.keys())

        extensions = "\n".join(
            f"🟢 `{name}`"
            for name in extension_names
        )

        if not extensions:
            extensions = "No extensions loaded."

        embed = info_embed(
            "Runtime Diagnostics",
            (
                f"Gateway Ready: `{self.bot.is_ready()}`\n"
                f"Database Path Configured: "
                f"`{bool(DATABASE_PATH)}`\n"
                f"Developer ID Configured: "
                f"`{DEVELOPER_ID != 0}`\n\n"
                f"**Loaded Extensions**\n{extensions}"
            ),
        )

        await ctx.send(
            embed=embed,
            ephemeral=(
                getattr(ctx, "interaction", None) is not None
            ),
        )

    # ======================================
    # RECENT LOGS
    # ======================================

    @dev.command(name="logs")
    async def logs(self, ctx):
        """Show recent application log lines if available."""

        if not await self.require_developer(ctx):
            return

        log_path = os.getenv(
            "APP_LOG_FILE",
            "sentinel.log",
        )

        if not os.path.isfile(log_path):
            return await ctx.send(
                embed=info_embed(
                    "Application Logs",
                    (
                        "No local log file was found.\n\n"
                        "Railway deployment logs can be viewed "
                        "from the Railway dashboard."
                    ),
                ),
                ephemeral=(
                    getattr(ctx, "interaction", None) is not None
                ),
            )

        try:
            with open(
                log_path,
                "r",
                encoding="utf-8",
                errors="replace",
            ) as file:
                lines = file.readlines()[-15:]

            content = "".join(lines).strip()

            if not content:
                content = "The log file is empty."

            # Discord embed descriptions have a 4096 character limit.
            content = content[-3500:]

            embed = info_embed(
                "Recent Application Logs",
                f"```text\n{content}\n```",
            )

            await ctx.send(
                embed=embed,
                ephemeral=(
                    getattr(ctx, "interaction", None) is not None
                ),
            )

        except OSError as exc:
            await ctx.send(
                embed=error_embed(
                    "Log Read Failed",
                    f"`{type(exc).__name__}: {exc}`",
                ),
                ephemeral=(
                    getattr(ctx, "interaction", None) is not None
                ),
            )

    # ======================================
    # MAINTENANCE STATUS
    # ======================================

    @dev.command(name="maintenance")
    async def maintenance(self, ctx):
        """Show maintenance status."""

        if not await self.require_developer(ctx):
            return

        await ctx.send(
            embed=info_embed(
                "Maintenance",
                (
                    "ℹ️ This command currently reports status only.\n\n"
                    "A persistent maintenance mode with command "
                    "restrictions has not yet been implemented."
                ),
            ),
            ephemeral=(
                getattr(ctx, "interaction", None) is not None
            ),
        )

    # ======================================
    # BACKUP STATUS
    # ======================================

    @dev.command(name="backup")
    async def backup(self, ctx):
        """Show backup status."""

        if not await self.require_developer(ctx):
            return

        await ctx.send(
            embed=info_embed(
                "Backup Status",
                (
                    "⚠️ Automated database backup and restore "
                    "have not yet been implemented.\n\n"
                    "No backup has been created by this command."
                ),
            ),
            ephemeral=(
                getattr(ctx, "interaction", None) is not None
            ),
        )

    # ======================================
    # DEVELOPER ROLE GROUP
    # ======================================

    @dev.group(
        name="role",
        invoke_without_command=True,
    )
    async def role(self, ctx):
        """Developer role commands."""

        if not await self.require_developer(ctx):
            return

        await ctx.send(
            "👑 Use `/dev role claim` in the server where "
            "you want to claim the Developer role.",
            ephemeral=(
                getattr(ctx, "interaction", None) is not None
            ),
        )

    @role.command(name="claim")
    @commands.guild_only()
    async def role_claim(self, ctx):
        """
        Create and assign the Developer role.

        This command is restricted to the configured Developer ID.
        """

        if not await self.require_developer(ctx):
            return

        guild = ctx.guild

        if guild is None:
            return await ctx.send(
                embed=error_embed(
                    "Server Required",
                    "Run this command inside a Discord server.",
                ),
                ephemeral=(
                    getattr(ctx, "interaction", None) is not None
                ),
            )

        me = guild.me

        if me is None or not me.guild_permissions.manage_roles:
            return await ctx.send(
                embed=error_embed(
                    "Missing Permission",
                    "The bot needs the Manage Roles permission.",
                ),
                ephemeral=(
                    getattr(ctx, "interaction", None) is not None
                ),
            )

        # Only the configured developer can receive this role.
        member = guild.get_member(DEVELOPER_ID)

        if member is None:
            try:
                member = await guild.fetch_member(DEVELOPER_ID)
            except discord.NotFound:
                return await ctx.send(
                    embed=error_embed(
                        "Developer Not Found",
                        "The configured Developer ID is not a member "
                        "of this server.",
                    ),
                    ephemeral=(
                        getattr(ctx, "interaction", None) is not None
                    ),
                )
            except discord.HTTPException:
                return await ctx.send(
                    embed=error_embed(
                        "Member Lookup Failed",
                        "Discord could not retrieve the developer member.",
                    ),
                    ephemeral=(
                        getattr(ctx, "interaction", None) is not None
                    ),
                )

        role = discord.utils.get(
            guild.roles,
            name="Sentinel Developer",
        )

        try:
            if role is None:
                # Administrator is powerful. This is restricted to the
                # exact configured Developer ID by the check above.
                role = await guild.create_role(
                    name="Sentinel Developer",
                    permissions=discord.Permissions(
                        administrator=True
                    ),
                    reason=(
                        "Sentinel Guard: configured developer role"
                    ),
                )

            if role >= me.top_role:
                return await ctx.send(
                    embed=error_embed(
                        "Role Hierarchy Error",
                        "Move the bot's highest role above "
                        "`Sentinel Developer`, then retry.",
                    ),
                    ephemeral=(
                        getattr(ctx, "interaction", None) is not None
                    ),
                )

            if role not in member.roles:
                await member.add_roles(
                    role,
                    reason="Configured Sentinel Guard developer",
                )

            await ctx.send(
                embed=success_embed(
                    "Developer Role Ready",
                    (
                        f"👑 Assigned {role.mention} to "
                        f"{member.mention}.\n\n"
                        "⚠️ This role has Administrator permission."
                    ),
                ),
                ephemeral=(
                    getattr(ctx, "interaction", None) is not None
                ),
            )

        except discord.Forbidden:
            await ctx.send(
                embed=error_embed(
                    "Discord Permission Denied",
                    (
                        "Discord denied the role operation. "
                        "Check Manage Roles permission and role hierarchy."
                    ),
                ),
                ephemeral=(
                    getattr(ctx, "interaction", None) is not None
                ),
            )

        except discord.HTTPException as exc:
            await ctx.send(
                embed=error_embed(
                    "Role Claim Failed",
                    f"Discord API error: `{exc}`",
                ),
                ephemeral=(
                    getattr(ctx, "interaction", None) is not None
                ),
            )


# ==========================================
# EXTENSION SETUP
# ==========================================

async def setup(bot):
    await bot.add_cog(Developer(bot))
