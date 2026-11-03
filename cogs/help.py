"""Sentinel Guard premium help panel.

Keep this file at: cogs/help.py
Place the banner image at: assets/help_banner.png

Requires discord.py 2.x.
The command/category content below is kept from the supplied help.py.
"""
from __future__ import annotations

import time
from pathlib import Path

import discord
from discord.ext import commands

from config import DEVELOPER_ID, DEFAULT_PREFIX
from core.emojis import component, custom_keys, e, refresh, upload_folder
from database.db import get_prefix

BLUE = discord.Color.from_rgb(35, 91, 170)
GOLD = discord.Color.from_rgb(230, 190, 92)
GREEN = discord.Color.from_rgb(46, 204, 113)
RED = discord.Color.from_rgb(231, 76, 60)

BASE_DIR = Path(__file__).resolve().parent.parent
BANNER_PATH = BASE_DIR / "assets" / "1793447579821.png"

# Replace this with your real support-server invite.
SUPPORT_URL = "https://discord.gg/YOUR_SUPPORT_INVITE"

PAGES: dict[str, dict] = {
    "Overview": {
        "emoji": "overview",
        "title": "Sentinel Guard - Security Center",
        "description": (
            "Your central control panel for server protection, moderation and recovery.\n"
            "Choose a module from the menu to see its commands and required permissions.\n\n"
            "**Quick Start:** `/security_setup` -> `/autosetup` -> Done!"
        ),
        "commands": [
            ("/help", "Open this interactive help panel.", "Everyone"),
            ("/security_setup", "Initial security setup (roles, logs, category).", "Manage Server"),
            ("/autosetup", "Fully automatic one-click server setup.", "Manage Server"),
            ("/securityconfig", "View this server's security configuration.", "Manage Server"),
            ("/setsecuritylogs #channel", "Choose the security log channel.", "Manage Server"),
            ("/antinuke rejoin on|off", "Send a one-time rejoin invite by DM when a member is unbanned.", "Manage Server"),
            ("/antinuke features", "List every protection AntiNuke provides.", "Everyone"),
            ("/antinuke status", "View AntiNuke configuration and status.", "Manage Server"),
            ("/automod status", "View AutoMod configuration and status.", "Manage Server"),
            ("/lockdown_status", "Check current lockdown/panic mode status.", "Manage Server"),
        ],
    },
    "Setup & Auto-Setup": {
        "emoji": "setup",
        "title": "Setup & Auto-Setup",
        "description": "One-command server security initialization and role synchronization.",
        "commands": [
            ("/security_setup", "Create Sentinel roles, log channel, and security category with colors.", "Manage Server"),
            ("/autosetup", "Fully automatic setup: roles, channels, configs, AntiNuke, AutoMod, Lockdown - all at once.", "Manage Server"),
            ("/syncroles", "Sync all Sentinel role colors, permissions, hoist, and mentionable settings.", "Manage Server"),
            ("/setsecuritylogs #channel", "Set or update the security log channel.", "Manage Server"),
            ("/setprefix <prefix>", "Change this server's command prefix (1-4 chars).", "Manage Server"),
            ("/securityconfig", "View complete security configuration overview.", "Manage Server"),
        ],
    },
    "AntiNuke": {
        "emoji": "antinuke",
        "title": "AntiNuke Protection",
        "description": "Configure destructive-action detection, trusted-member controls, and **automatic lockdown on nuke attempts**.",
        "commands": [
            ("/antinuke status", "Show AntiNuke configuration, threshold, window, alert channel.", "Manage Server"),
            ("/antinuke enable", "Enable AntiNuke monitoring (channel create/delete detection).", "Manage Server"),
            ("/antinuke disable", "Disable AntiNuke monitoring completely.", "Manage Server"),
            ("/antinuke toggle", "Quick toggle AntiNuke on/off.", "Manage Server"),
            ("/antinuke mode <alert|strip|kick|ban>", "Choose what happens to an attacker (default: ban).", "Server Owner / Extra Owner"),
            ("/antinuke threshold <count> <seconds>", "Set event threshold (2-20) and detection window (3-60s).", "Manage Server"),
            ("/antinuke alertchannel #channel", "Set where AntiNuke alerts are sent.", "Manage Server"),
            ("/antinuke whitelist-add @member", "Add a trusted member to the AntiNuke whitelist.", "Manage Server"),
            ("/antinuke whitelist-remove @member", "Remove a member from the whitelist.", "Manage Server"),
            ("/antinuke whitelist-list", "List all whitelisted members.", "Manage Server"),
            ("/antinuke incidents [limit]", "View recent AntiNuke incidents (default 10, max 25).", "Manage Server"),
        ],
    },
    "Lockdown / Panic Mode": {
        "emoji": "lockdown",
        "title": "Server Lockdown & Panic Mode",
        "description": "Emergency server lockdown - denies @everyone Send Messages in all text channels. **Auto-triggers on nuke detection.**\n\nOnly Server Owner or Extra Owners can use these.",
        "commands": [
            ("/lockdown state:Enable [reason]", "Enable full server lockdown (panic mode).", "Server Owner / Extra Owner"),
            ("/lockdown state:Disable [reason]", "Disable lockdown and restore permissions.", "Server Owner / Extra Owner"),
            ("/lockdown_status", "Check current lockdown state and locked channel count.", "Manage Server"),
            ("/panic enable|disable|toggle", "Quick panic mode toggle (alias for lockdown).", "Server Owner / Extra Owner"),
        ],
    },
    "AntiRaid": {
        "emoji": "antiraid",
        "title": "AntiRaid Monitoring",
        "description": "Monitor join spikes and configure raid protection with enable/disable.",
        "commands": [
            ("/raidstatus", "Review AntiRaid join-spike monitoring status.", "Manage Server"),
            ("/raidmode enable", "Enable AntiRaid monitoring and alerts.", "Manage Server"),
            ("/raidmode disable", "Disable AntiRaid monitoring.", "Manage Server"),
            ("/raidmode toggle", "Quick toggle AntiRaid on/off.", "Manage Server"),
            ("/raidmode config <threshold> <seconds>", "Set join threshold (3-50) and window (10-120s).", "Manage Server"),
        ],
    },
    "AutoMod": {
        "emoji": "automod",
        "title": "Automated Moderation",
        "description": "Message flood, mass mentions, suspicious links, invites, and duplicate detection with full config.",
        "commands": [
            ("/automod status", "Show AutoMod configuration and active filters.", "Manage Server"),
            ("/automod enable", "Enable AutoMod message filtering.", "Manage Server"),
            ("/automod disable", "Disable AutoMod completely.", "Manage Server"),
            ("/automod toggle", "Quick toggle AutoMod on/off.", "Manage Server"),
            ("/automod logging on|off", "Enable/disable AutoMod action logging to security logs.", "Manage Server"),
        ],
    },
    "Moderation": {
        "emoji": "moderation",
        "title": "Member Moderation",
        "description": "Standard moderation commands. Use responsibly and follow your server's rules.",
        "commands": [
            ("/kick @member [reason]", "Remove a member from the server.", "Kick Members"),
            ("/ban @member [reason]", "Ban a member from the server.", "Ban Members"),
            ("/timeout @member <minutes> [reason]", "Temporarily restrict a member (1-40320 min).", "Moderate Members"),
            ("/purge <amount>", "Delete recent messages (1-100).", "Manage Messages"),
            ("/warn @member [reason]", "Issue a warning (logged to database).", "Moderate Members"),
        ],
    },
    "Configuration": {
        "emoji": "config",
        "title": "Server Configuration",
        "description": "Manage server-specific prefix and security logging settings.",
        "commands": [
            ("/securityconfig", "View this server's current configuration.", "Manage Server"),
            ("/setprefix <prefix>", "Change this server's command prefix (1-4 chars).", "Manage Server"),
            ("/setsecuritylogs #channel", "Set the security log destination.", "Manage Server"),
        ],
    },
    "Recovery & Backups": {
        "emoji": "recovery",
        "title": "Recovery & Backups",
        "description": "Database health checks, SQLite snapshots, and configuration drift detection.",
        "commands": [
            ("/recovery_status", "Check database, backup, and security setup health.", "Manage Server"),
            ("/recovery_backup", "Create a consistent SQLite snapshot (local).", "Administrator"),
            ("/devrecovery", "Developer recovery diagnostics.", "Bot Developer"),
            ("/devbackup", "Create a SQLite recovery backup (dev).", "Bot Developer"),
            ("/devlogs", "Review application log information.", "Bot Developer"),
        ],
    },
    "Permissions & Whitelist": {
        "emoji": "permissions",
        "title": "Permissions & Whitelist",
        "description": "Server Owner only: Extra Owners, AntiNuke whitelist, and granular permissions.",
        "commands": [
            ("/extraowner_add @member", "Add a server-specific Extra Owner.", "Server Owner"),
            ("/extraowner_remove @member", "Remove an Extra Owner.", "Server Owner"),
            ("/extraowner_list", "List all Extra Owners.", "Server Owner"),
            ("/whitelist_add @member", "Add member to AntiNuke whitelist.", "Server Owner"),
            ("/whitelist_remove @member", "Remove from whitelist and clear permissions.", "Server Owner"),
            ("/whitelist_permission grant|revoke|check @member <permission>", "Manage whitelist permissions (channel_create, channel_delete, member_kick, member_ban, admin_grant).", "Server Owner"),
        ],
    },
    "Developer": {
        "emoji": "developer",
        "title": "Developer Operations",
        "description": "Restricted diagnostics and operational commands for the configured developer.",
        "commands": [
            ("/devhelp", "Open the developer command reference.", "Bot Developer"),
            ("/devsystem", "Inspect host resource usage (CPU, RAM, Disk, Network).", "Bot Developer"),
            ("/devcpu", "Inspect CPU usage.", "Bot Developer"),
            ("/devram", "Inspect memory usage.", "Bot Developer"),
            ("/devdisk", "Inspect disk usage.", "Bot Developer"),
            ("/devnetwork", "Inspect network information.", "Bot Developer"),
            ("/devuptime", "View bot/host uptime.", "Bot Developer"),
            ("/devhealth", "Check gateway and database health.", "Bot Developer"),
            ("/devstats", "View bot statistics.", "Bot Developer"),
            ("/devinfo", "Show bot information.", "Bot Developer"),
            ("/devbackup", "Create a database backup.", "Bot Developer"),
            ("/devlogs", "View log information.", "Bot Developer"),
            ("/devreload <extension>", "Reload an approved extension.", "Bot Developer"),
            ("/devservers", "List all servers the bot is in.", "Bot Developer"),
            ("/devsetup", "Check security setup status for current server.", "Bot Developer"),
            ("/devroleclaim", "Claim Sentinel Developer role (Owner only).", "Bot Developer"),
            ("/devmaintenance", "Maintenance status.", "Bot Developer"),
            ("/devversion", "Show software versions.", "Bot Developer"),
        ],
    },
}


def _uptime_text(bot: commands.Bot) -> str:
    started = getattr(bot, "started_at", None)
    if started is None:
        return "Not available"
    seconds = max(0, int(time.monotonic() - started))
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, _ = divmod(seconds, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def _visible_pages(developer_allowed: bool) -> list[str]:
    return [
        name for name in PAGES
        if name != "Developer" or developer_allowed
    ]


def build_embed(
    bot: commands.Bot,
    page_name: str,
    prefix: str,
    guild: discord.Guild | None,
) -> discord.Embed:
    page = PAGES[page_name]

    if page_name == "Overview":
        embed = discord.Embed(
            title=f"{e('overview')}  Sentinel Guard - Security Center",
            description=(
                "A powerful security and administration bot for your server.\n"
                "Everything you need to protect, moderate and manage your community.\n\n"
                "**Quick Start:** `/autosetup` - One command, full protection."
            ),
            color=BLUE,
        )

        categories = len(PAGES) - 1  # Exclude Developer from count
        total_commands = sum(len(item["commands"]) for name, item in PAGES.items() if name != "Developer")
        modules = "\n".join(
            f"{e(item['emoji'])}  **{name}**"
            for name, item in PAGES.items()
            if name not in ("Overview", "Developer")
        )
        embed.add_field(
            name=f"{e('quickstart')}  Modules",
            value=modules[:1024],
            inline=False,
        )
        embed.add_field(
            name=f"{e('stats')}  Quick Stats",
            value=(
                f"- **{categories}** Command Categories\n"
                f"- **{total_commands}** Listed Commands\n"
                "- **Security - Moderation - Recovery - Auto-Setup**"
            ),
            inline=False,
        )
        latency = round(bot.latency * 1000) if bot.latency is not None else "-"
        embed.add_field(
            name=f"{e('commands')}  System Status",
            value=(
                f"**Gateway latency:** `{latency} ms`\n"
                f"**Connected servers:** `{len(bot.guilds):,}`\n"
                f"**Bot uptime:** `{_uptime_text(bot)}`\n"
                f"**Server prefix:** `{discord.utils.escape_markdown(prefix)}`"
            ),
            inline=False,
        )
        if guild:
            embed.add_field(
                name="Current Server",
                value=discord.utils.escape_markdown(guild.name)[:100],
                inline=False,
            )
        embed.add_field(
            name="Choose a category",
            value="Select a category from the menu below to view its commands and required permissions.",
            inline=False,
        )
    else:
        color = GOLD if page_name == "Developer" else (RED if page_name == "Lockdown / Panic Mode" else BLUE)
        embed = discord.Embed(
            title=f"{e(page['emoji'])}  {page['title']}",
            description=page["description"],
            color=color,
        )
        for command_name, description, access in page["commands"]:
            embed.add_field(
                name=f"`{command_name}`",
                value=f"{description}\n**Required access:** {access}",
                inline=False,
            )

    embed.set_footer(text="Developed by MOD TRYOUT - Sentinel Guard")
    if bot.user:
        embed.set_author(
            name="Sentinel Guard Security Center",
            icon_url=bot.user.display_avatar.url,
        )
    # The uploaded banner is attached to the help message as help_banner.png.
    embed.set_image(url="attachment://help_banner.png")
    return embed


class HelpSelect(discord.ui.Select):
    def __init__(self, help_view: "HelpView"):
        self.help_view = help_view
        options = [
            discord.SelectOption(
                label=name,
                description=(
                    "Main help page" if name == "Overview"
                    else PAGES[name]["description"][:100]
                ),
                value=name,
                emoji=component("menu" if name == "Overview" else PAGES[name]["emoji"]),
                default=name == help_view.page_name,
            )
            for name in _visible_pages(help_view.developer_allowed)
        ]
        super().__init__(
            placeholder="Choose a category...",
            min_values=1,
            max_values=1,
            options=options,
            row=0,
        )

    async def callback(self, interaction: discord.Interaction) -> None:
        await self.help_view.show_page(interaction, self.values[0])


class HelpView(discord.ui.View):
    def __init__(
        self,
        bot: commands.Bot,
        prefix: str,
        requester_id: int,
    ):
        super().__init__(timeout=180)
        self.bot = bot
        self.prefix = prefix
        self.requester_id = requester_id
        self.developer_allowed = bool(DEVELOPER_ID and requester_id == DEVELOPER_ID)
        self.page_name = "Overview"
        self.home_button.emoji = component("home")
        self.close_button.emoji = component("close")
        self.add_item(HelpSelect(self))

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.requester_id:
            await interaction.response.send_message(
                "This help panel belongs to another user. Run the help command to open your own panel.",
                ephemeral=True,
            )
            return False
        return True

    async def show_page(self, interaction: discord.Interaction, page_name: str) -> None:
        if page_name not in _visible_pages(self.developer_allowed):
            await interaction.response.send_message(
                "This section is restricted to the configured bot developer.",
                ephemeral=True,
            )
            return

        self.page_name = page_name
        for item in list(self.children):
            if isinstance(item, HelpSelect):
                self.remove_item(item)
        self.add_item(HelpSelect(self))

        await interaction.response.edit_message(
            embed=build_embed(self.bot, page_name, self.prefix, interaction.guild),
            view=self,
        )

    @discord.ui.button(label="Home", style=discord.ButtonStyle.primary, row=1)
    async def home_button(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button,
    ) -> None:
        await self.show_page(interaction, "Overview")

    @discord.ui.button(label="Close", style=discord.ButtonStyle.danger, row=1)
    async def close_button(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button,
    ) -> None:
        for child in self.children:
            child.disabled = True
        await interaction.response.edit_message(view=self)


class Help(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    async def cog_load(self) -> None:
        await refresh(self.bot)

    @commands.hybrid_command(
        name="emojisync",
        description="Developer: upload assets/emojis/*.png as bot emojis and reload them",
    )
    async def emojisync(self, ctx: commands.Context) -> None:
        if not DEVELOPER_ID or ctx.author.id != DEVELOPER_ID:
            await ctx.send("Developer-only command.", ephemeral=ctx.interaction is not None)
            return

        await ctx.defer(ephemeral=ctx.interaction is not None)
        try:
            uploaded, skipped, errors = await upload_folder(self.bot)
        except Exception as exc:
            await ctx.send(f"Emoji sync failed: `{type(exc).__name__}`", ephemeral=ctx.interaction is not None)
            return

        wanted = sorted(
            {item["emoji"] for item in PAGES.values()}
            | {"menu", "home", "close", "invite", "support", "stats", "commands", "quickstart",
               "success", "error", "warning", "incident", "loading", "enabled", "disabled",
               "ban", "logs", "server", "database", "ping"}
        )
        have = set(custom_keys())
        lines = [
            f"Uploaded: {', '.join(uploaded) or 'none'}",
            f"Already existed: {', '.join(skipped) or 'none'}",
            f"Custom emojis active: {', '.join(sorted(have)) or 'none'}",
            f"Still using default emoji: {', '.join(k for k in wanted if k not in have) or 'none'}",
        ]
        if errors:
            lines.append("Errors: " + "; ".join(errors))
        await ctx.send("\n".join(lines)[:1900], ephemeral=ctx.interaction is not None)

    @commands.hybrid_command(
        name="help",
        description="Open the Sentinel Guard interactive help center",
    )
    async def help_command(self, ctx: commands.Context) -> None:
        prefix = DEFAULT_PREFIX
        if ctx.guild is not None:
            prefix = await get_prefix(ctx.guild.id, DEFAULT_PREFIX)

        view = HelpView(
            bot=self.bot,
            prefix=prefix,
            requester_id=ctx.author.id,
        )
        embed = build_embed(self.bot, "Overview", prefix, ctx.guild)

        files = []
        if BANNER_PATH.is_file():
            files.append(discord.File(BANNER_PATH, filename="help_banner.png"))
        else:
            embed.set_image(url=None)

        if self.bot.user:
            invite_url = (
                "https://discord.com/oauth2/authorize"
                f"?client_id={self.bot.user.id}&scope=bot%20applications.commands"
            )
            view.add_item(
                discord.ui.Button(
                    label="Invite Me",
                    style=discord.ButtonStyle.link,
                    url=invite_url,
                    emoji=component("invite"),
                    row=2,
                )
            )

        if SUPPORT_URL and "YOUR_SUPPORT_INVITE" not in SUPPORT_URL:
            view.add_item(
                discord.ui.Button(
                    label="Support",
                    style=discord.ButtonStyle.link,
                    url=SUPPORT_URL,
                    emoji=component("support"),
                    row=2,
                )
            )

        await ctx.send(
            embed=embed,
            view=view,
            files=files,
            ephemeral=ctx.interaction is not None,
        )


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(Help(bot))
