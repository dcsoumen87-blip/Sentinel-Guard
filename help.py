"""Interactive, permission-aware Sentinel Guard help center."""
from __future__ import annotations

import time
import discord
from discord.ext import commands

from config import DEVELOPER_ID, DEFAULT_PREFIX
from database.db import get_prefix


BLUE = discord.Color.from_rgb(47, 128, 237)
GOLD = discord.Color.from_rgb(226, 183, 82)

# Command names and syntax below are aligned with the cogs in this repository.
PAGES = {
    "Overview": {
        "emoji": "🛡️",
        "title": "Sentinel Guard | Security Center",
        "description": (
            "Centralized controls for server security, moderation, monitoring and recovery.\n"
            "Select a module below to review commands and access requirements."
        ),
        "commands": [
            ("{p}help", "Open this interactive command center", "Everyone"),
            ("{p}securityconfig", "Review this server's security configuration", "Manage Server"),
            ("{p}security_setup", "Initialize security roles and logging", "Manage Server"),
            ("/recovery_status", "Review database and recovery health", "Manage Server"),
        ],
    },
    "Security": {
        "emoji": "🛡️",
        "title": "Security Management",
        "description": "Configure the core security settings for this server.",
        "commands": [
            ("{p}security_setup", "Initialize security roles and the security log channel", "Manage Server"),
            ("{p}securityconfig", "Display the current security configuration", "Manage Server"),
            ("{p}setsecuritylogs #channel", "Set the security log destination", "Manage Server"),
            ("{p}setprefix <prefix>", "Set this server's command prefix", "Manage Server"),
            ("{p}raidstatus", "Review join-spike monitoring status", "Manage Server"),
            ("{p}automodstatus", "Review automated moderation status", "Manage Server"),
        ],
    },
    "AntiNuke": {
        "emoji": "☢️",
        "title": "AntiNuke Protection",
        "description": "Review protection status, tune thresholds and manage trusted members.",
        "commands": [
            ("{p}antinuke status", "Review current AntiNuke configuration", "Manage Server"),
            ("{p}antinuke setup", "Initialize AntiNuke protection", "Manage Server"),
            ("{p}antinuke alertchannel #channel", "Configure security alert delivery", "Manage Server"),
            ("{p}antinuke threshold <count> <seconds>", "Set event threshold and detection window", "Manage Server"),
            ("{p}antinuke whitelist-add @member", "Add a trusted member", "Manage Server"),
            ("{p}antinuke whitelist-remove @member", "Remove a trusted member", "Manage Server"),
        ],
    },
    "AntiRaid": {
        "emoji": "🚨",
        "title": "AntiRaid Protection",
        "description": "Inspect join activity and current raid monitoring state.",
        "commands": [
            ("{p}raidstatus", "Review raid monitoring status", "Manage Server"),
        ],
    },
    "AutoMod": {
        "emoji": "⚙️",
        "title": "Automated Moderation",
        "description": "Review the status of automated message protection.",
        "commands": [
            ("{p}automodstatus", "Review automated moderation status", "Manage Server"),
        ],
    },
    "Moderation": {
        "emoji": "⚖️",
        "title": "Member Moderation",
        "description": "Use moderation actions responsibly and follow your server's rules.",
        "commands": [
            ("{p}kick @member [reason]", "Remove a member from the server", "Kick Members"),
            ("{p}ban @member [reason]", "Ban a member from the server", "Ban Members"),
            ("{p}timeout @member <minutes> [reason]", "Temporarily restrict a member", "Moderate Members"),
            ("{p}purge <amount>", "Bulk-delete recent messages", "Manage Messages"),
            ("{p}warn @member [reason]", "Issue a moderation warning", "Moderate Members"),
        ],
    },
    "Recovery": {
        "emoji": "💾",
        "title": "Backup & Recovery",
        "description": "Check local recovery health and create SQLite snapshots.",
        "commands": [
            ("/recovery_status", "Review database, backup and setup health", "Manage Server"),
            ("/recovery_backup", "Create a consistent SQLite snapshot", "Administrator"),
        ],
    },
    "Utilities": {
        "emoji": "🔧",
        "title": "Configuration & Utilities",
        "description": "Manage server-specific settings and logging.",
        "commands": [
            ("{p}setprefix <prefix>", "Change this server's command prefix", "Manage Server"),
            ("{p}setsecuritylogs #channel", "Set the security log channel", "Manage Server"),
            ("{p}securityconfig", "View security configuration", "Manage Server"),
            ("{p}help", "Open the interactive command center", "Everyone"),
        ],
    },
    "Developer": {
        "emoji": "👑",
        "title": "Developer Operations",
        "description": "Restricted operational commands for the configured bot developer.",
        "commands": [
            ("{p}devhelp", "View the developer command reference", "Bot Developer"),
            ("{p}devsystem", "Inspect host resource usage", "Bot Developer"),
            ("{p}devhealth", "Check bot and database health", "Bot Developer"),
            ("{p}devstats", "Review bot statistics", "Bot Developer"),
            ("{p}devuptime", "Review bot and host uptime", "Bot Developer"),
            ("{p}devbackup", "Create a SQLite recovery backup", "Bot Developer"),
            ("{p}devlogs", "Review application log guidance", "Bot Developer"),
            ("{p}devreload <extension>", "Reload an approved extension", "Bot Developer"),
        ],
    },
}


def _uptime_text(bot: commands.Bot) -> str:
    started = getattr(bot, "started_at", None)
    if started is None:
        return "Unavailable"
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


def build_embed(bot: commands.Bot, page_name: str, prefix: str, guild: discord.Guild | None):
    page = PAGES[page_name]
    embed = discord.Embed(
        title=f"{page['emoji']}  {page['title']}",
        description=page["description"],
        color=GOLD if page_name == "Developer" else BLUE,
        timestamp=discord.utils.utcnow(),
    )

    if page_name == "Overview":
        latency = round(bot.latency * 1000) if bot.latency is not None else None
        embed.add_field(name="Gateway Latency", value=f"{latency} ms" if latency is not None else "Connecting", inline=True)
        embed.add_field(name="Connected Servers", value=f"{len(bot.guilds):,}", inline=True)
        embed.add_field(name="Bot Uptime", value=_uptime_text(bot), inline=True)
        embed.add_field(name="Server Prefix", value=f"`{prefix}`", inline=True)
        embed.add_field(
            name="Protection Modules",
            value="AntiNuke • AntiRaid • AutoMod • Moderation • Recovery",
            inline=False,
        )
        if guild:
            embed.add_field(name="Current Server", value=discord.utils.escape_markdown(guild.name)[:100], inline=True)

    for command, description, access in page["commands"]:
        rendered = command.replace("{p}", prefix)
        embed.add_field(
            name=rendered[:256],
            value=f"{description}\n**Access:** {access}",
            inline=False,
        )

    embed.set_footer(text="SENTINEL GUARD  •  SECURITY  •  MODERATION  •  RECOVERY")
    if bot.user:
        embed.set_author(name="Sentinel Guard Security Center", icon_url=bot.user.display_avatar.url)
    return embed


class HelpSelect(discord.ui.Select):
    def __init__(self, view: "HelpView"):
        self.help_view = view
        options = [
            discord.SelectOption(
                label=name,
                description=page["description"][:100],
                value=name,
                emoji=page["emoji"],
                default=name == view.page_name,
            )
            for name, page in PAGES.items()
            if name != "Developer" or view.developer_allowed
        ]
        super().__init__(
            placeholder="Select a security module…",
            min_values=1,
            max_values=1,
            options=options,
            row=0,
        )

    async def callback(self, interaction: discord.Interaction):
        name = self.values[0]
        if name == "Developer" and not self.help_view.developer_allowed:
            return await interaction.response.send_message(
                "This section is restricted to the configured bot developer.",
                ephemeral=True,
            )
        self.help_view.page_name = name
        self.help_view.refresh_select()
        await interaction.response.edit_message(
            embed=build_embed(
                self.help_view.bot,
                name,
                self.help_view.prefix,
                interaction.guild,
            ),
            view=self.help_view,
        )


class HelpView(discord.ui.View):
    def __init__(
        self,
        bot: commands.Bot,
        prefix: str,
        requester_id: int,
        guild_id: int | None,
    ):
        super().__init__(timeout=180)
        self.bot = bot
        self.prefix = prefix
        self.requester_id = requester_id
        self.guild_id = guild_id
        self.developer_allowed = bool(DEVELOPER_ID and requester_id == DEVELOPER_ID)
        self.page_name = "Overview"
        self.add_item(HelpSelect(self))

    def refresh_select(self):
        for item in self.children:
            if isinstance(item, HelpSelect):
                self.remove_item(item)
                break
        self.add_item(HelpSelect(self))

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        # The panel is personal to the person who opened it, avoiding other members
        # unexpectedly changing their menu selection.
        if interaction.user.id != self.requester_id:
            await interaction.response.send_message(
                "Run the help command to open your own command center.",
                ephemeral=True,
            )
            return False
        return True

    async def show_page(self, interaction: discord.Interaction, page_name: str):
        if page_name == "Developer" and not self.developer_allowed:
            return await interaction.response.send_message(
                "This section is restricted to the configured bot developer.",
                ephemeral=True,
            )
        self.page_name = page_name
        self.refresh_select()
        await interaction.response.edit_message(
            embed=build_embed(
                self.bot,
                page_name,
                self.prefix,
                interaction.guild,
            ),
            view=self,
        )

    @discord.ui.button(label="Previous", style=discord.ButtonStyle.secondary, emoji="◀️", row=1)
    async def previous(self, interaction: discord.Interaction, button: discord.ui.Button):
        pages = [name for name in PAGES if name != "Developer" or self.developer_allowed]
        index = pages.index(self.page_name) if self.page_name in pages else 0
        await self.show_page(interaction, pages[(index - 1) % len(pages)])

    @discord.ui.button(label="Home", style=discord.ButtonStyle.primary, emoji="🏠", row=1)
    async def home(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.show_page(interaction, "Overview")

    @discord.ui.button(label="Next", style=discord.ButtonStyle.secondary, emoji="▶️", row=1)
    async def next(self, interaction: discord.Interaction, button: discord.ui.Button):
        pages = [name for name in PAGES if name != "Developer" or self.developer_allowed]
        index = pages.index(self.page_name) if self.page_name in pages else 0
        await self.show_page(interaction, pages[(index + 1) % len(pages)])

    @discord.ui.button(label="Close", style=discord.ButtonStyle.danger, emoji="✖️", row=1)
    async def close(self, interaction: discord.Interaction, button: discord.ui.Button):
        for child in self.children:
            child.disabled = True
        await interaction.response.edit_message(view=self)


class Help(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    @commands.hybrid_command(
        name="help",
        description="Open the Sentinel Guard interactive security center",
    )
    async def help(self, ctx: commands.Context):
        prefix = DEFAULT_PREFIX
        if ctx.guild is not None:
            prefix = await get_prefix(ctx.guild.id, DEFAULT_PREFIX)

        view = HelpView(
            bot=self.bot,
            prefix=prefix,
            requester_id=ctx.author.id,
            guild_id=ctx.guild.id if ctx.guild else None,
        )
        embed = build_embed(self.bot, "Overview", prefix, ctx.guild)
        await ctx.send(
            embed=embed,
            view=view,
            ephemeral=ctx.interaction is not None,
        )


async def setup(bot: commands.Bot):
    await bot.add_cog(Help(bot))
