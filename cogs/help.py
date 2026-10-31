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
from database.db import get_prefix

BLUE = discord.Color.from_rgb(35, 91, 170)
GOLD = discord.Color.from_rgb(230, 190, 92)

BASE_DIR = Path(__file__).resolve().parent.parent
BANNER_PATH = BASE_DIR / "assets" / "1793447579821.png"

# Replace this with your real support-server invite.
SUPPORT_URL = "https://discord.gg/YOUR_SUPPORT_INVITE"

PAGES: dict[str, dict] = {
    "Overview": {
        "emoji": "🛡️",
        "title": "Sentinel Guard • Security Center",
        "description": (
            "Your central control panel for server protection, moderation and recovery.\n"
            "Choose a module from the menu to see its commands and required permissions."
        ),
        "commands": [
            ("{p}help", "Open this interactive help panel.", "Everyone"),
            ("{p}securityconfig", "View this server's security configuration.", "Manage Server"),
            ("{p}setsecuritylogs #channel", "Choose the security log channel.", "Manage Server"),
            ("{p}antinuke status", "View AntiNuke configuration and status.", "Manage Server"),
        ],
    },
    "AntiNuke": {
        "emoji": "☢️",
        "title": "AntiNuke Protection",
        "description": "Configure destructive-action detection and trusted-member controls.",
        "commands": [
            ("{p}antinuke status", "Show AntiNuke configuration.", "Manage Server"),
            ("{p}antinuke setup", "Initialize AntiNuke protection for this server.", "Manage Server"),
            ("{p}antinuke threshold <count> <seconds>", "Set the event threshold and detection window.", "Manage Server"),
            ("{p}antinuke alertchannel #channel", "Set where AntiNuke alerts are sent.", "Manage Server"),
            ("{p}antinuke whitelist-add @member", "Add a trusted member to the whitelist.", "Manage Server"),
            ("{p}antinuke whitelist-remove @member", "Remove a member from the whitelist.", "Manage Server"),
        ],
    },
    "AntiRaid": {
        "emoji": "🚨",
        "title": "AntiRaid Monitoring",
        "description": "Check the current join-spike and raid-monitoring status.",
        "commands": [
            ("{p}raidstatus", "Review AntiRaid monitoring status.", "Manage Server"),
        ],
    },
    "AutoMod": {
        "emoji": "⚙️",
        "title": "Automated Moderation",
        "description": "Inspect the automated moderation module's current status.",
        "commands": [
            ("{p}automodstatus", "Review AutoMod status.", "Manage Server"),
        ],
    },
    "Moderation": {
        "emoji": "⚖️",
        "title": "Member Moderation",
        "description": "Moderation commands. Use responsibly and follow your server's rules.",
        "commands": [
            ("{p}kick @member [reason]", "Remove a member from the server.", "Kick Members"),
            ("{p}ban @member [reason]", "Ban a member from the server.", "Ban Members"),
            ("{p}timeout @member <minutes> [reason]", "Temporarily restrict a member.", "Moderate Members"),
            ("{p}purge <amount>", "Delete a specified number of recent messages.", "Manage Messages"),
        ],
    },
    "Configuration": {
        "emoji": "🔧",
        "title": "Server Configuration",
        "description": "Manage server-specific prefix and security logging settings.",
        "commands": [
            ("{p}securityconfig", "View this server's current configuration.", "Manage Server"),
            ("{p}setprefix <prefix>", "Change this server's command prefix.", "Manage Server"),
            ("{p}setsecuritylogs #channel", "Set the security log destination.", "Manage Server"),
        ],
    },
    "Recovery": {
        "emoji": "💾",
        "title": "Recovery & Backups",
        "description": "Recovery and backup operations available in the current command set.",
        "commands": [
            ("{p}devrecovery", "Review developer recovery information.", "Bot Developer"),
            ("{p}devbackup", "Create a SQLite recovery backup.", "Bot Developer"),
            ("{p}devlogs", "Review application log information.", "Bot Developer"),
        ],
    },
    "Developer": {
        "emoji": "👑",
        "title": "Developer Operations",
        "description": "Restricted diagnostics and operational commands for the configured developer.",
        "commands": [
            ("{p}devhelp", "Open the developer command reference.", "Bot Developer"),
            ("{p}devsystem", "Inspect host resource usage.", "Bot Developer"),
            ("{p}devcpu", "Inspect CPU usage.", "Bot Developer"),
            ("{p}devram", "Inspect memory usage.", "Bot Developer"),
            ("{p}devdisk", "Inspect disk usage.", "Bot Developer"),
            ("{p}devnetwork", "Inspect network information.", "Bot Developer"),
            ("{p}devuptime", "View bot/host uptime.", "Bot Developer"),
            ("{p}devhealth", "Check gateway and database health.", "Bot Developer"),
            ("{p}devstats", "View bot statistics.", "Bot Developer"),
            ("{p}devbackup", "Create a database backup.", "Bot Developer"),
            ("{p}devlogs", "View log information.", "Bot Developer"),
            ("{p}devreload <extension>", "Reload an approved extension.", "Bot Developer"),
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
            title="Sentinel Guard Help!",
            description=(
                "A powerful security and administration bot for your server.\n"
                "Everything you need to protect, moderate and manage your community."
            ),
            color=BLUE,
        )

        categories = len(PAGES)
        total_commands = sum(len(item["commands"]) for item in PAGES.values())
        embed.add_field(
            name="Quick Stats",
            value=(
                f"• **{categories}** Command Categories\n"
                f"• **{total_commands}** Listed Commands\n"
                "• **Security • Moderation • Recovery**"
            ),
            inline=False,
        )
        latency = round(bot.latency * 1000) if bot.latency is not None else "—"
        embed.add_field(
            name="System Status",
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
        embed = discord.Embed(
            title=f"{page['emoji']}  {page['title']}",
            description=page["description"],
            color=GOLD if page_name == "Developer" else BLUE,
        )
        for command_name, description, access in page["commands"]:
            rendered = command_name.replace("{p}", prefix)
            embed.add_field(
                name=f"`{rendered}`",
                value=f"{description}\n**Required access:** {access}",
                inline=False,
            )

    embed.set_footer(text="Develop by MOD TRYOUT")
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
                emoji="📖" if name == "Overview" else PAGES[name]["emoji"],
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

    @discord.ui.button(label="Home", style=discord.ButtonStyle.primary, emoji="🏠", row=1)
    async def home_button(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button,
    ) -> None:
        await self.show_page(interaction, "Overview")

    @discord.ui.button(label="Close", style=discord.ButtonStyle.danger, emoji="✖️", row=1)
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
                    emoji="🤖",
                    row=2,
                )
            )

        if SUPPORT_URL and "YOUR_SUPPORT_INVITE" not in SUPPORT_URL:
            view.add_item(
                discord.ui.Button(
                    label="Support",
                    style=discord.ButtonStyle.link,
                    url=SUPPORT_URL,
                    emoji="🔗",
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
