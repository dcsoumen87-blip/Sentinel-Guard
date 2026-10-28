"""Premium interactive help center for Sentinel Guard.

Replace the existing cogs/help.py with this file.
Requires discord.py 2.x and the project's existing config.py/database.db modules.
"""
from __future__ import annotations

import time
import discord
from discord.ext import commands

from config import DEVELOPER_ID, DEFAULT_PREFIX
from database.db import get_prefix

BLUE = discord.Color.from_rgb(35, 91, 170)
DARK_BLUE = discord.Color.from_rgb(18, 31, 55)
GOLD = discord.Color.from_rgb(230, 190, 92)
GREEN = discord.Color.from_rgb(46, 204, 113)
RED = discord.Color.from_rgb(231, 76, 60)

# Keep command names aligned with the commands currently present in this repository.
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


def build_embed(
    bot: commands.Bot,
    page_name: str,
    prefix: str,
    guild: discord.Guild | None,
) -> discord.Embed:
    page = PAGES[page_name]
    embed = discord.Embed(
        title=f"{page['emoji']}  {page['title']}",
        description=page["description"],
        color=GOLD if page_name == "Developer" else BLUE,
        timestamp=discord.utils.utcnow(),
    )

    if page_name == "Overview":
        latency = round(bot.latency * 1000) if bot.latency is not None else None
        embed.add_field(
            name="📡 Gateway Latency",
            value=f"`{latency} ms`" if latency is not None else "`Connecting…`",
            inline=True,
        )
        embed.add_field(name="🌐 Connected Servers", value=f"`{len(bot.guilds):,}`", inline=True)
        embed.add_field(name="⏱️ Bot Uptime", value=f"`{_uptime_text(bot)}`", inline=True)
        embed.add_field(name="⌨️ Server Prefix", value=f"`{discord.utils.escape_markdown(prefix)}`", inline=True)
        if guild:
            embed.add_field(
                name="🏠 Current Server",
                value=discord.utils.escape_markdown(guild.name)[:100],
                inline=True,
            )
        embed.add_field(
            name="🧩 Protection Modules",
            value="`AntiNuke`  •  `AntiRaid`  •  `AutoMod`  •  `Moderation`  •  `Recovery`",
            inline=False,
        )

    for command_name, description, access in page["commands"]:
        rendered = command_name.replace("{p}", prefix)
        # Prevent a page from exceeding Discord's 25-field embed limit.
        if len(embed.fields) >= 24:
            embed.add_field(name="More commands", value="Use the developer command reference for additional operations.", inline=False)
            break
        embed.add_field(
            name=f"`{rendered}`",
            value=f"{description}\n**Required access:** {access}",
            inline=False,
        )

    embed.set_footer(text="SENTINEL GUARD  •  SECURITY  •  MODERATION  •  RECOVERY")
    if bot.user:
        embed.set_author(name="Sentinel Guard Security Center", icon_url=bot.user.display_avatar.url)
    return embed


class HelpSelect(discord.ui.Select):
    def __init__(self, help_view: "HelpView"):
        self.help_view = help_view
        options = [
            discord.SelectOption(
                label=name,
                description=page["description"][:100],
                value=name,
                emoji=page["emoji"],
                default=name == help_view.page_name,
            )
            for name, page in PAGES.items()
            if name != "Developer" or help_view.developer_allowed
        ]
        super().__init__(
            placeholder="Choose a security module…",
            min_values=1,
            max_values=1,
            options=options,
            row=0,
        )

    async def callback(self, interaction: discord.Interaction) -> None:
        selected = self.values[0]
        await self.help_view.show_page(interaction, selected)


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

    def refresh_select(self) -> None:
        for item in list(self.children):
            if isinstance(item, HelpSelect):
                self.remove_item(item)
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
        if page_name == "Developer" and not self.developer_allowed:
            await interaction.response.send_message(
                "This section is restricted to the configured bot developer.",
                ephemeral=True,
            )
            return

        self.page_name = page_name
        self.refresh_select()
        await interaction.response.edit_message(
            embed=build_embed(self.bot, page_name, self.prefix, interaction.guild),
            view=self,
        )

    @discord.ui.button(label="Previous", style=discord.ButtonStyle.secondary, emoji="◀️", row=1)
    async def previous_button(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button,
    ) -> None:
        pages = [name for name in PAGES if name != "Developer" or self.developer_allowed]
        current = pages.index(self.page_name) if self.page_name in pages else 0
        await self.show_page(interaction, pages[(current - 1) % len(pages)])

    @discord.ui.button(label="Home", style=discord.ButtonStyle.primary, emoji="🏠", row=1)
    async def home_button(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button,
    ) -> None:
        await self.show_page(interaction, "Overview")

    @discord.ui.button(label="Next", style=discord.ButtonStyle.secondary, emoji="▶️", row=1)
    async def next_button(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button,
    ) -> None:
        pages = [name for name in PAGES if name != "Developer" or self.developer_allowed]
        current = pages.index(self.page_name) if self.page_name in pages else 0
        await self.show_page(interaction, pages[(current + 1) % len(pages)])

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
        description="Open the Sentinel Guard interactive security center",
    )
    async def help_command(self, ctx: commands.Context) -> None:
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


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(Help(bot))
