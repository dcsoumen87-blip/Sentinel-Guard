import discord
from discord.ext import commands

from config import BOT_NAME, BOT_VERSION
from utils.security import is_developer


# =========================================================
# HELP PANEL CATEGORIES
# =========================================================

PAGES = [
    {
        "key": "home",
        "title": "🏠 Home",
        "description": (
            "Welcome to **Sentinel Guard**!\n\n"
            "🛡️ **Your Server. Our Shield.**\n\n"
            "Sentinel Guard is designed to help protect "
            "Discord servers with security and moderation tools.\n\n"
            "📂 Select a category from the dropdown below."
        ),
    },
    {
        "key": "security",
        "title": "🛡️ Security",
        "description": (
            "### 🛡️ Security Commands\n\n"
            "`/security setup` — Configure baseline security\n"
            "`/antinuke status` — View Anti-Nuke status\n"
            "`/raidmode` — Raid Mode command\n"
            "`/automod` — View AutoMod module information\n\n"
            "⚠️ Some advanced protection features still "
            "require implementation and configuration."
        ),
    },
    {
        "key": "moderation",
        "title": "🔨 Moderation",
        "description": (
            "### 🔨 Moderation Commands\n\n"
            "🔨 `/ban` — Ban a member\n"
            "🔓 `/unban` — Unban a user\n"
            "👢 `/kick` — Kick a member\n"
            "⏳ `/timeout` — Timeout a member\n"
            "🔊 `/untimeout` — Remove timeout\n"
            "🔇 `/mute` — Apply mute role\n"
            "🔊 `/unmute` — Remove mute role\n"
            "⚠️ `/warn` — Record a warning\n"
            "📋 `/warnings` — View warnings\n"
            "🧹 `/clearwarnings` — Clear warnings\n"
            "🗑️ `/purge` — Delete messages\n"
            "📜 `/modlogs` — View moderation logs"
        ),
    },
    {
        "key": "configuration",
        "title": "⚙️ Configuration",
        "description": (
            "### ⚙️ Configuration Commands\n\n"
            "`/prefix` — View or change server prefix\n"
            "`/security setup` — Configure baseline roles\n\n"
            "🔒 Configuration commands require the "
            "appropriate server permissions."
        ),
    },
    {
        "key": "utility",
        "title": "🔧 Utility",
        "description": (
            "### 🔧 Utility Commands\n\n"
            "🏓 `/ping` — Check bot latency\n"
            "🤖 `/botinfo` — View bot information\n"
            "📚 `/help` — Open this help panel\n\n"
            "Prefix equivalents are available where "
            "the corresponding hybrid command is implemented."
        ),
    },
    {
        "key": "developer",
        "title": "👑 Developer",
        "description": (
            "### 👑 Developer Commands\n\n"
            "`/dev health` — Check bot health\n"
            "`/dev stats` — View bot statistics\n"
            "`/dev servers` — List connected servers\n"
            "`/dev config` — View safe configuration status\n"
            "`/dev version` — View bot version\n"
            "`/dev role claim` — Claim configured developer role\n\n"
            "🔐 These commands are restricted to the configured "
            "Developer ID."
        ),
    },
]


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def visible_pages(user_id: int):
    """
    Return only categories visible to the specified user.

    Developer category is visible only to DEVELOPER_ID.
    """
    developer = is_developer(user_id)

    return [
        page
        for page in PAGES
        if page["key"] != "developer" or developer
    ]


def make_embed(page: dict, page_number: int, total_pages: int):
    """Create a premium-looking help embed."""

    embed = discord.Embed(
        title=f"🛡️ {BOT_NAME} • {page['title']}",
        description=page["description"],
        color=discord.Color.from_rgb(74, 103, 255),
    )

    embed.set_footer(
        text=(
            f"{BOT_NAME} v{BOT_VERSION} "
            f"• Page {page_number + 1}/{total_pages}"
        )
    )

    return embed


# =========================================================
# DROPDOWN
# =========================================================

class HelpSelect(discord.ui.Select):

    def __init__(self, view):
        self.help_view = view

        options = []

        for index, page in enumerate(view.pages):
            emoji, label = page["title"].split(" ", 1)

            options.append(
                discord.SelectOption(
                    label=label,
                    value=str(index),
                    emoji=emoji,
                    default=index == view.page,
                )
            )

        super().__init__(
            placeholder="📂 Choose a help category...",
            min_values=1,
            max_values=1,
            options=options,
        )

    async def callback(self, interaction: discord.Interaction):

        view = self.help_view

        if interaction.user.id != view.owner_id:
            await interaction.response.send_message(
                "❌ Only the person who opened this panel "
                "can use its controls.",
                ephemeral=True,
            )
            return

        # Re-check access in case the configured ID changed.
        view.refresh_pages()

        requested_page = int(self.values[0])

        if requested_page >= len(view.pages):
            requested_page = 0

        view.page = requested_page
        view.rebuild()

        await interaction.response.edit_message(
            embed=view.current_embed(),
            view=view,
        )


# =========================================================
# BUTTONS
# =========================================================

class HelpButton(discord.ui.Button):

    def __init__(self, help_view, label, action):
        self.help_view = help_view
        self.action = action

        super().__init__(
            label=label,
            style=discord.ButtonStyle.secondary,
        )

    async def callback(self, interaction: discord.Interaction):

        view = self.help_view

        if interaction.user.id != view.owner_id:
            await interaction.response.send_message(
                "❌ Only the person who opened this panel "
                "can use its controls.",
                ephemeral=True,
            )
            return

        view.refresh_pages()

        if self.action == "close":

            for item in view.children:
                item.disabled = True

            embed = discord.Embed(
                title="🛡️ Sentinel Guard",
                description="✅ Help panel closed.",
                color=discord.Color.red(),
            )

            await interaction.response.edit_message(
                embed=embed,
                view=view,
            )

            view.stop()
            return

        if self.action == "previous":
            view.page = (
                view.page - 1
            ) % len(view.pages)

        elif self.action == "next":
            view.page = (
                view.page + 1
            ) % len(view.pages)

        elif self.action == "refresh":
            view.page = min(
                view.page,
                len(view.pages) - 1,
            )

        view.rebuild()

        await interaction.response.edit_message(
            embed=view.current_embed(),
            view=view,
        )


# =========================================================
# HELP PANEL VIEW
# =========================================================

class HelpView(discord.ui.View):

    def __init__(self, owner_id: int):
        super().__init__(timeout=180)

        self.owner_id = owner_id
        self.page = 0
        self.pages = []

        self.refresh_pages()
        self.rebuild()

    def refresh_pages(self):
        """Update category visibility for the panel owner."""

        self.pages = visible_pages(self.owner_id)

        if not self.pages:
            self.page = 0
        elif self.page >= len(self.pages):
            self.page = len(self.pages) - 1

    def current_embed(self):
        """Return the embed for the selected category."""

        self.refresh_pages()

        page = self.pages[self.page]

        return make_embed(
            page,
            self.page,
            len(self.pages),
        )

    def rebuild(self):
        """Rebuild dropdown and navigation buttons."""

        self.clear_items()

        self.refresh_pages()

        self.add_item(HelpSelect(self))

        self.add_item(
            HelpButton(self, "◀️ Previous", "previous")
        )

        self.add_item(
            HelpButton(self, "Next ▶️", "next")
        )

        self.add_item(
            HelpButton(self, "🔄 Refresh", "refresh")
        )

        self.add_item(
            HelpButton(self, "❌ Close", "close")
        )

    async def interaction_check(
        self,
        interaction: discord.Interaction,
    ):
        """Prevent other users from controlling this panel."""

        if interaction.user.id != self.owner_id:
            await interaction.response.send_message(
                "❌ This help panel belongs to another user.",
                ephemeral=True,
            )
            return False

        return True

    async def on_timeout(self):
        """Disable controls when the panel expires."""

        for item in self.children:
            item.disabled = True

        # The message is not stored here, so the expired
        # controls are disabled on the next interaction only
        # unless the message is separately edited.


# =========================================================
# HELP COG
# =========================================================

class Help(commands.Cog):

    def __init__(self, bot):
        self.bot = bot

    @commands.hybrid_command(name="help")
    async def help_panel(self, ctx):
        """Open the Sentinel Guard interactive help panel."""

        view = HelpView(ctx.author.id)

        await ctx.send(
            embed=view.current_embed(),
            view=view,
        )


# =========================================================
# EXTENSION SETUP
# =========================================================

async def setup(bot):
    await bot.add_cog(Help(bot))
