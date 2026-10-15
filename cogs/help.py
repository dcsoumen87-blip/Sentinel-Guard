import discord
from discord.ext import commands
from config import BOT_NAME, BOT_VERSION, DEVELOPER_ID
from utils.security import is_developer

PAGES = [
    ("🏠 Home", "Welcome to **Sentinel Guard**.\nYour server. Our shield.\n\nChoose a category from the menu below."),
    ("🛡️ Security", "`/security setup` — configure baseline protection\n`/raidmode` — inspect/toggle raid mode\n`/antinuke status` — view monitoring status\n\nSecurity modules are loaded separately and must be configured."),
    ("🔨 Moderation", "`/ban` `/unban` `/kick`\n`/timeout` `/untimeout`\n`/mute` `/unmute`\n`/warn` `/warnings` `/clearwarnings`\n`/purge` `/modlogs`"),
    ("⚙️ Configuration", "`/prefix` — change this server's prefix\n`/security setup` — create baseline roles and settings"),
    ("🔧 Utility", "`/ping` — response latency\n`/botinfo` — bot information\n`/help` — open this panel"),
    ("👑 Developer", "`/dev health` `/dev stats` `/dev servers`\n`/dev logs` `/dev diagnostics` `/dev backup`\n`/dev config` `/dev role claim`\nDeveloper commands are restricted to the configured Developer ID.")
]


class HelpSelect(discord.ui.Select):
    def __init__(self, owner_id, page=0):
        options = [
            discord.SelectOption(label=label.split(" ", 1)[1], emoji=label.split(" ", 1)[0],
                                 value=str(i), default=(i == page))
            for i, (label, _) in enumerate(PAGES)
            if i != 5 or is_developer(owner_id)
        ]
        super().__init__(placeholder="📂 Choose a help category...", min_values=1,
                         max_values=1, options=options)
        self.owner_id = owner_id

    async def callback(self, interaction: discord.Interaction):
        if interaction.user.id != self.owner_id:
            return await interaction.response.send_message(
                "This help panel belongs to another user.", ephemeral=True
            )
        page = int(self.values[0])
        self.view.page = page
        self.view.rebuild()
        await interaction.response.edit_message(embed=self.view.make_embed(), view=self.view)


class HelpView(discord.ui.View):
    def __init__(self, owner_id):
        super().__init__(timeout=180)
        self.owner_id = owner_id
        self.page = 0
        self.rebuild()

    def rebuild(self):
        self.clear_items()
        self.add_item(HelpSelect(self.owner_id, self.page))
        self.add_item(HelpButton("◀️ Previous", "previous"))
        self.add_item(HelpButton("Next ▶️", "next"))
        self.add_item(HelpButton("🔄 Refresh", "refresh"))
        self.add_item(HelpButton("❌ Close", "close"))

    def make_embed(self):
        title, description = PAGES[self.page]
        embed = discord.Embed(
            title=f"🛡️ {BOT_NAME} • {title}",
            description=description,
            color=discord.Color.from_rgb(74, 103, 255)
        )
        embed.set_footer(text=f"Version {BOT_VERSION} • Page {self.page + 1}/{len(PAGES)}")
        return embed

    async def interaction_check(self, interaction):
        if interaction.user.id != self.owner_id:
            await interaction.response.send_message(
                "Only the person who opened this panel can use it.", ephemeral=True
            )
            return False
        return True


class HelpButton(discord.ui.Button):
    def __init__(self, label, action):
        super().__init__(label=label, style=discord.ButtonStyle.secondary)
        self.action = action

    async def callback(self, interaction: discord.Interaction):
        view: HelpView = self.view
        if self.action == "close":
            for item in view.children:
                item.disabled = True
            await interaction.response.edit_message(
                embed=discord.Embed(title="🛡️ Sentinel Guard", description="Help panel closed."),
                view=view
            )
            view.stop()
            return
        if self.action == "previous":
            view.page = (view.page - 1) % len(PAGES)
        elif self.action == "next":
            view.page = (view.page + 1) % len(PAGES)
        view.rebuild()
        await interaction.response.edit_message(embed=view.make_embed(), view=view)


class Help(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.hybrid_command(name="help")
    async def help_panel(self, ctx):
        """Open the interactive Sentinel Guard help panel."""
        view = HelpView(ctx.author.id)
        await ctx.send(embed=view.make_embed(), view=view)


async def setup(bot):
    await bot.add_cog(Help(bot))
