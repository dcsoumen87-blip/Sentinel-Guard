import discord
from discord.ext import commands

PAGES = {
    "Overview": ("🛡️ Sentinel Guard • Level 7", "Premium-style security dashboard for setup, monitoring, moderation and recovery.\n\nUse the menu below to explore modules. Commands require the appropriate Discord permissions."),
    "Security": ("☢️ Security Operations", "`/security_setup` — create Sentinel roles and log channel\n`/antinuke` commands — configure anti-nuke thresholds and whitelist\n`/raidstatus` — inspect join-spike monitoring\n`/automodstatus` — inspect AutoMod state"),
    "Moderation": ("⚖️ Moderation Suite", "`/kick` • `/ban` • `/timeout` • `/purge` • `/warn`\nModeration actions are permission-checked and should be tested in a private server."),
    "Recovery": ("💾 Recovery & Diagnostics", "`/recovery_status` — database, backup and setup health\n`/recovery_backup` — create a consistent SQLite snapshot\nSnapshots are stored on the host; copy backups off-host for disaster recovery."),
    "Developer": ("👑 Developer Tools", "Developer-only commands are intended to be restricted by the configured DEVELOPER_ID. Never share your bot token or commit `.env` to GitHub."),
}

class HelpSelect(discord.ui.Select):
    def __init__(self):
        options = [discord.SelectOption(label=name, description=title[:90], value=name, emoji=emoji) for name, (title, _) in PAGES.items() for emoji in ["🛡️" if name == "Overview" else "☢️" if name == "Security" else "⚖️" if name == "Moderation" else "💾" if name == "Recovery" else "👑"]]
        super().__init__(placeholder="Choose a module…", min_values=1, max_values=1, options=options)
    async def callback(self, interaction: discord.Interaction):
        name = self.values[0]
        if name == "Developer":
            from config import DEVELOPER_ID
            if interaction.user.id != DEVELOPER_ID or DEVELOPER_ID == 0:
                return await interaction.response.send_message("🔒 Developer section is restricted.", ephemeral=True)
        title, description = PAGES[name]
        embed = discord.Embed(title=title, description=description, color=discord.Color.blurple())
        embed.set_footer(text="SENTINEL GUARD • DEFENSIVE SECURITY • L7")
        await interaction.response.edit_message(embed=embed, view=self.view)

class HelpView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=180)
        self.add_item(HelpSelect())
    @discord.ui.button(label="Home", style=discord.ButtonStyle.primary, emoji="🏠", row=1)
    async def home(self, interaction: discord.Interaction, button: discord.ui.Button):
        title, description = PAGES["Overview"]
        embed = discord.Embed(title=title, description=description, color=discord.Color.blurple())
        embed.set_footer(text="SENTINEL GUARD • DEFENSIVE SECURITY • L7")
        await interaction.response.edit_message(embed=embed, view=self)
    @discord.ui.button(label="Close", style=discord.ButtonStyle.secondary, emoji="✖️", row=1)
    async def close(self, interaction: discord.Interaction, button: discord.ui.Button):
        for child in self.children: child.disabled = True
        await interaction.response.edit_message(view=self)

class Help(commands.Cog):
    def __init__(self, bot): self.bot = bot
    @commands.hybrid_command(name="help", description="Open the Sentinel Guard interactive dashboard")
    async def help(self, ctx):
        title, description = PAGES["Overview"]
        embed = discord.Embed(title=title, description=description, color=discord.Color.blurple())
        embed.add_field(name="Quick start", value="`/security_setup`  •  `/recovery_status`  •  `/recovery_backup`", inline=False)
        embed.set_footer(text="SENTINEL GUARD • DEFENSIVE SECURITY • L7")
        await ctx.send(embed=embed, view=HelpView(), ephemeral=ctx.interaction is not None)

async def setup(bot): await bot.add_cog(Help(bot))
