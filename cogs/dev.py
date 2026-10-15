"""Developer-only diagnostics for Sentinel Guard.

All commands are restricted by the configured DEVELOPER_ID. Metrics describe
this Python process/host (e.g. the EC2 instance), not the user's phone.
"""
from __future__ import annotations

import os
import platform
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

import discord
import psutil
from discord.ext import commands

from config import DATA_DIR, DEVELOPER_ID, DB_PATH

STARTED_AT = time.time()
RUNTIME_FILE = Path(DATA_DIR) / "runtime.json"


def _read_runtime() -> dict:
    try:
        import json
        data = json.loads(RUNTIME_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _cpu_name() -> str:
    """Best-effort CPU model lookup across Linux/Windows/macOS."""
    name = platform.processor().strip()
    if os.path.exists("/proc/cpuinfo"):
        try:
            for line in Path("/proc/cpuinfo").read_text(errors="ignore").splitlines():
                if line.lower().startswith(("model name", "hardware")) and ":" in line:
                    name = line.split(":", 1)[1].strip()
                    break
        except OSError:
            pass
    return name or "Unavailable in this virtual environment"


def _bytes(value: int) -> str:
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _uptime(seconds: float) -> str:
    seconds = max(0, int(seconds))
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    return f"{days}d {hours}h {minutes}m {seconds}s"


class Developer(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot
        self.process = psutil.Process(os.getpid())
        # Prime psutil's non-blocking CPU counter for a useful later reading.
        self.process.cpu_percent(None)
        psutil.cpu_percent(None)

    def allowed(self, ctx: commands.Context) -> bool:
        return DEVELOPER_ID != 0 and ctx.author.id == DEVELOPER_ID

    async def deny(self, ctx: commands.Context) -> None:
        text = "⛔ Developer-only command."
        if ctx.interaction:
            if not ctx.interaction.response.is_done():
                await ctx.interaction.response.send_message(text, ephemeral=True)
            else:
                await ctx.interaction.followup.send(text, ephemeral=True)
        else:
            await ctx.send(text, delete_after=8)

    async def require_developer(self, ctx: commands.Context) -> bool:
        if self.allowed(ctx):
            return True
        await self.deny(ctx)
        return False

    async def send_embed(self, ctx: commands.Context, embed: discord.Embed) -> None:
        if ctx.interaction:
            await ctx.send(embed=embed, ephemeral=True)
        else:
            await ctx.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())

    @commands.hybrid_command(name="devhelp", description="Show private Sentinel Guard developer commands")
    async def devhelp(self, ctx: commands.Context):
        if not await self.require_developer(ctx):
            return
        embed = discord.Embed(title="👑 Sentinel Guard • Developer Console", color=discord.Color.blurple())
        embed.description = "Developer-only diagnostics. Prefix commands use your server's configured prefix."
        embed.add_field(name="System", value="`!devsystem` `!devcpu` `!devram` `!devdisk` `!devnetwork`", inline=False)
        embed.add_field(name="Bot & health", value="`!devhealth` `!devinfo` `!devstats` `!devuptime` `!devversion`", inline=False)
        embed.add_field(name="Security & recovery", value="`!devsetup` `!devrecovery` `!devlogs` `!devservers`", inline=False)
        embed.add_field(name="Operations", value="`!devbackup` `!devmaintenance` `!devreload` `!devroleclaim`", inline=False)
        embed.set_footer(text="Prefix examples are illustrative; use the prefix configured for that server.")
        await self.send_embed(ctx, embed)

    @commands.hybrid_command(name="devsystem", description="Show host and Sentinel Guard resource usage")
    async def devsystem(self, ctx: commands.Context):
        if not await self.require_developer(ctx):
            return
        vm = psutil.virtual_memory()
        disk = psutil.disk_usage(str(Path(DB_PATH).parent))
        cpu_percent = psutil.cpu_percent(interval=0.35)
        try:
            proc_mem = self.process.memory_info().rss
            proc_cpu = self.process.cpu_percent(interval=0.15)
        except (psutil.Error, OSError):
            proc_mem, proc_cpu = 0, 0.0
        runtime = _read_runtime()
        db_size = Path(DB_PATH).stat().st_size if Path(DB_PATH).exists() else 0
        embed = discord.Embed(title="🖥️ Sentinel Guard • System Monitor", color=discord.Color.blurple(), timestamp=datetime.now(timezone.utc))
        embed.add_field(name="Host", value=f"**OS:** {platform.system()} {platform.release()}\n**Machine:** {platform.machine()}\n**CPU:** {_cpu_name()[:180]}\n**Cores:** {psutil.cpu_count(logical=False) or 'N/A'} physical / {psutil.cpu_count(logical=True) or 'N/A'} logical", inline=False)
        embed.add_field(name="CPU", value=f"Host usage: **{cpu_percent:.1f}%**\nBot process: **{proc_cpu:.1f}%**", inline=True)
        embed.add_field(name="RAM", value=f"Host: **{vm.percent:.1f}%**\nUsed: {_bytes(vm.used)} / {_bytes(vm.total)}\nBot RSS: **{_bytes(proc_mem)}**", inline=True)
        embed.add_field(name="Disk", value=f"Used: **{disk.percent:.1f}%**\n{_bytes(disk.used)} / {_bytes(disk.total)}\nFree: {_bytes(disk.free)}", inline=True)
        embed.add_field(name="Runtime", value=f"Bot uptime: **{_uptime(time.time() - STARTED_AT)}**\nRestarts recorded: **{runtime.get('restart_count', 0)}**\nPython: `{platform.python_version()}`\ndiscord.py: `{discord.__version__}`", inline=True)
        embed.add_field(name="Network I/O", value=self._network_summary(), inline=True)
        embed.add_field(name="Database & Gateway", value=f"SQLite file: **{_bytes(db_size)}**\nGateway latency: **{self.bot.latency * 1000:.0f} ms**\nGuilds: **{len(self.bot.guilds)}**", inline=True)
        embed.set_footer(text="Metrics describe the host running the bot (e.g. EC2), not your phone.")
        await self.send_embed(ctx, embed)

    def _network_summary(self) -> str:
        try:
            stats = psutil.net_io_counters()
            return f"Sent: {_bytes(stats.bytes_sent)}\nReceived: {_bytes(stats.bytes_recv)}"
        except (psutil.Error, OSError):
            return "Unavailable"

    @commands.hybrid_command(name="devcpu", description="Show CPU details and usage")
    async def devcpu(self, ctx: commands.Context):
        if not await self.require_developer(ctx): return
        usage = psutil.cpu_percent(interval=0.5)
        embed = discord.Embed(title="⚙️ CPU Diagnostics", color=discord.Color.blurple(), description=f"**Model:** {_cpu_name()}\n**Usage:** {usage:.1f}%\n**Physical cores:** {psutil.cpu_count(logical=False) or 'N/A'}\n**Logical cores:** {psutil.cpu_count(logical=True) or 'N/A'}\n**Bot process CPU:** {self.process.cpu_percent(interval=0.15):.1f}%")
        await self.send_embed(ctx, embed)

    @commands.hybrid_command(name="devram", description="Show RAM and bot process memory")
    async def devram(self, ctx: commands.Context):
        if not await self.require_developer(ctx): return
        vm = psutil.virtual_memory()
        try: rss = self.process.memory_info().rss
        except psutil.Error: rss = 0
        embed = discord.Embed(title="🧠 RAM Diagnostics", color=discord.Color.blurple(), description=f"**Total:** {_bytes(vm.total)}\n**Used:** {_bytes(vm.used)} ({vm.percent:.1f}%)\n**Available:** {_bytes(vm.available)}\n**Bot process RSS:** {_bytes(rss)}")
        await self.send_embed(ctx, embed)

    @commands.hybrid_command(name="devdisk", description="Show disk space")
    async def devdisk(self, ctx: commands.Context):
        if not await self.require_developer(ctx): return
        disk = psutil.disk_usage(str(Path(DB_PATH).parent))
        embed = discord.Embed(title="💽 Disk Diagnostics", color=discord.Color.blurple(), description=f"**Path:** `{Path(DB_PATH).parent}`\n**Total:** {_bytes(disk.total)}\n**Used:** {_bytes(disk.used)} ({disk.percent:.1f}%)\n**Free:** {_bytes(disk.free)}")
        await self.send_embed(ctx, embed)

    @commands.hybrid_command(name="devnetwork", description="Show host network I/O counters")
    async def devnetwork(self, ctx: commands.Context):
        if not await self.require_developer(ctx): return
        stats = psutil.net_io_counters()
        embed = discord.Embed(title="🌐 Network Diagnostics", color=discord.Color.blurple(), description=f"**Bytes sent:** {_bytes(stats.bytes_sent)}\n**Bytes received:** {_bytes(stats.bytes_recv)}\n**Packets sent:** {stats.packets_sent:,}\n**Packets received:** {stats.packets_recv:,}\n**Errors in/out:** {stats.errin:,} / {stats.errout:,}")
        await self.send_embed(ctx, embed)

    @commands.hybrid_command(name="devuptime", description="Show bot and host uptime")
    async def devuptime(self, ctx: commands.Context):
        if not await self.require_developer(ctx): return
        runtime = _read_runtime()
        host_uptime = max(0, time.time() - psutil.boot_time())
        embed = discord.Embed(title="⏱️ Uptime", color=discord.Color.green(), description=f"**Bot:** {_uptime(time.time() - STARTED_AT)}\n**Host:** {_uptime(host_uptime)}\n**Recorded restarts:** {runtime.get('restart_count', 0)}")
        await self.send_embed(ctx, embed)

    @commands.hybrid_command(name="devhealth", description="Check bot and database health")
    async def health(self, ctx: commands.Context):
        if not await self.require_developer(ctx): return
        db_status = "missing"
        try:
            if Path(DB_PATH).exists():
                with sqlite3.connect(DB_PATH, timeout=2) as connection:
                    db_status = connection.execute("PRAGMA quick_check").fetchone()[0]
        except sqlite3.Error as exc:
            db_status = f"error: {type(exc).__name__}"
        embed = discord.Embed(title="🩺 Sentinel Guard • Health", color=discord.Color.green() if db_status == "ok" else discord.Color.orange())
        embed.add_field(name="Discord Gateway", value=f"{self.bot.latency * 1000:.0f} ms", inline=True)
        embed.add_field(name="Guilds", value=str(len(self.bot.guilds)), inline=True)
        embed.add_field(name="SQLite", value=f"`{db_status}`", inline=True)
        embed.add_field(name="DB path", value=f"`{DB_PATH}`", inline=False)
        await self.send_embed(ctx, embed)

    @commands.hybrid_command(name="devinfo", description="Show bot runtime information")
    async def info(self, ctx: commands.Context):
        if not await self.require_developer(ctx): return
        embed = discord.Embed(title="ℹ️ Sentinel Guard • Runtime", color=discord.Color.blurple(), description=f"**Python:** `{platform.python_version()}`\n**discord.py:** `{discord.__version__}`\n**OS:** `{platform.platform()}`\n**Guilds:** {len(self.bot.guilds)}\n**Latency:** {self.bot.latency * 1000:.0f} ms\n**Database:** `{DB_PATH}`")
        await self.send_embed(ctx, embed)

    @commands.hybrid_command(name="devstats", description="Show bot statistics")
    async def stats(self, ctx: commands.Context):
        if not await self.require_developer(ctx): return
        members = sum(g.member_count or 0 for g in self.bot.guilds)
        embed = discord.Embed(title="📊 Sentinel Guard • Statistics", color=discord.Color.blurple(), description=f"**Guilds:** {len(self.bot.guilds):,}\n**Cached members total:** {members:,}\n**Loaded commands:** {len(self.bot.commands):,}\n**Latency:** {self.bot.latency * 1000:.0f} ms")
        await self.send_embed(ctx, embed)

    @commands.hybrid_command(name="devversion", description="Show current versions")
    async def version(self, ctx: commands.Context):
        if not await self.require_developer(ctx): return
        await ctx.send(f"Sentinel Guard Level 7 • Python `{platform.python_version()}` • discord.py `{discord.__version__}` • psutil `{psutil.__version__}`", ephemeral=ctx.interaction is not None)

    @commands.hybrid_command(name="devservers", description="List servers the bot is in")
    async def servers(self, ctx: commands.Context):
        if not await self.require_developer(ctx): return
        lines = [f"`{g.id}` • {discord.utils.escape_markdown(g.name)} • {g.member_count or 0} members" for g in sorted(self.bot.guilds, key=lambda x: x.name.lower())]
        text = "\n".join(lines) or "No guilds cached."
        # Keep within Discord's message limit.
        await ctx.send(text[:1900], ephemeral=ctx.interaction is not None)

    @commands.hybrid_command(name="devsetup", description="Check setup roles and log channel in this server")
    @commands.guild_only()
    async def setup_status(self, ctx: commands.Context):
        if not await self.require_developer(ctx): return
        guild = ctx.guild
        required = ("Sentinel Developer", "Sentinel Owner", "Sentinel Admin", "Sentinel Moderator", "Sentinel Trusted", "Sentinel Member")
        missing = [name for name in required if discord.utils.get(guild.roles, name=name) is None]
        channel = discord.utils.get(guild.text_channels, name="sentinel-logs")
        await ctx.send(("Missing roles: " + ", ".join(missing) if missing else "All six Sentinel roles exist.") + ("\n#sentinel-logs exists." if channel else "\n#sentinel-logs is missing."), ephemeral=ctx.interaction is not None)

    @commands.hybrid_command(name="devrecovery", description="Show local database backup status")
    async def recovery_status(self, ctx: commands.Context):
        if not await self.require_developer(ctx): return
        backup_dir = Path(DATA_DIR) / "backups"
        backups = sorted(backup_dir.glob("sentinel_guard_*.sqlite3"), key=lambda p: p.stat().st_mtime, reverse=True) if backup_dir.exists() else []
        latest = f"{backups[0].name} ({_bytes(backups[0].stat().st_size)})" if backups else "No local backup found"
        embed = discord.Embed(title="🔄 Recovery Diagnostics", color=discord.Color.blurple(), description=f"**Database exists:** {Path(DB_PATH).exists()}\n**Backup count:** {len(backups)}\n**Latest:** {latest}\n**Backup location:** `{backup_dir}`")
        embed.set_footer(text="Local backups do not protect against loss of the entire host.")
        await self.send_embed(ctx, embed)

    @commands.hybrid_command(name="devbackup", description="Create a SQLite recovery backup")
    async def backup(self, ctx: commands.Context):
        if not await self.require_developer(ctx): return
        recovery = self.bot.get_cog("Recovery")
        if recovery is None or not hasattr(recovery, "make_backup"):
            await ctx.send("❌ Recovery backup service is unavailable.", ephemeral=ctx.interaction is not None)
            return
        if ctx.interaction:
            await ctx.defer(ephemeral=True, thinking=True)
        try:
            path = await recovery.make_backup()
            await ctx.send(f"✅ Backup created: `{path.name}` • {_bytes(path.stat().st_size)}", ephemeral=ctx.interaction is not None)
        except Exception as exc:
            await ctx.send(f"❌ Backup failed: `{type(exc).__name__}`. Check host logs.", ephemeral=ctx.interaction is not None)

    @commands.hybrid_command(name="devlogs", description="Show recent bot process log guidance")
    async def logs(self, ctx: commands.Context):
        if not await self.require_developer(ctx): return
        await ctx.send("Bot logs are written to the host process output. On EC2 with systemd, inspect with `journalctl -u sentinel-guard -n 100 --no-pager`. Secrets are not shown here.", ephemeral=ctx.interaction is not None)

    @commands.hybrid_command(name="devroleclaim", description="Claim the privileged Sentinel Developer role")
    @commands.guild_only()
    async def role_claim(self, ctx: commands.Context):
        if not await self.require_developer(ctx): return
        guild = ctx.guild
        if guild.owner_id != ctx.author.id:
            await ctx.send("For safety, the configured developer must also be the server owner to self-assign this Administrator role. Use a separately reviewed owner-approved process otherwise.", ephemeral=ctx.interaction is not None)
            return
        role = discord.utils.get(guild.roles, name="Sentinel Developer")
        try:
            if role is None:
                role = await guild.create_role(name="Sentinel Developer", permissions=discord.Permissions(administrator=True), reason="Configured developer role claim")
            elif not role.permissions.administrator:
                await role.edit(permissions=discord.Permissions(administrator=True), reason="Configured developer role claim")
            me = guild.me
            if me is None or role >= me.top_role:
                await ctx.send("❌ Move the bot's role above Sentinel Developer in Server Settings → Roles, then retry.", ephemeral=ctx.interaction is not None)
                return
            await ctx.author.add_roles(role, reason="Verified configured developer role claim")
            await ctx.send("✅ Sentinel Developer role created/verified and assigned with Administrator permission.", ephemeral=ctx.interaction is not None)
        except discord.Forbidden:
            await ctx.send("❌ Missing Manage Roles permission or role hierarchy is too low.", ephemeral=ctx.interaction is not None)
        except discord.HTTPException as exc:
            await ctx.send(f"❌ Discord rejected the role update ({exc.status}).", ephemeral=ctx.interaction is not None)

    # These operations are deliberately honest placeholders: they do not pretend
    # to implement global maintenance or hot-reload until those systems exist.
    @commands.hybrid_command(name="devmaintenance", description="Report maintenance control status")
    async def maintenance(self, ctx: commands.Context):
        if not await self.require_developer(ctx): return
        await ctx.send("ℹ️ Maintenance toggle is not implemented in this build; no state was changed.", ephemeral=ctx.interaction is not None)

    @commands.hybrid_command(name="devreload", description="Reload a bot extension (disabled by default)")
    async def reload_extension(self, ctx: commands.Context, extension: str):
        if not await self.require_developer(ctx): return
        allowed = {"cogs.help", "cogs.configuration", "cogs.moderation", "cogs.automod", "cogs.antiraid", "cogs.antinuke", "cogs.dev"}
        if extension not in allowed:
            await ctx.send("❌ Extension is not in the reload allow-list.", ephemeral=ctx.interaction is not None)
            return
        try:
            await self.bot.reload_extension(extension)
            await ctx.send(f"✅ Reloaded `{extension}`", ephemeral=ctx.interaction is not None)
        except Exception as exc:
            await ctx.send(f"❌ Reload failed: `{type(exc).__name__}`. Check host logs.", ephemeral=ctx.interaction is not None)

async def setup(bot: commands.Bot):
    await bot.add_cog(Developer(bot))
