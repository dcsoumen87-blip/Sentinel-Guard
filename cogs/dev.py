"""Developer-only diagnostics for Sentinel Guard."""

from __future__ import annotations

import json
import logging
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

log = logging.getLogger("sentinel_guard.dev")

STARTED_AT = time.time()
RUNTIME_FILE = Path(DATA_DIR) / "runtime.json"


def _read_runtime() -> dict:
    try:
        data = json.loads(RUNTIME_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _cpu_name() -> str:
    name = platform.processor().strip()

    if os.path.exists("/proc/cpuinfo"):
        try:
            for line in Path("/proc/cpuinfo").read_text(
                errors="ignore"
            ).splitlines():
                if line.lower().startswith(("model name", "hardware")):
                    if ":" in line:
                        name = line.split(":", 1)[1].strip()
                        break
        except OSError:
            pass

    return name or "Unavailable"


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
        self.process.cpu_percent(None)
        psutil.cpu_percent(None)

    def allowed(self, ctx: commands.Context) -> bool:
        return bool(
            DEVELOPER_ID
            and ctx.author.id == DEVELOPER_ID
        )

    async def deny(self, ctx: commands.Context):
        message = "⛔ Developer-only command."

        if ctx.interaction:
            if not ctx.interaction.response.is_done():
                await ctx.interaction.response.send_message(
                    message,
                    ephemeral=True,
                )
            else:
                await ctx.interaction.followup.send(
                    message,
                    ephemeral=True,
                )
        else:
            await ctx.send(message, delete_after=8)

    async def require_developer(
        self,
        ctx: commands.Context,
    ) -> bool:
        if self.allowed(ctx):
            return True

        await self.deny(ctx)
        return False

    async def send_embed(
        self,
        ctx: commands.Context,
        embed: discord.Embed,
    ):
        if ctx.interaction:
            await ctx.send(embed=embed, ephemeral=True)
        else:
            await ctx.send(
                embed=embed,
                allowed_mentions=discord.AllowedMentions.none(),
            )

    @commands.hybrid_command(
        name="devhelp",
        description="Show developer commands",
    )
    async def devhelp(self, ctx: commands.Context):
        if not await self.require_developer(ctx):
            return

        embed = discord.Embed(
            title="👑 Sentinel Guard • Developer Console",
            description="Private developer diagnostics.",
            color=discord.Color.blurple(),
        )

        embed.add_field(
            name="System",
            value=(
                "`devsystem` `devcpu` `devram` "
                "`devdisk` `devnetwork`"
            ),
            inline=False,
        )

        embed.add_field(
            name="Bot & Health",
            value=(
                "`devhealth` `devinfo` `devstats` "
                "`devuptime` `devversion`"
            ),
            inline=False,
        )

        embed.add_field(
            name="Security & Recovery",
            value=(
                "`devsetup` `devrecovery` `devlogs` "
                "`devservers`"
            ),
            inline=False,
        )

        embed.add_field(
            name="Operations",
            value=(
                "`devbackup` `devmaintenance` "
                "`devreload` `devroleclaim`"
            ),
            inline=False,
        )

        await self.send_embed(ctx, embed)

    @commands.hybrid_command(
        name="devsystem",
        description="Show host resource usage",
    )
    async def devsystem(self, ctx: commands.Context):
        if not await self.require_developer(ctx):
            return

        vm = psutil.virtual_memory()
        disk = psutil.disk_usage(str(Path(DB_PATH).parent))
        cpu = psutil.cpu_percent(interval=0.35)

        try:
            memory = self.process.memory_info().rss
            process_cpu = self.process.cpu_percent(interval=0.15)
        except (psutil.Error, OSError):
            memory, process_cpu = 0, 0.0

        runtime = _read_runtime()
        db_size = (
            Path(DB_PATH).stat().st_size
            if Path(DB_PATH).exists()
            else 0
        )

        embed = discord.Embed(
            title="🖥️ Sentinel Guard • System Monitor",
            color=discord.Color.blurple(),
            timestamp=datetime.now(timezone.utc),
        )

        embed.add_field(
            name="Host",
            value=(
                f"OS: {platform.system()} {platform.release()}\n"
                f"Machine: {platform.machine()}\n"
                f"CPU: {_cpu_name()[:150]}\n"
                f"Physical cores: {psutil.cpu_count(logical=False) or 'N/A'}\n"
                f"Logical cores: {psutil.cpu_count(logical=True) or 'N/A'}"
            ),
            inline=False,
        )

        embed.add_field(
            name="CPU",
            value=f"Host: {cpu:.1f}%\nBot process: {process_cpu:.1f}%",
            inline=True,
        )

        embed.add_field(
            name="RAM",
            value=(
                f"Used: {_bytes(vm.used)} / {_bytes(vm.total)}\n"
                f"Usage: {vm.percent:.1f}%\n"
                f"Bot RSS: {_bytes(memory)}"
            ),
            inline=True,
        )

        embed.add_field(
            name="Disk",
            value=(
                f"Usage: {disk.percent:.1f}%\n"
                f"Free: {_bytes(disk.free)}"
            ),
            inline=True,
        )

        embed.add_field(
            name="Runtime",
            value=(
                f"Bot uptime: {_uptime(time.time() - STARTED_AT)}\n"
                f"Restarts: {runtime.get('restart_count', 0)}\n"
                f"Python: {platform.python_version()}\n"
                f"discord.py: {discord.__version__}"
            ),
            inline=False,
        )

        embed.add_field(
            name="Database & Gateway",
            value=(
                f"Database: {_bytes(db_size)}\n"
                f"Latency: {self.bot.latency * 1000:.0f} ms\n"
                f"Guilds: {len(self.bot.guilds)}"
            ),
            inline=False,
        )

        embed.set_footer(
            text="Metrics describe the host running Sentinel Guard."
        )

        await self.send_embed(ctx, embed)

    @commands.hybrid_command(
        name="devcpu",
        description="Show CPU diagnostics",
    )
    async def devcpu(self, ctx: commands.Context):
        if not await self.require_developer(ctx):
            return

        usage = psutil.cpu_percent(interval=0.5)

        embed = discord.Embed(
            title="⚙️ CPU Diagnostics",
            description=(
                f"Model: {_cpu_name()}\n"
                f"Usage: {usage:.1f}%\n"
                f"Physical cores: {psutil.cpu_count(logical=False) or 'N/A'}\n"
                f"Logical cores: {psutil.cpu_count(logical=True) or 'N/A'}"
            ),
            color=discord.Color.blurple(),
        )

        await self.send_embed(ctx, embed)

    @commands.hybrid_command(
        name="devram",
        description="Show RAM diagnostics",
    )
    async def devram(self, ctx: commands.Context):
        if not await self.require_developer(ctx):
            return

        vm = psutil.virtual_memory()

        try:
            rss = self.process.memory_info().rss
        except psutil.Error:
            rss = 0

        embed = discord.Embed(
            title="🧠 RAM Diagnostics",
            description=(
                f"Total: {_bytes(vm.total)}\n"
                f"Used: {_bytes(vm.used)} ({vm.percent:.1f}%)\n"
                f"Available: {_bytes(vm.available)}\n"
                f"Bot RSS: {_bytes(rss)}"
            ),
            color=discord.Color.blurple(),
        )

        await self.send_embed(ctx, embed)

    @commands.hybrid_command(
        name="devdisk",
        description="Show disk diagnostics",
    )
    async def devdisk(self, ctx: commands.Context):
        if not await self.require_developer(ctx):
            return

        disk = psutil.disk_usage(str(Path(DB_PATH).parent))

        embed = discord.Embed(
            title="💽 Disk Diagnostics",
            description=(
                f"Path: `{Path(DB_PATH).parent}`\n"
                f"Total: {_bytes(disk.total)}\n"
                f"Used: {_bytes(disk.used)} ({disk.percent:.1f}%)\n"
                f"Free: {_bytes(disk.free)}"
            ),
            color=discord.Color.blurple(),
        )

        await self.send_embed(ctx, embed)

    @commands.hybrid_command(
        name="devnetwork",
        description="Show network statistics",
    )
    async def devnetwork(self, ctx: commands.Context):
        if not await self.require_developer(ctx):
            return

        try:
            stats = psutil.net_io_counters()

            description = (
                f"Sent: {_bytes(stats.bytes_sent)}\n"
                f"Received: {_bytes(stats.bytes_recv)}\n"
                f"Packets sent: {stats.packets_sent:,}\n"
                f"Packets received: {stats.packets_recv:,}\n"
                f"Errors in/out: {stats.errin:,} / {stats.errout:,}"
            )
        except (psutil.Error, OSError):
            description = "Network statistics unavailable."

        embed = discord.Embed(
            title="🌐 Network Diagnostics",
            description=description,
            color=discord.Color.blurple(),
        )

        await self.send_embed(ctx, embed)

    @commands.hybrid_command(
        name="devuptime",
        description="Show bot and host uptime",
    )
    async def devuptime(self, ctx: commands.Context):
        if not await self.require_developer(ctx):
            return

        runtime = _read_runtime()
        host_uptime = max(0, time.time() - psutil.boot_time())

        embed = discord.Embed(
            title="⏱️ Uptime",
            description=(
                f"Bot: {_uptime(time.time() - STARTED_AT)}\n"
                f"Host: {_uptime(host_uptime)}\n"
                f"Recorded restarts: {runtime.get('restart_count', 0)}"
            ),
            color=discord.Color.green(),
        )

        await self.send_embed(ctx, embed)

    @commands.hybrid_command(
        name="devhealth",
        description="Check bot and database health",
    )
    async def health(self, ctx: commands.Context):
        if not await self.require_developer(ctx):
            return

        db_status = "missing"

        try:
            if Path(DB_PATH).exists():
                with sqlite3.connect(DB_PATH, timeout=2) as connection:
                    db_status = connection.execute(
                        "PRAGMA quick_check"
                    ).fetchone()[0]
        except sqlite3.Error as exc:
            db_status = f"error: {type(exc).__name__}"

        embed = discord.Embed(
            title="🩺 Sentinel Guard • Health",
            color=(
                discord.Color.green()
                if db_status == "ok"
                else discord.Color.orange()
            ),
        )

        embed.add_field(
            name="Gateway",
            value=f"{self.bot.latency * 1000:.0f} ms",
            inline=True,
        )

        embed.add_field(
            name="Guilds",
            value=str(len(self.bot.guilds)),
            inline=True,
        )

        embed.add_field(
            name="SQLite",
            value=f"`{db_status}`",
            inline=True,
        )

        embed.add_field(
            name="Database path",
            value=f"`{DB_PATH}`",
            inline=False,
        )

        await self.send_embed(ctx, embed)

    @commands.hybrid_command(
        name="devinfo",
        description="Show bot runtime information",
    )
    async def info(self, ctx: commands.Context):
        if not await self.require_developer(ctx):
            return

        embed = discord.Embed(
            title="ℹ️ Sentinel Guard • Runtime",
            description=(
                f"Python: `{platform.python_version()}`\n"
                f"discord.py: `{discord.__version__}`\n"
                f"OS: `{platform.platform()}`\n"
                f"Guilds: {len(self.bot.guilds)}\n"
                f"Latency: {self.bot.latency * 1000:.0f} ms\n"
                f"Database: `{DB_PATH}`"
            ),
            color=discord.Color.blurple(),
        )

        await self.send_embed(ctx, embed)

    @commands.hybrid_command(
        name="devstats",
        description="Show bot statistics",
    )
    async def stats(self, ctx: commands.Context):
        if not await self.require_developer(ctx):
            return

        members = sum(g.member_count or 0 for g in self.bot.guilds)

        embed = discord.Embed(
            title="📊 Sentinel Guard • Statistics",
            description=(
                f"Guilds: {len(self.bot.guilds):,}\n"
                f"Cached members: {members:,}\n"
                f"Loaded commands: {len(self.bot.commands):,}\n"
                f"Latency: {self.bot.latency * 1000:.0f} ms"
            ),
            color=discord.Color.blurple(),
        )

        await self.send_embed(ctx, embed)

    @commands.hybrid_command(
        name="devversion",
        description="Show software versions",
    )
    async def version(self, ctx: commands.Context):
        if not await self.require_developer(ctx):
            return

        await ctx.send(
            f"Sentinel Guard • Python `{platform.python_version()}` • "
            f"discord.py `{discord.__version__}` • "
            f"psutil `{psutil.__version__}`",
            ephemeral=ctx.interaction is not None,
        )

    @commands.hybrid_command(
        name="devservers",
        description="List servers the bot is in",
    )
    async def servers(self, ctx: commands.Context):
        if not await self.require_developer(ctx):
            return

        lines = [
            f"`{guild.id}` • "
            f"{discord.utils.escape_markdown(guild.name)} • "
            f"{guild.member_count or 0} members"
            for guild in sorted(
                self.bot.guilds,
                key=lambda item: item.name.lower(),
            )
        ]

        message = "\n".join(lines) or "No guilds cached."

        await ctx.send(
            message[:1900],
            ephemeral=ctx.interaction is not None,
        )

    @commands.hybrid_command(
        name="devsetup",
        description="Check security setup",
    )
    @commands.guild_only()
    async def setup_status(self, ctx: commands.Context):
        if not await self.require_developer(ctx):
            return

        guild = ctx.guild

        required = (
            "Sentinel Developer",
            "Sentinel Owner",
            "Sentinel Admin",
            "Sentinel Moderator",
            "Sentinel Trusted",
            "Sentinel Member",
        )

        missing = [
            name
            for name in required
            if discord.utils.get(guild.roles, name=name) is None
        ]

        channel = discord.utils.get(
            guild.text_channels,
            name="sentinel-logs",
        )

        message = (
            "Missing roles: " + ", ".join(missing)
            if missing
            else "All six Sentinel roles exist."
        )

        message += (
            "\n#sentinel-logs exists."
            if channel
            else "\n#sentinel-logs is missing."
        )

        await ctx.send(
            message,
            ephemeral=ctx.interaction is not None,
        )

    @commands.hybrid_command(
        name="devrecovery",
        description="Show local backup status",
    )
    async def recovery_status(self, ctx: commands.Context):
        if not await self.require_developer(ctx):
            return

        backup_dir = Path(DATA_DIR) / "backups"

        backups = (
            sorted(
                backup_dir.glob("sentinel_guard_*.sqlite3"),
                key=lambda path: path.stat().st_mtime,
                reverse=True,
            )
            if backup_dir.exists()
            else []
        )

        latest = (
            f"{backups[0].name} "
            f"({_bytes(backups[0].stat().st_size)})"
            if backups
            else "No local backup found"
        )

        embed = discord.Embed(
            title="🔄 Recovery Diagnostics",
            description=(
                f"Database exists: {Path(DB_PATH).exists()}\n"
                f"Backup count: {len(backups)}\n"
                f"Latest: {latest}\n"
                f"Backup directory: `{backup_dir}`"
            ),
            color=discord.Color.blurple(),
        )

        embed.set_footer(
            text="Local backups do not protect against full host loss."
        )

        await self.send_embed(ctx, embed)

    @commands.hybrid_command(
        name="devbackup",
        description="Create a SQLite recovery backup",
    )
    async def backup(self, ctx: commands.Context):
        if not await self.require_developer(ctx):
            return

        recovery = self.bot.get_cog("Recovery")

        if recovery is None or not hasattr(recovery, "make_backup"):
            await ctx.send(
                "❌ Recovery backup service is unavailable.",
                ephemeral=ctx.interaction is not None,
            )
            return

        # Defer slash-command response before doing the backup.
        # Context.defer() in the installed discord.py does not accept
        # the 'thinking' keyword.
        if ctx.interaction:
            await ctx.defer(ephemeral=True)

        try:
            path = await recovery.make_backup()
            size = _bytes(path.stat().st_size)

            message = (
                f"✅ Backup created: `{path.name}` • {size}"
            )

        except Exception as exc:
            log.exception("Developer backup failed")
            message = (
                f"❌ Backup failed: `{type(exc).__name__}`. "
                "Check host logs."
            )

        if ctx.interaction:
            await ctx.send(message, ephemeral=True)
        else:
            await ctx.send(
                message,
                allowed_mentions=discord.AllowedMentions.none(),
            )

    @commands.hybrid_command(
        name="devlogs",
        description="Show bot log instructions",
    )
    async def logs(self, ctx: commands.Context):
        if not await self.require_developer(ctx):
            return

        await ctx.send(
            "Bot logs are written to the host process output. "
            "For a systemd deployment, use "
            "`journalctl -u sentinel-guard -n 100 --no-pager`. "
            "Secrets are not displayed.",
            ephemeral=ctx.interaction is not None,
        )

    @commands.hybrid_command(
        name="devroleclaim",
        description="Claim the privileged Sentinel Developer role",
    )
    @commands.guild_only()
    async def role_claim(self, ctx: commands.Context):
        if not await self.require_developer(ctx):
            return

        guild = ctx.guild

        if guild.owner_id != ctx.author.id:
            await ctx.send(
                "🔒 For safety, the configured developer must also "
                "be this server's owner to claim the Administrator role.",
                ephemeral=ctx.interaction is not None,
            )
            return

        role = discord.utils.get(
            guild.roles,
            name="Sentinel Developer",
        )

        try:
            me = guild.me

            if me is None:
                await ctx.send(
                    "❌ Bot member information is unavailable.",
                    ephemeral=ctx.interaction is not None,
                )
                return

            if role is None:
                role = await guild.create_role(
                    name="Sentinel Developer",
                    permissions=discord.Permissions.none(),
                    reason="Configured developer role claim",
                )

            # Verify hierarchy before granting Administrator.
            if role >= me.top_role:
                await ctx.send(
                    "❌ Move the bot's highest role above "
                    "Sentinel Developer and retry.",
                    ephemeral=ctx.interaction is not None,
                )
                return

            if not role.permissions.administrator:
                await role.edit(
                    permissions=discord.Permissions(administrator=True),
                    reason="Explicit configured developer role claim",
                )

            await ctx.author.add_roles(
                role,
                reason="Verified configured developer role claim",
            )

            await ctx.send(
                "✅ Sentinel Developer role assigned with "
                "Administrator permission.",
                ephemeral=ctx.interaction is not None,
            )

        except discord.Forbidden:
            await ctx.send(
                "❌ Missing Manage Roles permission or role hierarchy "
                "is too low.",
                ephemeral=ctx.interaction is not None,
            )

        except discord.HTTPException as exc:
            await ctx.send(
                f"❌ Discord rejected the role update "
                f"({exc.status}).",
                ephemeral=ctx.interaction is not None,
            )

    @commands.hybrid_command(
        name="devmaintenance",
        description="Show maintenance status",
    )
    async def maintenance(self, ctx: commands.Context):
        if not await self.require_developer(ctx):
            return

        await ctx.send(
            "ℹ️ Maintenance toggle is not implemented; no state changed.",
            ephemeral=ctx.interaction is not None,
        )

    @commands.hybrid_command(
        name="devreload",
        description="Reload an approved extension",
    )
    async def reload_extension(
        self,
        ctx: commands.Context,
        extension: str,
    ):
        if not await self.require_developer(ctx):
            return

        allowed = {
            "cogs.help",
            "cogs.configuration",
            "cogs.moderation",
            "cogs.automod",
            "cogs.antiraid",
            "cogs.antinuke",
            "cogs.dev",
        }

        if extension not in allowed:
            await ctx.send(
                "❌ Extension is not in the reload allow-list.",
                ephemeral=ctx.interaction is not None,
            )
            return

        try:
            await self.bot.reload_extension(extension)

            await ctx.send(
                f"✅ Reloaded `{extension}`",
                ephemeral=ctx.interaction is not None,
            )

        except Exception as exc:
            log.exception("Extension reload failed: %s", extension)

            await ctx.send(
                f"❌ Reload failed: `{type(exc).__name__}`. "
                "Check host logs.",
                ephemeral=ctx.interaction is not None,
            )


async def setup(bot: commands.Bot):
    await bot.add_cog(Developer(bot))
