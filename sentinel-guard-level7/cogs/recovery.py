"""Persistent recovery, safe SQLite backups, and configuration drift checks."""
import asyncio
import os
from datetime import datetime, timezone
from pathlib import Path
import discord
from discord import app_commands
from discord.ext import commands
import aiosqlite
from config import DB_PATH, DATA_DIR
from database.db import add_security_log

BACKUP_DIR = Path(DATA_DIR) / "backups"

class Recovery(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self._backup_lock = asyncio.Lock()

    async def make_backup(self) -> Path:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        destination = BACKUP_DIR / f"sentinel_guard_{stamp}.sqlite3"
        async with self._backup_lock:
            async with aiosqlite.connect(DB_PATH) as source:
                async with aiosqlite.connect(str(destination)) as target:
                    await source.backup(target)
                    await target.commit()
            # Keep the 10 newest local snapshots; never delete the active DB.
            backups = sorted(BACKUP_DIR.glob("sentinel_guard_*.sqlite3"), key=lambda p: p.stat().st_mtime, reverse=True)
            for old in backups[10:]:
                try:
                    old.unlink()
                except OSError:
                    pass
        return destination

    @app_commands.command(name="recovery_status", description="Check database, backup and security setup health")
    @app_commands.guild_only()
    @app_commands.checks.has_permissions(manage_guild=True)
    async def recovery_status(self, interaction: discord.Interaction):
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        backups = sorted(BACKUP_DIR.glob("sentinel_guard_*.sqlite3"), key=lambda p: p.stat().st_mtime, reverse=True)
        db_ok = os.path.isfile(DB_PATH) and os.access(DB_PATH, os.R_OK | os.W_OK)
        guild = interaction.guild
        missing_roles = [name for name in ("Sentinel Developer", "Sentinel Owner", "Sentinel Admin", "Sentinel Moderator", "Sentinel Trusted", "Sentinel Member") if discord.utils.get(guild.roles, name=name) is None]
        missing_channel = discord.utils.get(guild.text_channels, name="sentinel-logs") is None
        embed = discord.Embed(title="🛡️ Sentinel Guard • Recovery Health", color=discord.Color.blurple(), timestamp=datetime.now(timezone.utc))
        embed.add_field(name="SQLite database", value="🟢 Read/write available" if db_ok else "🔴 Missing or not writable", inline=True)
        embed.add_field(name="Local backups", value=f"🟢 {len(backups)} snapshot(s)" if backups else "🟠 No backups yet", inline=True)
        embed.add_field(name="Configuration drift", value=(f"🔴 Missing roles: {', '.join(missing_roles)}" if missing_roles else "🟢 Required roles present") + ("\n🔴 #sentinel-logs missing" if missing_channel else "\n🟢 Log channel present"), inline=False)
        if backups:
            embed.add_field(name="Latest snapshot", value=f"`{backups[0].name}` • {datetime.fromtimestamp(backups[0].stat().st_mtime, timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", inline=False)
        embed.set_footer(text="Health check only • backups are local to this host")
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @app_commands.command(name="recovery_backup", description="Create a consistent SQLite snapshot")
    @app_commands.guild_only()
    @app_commands.checks.has_permissions(administrator=True)
    async def recovery_backup(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            path = await self.make_backup()
            await add_security_log(interaction.guild_id, "recovery_backup", f"Created {path.name}", interaction.user.id)
            embed = discord.Embed(title="✅ Recovery Snapshot Created", description=f"`{path.name}`\nSize: **{path.stat().st_size:,} bytes**", color=discord.Color.green())
            embed.set_footer(text="Store an additional copy off-host for disaster recovery.")
            await interaction.followup.send(embed=embed, ephemeral=True)
        except Exception as exc:
            await add_security_log(interaction.guild_id, "recovery_backup_failed", type(exc).__name__, interaction.user.id)
            await interaction.followup.send(f"❌ Backup failed: `{type(exc).__name__}`. Check host logs and disk permissions.", ephemeral=True)

    @commands.Cog.listener()
    async def on_ready(self):
        # Startup recovery is deliberately non-destructive: validate DB and create a checkpoint.
        try:
            async with aiosqlite.connect(DB_PATH) as db:
                cursor = await db.execute("PRAGMA quick_check")
                row = await cursor.fetchone()
                if not row or row[0] != "ok":
                    raise RuntimeError(f"SQLite quick_check returned {row!r}")
            await self.make_backup()
        except Exception:
            # Don't crash the bot or overwrite a potentially damaged DB automatically.
            import logging
            logging.getLogger("sentinel_guard.recovery").exception("STARTUP_RECOVERY_CHECK_FAILED; inspect database and backups")

async def setup(bot):
    await bot.add_cog(Recovery(bot))
