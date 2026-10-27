import asyncio
import json
import logging
import os
import platform
import time
from pathlib import Path

import aiohttp
import discord
from discord.ext import commands

from config import BOT_TOKEN, DEFAULT_PREFIX, DATA_DIR
from database.db import init_db, get_prefix
from core.whitelist_permissions import init_whitelist_permissions

LOG_DIR = Path(DATA_DIR) / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_DIR / "sentinel.log", encoding="utf-8"),
    ],
)
log = logging.getLogger("sentinel_guard")

# Set these in .env. Never hard-code the token.
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "").strip().rstrip("/")
LOG_INGEST_TOKEN = os.getenv("LOG_INGEST_TOKEN", "").strip()
REPORT_INTERVAL = max(30, int(os.getenv("DASHBOARD_REPORT_INTERVAL", "60")))
HTTP_TIMEOUT = aiohttp.ClientTimeout(total=15)


class SentinelGuard(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.guilds = True
        intents.members = True
        intents.message_content = True
        intents.moderation = True

        super().__init__(
            command_prefix=self.resolve_prefix,
            intents=intents,
            help_command=None,
            allowed_mentions=discord.AllowedMentions(
                everyone=False, roles=False, users=True, replied_user=False
            ),
        )
        self.started_at = time.monotonic()
        self.dashboard_session = None
        self.report_task = None

    async def resolve_prefix(self, bot, message):
        if message.guild is None:
            return DEFAULT_PREFIX
        return await get_prefix(message.guild.id, DEFAULT_PREFIX)

    async def setup_hook(self):
        await init_db()
        await init_whitelist_permissions()
        log.info("Database initialized successfully")

        extensions = (
            "cogs.help", "cogs.setup", "cogs.configuration", "cogs.moderation",
            "cogs.antinuke", "cogs.antiraid", "cogs.automod", "cogs.dev",
            "cogs.recovery", "cogs.permissions",
        )
        for ext in extensions:
            try:
                await self.load_extension(ext)
                log.info("Loaded extension: %s", ext)
            except Exception:
                log.exception("Could not load extension: %s", ext)
                raise

        await self.tree.sync()
        log.info("Slash commands synced")

        if DASHBOARD_URL and LOG_INGEST_TOKEN:
            self.dashboard_session = aiohttp.ClientSession(timeout=HTTP_TIMEOUT)
            self.report_task = asyncio.create_task(self._dashboard_report_loop())
            log.info("Dashboard reporting enabled")
        else:
            log.warning("Dashboard reporting disabled; configure DASHBOARD_URL and LOG_INGEST_TOKEN in .env")

    async def on_ready(self):
        log.info("Logged in as %s (%s)", self.user, self.user.id)
        await self.change_presence(
            activity=discord.Activity(
                type=discord.ActivityType.watching, name="your server security"
            )
        )
        await self.report_dashboard_state()

    async def _dashboard_post(self, endpoint, payload):
        if not self.dashboard_session or not DASHBOARD_URL or not LOG_INGEST_TOKEN:
            return False
        headers = {
            "Authorization": f"Bearer {LOG_INGEST_TOKEN}",
            "Content-Type": "application/json",
        }
        try:
            async with self.dashboard_session.post(
                f"{DASHBOARD_URL}{endpoint}", json=payload, headers=headers
            ) as response:
                if response.status == 200:
                    return True
                log.warning("Dashboard API %s returned HTTP %s", endpoint, response.status)
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            log.warning("Dashboard request %s failed: %s", endpoint, type(exc).__name__)
        return False

    @staticmethod
    def _missing_permissions(guild):
        me = guild.me
        if me is None:
            return ["bot_member_unknown"]
        p = me.guild_permissions
        required = {
            "view_audit_log": p.view_audit_log,
            "manage_guild": p.manage_guild,
            "ban_members": p.ban_members,
            "kick_members": p.kick_members,
            "manage_roles": p.manage_roles,
        }
        return [name for name, allowed in required.items() if not allowed]

    async def report_dashboard_state(self):
        if not self.is_ready():
            return

        guilds = list(self.guilds)
        members = sum(g.member_count or len(g.members) for g in guilds)
        latency_ms = int(self.latency * 1000) if self.latency is not None else None

        try:
            import psutil
            process = psutil.Process(os.getpid())
            vm = psutil.virtual_memory()
            disk = psutil.disk_usage(str(Path(DATA_DIR).resolve()))
            cpu_percent = psutil.cpu_percent(interval=None)
            process_cpu = process.cpu_percent(interval=None)
            process_rss = process.memory_info().rss
            cpu_cores = psutil.cpu_count() or 1
            ram_used, ram_total, ram_percent = vm.used, vm.total, vm.percent
            disk_used, disk_total, disk_percent = disk.used, disk.total, disk.percent
        except Exception:
            cpu_percent, process_cpu, process_rss = 0, None, None
            cpu_cores = os.cpu_count() or 1
            ram_used = ram_total = ram_percent = 0
            disk_used = disk_total = disk_percent = 0

        db_path = Path(DATA_DIR) / "sentinel_guard.sqlite3"
        bot_payload = {
            "type": "bot",
            "uptime_s": int(time.monotonic() - self.started_at),
            "latency_ms": latency_ms,
            "guilds": len(guilds),
            "members": members,
            "cpu_cores": cpu_cores,
            "cpu_percent": cpu_percent,
            "process_cpu_percent": process_cpu,
            "ram_used": ram_used,
            "ram_total": ram_total,
            "ram_percent": ram_percent,
            "process_rss": process_rss,
            "disk_used": disk_used,
            "disk_total": disk_total,
            "disk_percent": disk_percent,
            "db_size": db_path.stat().st_size if db_path.exists() else 0,
            "python": platform.python_version(),
            "discord_py": discord.__version__,
            "platform": platform.platform(),
            "guild_ids": [g.id for g in guilds],
        }
        await self._dashboard_post("/api/state", bot_payload)

        # Server snapshots. Sensitive member lists are not transmitted.
        for guild in guilds:
            owner = guild.owner
            if owner is None and guild.owner_id:
                try:
                    owner = await guild.fetch_member(guild.owner_id)
                except discord.HTTPException:
                    owner = None
            me = guild.me
            payload = {
                "type": "guild",
                "id": guild.id,
                "name": guild.name,
                "member_count": guild.member_count or len(guild.members),
                "owner": {"id": guild.owner_id, "name": str(owner) if owner else None},
                "bot_joined": me.joined_at.isoformat() if me and me.joined_at else None,
                "missing_perms": self._missing_permissions(guild),
                "roles_above_bot": sum(
                    1 for role in guild.roles
                    if me and role > me.top_role and not role.is_default()
                ),
                # Connect these fields to the DB-backed modules separately if needed.
                "whitelist": [],
                "extra_owners": [],
                "events": [],
                "incidents": [],
                "incident_total": 0,
            }
            await self._dashboard_post("/api/state", payload)

        # The existing Dashboard accepts heartbeat through /api/logs.
        await self._dashboard_post("/api/logs", {
            "type": "heartbeat",
            "guilds": len(guilds),
            "latency_ms": latency_ms,
        })

    async def _dashboard_report_loop(self):
        await self.wait_until_ready()
        while not self.is_closed():
            try:
                await self.report_dashboard_state()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Dashboard reporting cycle failed")
            await asyncio.sleep(REPORT_INTERVAL)

    async def close(self):
        if self.report_task:
            self.report_task.cancel()
            try:
                await self.report_task
            except asyncio.CancelledError:
                pass
        if self.dashboard_session and not self.dashboard_session.closed:
            await self.dashboard_session.close()
        await super().close()


def record_startup() -> None:
    path = Path(DATA_DIR) / "runtime.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        if not isinstance(data, dict):
            data = {}
    except (OSError, ValueError):
        data = {}
    data["restart_count"] = int(data.get("restart_count", 0) or 0) + 1
    data["last_startup_utc"] = discord.utils.utcnow().isoformat()
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2), encoding="utf-8")
    temporary.replace(path)


async def main():
    if not BOT_TOKEN:
        raise RuntimeError("DISCORD_TOKEN is missing. Set it in .env")
    Path(DATA_DIR).mkdir(parents=True, exist_ok=True)
    record_startup()
    bot = SentinelGuard()
    async with bot:
        await bot.start(BOT_TOKEN)


if __name__ == "__main__":
    asyncio.run(main())
