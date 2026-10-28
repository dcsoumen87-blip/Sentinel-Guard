import asyncio
import json
import logging
import os
import platform
import sqlite3
import time
import uuid
from pathlib import Path

import aiohttp
import discord
from discord.ext import commands

from config import BOT_TOKEN, DEFAULT_PREFIX, DATA_DIR, DB_PATH
from database.db import init_db, get_prefix
from core.whitelist_permissions import init_whitelist_permissions


LOG_DIR = Path(DATA_DIR) / "logs"
BACKUP_DIR = Path(DATA_DIR) / "backups"

LOG_DIR.mkdir(parents=True, exist_ok=True)
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_DIR / "sentinel.log", encoding="utf-8"),
    ],
)

log = logging.getLogger("sentinel_guard")

DASHBOARD_URL = os.getenv("DASHBOARD_URL", "").strip().rstrip("/")
LOG_INGEST_TOKEN = os.getenv("LOG_INGEST_TOKEN", "").strip()
REPORT_INTERVAL = max(30, int(os.getenv("DASHBOARD_REPORT_INTERVAL", "60")))


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
                everyone=False,
                roles=False,
                users=True,
                replied_user=False,
            ),
        )

        self.started_at = time.monotonic()
        self.session = None
        self.report_task = None
        self.command_task = None
        self.processed_commands = set()

    async def resolve_prefix(self, bot, message):
        if message.guild is None:
            return DEFAULT_PREFIX
        return await get_prefix(message.guild.id, DEFAULT_PREFIX)

    async def setup_hook(self):
        await init_db()
        await init_whitelist_permissions()
        log.info("Database initialized")

        extensions = (
            "cogs.help",
            "cogs.setup",
            "cogs.configuration",
            "cogs.moderation",
            "cogs.antinuke",
            "cogs.antiraid",
            "cogs.automod",
            "cogs.dev",
            "cogs.recovery",
            "cogs.permissions",
        )

        for extension in extensions:
            await self.load_extension(extension)
            log.info("Loaded: %s", extension)

        await self.tree.sync()
        log.info("Slash commands synced")

        if DASHBOARD_URL and LOG_INGEST_TOKEN:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=15)
            )
            self.report_task = asyncio.create_task(self._report_loop())
            self.command_task = asyncio.create_task(self._command_loop())
            log.info("Dashboard connected")
        else:
            log.warning("Dashboard URL or token missing")

    async def on_ready(self):
        log.info("Logged in as %s (%s)", self.user, self.user.id)

        await self.change_presence(
            activity=discord.Activity(
                type=discord.ActivityType.watching,
                name="your server security",
            )
        )

        await self.report_state()

    async def api(self, method, endpoint, payload=None):
        if not self.session:
            return None

        try:
            async with self.session.request(
                method,
                f"{DASHBOARD_URL}{endpoint}",
                json=payload,
                headers={
                    "Authorization": f"Bearer {LOG_INGEST_TOKEN}",
                    "Content-Type": "application/json",
                },
            ) as response:
                body = await response.text()

                if response.status != 200:
                    log.warning("%s returned HTTP %s", endpoint, response.status)
                    return None

                if not body:
                    return {}

                try:
                    return json.loads(body)
                except json.JSONDecodeError:
                    log.warning("Invalid JSON from %s", endpoint)
                    return None

        except asyncio.CancelledError:
            raise
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            log.warning("Dashboard request failed: %s", type(exc).__name__)
            return None

    @staticmethod
    def create_backup():
        source = Path(DB_PATH)

        if not source.is_file():
            raise FileNotFoundError("Database file not found")

        target = BACKUP_DIR / (
            f"backup-{time.strftime('%Y%m%d-%H%M%S')}-"
            f"{uuid.uuid4().hex[:6]}.sqlite3"
        )
        temporary = target.with_suffix(".tmp")

        try:
            with sqlite3.connect(str(source), timeout=30) as src:
                with sqlite3.connect(str(temporary), timeout=30) as dst:
                    src.backup(dst)

            temporary.replace(target)
            return f"Backup created: {target.name}"

        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    async def execute_command(self, command):
        command_id = str(command.get("id", ""))
        action = command.get("action")

        if not command_id or command_id in self.processed_commands:
            return

        self.processed_commands.add(command_id)

        if action == "backup_now":
            try:
                message = await asyncio.to_thread(self.create_backup)
                result = {"ok": True, "message": message}
                log.info("%s", message)
            except Exception as exc:
                log.exception("Backup failed")
                result = {
                    "ok": False,
                    "message": f"Backup failed: {type(exc).__name__}",
                }
        else:
            result = {
                "ok": False,
                "message": f"Unsupported action: {action}",
            }

        response = await self.api(
            "POST",
            f"/api/commands/{command_id}/result",
            result,
        )

        if response is not None:
            log.info("Command result submitted: %s", command_id)
        else:
            log.error("Command result submission failed: %s", command_id)

    async def _command_loop(self):
        await self.wait_until_ready()
        log.info("Dashboard command polling started")

        while not self.is_closed():
            try:
                data = await self.api("GET", "/api/commands")

                if data is None:
                    log.warning("Could not fetch dashboard commands")
                elif isinstance(data, dict):
                    commands_list = data.get("commands", [])

                    if not isinstance(commands_list, list):
                        log.warning("Invalid commands list")
                    else:
                        if commands_list:
                            log.info("Received %s command(s)", len(commands_list))

                        for command in commands_list:
                            if (
                                isinstance(command, dict)
                                and command.get("status") == "pending"
                            ):
                                await self.execute_command(command)

            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Command polling error")

            await asyncio.sleep(5)

    @staticmethod
    def missing_permissions(guild):
        me = guild.me

        if me is None:
            return ["bot_member_unknown"]

        required = (
            "view_audit_log",
            "manage_guild",
            "ban_members",
            "kick_members",
            "manage_roles",
        )

        return [
            name for name in required
            if not getattr(me.guild_permissions, name)
        ]

    async def report_state(self):
        if not self.is_ready():
            return

        guilds = list(self.guilds)
        latency = int(self.latency * 1000) if self.latency is not None else None

        try:
            import psutil

            process = psutil.Process(os.getpid())
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage(str(Path(DATA_DIR).resolve()))

            metrics = {
                "cpu_cores": psutil.cpu_count() or 1,
                "cpu_percent": psutil.cpu_percent(interval=None),
                "process_cpu_percent": process.cpu_percent(interval=None),
                "ram_used": memory.used,
                "ram_total": memory.total,
                "ram_percent": memory.percent,
                "process_rss": process.memory_info().rss,
                "disk_used": disk.used,
                "disk_total": disk.total,
                "disk_percent": disk.percent,
            }
        except Exception:
            log.exception("Host metrics unavailable")
            metrics = {}

        database = Path(DB_PATH)

        await self.api("POST", "/api/state", {
            "type": "bot",
            "uptime_s": int(time.monotonic() - self.started_at),
            "latency_ms": latency,
            "guilds": len(guilds),
            "members": sum(g.member_count or len(g.members) for g in guilds),
            "db_size": database.stat().st_size if database.exists() else 0,
            "python": platform.python_version(),
            "discord_py": discord.__version__,
            "platform": platform.platform(),
            "guild_ids": [g.id for g in guilds],
            **metrics,
        })

        for guild in guilds:
            me = guild.me
            owner = guild.owner

            await self.api("POST", "/api/state", {
                "type": "guild",
                "id": guild.id,
                "name": guild.name,
                "member_count": guild.member_count or len(guild.members),
                "owner": {
                    "id": guild.owner_id,
                    "name": str(owner) if owner else None,
                },
                "bot_joined": (
                    me.joined_at.isoformat()
                    if me and me.joined_at else None
                ),
                "missing_perms": self.missing_permissions(guild),
                "roles_above_bot": sum(
                    1 for role in guild.roles
                    if me and role > me.top_role and not role.is_default()
                ),
                "whitelist": [],
                "extra_owners": [],
                "events": [],
                "incidents": [],
                "incident_total": 0,
            })

        await self.api("POST", "/api/logs", {
            "type": "heartbeat",
            "guilds": len(guilds),
            "latency_ms": latency,
        })

    async def _report_loop(self):
        await self.wait_until_ready()

        while not self.is_closed():
            try:
                await self.report_state()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Dashboard reporting failed")

            await asyncio.sleep(REPORT_INTERVAL)

    async def close(self):
        for task in (self.report_task, self.command_task):
            if task and not task.done():
                task.cancel()

        for task in (self.report_task, self.command_task):
            if task:
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        if self.session and not self.session.closed:
            await self.session.close()

        await super().close()


def record_startup():
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
        raise RuntimeError("DISCORD_TOKEN is missing from .env")

    Path(DATA_DIR).mkdir(parents=True, exist_ok=True)
    record_startup()

    async with SentinelGuard() as bot:
        await bot.start(BOT_TOKEN)


if __name__ == "__main__":
    asyncio.run(main())
