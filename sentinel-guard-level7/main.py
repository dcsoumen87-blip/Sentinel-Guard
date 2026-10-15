import asyncio
import logging
import json
from pathlib import Path
import discord
from discord.ext import commands
from config import BOT_TOKEN, DEFAULT_PREFIX, DATA_DIR
from database.db import init_db, get_prefix

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
log = logging.getLogger("sentinel_guard")

class SentinelGuard(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.guilds = True
        intents.members = True
        intents.message_content = True
        intents.moderation = True
        super().__init__(command_prefix=self.resolve_prefix, intents=intents, help_command=None,
                         allowed_mentions=discord.AllowedMentions(everyone=False, roles=False, users=True, replied_user=False))

    async def resolve_prefix(self, bot, message):
        if message.guild is None:
            return DEFAULT_PREFIX
        return await get_prefix(message.guild.id, DEFAULT_PREFIX)

    async def setup_hook(self):
        await init_db()
        for ext in ("cogs.help", "cogs.setup", "cogs.configuration", "cogs.moderation", "cogs.antinuke", "cogs.antiraid", "cogs.automod", "cogs.dev", "cogs.recovery"):
            try:
                await self.load_extension(ext)
                log.info("Loaded extension: %s", ext)
            except Exception:
                log.exception("Could not load extension: %s", ext)
                raise
        await self.tree.sync()
        log.info("Slash commands synced")

    async def on_ready(self):
        log.info("Logged in as %s (%s)", self.user, self.user.id)
        await self.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name="your server security"))

def record_startup() -> None:
    """Persist a best-effort restart counter for developer diagnostics."""
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
    record_startup()
    bot = SentinelGuard()
    async with bot:
        await bot.start(BOT_TOKEN)

if __name__ == "__main__":
    asyncio.run(main())
