import asyncio
import logging
import discord
from discord.ext import commands

from config import BOT_TOKEN, DEFAULT_PREFIX, DEVELOPER_ID
from database.db import init_db, get_prefix

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)
log = logging.getLogger("sentinel_guard")


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

    async def resolve_prefix(self, bot, message):
        if message.guild is None:
            return DEFAULT_PREFIX
        return await get_prefix(message.guild.id, DEFAULT_PREFIX)

    async def setup_hook(self):
        await init_db()
        for extension in (
            "cogs.help",
            "cogs.dev",
            "cogs.setup",
            "cogs.moderation",
            "cogs.antinuke",
            "cogs.antiraid",
            "cogs.automod",
        ):
            try:
                await self.load_extension(extension)
                log.info("Loaded extension: %s", extension)
            except Exception:
                log.exception("Could not load extension: %s", extension)
                raise
        await self.tree.sync()

    async def on_ready(self):
        log.info("Logged in as %s (%s)", self.user, self.user.id)
        await self.change_presence(
            activity=discord.Activity(
                type=discord.ActivityType.watching,
                name="your server security"
            )
        )


async def main():
    if not BOT_TOKEN:
        raise RuntimeError("DISCORD_TOKEN is missing. Set it in your hosting variables.")
    bot = SentinelGuard()
    async with bot:
        await bot.start(BOT_TOKEN)


if __name__ == "__main__":
    asyncio.run(main())
