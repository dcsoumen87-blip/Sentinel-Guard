# Sentinel Guard

Enterprise-oriented Discord security bot built with `discord.py`, SQLite and `aiosqlite`.

## Interactive Help Center

Use `!help` (or this server's configured prefix) or `/help` to open the interactive Security Center.

The Help Center includes:
- Live gateway latency, connected server count, uptime and current server prefix.
- Interactive module selector and Previous / Home / Next / Close buttons.
- Security, AntiNuke, AntiRaid, AutoMod, Moderation, Recovery and Configuration references.
- Developer Operations section restricted to the configured `DEVELOPER_ID`.
- Permission labels and syntax based on the commands present in this repository.

## Configuration

Copy `.env.example` to `.env` and configure the bot token and `DEVELOPER_ID` before running the bot. Never commit `.env` or share your bot token.

Install dependencies with `pip install -r requirements.txt`, then start with `python main.py`.

Test changes in a private Discord server before production deployment. Ensure the bot has the required Discord intents and permissions.
