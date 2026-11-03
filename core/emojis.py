"""Custom ("premium") emoji registry for Sentinel Guard.

Emojis are Discord *application emojis* owned by the bot, so they work in
every server without Nitro or server boosts. They are looked up by name:
an emoji called ``sg_antinuke`` is used for the key ``antinuke``.

Add them either by:
  1. Uploading them in Developer Portal > your app > Emojis, named ``sg_<key>``, or
  2. Putting ``<key>.png`` files in ``assets/emojis/`` and running ``/emojisync``.

Any key without a custom emoji automatically falls back to a normal emoji.
"""

from __future__ import annotations

import base64
import logging
from pathlib import Path

import discord

try:
    from core.emoji_data import EMOJI_DATA
except ImportError:  # optional file
    EMOJI_DATA = {}

log = logging.getLogger("sentinel_guard.emojis")

PREFIX = "sg_"
MAX_BYTES = 256 * 1024
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp"}
EMOJI_DIR = Path(__file__).resolve().parent.parent / "assets" / "emojis"

# key -> fallback unicode emoji (used until a custom emoji exists)
FALLBACKS: dict[str, str] = {
    "overview": "\U0001F6E1\uFE0F",
    "setup": "\u26A1",
    "antinuke": "\u2622\uFE0F",
    "lockdown": "\U0001F512",
    "antiraid": "\U0001F6A8",
    "automod": "\u2699\uFE0F",
    "moderation": "\u2696\uFE0F",
    "config": "\U0001F527",
    "recovery": "\U0001F4BE",
    "permissions": "\U0001F510",
    "developer": "\U0001F451",
    "home": "\U0001F3E0",
    "close": "\u2716\uFE0F",
    "invite": "\U0001F916",
    "support": "\U0001F517",
    "menu": "\U0001F4D6",
    "stats": "\U0001F4CA",
    "commands": "\U0001F4DA",
    "quickstart": "\U0001F7E2",
    "success": "\u2705",
    "error": "\u274C",
    "warning": "\u26A0\uFE0F",
    "incident": "\U0001F6A8",
    "loading": "\u23F3",
    "enabled": "\U0001F7E2",
    "disabled": "\U0001F534",
    "ban": "\U0001F528",
    "logs": "\U0001F4E2",
    "server": "\U0001F5A5\uFE0F",
    "database": "\U0001F5C4\uFE0F",
    "ping": "\U0001F4F6",
}

_custom: dict[str, str] = {}


def e(key: str) -> str:
    """Text form of an emoji (for embed titles / descriptions / fields)."""
    return _custom.get(key) or FALLBACKS.get(key, "")


def component(key: str) -> discord.PartialEmoji | None:
    """Emoji object for buttons and select options."""
    value = e(key)
    return discord.PartialEmoji.from_str(value) if value else None


_ERROR_WORDS = ("could not", "failed", "warning", "missing", "not moved", "inconsistent")


def decorate(lines) -> str:
    """Join status lines, adding a success/error emoji to each plain line.

    Lines that are empty or start with ** (headings) are left untouched.
    """
    out = []
    for entry in lines:
        for line in str(entry).split("\n"):
            stripped = line.strip()
            if not stripped or stripped.startswith("**"):
                out.append(line)
                continue
            icon = "error" if any(w in stripped.lower() for w in _ERROR_WORDS) else "success"
            out.append(f"{e(icon)} {stripped}")
    return "\n".join(out)


def custom_keys() -> list[str]:
    return sorted(_custom)


async def refresh(bot: discord.Client) -> int:
    """Load all ``sg_*`` application emojis from Discord. Returns the count."""
    try:
        found = await bot.fetch_application_emojis()
    except Exception:
        log.exception("Could not fetch application emojis")
        return len(_custom)

    _custom.clear()
    for emoji in found:
        if emoji.name.startswith(PREFIX):
            _custom[emoji.name[len(PREFIX):].lower()] = str(emoji)
    log.info("Loaded %d custom emoji(s)", len(_custom))
    return len(_custom)


async def upload_folder(bot: discord.Client) -> tuple[list[str], list[str], list[str]]:
    """Upload images from assets/emojis/. Returns (uploaded, skipped, errors)."""
    uploaded: list[str] = []
    skipped: list[str] = []
    errors: list[str] = []

    EMOJI_DIR.mkdir(parents=True, exist_ok=True)
    existing = {emoji.name for emoji in await bot.fetch_application_emojis()}

    # Images from the folder win over the built-in ones.
    sources: dict[str, tuple[str, bytes]] = {}
    for key, b64 in EMOJI_DATA.items():
        sources[key.lower()] = (f"{key}.png (built-in)", base64.b64decode("".join(b64.split())))
    for path in sorted(EMOJI_DIR.iterdir()):
        if path.suffix.lower() in IMAGE_SUFFIXES:
            sources[path.stem.lower()] = (path.name, path.read_bytes())

    for key, (label, data) in sorted(sources.items()):
        name = PREFIX + key
        if name in existing:
            skipped.append(key)
            continue
        if len(data) > MAX_BYTES:
            errors.append(f"{label}: larger than 256 KB")
            continue
        try:
            await bot.create_application_emoji(name=name, image=data)
            uploaded.append(key)
        except discord.HTTPException as exc:
            errors.append(f"{label}: {type(exc).__name__}")

    await refresh(bot)
    return uploaded, skipped, errors
