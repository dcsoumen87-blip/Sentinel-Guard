"""Shared Sentinel role definitions and role-hierarchy helper."""

from __future__ import annotations

import logging

import discord

log = logging.getLogger("sentinel_guard.roles")

# Order matters: highest rank first. This is also the order they are placed
# in the role list, directly below the bot's own top role.
ROLE_ORDER = (
    "Sentinel Developer",
    "Sentinel Owner",
    "Sentinel Admin",
    "Sentinel Moderator",
    "Sentinel Trusted",
    "Sentinel Member",
)

ROLE_DEFINITIONS = {
    "Sentinel Developer": {
        "permissions": discord.Permissions.none(),
        "color": discord.Color.from_rgb(255, 0, 128),
        "hoist": True,
        "mentionable": True,
    },
    "Sentinel Owner": {
        "permissions": discord.Permissions(
            manage_guild=True,
            manage_channels=True,
            manage_roles=True,
            view_audit_log=True,
        ),
        "color": discord.Color.from_rgb(255, 215, 0),
        "hoist": True,
        "mentionable": True,
    },
    "Sentinel Admin": {
        "permissions": discord.Permissions(
            manage_messages=True,
            kick_members=True,
            ban_members=True,
            moderate_members=True,
            view_audit_log=True,
        ),
        "color": discord.Color.from_rgb(255, 69, 0),
        "hoist": True,
        "mentionable": True,
    },
    "Sentinel Moderator": {
        "permissions": discord.Permissions(
            manage_messages=True,
            kick_members=True,
            moderate_members=True,
            view_audit_log=True,
        ),
        "color": discord.Color.from_rgb(0, 191, 255),
        "hoist": True,
        "mentionable": True,
    },
    "Sentinel Trusted": {
        "permissions": discord.Permissions(
            view_channel=True,
            send_messages=True,
            read_message_history=True,
        ),
        "color": discord.Color.from_rgb(50, 205, 50),
        "hoist": False,
        "mentionable": False,
    },
    "Sentinel Member": {
        "permissions": discord.Permissions(
            view_channel=True,
            send_messages=True,
            read_message_history=True,
        ),
        "color": discord.Color.from_rgb(100, 149, 237),
        "hoist": False,
        "mentionable": False,
    },
}


async def arrange_sentinel_roles(guild: discord.Guild) -> tuple[bool, str]:
    """Move all Sentinel roles to sit directly under the bot's top role.

    Returns (ok, message). Never raises for normal Discord errors.
    Roles at or above the bot's top role cannot be moved by the bot; those
    are reported in the message so the owner can drag the bot role up.
    """
    me = guild.me
    if me is None:
        return False, "Bot member not found; could not arrange roles."

    bot_top = me.top_role
    if bot_top.is_default():
        return False, "Bot has no role of its own; could not arrange roles."

    sentinel = [
        role
        for name in ROLE_ORDER
        if (role := discord.utils.get(guild.roles, name=name)) is not None
    ]
    if not sentinel:
        return True, "No Sentinel roles to arrange."

    too_high = [r.name for r in sentinel if r >= bot_top]
    movable_sentinel = [r for r in sentinel if r < bot_top]
    if not movable_sentinel:
        return False, (
            "All Sentinel roles are above the bot role. "
            "Drag the bot's role above them in Server Settings > Roles."
        )

    sentinel_ids = {r.id for r in movable_sentinel}

    # Roles below the bot that the bot cannot move (managed/integration roles)
    # keep their slots. Everything else below the bot is re-laid out.
    below = [r for r in guild.roles if r < bot_top and not r.is_default()]
    fixed_positions = {r.position for r in below if r.managed}
    free_roles = [r for r in below if not r.managed]

    slots = [
        pos for pos in range(1, bot_top.position)
        if pos not in fixed_positions
    ]
    slots.sort()  # ascending: lowest slot first

    others = sorted(
        (r for r in free_roles if r.id not in sentinel_ids),
        key=lambda r: r.position,
    )
    # Bottom -> top: other roles first, then Sentinel roles (Member ... Developer)
    ordered = others + list(reversed(movable_sentinel))

    if len(ordered) > len(slots):
        return False, "Role layout is inconsistent; could not arrange roles."

    positions = {role: slots[i] for i, role in enumerate(ordered)}
    positions = {r: p for r, p in positions.items() if r.position != p}

    if positions:
        try:
            await guild.edit_role_positions(
                positions=positions,
                reason="Sentinel Guard: place Sentinel roles under the bot role",
            )
        except discord.Forbidden:
            return False, (
                "Missing permission to move roles. Make sure the bot role "
                "has Manage Roles and sits above the Sentinel roles."
            )
        except discord.HTTPException as exc:
            log.warning("edit_role_positions failed: %s", exc)
            return False, f"Could not move roles ({type(exc).__name__})."

    message = "Sentinel roles placed directly under the bot role."
    if too_high:
        message += (
            " Not moved (above the bot role): " + ", ".join(too_high)
            + ". Drag the bot's role above them."
        )
    return True, message
