import discord
from config import DEVELOPER_ID


def is_developer(user_id: int) -> bool:
    return bool(DEVELOPER_ID) and user_id == DEVELOPER_ID


def can_moderate_target(actor: discord.Member, target: discord.Member) -> tuple[bool, str]:
    if actor.id == target.id:
        return False, "You cannot use this action on yourself."
    if target.id == actor.guild.owner_id:
        return False, "The server owner cannot be targeted."
    if actor.id != actor.guild.owner_id and actor.top_role <= target.top_role:
        return False, "Your top role must be higher than the target's top role."
    me = actor.guild.me
    if me is None or me.top_role <= target.top_role:
        return False, "My highest role must be above the target's highest role."
    return True, ""


def embed_ok(title, description):
    return discord.Embed(title=f"✅ {title}", description=description,
                         color=discord.Color.green())


def embed_error(title, description):
    return discord.Embed(title=f"❌ {title}", description=description,
                         color=discord.Color.red())


def embed_info(title, description):
    return discord.Embed(title=f"🛡️ {title}", description=description,
                         color=discord.Color.blurple())
