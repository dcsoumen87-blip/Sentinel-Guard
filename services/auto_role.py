import asyncio
import discord


async def ensure_member_role(guild: discord.Guild):
    role = discord.utils.get(guild.roles, name="Sentinel Member")
    if role is None:
        role = await guild.create_role(
            name="Sentinel Member",
            permissions=discord.Permissions.none(),
            reason="Sentinel Guard baseline member role"
        )

    if guild.me is None or role >= guild.me.top_role:
        raise RuntimeError("Move the bot's highest role above Sentinel Member.")

    assigned = 0
    failed = 0
    # Requires Server Members Intent. Yield between operations and report actual outcomes.
    async for member in guild.fetch_members(limit=None):
        if member.bot or role in member.roles:
            continue
        try:
            await member.add_roles(role, reason="Sentinel Guard member setup")
            assigned += 1
        except (discord.Forbidden, discord.HTTPException):
            failed += 1
        await asyncio.sleep(0.35)
    return role, assigned, failed


async def assign_new_member(member: discord.Member):
    role = discord.utils.get(member.guild.roles, name="Sentinel Member")
    if role is None:
        return
    if member.guild.me is None or role >= member.guild.me.top_role:
        return
    try:
        await member.add_roles(role, reason="Sentinel Guard auto-role")
    except (discord.Forbidden, discord.HTTPException):
        pass
