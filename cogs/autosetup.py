"""Auto-setup cog: one-command full server security initialization."""

import asyncio
import logging

import aiosqlite
import discord
from discord.ext import commands

from config import DB_PATH
from core.emojis import decorate, e as emoji
from core.roles import ROLE_DEFINITIONS, arrange_sentinel_roles
from database.db import add_security_log, set_log_channel

log = logging.getLogger("sentinel_guard.autosetup")


class AutoSetup(commands.Cog):
    """Fully automatic one-click server security setup."""

    def __init__(self, bot: commands.Bot):
        self.bot = bot

    @commands.hybrid_command(
        name="autosetup",
        description="Fully automatic one-click server security setup",
    )
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    @commands.bot_has_guild_permissions(
        manage_roles=True,
        manage_channels=True,
        view_audit_log=True,
    )
    async def autosetup(self, ctx: commands.Context):
        """Roles, channels, AntiNuke, AntiRaid, AutoMod and Lockdown in one go."""
        guild = ctx.guild
        if guild is None:
            return

        ephemeral = ctx.interaction is not None
        await ctx.defer(ephemeral=ephemeral)

        status: list[str] = []
        created_roles: list[str] = []
        errors: list[str] = []

        try:
            # 1. Create / update Sentinel roles
            status.append("**Setting up Sentinel roles...**")
            for name, cfg in ROLE_DEFINITIONS.items():
                role = discord.utils.get(guild.roles, name=name)
                if role is None:
                    try:
                        await guild.create_role(
                            name=name,
                            permissions=cfg["permissions"],
                            color=cfg["color"],
                            hoist=cfg["hoist"],
                            mentionable=cfg["mentionable"],
                            reason="Sentinel Guard auto-setup",
                        )
                        created_roles.append(name)
                        status.append(f"Created: **{name}**")
                    except discord.HTTPException as exc:
                        errors.append(f"Failed to create **{name}**: {type(exc).__name__}")
                else:
                    try:
                        await role.edit(
                            permissions=cfg["permissions"],
                            color=cfg["color"],
                            hoist=cfg["hoist"],
                            mentionable=cfg["mentionable"],
                            reason="Sentinel Guard auto-setup sync",
                        )
                        status.append(f"Updated: **{name}**")
                    except discord.HTTPException as exc:
                        errors.append(f"Failed to update **{name}**: {type(exc).__name__}")
                await asyncio.sleep(0.2)

            # 1b. Move all Sentinel roles right under the bot's role
            ok, message = await arrange_sentinel_roles(guild)
            if ok:
                status.append(message)
            else:
                errors.append(message)

            # 1c. The bot role must be above every role that can be used to nuke
            me = guild.me
            if me is not None:
                above = [
                    r.name for r in guild.roles
                    if r > me.top_role and not r.is_default()
                ]
                if above:
                    errors.append(
                        "Warning: roles above the bot role can nuke without being stopped: "
                        + ", ".join(above[:5])
                        + ". Drag the Sentinel bot role to the very top."
                    )

            # 2. Security category
            status.append("\n**Creating security category...**")
            category = discord.utils.get(guild.categories, name="Sentinel Security")
            if category is None:
                try:
                    category = await guild.create_category(
                        "Sentinel Security",
                        reason="Sentinel Guard auto-setup",
                    )
                    status.append("Created category: **Sentinel Security**")
                except discord.HTTPException as exc:
                    errors.append(f"Category creation failed: {type(exc).__name__}")
            else:
                status.append("Category already exists: **Sentinel Security**")

            # 3. Log channel
            status.append("\n**Creating log channel...**")
            log_channel = discord.utils.get(guild.text_channels, name="sentinel-logs")
            if log_channel is None and category is not None:
                try:
                    log_channel = await guild.create_text_channel(
                        "sentinel-logs",
                        category=category,
                        reason="Sentinel Guard auto-setup",
                    )
                    status.append("Created channel: **#sentinel-logs**")
                except discord.HTTPException as exc:
                    errors.append(f"Log channel creation failed: {type(exc).__name__}")
            elif log_channel is not None:
                status.append("Log channel already exists: **#sentinel-logs**")

            if log_channel is not None:
                try:
                    await set_log_channel(guild.id, log_channel.id)
                    status.append("Log channel saved to database.")
                except Exception:
                    log.exception("Could not save log channel for guild %s", guild.id)
                    errors.append("Could not save log channel to database.")

            alert_id = log_channel.id if log_channel else None

            # 4. AutoMod
            status.append("\n**Configuring AutoMod...**")
            try:
                async with aiosqlite.connect(DB_PATH) as db:
                    await db.execute(
                        """
                        INSERT INTO automod_config (guild_id, enabled, log_actions)
                        VALUES (?, 1, 1)
                        ON CONFLICT(guild_id) DO UPDATE SET enabled=1, log_actions=1
                        """,
                        (guild.id,),
                    )
                    await db.commit()
                status.append("AutoMod enabled with action logging.")
            except Exception as exc:
                errors.append(f"AutoMod config failed: {type(exc).__name__}")

            # 5. AntiNuke
            status.append("\n**Configuring AntiNuke...**")
            try:
                async with aiosqlite.connect(DB_PATH) as db:
                    await db.execute(
                        """
                        INSERT INTO antinuke_config
                            (guild_id, enabled, threshold, window_seconds, alert_channel_id, mode)
                        VALUES (?, 1, 3, 10, ?, 'ban')
                        ON CONFLICT(guild_id) DO UPDATE SET
                            enabled=1, threshold=3, window_seconds=10,
                            alert_channel_id=excluded.alert_channel_id, mode='ban'
                        """,
                        (guild.id, alert_id),
                    )
                    await db.commit()
                status.append("AntiNuke enabled (4 actions/10s, attacker is banned, alerts to #sentinel-logs).")
            except Exception as exc:
                errors.append(f"AntiNuke config failed: {type(exc).__name__}")

            # 6. AntiRaid
            status.append("\n**Configuring AntiRaid...**")
            try:
                async with aiosqlite.connect(DB_PATH) as db:
                    await db.execute(
                        """
                        INSERT INTO antiraid_config
                            (guild_id, enabled, threshold, window_seconds, alert_channel_id)
                        VALUES (?, 1, 8, 20, ?)
                        ON CONFLICT(guild_id) DO UPDATE SET
                            enabled=1, threshold=8, window_seconds=20,
                            alert_channel_id=excluded.alert_channel_id
                        """,
                        (guild.id, alert_id),
                    )
                    await db.commit()
                status.append("AntiRaid enabled (threshold: 8 joins/20s, alerts to #sentinel-logs).")
            except Exception as exc:
                errors.append(f"AntiRaid config failed: {type(exc).__name__}")

            # 7. Lockdown (disabled by default)
            status.append("\n**Initializing Lockdown system...**")
            try:
                async with aiosqlite.connect(DB_PATH) as db:
                    await db.execute(
                        """
                        INSERT INTO guild_settings (guild_id, raid_mode)
                        VALUES (?, 0)
                        ON CONFLICT(guild_id) DO UPDATE SET raid_mode=0
                        """,
                        (guild.id,),
                    )
                    await db.commit()
                status.append("Lockdown system ready (currently disabled).")
            except Exception as exc:
                errors.append(f"Lockdown init failed: {type(exc).__name__}")

            # 8. Sentinel Member role for existing humans
            status.append("\n**Assigning Sentinel Member role to members...**")
            member_role = discord.utils.get(guild.roles, name="Sentinel Member")
            assigned = failed = skipped = 0

            if member_role is not None:
                try:
                    async for member in guild.fetch_members(limit=None):
                        if member.bot or member_role in member.roles:
                            skipped += 1
                            continue
                        try:
                            await member.add_roles(
                                member_role,
                                reason="Sentinel Guard auto-setup initial member role",
                            )
                            assigned += 1
                        except (discord.Forbidden, discord.HTTPException):
                            failed += 1
                        if (assigned + failed) % 20 == 0:
                            await asyncio.sleep(1)
                except (discord.Forbidden, discord.HTTPException):
                    errors.append("Could not fetch all members (check Server Members Intent).")

            status.append(
                f"Assigned: **{assigned}** | Skipped: **{skipped}** | Failed: **{failed}**"
            )

            # 9. Audit record
            try:
                await add_security_log(
                    guild.id,
                    "autosetup_completed",
                    f"Roles created: {', '.join(created_roles) or 'none'}; "
                    f"Members assigned: {assigned}; Errors: {len(errors)}",
                    ctx.author.id,
                )
            except Exception:
                log.exception("Could not record autosetup for guild %s", guild.id)

            embed = discord.Embed(
                title="Sentinel Guard | Auto-Setup Complete",
                description=(
                    ("Your server is now protected!" if not errors
                     else "Setup finished with some warnings.")
                    + "\n\n**Completed Steps**\n"
                    + decorate(status)
                )[:4000],
                color=discord.Color.green() if not errors else discord.Color.orange(),
                timestamp=discord.utils.utcnow(),
            )
            if errors:
                embed.add_field(
                    name="Warnings / Errors",
                    value="\n".join(f"{emoji('error')} {x}" for x in errors)[:1024],
                    inline=False,
                )
            embed.add_field(
                name="Next Steps",
                value=(
                    "- Use `/securityconfig` to verify configuration\n"
                    "- Use `/help` to explore all commands\n"
                    "- Use `/lockdown` if an emergency arises\n"
                    "- Adjust `/antinuke threshold` if needed"
                ),
                inline=False,
            )
            embed.set_footer(text=f"Server: {guild.name} | ID: {guild.id}")

            await ctx.send(embed=embed, ephemeral=ephemeral)

        except Exception as exc:
            log.exception("Auto-setup failed for guild %s", guild.id)
            try:
                await add_security_log(
                    guild.id, "autosetup_failed", f"{type(exc).__name__}: {exc}", ctx.author.id
                )
            except Exception:
                pass
            await ctx.send(
                f"Auto-setup failed: `{type(exc).__name__}`. Check logs.",
                ephemeral=ephemeral,
            )


async def setup(bot: commands.Bot):
    await bot.add_cog(AutoSetup(bot))
