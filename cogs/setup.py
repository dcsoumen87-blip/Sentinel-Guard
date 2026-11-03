import asyncio
import logging

import discord
from discord.ext import commands

from core.roles import ROLE_DEFINITIONS, arrange_sentinel_roles
from database.db import set_log_channel, add_security_log

log = logging.getLogger("sentinel_guard.setup")


class Setup(commands.Cog):

    def __init__(self, bot: commands.Bot):
        self.bot = bot

    @commands.hybrid_command(
        name="security_setup",
        description="Set up Sentinel Guard security roles and logs",
    )
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    @commands.bot_has_guild_permissions(
        manage_roles=True,
        manage_channels=True,
        view_audit_log=True,
    )
    async def security_setup(self, ctx: commands.Context):

        guild = ctx.guild

        if guild is None:
            return

        await ctx.defer(ephemeral=ctx.interaction is not None)

        status = []
        created_roles = []

        # Create security roles with colors.
        for name, config in ROLE_DEFINITIONS.items():

            role = discord.utils.get(
                guild.roles,
                name=name,
            )

            if role is None:
                try:
                    await guild.create_role(
                        name=name,
                        permissions=config["permissions"],
                        color=config["color"],
                        hoist=config["hoist"],
                        mentionable=config["mentionable"],
                        reason="Sentinel Guard security setup",
                    )

                    created_roles.append(name)
                    status.append(
                        f"Created role: **{name}**"
                    )

                except discord.HTTPException as exc:
                    status.append(
                        f"Could not create **{name}**: "
                        f"`{type(exc).__name__}`"
                    )

            else:
                # Update existing role with correct color/permissions/hoist/mentionable
                try:
                    await role.edit(
                        permissions=config["permissions"],
                        color=config["color"],
                        hoist=config["hoist"],
                        mentionable=config["mentionable"],
                        reason="Sentinel Guard configuration sync",
                    )
                    status.append(
                        f"Updated role: **{name}**"
                    )
                except discord.HTTPException as exc:
                    status.append(
                        f"Could not update **{name}**: "
                        f"`{type(exc).__name__}`"
                    )

        ok, arrange_message = await arrange_sentinel_roles(guild)
        status.append(arrange_message if ok else f"Warning: {arrange_message}")

        # Create security category.
        category = discord.utils.get(
            guild.categories,
            name="Sentinel Security",
        )

        if category is None:
            try:
                category = await guild.create_category(
                    "Sentinel Security",
                    reason="Sentinel Guard security setup",
                )

                status.append(
                    "Created category: **Sentinel Security**"
                )

            except discord.HTTPException as exc:
                category = None

                status.append(
                    "Category creation failed: "
                    f"`{type(exc).__name__}`"
                )

        # Create the log channel if it does not exist.
        log_channel = discord.utils.get(
            guild.text_channels,
            name="sentinel-logs",
        )

        if log_channel is None and category is not None:
            try:
                log_channel = await guild.create_text_channel(
                    "sentinel-logs",
                    category=category,
                    reason="Sentinel Guard security setup",
                )

                status.append(
                    "Created channel: **#sentinel-logs**"
                )

            except discord.HTTPException as exc:
                status.append(
                    "Log channel creation failed: "
                    f"`{type(exc).__name__}`"
                )

        elif log_channel is not None:
            status.append(
                "Log channel already exists: **#sentinel-logs**"
            )

        # Save the log channel in SQLite.
        if log_channel is not None:
            try:
                await set_log_channel(
                    guild.id,
                    log_channel.id,
                )

                status.append(
                    "Log channel saved to database."
                )

            except Exception:
                log.exception(
                    "Failed to save log channel for guild %s",
                    guild.id,
                )

                status.append(
                    "Could not save the log channel to SQLite."
                )

        # Record the setup event.
        try:
            await add_security_log(
                guild.id,
                "security_setup",
                (
                    "Roles created: "
                    + (", ".join(created_roles) or "none")
                ),
                ctx.author.id,
            )

        except Exception:
            log.exception(
                "Failed to record setup event for guild %s",
                guild.id,
            )

        # Assign the basic member role to existing members.
        member_role = discord.utils.get(
            guild.roles,
            name="Sentinel Member",
        )

        assigned = 0
        failed = 0
        skipped = 0

        if member_role is not None:

            try:
                async for member in guild.fetch_members(limit=None):

                    if member.bot:
                        skipped += 1
                        continue

                    if member_role in member.roles:
                        skipped += 1
                        continue

                    try:
                        await member.add_roles(
                            member_role,
                            reason="Sentinel Guard initial member role assignment",
                        )

                        assigned += 1

                    except discord.Forbidden:
                        failed += 1

                    except discord.HTTPException:
                        failed += 1

                    # Avoid sending role requests too quickly.
                    if (assigned + failed) % 20 == 0:
                        await asyncio.sleep(1)

            except (discord.Forbidden, discord.HTTPException):
                status.append(
                    "Could not fetch all members. "
                    "Check Server Members Intent and permissions."
                )

        status.append(
            f"Members assigned: **{assigned}**\n"
            f"Members skipped: **{skipped}**\n"
            f"Assignment failures: **{failed}**"
        )

        status.append(
            "New members can receive Sentinel Member "
            "automatically when the bot has the required permissions."
        )

        # Send the setup report.
        embed = discord.Embed(
            title="Sentinel Guard Setup Report",
            description="\n".join(status)[:4000],
            color=discord.Color.blurple(),
        )

        embed.set_footer(
            text=f"Server: {guild.name} - ID: {guild.id}"
        )

        await ctx.send(
            embed=embed,
            ephemeral=ctx.interaction is not None,
        )

    @commands.hybrid_command(
        name="syncroles",
        description="Sync Sentinel role colors, permissions, and settings",
    )
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    @commands.bot_has_guild_permissions(manage_roles=True)
    async def syncroles(self, ctx: commands.Context):
        """Sync all Sentinel role colors, permissions, hoist, and mentionable settings."""
        guild = ctx.guild

        if guild is None:
            return

        await ctx.defer(ephemeral=ctx.interaction is not None)

        status = []

        for name, config in ROLE_DEFINITIONS.items():
            role = discord.utils.get(guild.roles, name=name)

            if role is None:
                status.append(f"Role missing: **{name}** (run `/security_setup` first)")
                continue

            try:
                await role.edit(
                    permissions=config["permissions"],
                    color=config["color"],
                    hoist=config["hoist"],
                    mentionable=config["mentionable"],
                    reason="Sentinel Guard role sync",
                )
                status.append(f"Synced: **{name}**")
            except discord.HTTPException as exc:
                status.append(f"Failed to sync **{name}**: `{type(exc).__name__}`")

        ok, arrange_message = await arrange_sentinel_roles(guild)
        status.append(arrange_message if ok else f"Warning: {arrange_message}")

        embed = discord.Embed(
            title="Role Sync Report",
            description="\n".join(status)[:4000],
            color=discord.Color.blurple(),
        )

        await ctx.send(
            embed=embed,
            ephemeral=ctx.interaction is not None,
        )

    # Automatically assign the basic member role to new members.
    @commands.Cog.listener()
    async def on_member_join(
        self,
        member: discord.Member,
    ):

        if member.bot:
            return

        role = discord.utils.get(
            member.guild.roles,
            name="Sentinel Member",
        )

        if role is None:
            return

        try:
            await member.add_roles(
                role,
                reason="Sentinel Guard automatic member role",
            )

            log.info(
                "AUTO_ROLE_ASSIGNED guild=%s member=%s",
                member.guild.id,
                member.id,
            )

        except discord.Forbidden:
            log.error(
                "AUTO_ROLE_FORBIDDEN guild=%s; "
                "move the bot role above Sentinel Member",
                member.guild.id,
            )

        except discord.HTTPException:
            log.exception(
                "AUTO_ROLE_ERROR guild=%s member=%s",
                member.guild.id,
                member.id,
            )


async def setup(bot: commands.Bot):
    await bot.add_cog(Setup(bot))
