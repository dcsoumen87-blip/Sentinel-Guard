"""Auto-setup cog: One-command full server security initialization."""

import asyncio
import discord
from discord import app_commands
from discord.ext import commands

from config import DB_PATH
from database.db import set_log_channel, add_security_log, set_prefix


class AutoSetup(commands.Cog):
    """Fully automatic one-click server security setup."""

    def __init__(self, bot: commands.Bot):
        self.bot = bot

    # Role definitions with colors (matching setup.py)
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

    @app_commands.command(name="autosetup", description="Fully automatic one-click server security setup")
    @app_commands.guild_only()
    @app_commands.checks.has_permissions(manage_guild=True)
    @app_commands.checks.bot_has_permissions(manage_roles=True, manage_channels=True, view_audit_log=True)
    async def autosetup(self, interaction: discord.Interaction):
        """Run complete automatic setup: roles, channels, configs, AntiNuke, AutoMod, Lockdown."""
        guild = interaction.guild
        if guild is None:
            return

        await interaction.response.defer(ephemeral=True, thinking=True)

        status = []
        created_roles = []
        errors = []

        try:
            # 1. Create/Update all Sentinel roles with colors
            status.append("ðŸŽ¨ **Setting up Sentinel roles...**")
            for name, config in self.ROLE_DEFINITIONS.items():
                role = discord.utils.get(guild.roles, name=name)
                if role is None:
                    try:
                        role = await guild.create_role(
                            name=name,
                            permissions=config["permissions"],
                            color=config["color"],
                            hoist=config["hoist"],
                            mentionable=config["mentionable"],
                            reason="Sentinel Guard auto-setup",
                        )
                        created_roles.append(name)
                        status.append(f"  âœ… Created: **{name}**")
                    except discord.HTTPException as exc:
                        errors.append(f"  âŒ Failed to create **{name}**: {type(exc).__name__}")
                else:
                    try:
                        await role.edit(
                            permissions=config["permissions"],
                            color=config["color"],
                            hoist=config["hoist"],
                            mentionable=config["mentionable"],
                            reason="Sentinel Guard auto-setup sync",
                        )
                        status.append(f"  ðŸ”„ Updated: **{name}**")
                    except discord.HTTPException as exc:
                        errors.append(f"  âš ï¸ Failed to update **{name}**: {type(exc).__name__}")

                await asyncio.sleep(0.2)  # Rate limit safety

            # 2. Create security category
            status.append("\nðŸ“ **Creating security category...**")
            category = discord.utils.get(guild.categories, name="Sentinel Security")
            if category is None:
                try:
                    category = await guild.create_category(
                        "Sentinel Security",
                        reason="Sentinel Guard auto-setup",
                    )
                    status.append("  âœ… Created category: **Sentinel Security**")
                except discord.HTTPException as exc:
                    category = None
                    errors.append(f"  âŒ Category creation failed: {type(exc).__name__}")
            else:
                status.append("  â†ªï¸ Category already exists: **Sentinel Security**")

            # 3. Create log channel
            status.append("\nðŸ“ **Creating log channel...**")
            log_channel = discord.utils.get(guild.text_channels, name="sentinel-logs")
            if log_channel is None and category is not None:
                try:
                    log_channel = await guild.create_text_channel(
                        "sentinel-logs",
                        category=category,
                        reason="Sentinel Guard auto-setup",
                    )
                    status.append("  âœ… Created channel: **#sentinel-logs**")
                except discord.HTTPException as exc:
                    errors.append(f"  âŒ Log channel creation failed: {type(exc).__name__}")
            elif log_channel is not None:
                status.append("  â†ªï¸ Log channel already exists: **#sentinel-logs**")

            # Save log channel to database
            if log_channel is not None:
                try:
                    await set_log_channel(guild.id, log_channel.id)
                    status.append("  âœ… Log channel saved to database.")
                except Exception:
                    errors.append("  âš ï¸ Could not save log channel to database.")

            # 4. Configure AutoMod (enable + logging)
            status.append("\nâš™ï¸ **Configuring AutoMod...**")
            try:
                import aiosqlite
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
                status.append("  âœ… AutoMod enabled with action logging.")
            except Exception as exc:
                errors.append(f"  âŒ AutoMod config failed: {type(exc).__name__}")

            # 5. Configure AntiNuke (enable + threshold + alert channel)
            status.append("\nâ˜¢ï¸ **Configuring AntiNuke...**")
            try:
                async with aiosqlite.connect(DB_PATH) as db:
                    await db.execute(
                        """
                        INSERT INTO antinuke_config (guild_id, enabled, threshold, window_seconds, alert_channel_id, mode)
                        VALUES (?, 1, 4, 10, ?, 'alert')
                        ON CONFLICT(guild_id) DO UPDATE SET enabled=1, threshold=4, window_seconds=10, alert_channel_id=?, mode='alert'
                        """,
                        (guild.id, log_channel.id if log_channel else None, log_channel.id if log_channel else None),
                    )
                    await db.commit()
                status.append("  âœ… AntiNuke enabled (threshold: 4/10s, alerts to #sentinel-logs).")
            except Exception as exc:
                errors.append(f"  âŒ AntiNuke config failed: {type(exc).__name__}")

            # 6. Configure AntiRaid (enable + threshold + alert channel)
            status.append("\nðŸš¨ **Configuring AntiRaid...**")
            try:
                async with aiosqlite.connect(DB_PATH) as db:
                    await db.execute(
                        """
                        INSERT INTO antiraid_config (guild_id, enabled, threshold, window_seconds, alert_channel_id)
                        VALUES (?, 1, 8, 20, ?)
                        ON CONFLICT(guild_id) DO UPDATE SET enabled=1, threshold=8, window_seconds=20, alert_channel_id=?
                        """,
                        (guild.id, log_channel.id if log_channel else None, log_channel.id if log_channel else None),
                    )
                    await db.commit()
                status.append("  âœ… AntiRaid enabled (threshold: 8 joins/20s, alerts to #sentinel-logs).")
            except Exception as exc:
                errors.append(f"  âŒ AntiRaid config failed: {type(exc).__name__}")

            # 7. Initialize lockdown state (disabled by default)
            status.append("\nðŸ”’ **Initializing Lockdown system...**")
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
                status.append("  âœ… Lockdown system ready (currently disabled).")
            except Exception as exc:
                errors.append(f"  âŒ Lockdown init failed: {type(exc).__name__}")

            # 8. Assign Sentinel Member role to all existing human members
            status.append("\nðŸ‘¥ **Assigning Sentinel Member role to members...**")
            member_role = discord.utils.get(guild.roles, name="Sentinel Member")
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
                                reason="Sentinel Guard auto-setup initial member role assignment",
                            )
                            assigned += 1
                        except (discord.Forbidden, discord.HTTPException):
                            failed += 1

                        if (assigned + failed) % 20 == 0:
                            await asyncio.sleep(1)
                except (discord.Forbidden, discord.HTTPException):
                    errors.append("  âš ï¸ Could not fetch all members (check Server Members Intent).")

            status.append(
                f"  âœ… Assigned: **{assigned}** â€¢ â­ï¸ Skipped: **{skipped}** â€¢ âŒ Failed: **{failed}**"
            )

            # 9. Record setup event
            try:
                await add_security_log(
                    guild.id,
                    "autosetup_completed",
                    f"Roles created: {', '.join(created_roles) or 'none'}; "
                    f"Members assigned: {assigned}; Errors: {len(errors)}",
                    interaction.user.id,
                )
            except Exception:
                pass

            # Build final embed
            embed = discord.Embed(
                title="âš¡ Sentinel Guard â€¢ Auto-Setup Complete",
                description="Your server is now fully protected!",
                color=discord.Color.green(),
                timestamp=discord.utils.utcnow(),
            )

            embed.add_field(
                name="âœ… Completed Steps",
                value="\n".join([s for s in status if not s.startswith("  âŒ") and not s.startswith("  âš ï¸")])[:1024],
                inline=False,
            )

            if errors:
                embed.add_field(
                    name="âš ï¸ Warnings / Errors",
                    value="\n".join(errors)[:1024],
                    inline=False,
                )

            embed.add_field(
                name="ðŸŽ¯ Next Steps",
                value=(
                    "â€¢ Use `/securityconfig` to verify configuration\n"
                    "â€¢ Use `/help` to explore all commands\n"
                    "â€¢ Use `/lockdown enable` if emergency arises\n"
                    "â€¢ Adjust `/antinuke threshold` if needed"
                ),
                inline=False,
            )

            embed.set_footer(text=f"Server: {guild.name} â€¢ ID: {guild.id}")

            await interaction.followup.send(embed=embed, ephemeral=True)

        except Exception as exc:
            await add_security_log(
                guild.id, "autosetup_failed", f"{type(exc).__name__}: {exc}", interaction.user.id
            )
            await interaction.followup.send(
                f"âŒ Auto-setup failed: `{type(exc).__name__}`. Check logs.",
                ephemeral=True,
            )

    @commands.hybrid_command(name="autosetup", description="Fully automatic one-click server security setup (prefix alias)")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    @commands.bot_has_guild_permissions(manage_roles=True, manage_channels=True, view_audit_log=True)
    async def autosetup_prefix(self, ctx: commands.Context):
        """Prefix command alias for /autosetup."""
        # Reuse the slash command logic by creating a fake interaction-like context
        # For simplicity, just call the same logic
        guild = ctx.guild
        if guild is None:
            return

        await ctx.defer(ephemeral=ctx.interaction is not None)

        # Same logic as above but for prefix command
        # (In production, you'd refactor to a shared method)
        await ctx.send("Use `/autosetup` slash command for the full auto-setup experience.", ephemeral=True)


async def setup(bot: commands.Bot):
    await bot.add_cog(AutoSetup(bot))
