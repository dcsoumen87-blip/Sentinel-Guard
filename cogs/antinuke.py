import asyncio
import logging
import time
from collections import defaultdict, deque
import discord
import aiosqlite
from discord.ext import commands
from config import DB_PATH
from core.emojis import e as emoji
from core.permissions import can_manage_security, is_extra_owner
from database.db import add_security_log, get_log_channel

log = logging.getLogger("sentinel_guard.antinuke")

# Audit-log actions that count towards a nuke attempt.
TRACKED = {
    discord.AuditLogAction.channel_create: "channel_create",
    discord.AuditLogAction.channel_delete: "channel_delete",
    discord.AuditLogAction.channel_update: "channel_update",
    discord.AuditLogAction.role_create: "role_create",
    discord.AuditLogAction.role_delete: "role_delete",
    discord.AuditLogAction.role_update: "role_update",
    discord.AuditLogAction.webhook_create: "webhook_create",
    discord.AuditLogAction.webhook_update: "webhook_update",
    discord.AuditLogAction.webhook_delete: "webhook_delete",
    discord.AuditLogAction.emoji_delete: "emoji_delete",
    discord.AuditLogAction.sticker_delete: "sticker_delete",
    discord.AuditLogAction.integration_create: "integration_create",
    discord.AuditLogAction.guild_update: "guild_update",
    discord.AuditLogAction.member_prune: "member_prune",
    discord.AuditLogAction.bot_add: "bot_add",
    discord.AuditLogAction.member_role_update: "member_role_update",
    discord.AuditLogAction.ban: "member_ban",
    discord.AuditLogAction.kick: "member_kick",
}

# One strike and the actor is punished (no threshold).
INSTANT = {"bot_add", "member_prune"}
# Only checked for dangerous permission grants, never counted.
NOT_COUNTED = {"member_role_update"}

# Permissions that make a role dangerous to hand out.
DANGEROUS_PERMS = (
    "administrator",
    "manage_guild",
    "manage_roles",
    "manage_channels",
    "ban_members",
    "kick_members",
    "manage_webhooks",
)

FEATURES = (
    "Mass channel create / delete / edit",
    "Mass role create / delete / edit",
    "Mass ban / kick / prune",
    "Webhook, emoji, sticker and integration abuse",
    "Server settings (name, icon, vanity) changes",
    "Unauthorized bot add: bot removed, adder punished",
    "Dangerous permission grants to roles/members: reverted + punished",
    "Auto-revert: deleted channels/roles restored, created ones removed, bans undone",
    "Attacker bot: the person who added it is punished too",
    "Auto lockdown if the attacker cannot be removed",
    "Unbanned or attacker-kicked members get a one-time rejoin invite by DM",
    "Only Owner, Extra Owners and whitelisted users are exempt",
)

MODES = {
    "alert": "Alert + server lockdown only (attacker is NOT removed)",
    "strip": "Remove the attacker's roles + clean up",
    "kick": "Kick the attacker + clean up",
    "ban": "Ban the attacker + clean up (recommended)",
}
PUNISHED_TTL = 300  # seconds an attacker stays "marked" after being punished


class AntiNuke(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.events = defaultdict(deque)
        self.cooldowns = {}
        self.processed = {}
        self.punished = {}
        self.locks = defaultdict(asyncio.Lock)
        self._lockdown_locks = {}

    async def config(self, gid):
        async with aiosqlite.connect(DB_PATH) as db:
            cur = await db.execute(
                "SELECT enabled,threshold,window_seconds,alert_channel_id,mode FROM antinuke_config WHERE guild_id=?",
                (gid,),
            )
            r = await cur.fetchone()
            if r:
                return {
                    "enabled": bool(r[0]),
                    "threshold": r[1],
                    "window": r[2],
                    "alert": r[3],
                    "mode": r[4],
                }
            await db.execute(
                "INSERT OR IGNORE INTO antinuke_config(guild_id, mode) VALUES(?, 'ban')", (gid,)
            )
            await db.commit()
        return {"enabled": True, "threshold": 4, "window": 10, "alert": None, "mode": "ban"}

    async def incident(self, gid, actor, action, count, details):
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "INSERT INTO antinuke_incidents(guild_id,actor_id,action,event_count,details) VALUES(?,?,?,?,?)",
                (gid, actor, action, count, details[:1500]),
            )
            await db.commit()
        await add_security_log(gid, action, details, actor)

    async def whitelisted(self, gid, uid):
        async with aiosqlite.connect(DB_PATH) as db:
            cur = await db.execute(
                "SELECT 1 FROM antinuke_whitelist WHERE guild_id=? AND user_id=?", (gid, uid)
            )
            return await cur.fetchone() is not None

    async def alert(self, guild, cfg, actor_id, label, count, result, cleaned, note=None):
        channel_id = cfg["alert"] or await get_log_channel(guild.id)
        if not channel_id:
            log.warning("ALERT_NOT_CONFIGURED guild=%s actor=%s count=%s", guild.id, actor_id, count)
            return
        ch = guild.get_channel(channel_id)
        if not isinstance(ch, discord.TextChannel):
            log.error("ALERT_CHANNEL_MISSING guild=%s id=%s", guild.id, channel_id)
            return
        e = discord.Embed(
            title="Sentinel Guard | Anti-Nuke Alert",
            description="Rapid destructive activity reached the configured threshold.",
            color=discord.Color.red(),
            timestamp=discord.utils.utcnow(),
        )
        e.add_field(name="Actor", value=f"<@{actor_id}> (`{actor_id}`)", inline=False)
        e.add_field(name="Last activity", value=label, inline=True)
        e.add_field(name="Events", value=f"{count} in {cfg['window']} seconds", inline=True)
        e.add_field(name="Action taken", value=result[:1000], inline=False)
        if note:
            e.add_field(name="Details", value=note[:1000], inline=False)
        if cleaned:
            e.add_field(name="Reverted", value=f"{cleaned} change(s) reverted", inline=True)
        try:
            await ch.send(embed=e)
            log.warning("ALERT_SENT guild=%s actor=%s count=%s", guild.id, actor_id, count)
        except discord.Forbidden:
            log.error("ALERT_FORBIDDEN guild=%s channel=%s", guild.id, ch.id)
        except discord.HTTPException as exc:
            log.error("ALERT_HTTP_ERROR guild=%s error=%r", guild.id, exc)

    async def _trigger_auto_lockdown(self, guild: discord.Guild, actor: discord.Member, reason: str):
        """Automatically trigger lockdown when nuke threshold is exceeded."""
        # Check if lockdown is already active
        async with aiosqlite.connect(DB_PATH) as db:
            cur = await db.execute(
                "SELECT raid_mode FROM guild_settings WHERE guild_id = ?", (guild.id,)
            )
            row = await cur.fetchone()
            if row and row[0]:
                log.info("LOCKDOWN_ALREADY_ACTIVE guild=%s", guild.id)
                return False  # Already locked down

        # Prevent concurrent lockdown operations
        lock = self._lockdown_locks.setdefault(guild.id, asyncio.Lock())
        async with lock:
            # Double-check after acquiring lock
            async with aiosqlite.connect(DB_PATH) as db:
                cur = await db.execute(
                    "SELECT raid_mode FROM guild_settings WHERE guild_id = ?", (guild.id,)
                )
                row = await cur.fetchone()
                if row and row[0]:
                    return False

            me = guild.me
            if me is None:
                log.error("LOCKDOWN_BOT_MEMBER_UNAVAILABLE guild=%s", guild.id)
                return False

            everyone_role = guild.default_role
            affected_channels = []
            failed_channels = []

            # Lock all text channels where @everyone can currently send messages
            for channel in guild.text_channels:
                perms = channel.permissions_for(everyone_role)
                if perms.send_messages:
                    try:
                        await channel.set_permissions(
                            everyone_role,
                            send_messages=False,
                            reason=f"Auto-lockdown triggered by {actor} ({actor.id}): {reason}",
                        )
                        affected_channels.append(channel)
                    except discord.Forbidden:
                        failed_channels.append(channel)
                    except discord.HTTPException:
                        failed_channels.append(channel)

            # Save lockdown state
            async with aiosqlite.connect(DB_PATH) as db:
                await db.execute(
                    """
                    INSERT INTO guild_settings (guild_id, raid_mode)
                    VALUES (?, 1)
                    ON CONFLICT(guild_id) DO UPDATE SET raid_mode = 1
                    """,
                    (guild.id,),
                )
                await db.commit()

            await add_security_log(
                guild.id,
                "auto_lockdown_triggered",
                f"Auto-lockdown by AntiNuke. Locked {len(affected_channels)} channels. Failed: {len(failed_channels)}. Trigger: {reason}",
                actor.id,
            )

            # Send alert to log channel
            log_channel_id = await get_log_channel(guild.id)
            if log_channel_id:
                log_channel = guild.get_channel(log_channel_id)
                if isinstance(log_channel, discord.TextChannel):
                    try:
                        embed = discord.Embed(
                            title="AUTO-LOCKDOWN TRIGGERED",
                            description=(
                                f"**AntiNuke detected nuke attempt - server automatically locked down.**\n\n"
                                f"**Trigger:** {reason}\n"
                                f"**Actor:** {actor.mention} (`{actor.id}`)\n"
                                f"**Channels locked:** {len(affected_channels)}\n"
                                f"**Channels failed:** {len(failed_channels)}"
                            ),
                            color=discord.Color.red(),
                            timestamp=discord.utils.utcnow(),
                        )
                        embed.set_footer(text="Use /lockdown disable to restore when safe")
                        await log_channel.send(embed=embed)
                    except discord.HTTPException:
                        pass

            log.warning("AUTO_LOCKDOWN_TRIGGERED guild=%s actor=%s locked=%s failed=%s",
                       guild.id, actor.id, len(affected_channels), len(failed_channels))
            return True

    async def _punish(self, guild, actor_id, mode, reason):
        """Remove the attacker. Returns a human readable result."""
        me = guild.me
        if me is None:
            return "NOT PUNISHED: bot member unavailable."
        member = guild.get_member(actor_id)
        if member is not None and member.top_role >= me.top_role:
            return (
                "NOT PUNISHED: the attacker's role is above (or equal to) the bot's role. "
                "Drag the Sentinel bot role to the very top of the role list."
            )

        async def strip():
            if member is None:
                return "Attacker already left the server."
            removable = [
                r for r in member.roles
                if not r.is_default() and not r.managed and r < me.top_role
            ]
            if removable:
                await member.remove_roles(*removable, reason=reason)
                return f"Removed {len(removable)} role(s)."
            if member.bot:
                await member.kick(reason=reason)
                return "Bot has only managed roles - kicked instead."
            return "No removable roles."

        try:
            if mode == "ban":
                await guild.ban(discord.Object(id=actor_id), reason=reason, delete_message_seconds=0)
                return "Banned."
            if mode == "kick":
                if member is None:
                    return "Attacker already left the server."
                await member.kick(reason=reason)
                return "Kicked."
            return await strip()
        except discord.Forbidden:
            if mode != "strip":
                try:
                    return "Ban/kick forbidden. Fallback: " + await strip()
                except (discord.Forbidden, discord.HTTPException):
                    pass
            return "NOT PUNISHED: Discord refused (missing permission or role hierarchy)."
        except discord.HTTPException as exc:
            return f"NOT PUNISHED: Discord error {type(exc).__name__}."

    # ------------------------------------------------------------------ helpers

    async def _is_exempt(self, guild, uid):
        if uid == guild.owner_id:
            return True
        if await is_extra_owner(guild.id, uid):
            return True
        return await self.whitelisted(guild.id, uid)

    @staticmethod
    def _snapshot(entry, label):
        """Remember what a deleted channel/role looked like so it can be restored."""
        before = entry.before
        if label == "channel_delete":
            return {
                "name": getattr(before, "name", None),
                "type": getattr(before, "type", None),
                "position": getattr(before, "position", None),
                "topic": getattr(before, "topic", None),
                "nsfw": getattr(before, "nsfw", None),
                "slowmode": getattr(before, "slowmode_delay", None),
                "bitrate": getattr(before, "bitrate", None),
                "user_limit": getattr(before, "user_limit", None),
                "overwrites": getattr(before, "overwrites", None),
                "category": getattr(before, "category", None),
            }
        if label == "role_delete":
            return {
                "name": getattr(before, "name", None),
                "colour": getattr(before, "colour", None) or getattr(before, "color", None),
                "hoist": getattr(before, "hoist", None),
                "mentionable": getattr(before, "mentionable", None),
                "permissions": getattr(before, "permissions", None),
            }
        return None

    async def _restore_channel(self, guild, s):
        name = s.get("name")
        ctype = s.get("type")
        if not name:
            return False
        if isinstance(ctype, int):
            ctype = discord.ChannelType(ctype)

        parent = s.get("category")
        if parent is not None and not isinstance(parent, discord.CategoryChannel):
            parent = guild.get_channel(getattr(parent, "id", 0))
            if not isinstance(parent, discord.CategoryChannel):
                parent = None

        overwrites = {}
        for target, overwrite in (s.get("overwrites") or []):
            real = guild.get_role(target.id) or guild.get_member(target.id)
            if real is not None:
                overwrites[real] = overwrite

        reason = "Sentinel Guard: restoring channel deleted by attacker"
        common = {"overwrites": overwrites, "reason": reason}

        try:
            if ctype in (discord.ChannelType.text, discord.ChannelType.news):
                extra = {}
                if s.get("topic"):
                    extra["topic"] = s["topic"]
                if s.get("nsfw") is not None:
                    extra["nsfw"] = s["nsfw"]
                if s.get("slowmode"):
                    extra["slowmode_delay"] = s["slowmode"]
                await guild.create_text_channel(name, category=parent, **extra, **common)
            elif ctype == discord.ChannelType.voice:
                try:
                    extra = {}
                    if s.get("user_limit"):
                        extra["user_limit"] = s["user_limit"]
                    if s.get("bitrate"):
                        extra["bitrate"] = s["bitrate"]
                    await guild.create_voice_channel(name, category=parent, **extra, **common)
                except discord.HTTPException:
                    await guild.create_voice_channel(name, category=parent, **common)
            elif ctype == discord.ChannelType.category:
                await guild.create_category(name, **common)
            else:
                return False
            return True
        except (discord.Forbidden, discord.HTTPException):
            return False

    async def _restore_role(self, guild, s):
        if not s.get("name"):
            return False
        kwargs = {"name": s["name"], "reason": "Sentinel Guard: restoring role deleted by attacker"}
        if s.get("permissions") is not None:
            kwargs["permissions"] = s["permissions"]
        if s.get("colour") is not None:
            kwargs["colour"] = s["colour"]
        if s.get("hoist") is not None:
            kwargs["hoist"] = s["hoist"]
        if s.get("mentionable") is not None:
            kwargs["mentionable"] = s["mentionable"]
        try:
            await guild.create_role(**kwargs)
            return True
        except (discord.Forbidden, discord.HTTPException):
            return False

    async def _revert(self, guild, label, target_id, snapshot):
        """Undo one attacker action. Returns True if something was reverted."""
        reason = "Sentinel Guard: reverting nuke activity"
        try:
            if label == "channel_create" and target_id:
                ch = guild.get_channel(target_id) or await guild.fetch_channel(target_id)
                await ch.delete(reason=reason)
                return True
            if label == "role_create" and target_id:
                role = guild.get_role(target_id)
                if role is not None:
                    await role.delete(reason=reason)
                    return True
                return False
            if label == "channel_delete" and snapshot:
                return await self._restore_channel(guild, snapshot)
            if label == "role_delete" and snapshot:
                return await self._restore_role(guild, snapshot)
            if label == "member_ban" and target_id:
                await guild.unban(discord.Object(id=target_id), reason=reason)
                return True
            if label == "member_kick" and target_id:
                user = self.bot.get_user(target_id) or await self.bot.fetch_user(target_id)
                return await self._send_rejoin(guild, user, "you were removed by an attacker")
            if label == "webhook_create" and target_id:
                for hook in await guild.webhooks():
                    if hook.id == target_id:
                        await hook.delete(reason=reason)
                        return True
        except (discord.NotFound, discord.Forbidden, discord.HTTPException):
            return False
        return False

    async def _cleanup(self, guild, items):
        """Revert a list of (label, target_id, snapshot). Returns how many were reverted."""
        done = 0
        for label, target_id, snapshot in items:
            if await self._revert(guild, label, target_id, snapshot):
                done += 1
        return done

    async def _remove_bot(self, guild, bot_id, mode, reason):
        """Remove an unauthorized bot. Returns a short result string."""
        try:
            if mode == "ban":
                await guild.ban(discord.Object(id=bot_id), reason=reason, delete_message_seconds=0)
                return "Unauthorized bot banned."
            member = guild.get_member(bot_id)
            if member is not None:
                await member.kick(reason=reason)
                return "Unauthorized bot kicked."
            return "Unauthorized bot already gone."
        except (discord.Forbidden, discord.HTTPException):
            return "COULD NOT REMOVE the unauthorized bot (role hierarchy?)."

    async def _find_adder(self, guild, bot_id):
        """Who invited this bot? Looks it up in the audit log."""
        try:
            async for item in guild.audit_logs(limit=100, action=discord.AuditLogAction.bot_add):
                if getattr(item.target, "id", None) == bot_id:
                    return item.user_id
        except (discord.Forbidden, discord.HTTPException):
            pass
        return None

    async def _guard_permissions(self, entry, guild, label):
        """Detect and revert dangerous permission grants. Returns a note or None."""
        if label == "role_update":
            before = getattr(entry.before, "permissions", None)
            after = getattr(entry.after, "permissions", None)
            if before is None or after is None:
                return None
            gained = [p for p in DANGEROUS_PERMS if getattr(after, p) and not getattr(before, p)]
            if not gained:
                return None
            note = "Role permissions escalated: " + ", ".join(gained)
            role = guild.get_role(getattr(entry.target, "id", 0))
            if role is not None:
                try:
                    await role.edit(permissions=before, reason="Sentinel Guard: revert permission escalation")
                    note += " (reverted)"
                except (discord.Forbidden, discord.HTTPException):
                    note += " (COULD NOT revert)"
            return note

        if label == "member_role_update":
            added = getattr(entry.after, "roles", None) or []
            bad = []
            for ref in added:
                role = guild.get_role(ref.id)
                if role is None or role.managed:
                    continue
                if any(getattr(role.permissions, p) for p in DANGEROUS_PERMS):
                    bad.append(role)
            if not bad:
                return None
            note = "Dangerous role(s) given: " + ", ".join(r.name for r in bad)
            member = guild.get_member(getattr(entry.target, "id", 0))
            if member is not None:
                try:
                    await member.remove_roles(*bad, reason="Sentinel Guard: revert dangerous role grant")
                    note += " (removed again)"
                except (discord.Forbidden, discord.HTTPException):
                    note += " (COULD NOT remove)"
            return note
        return None

    async def _violation(self, guild, entry, cfg, mode, label, count, items, note=None, bot_target=None):
        """Punish the actor, revert damage, log and alert."""
        actor_id = entry.user_id
        reason = f"Sentinel Guard AntiNuke: {label} x{count} in {cfg['window']}s"
        result = "Alert only (mode: alert)."
        cleaned = 0
        parts = []

        if mode != "alert":
            result = await self._punish(guild, actor_id, mode, reason)
            cleaned = await self._cleanup(guild, items)
            if bot_target:
                parts.append(await self._remove_bot(guild, bot_target, mode, reason))

            # If the attacker is a bot, punish whoever added it as well.
            actor_member = guild.get_member(actor_id)
            if actor_member is not None and actor_member.bot:
                adder_id = await self._find_adder(guild, actor_id)
                if adder_id and adder_id != self.bot.user.id and not await self._is_exempt(guild, adder_id):
                    adder_result = await self._punish(guild, adder_id, mode, f"Added attacker bot {actor_id}")
                    parts.append(f"Bot adder <@{adder_id}>: {adder_result}")
        elif bot_target:
            parts.append("Alert mode: the unauthorized bot was NOT removed.")

        full_result = " ".join([result] + parts)
        details = f"{label}; {note or ''}"
        await self.incident(
            guild.id, actor_id, "antinuke_triggered", count,
            f"{count} x {label} by {actor_id} within {cfg['window']}s; mode={mode}; "
            f"result={full_result}; reverted={cleaned}; {note or ''}",
        )
        await self.alert(guild, cfg, actor_id, label, count, full_result, cleaned, note)

        if mode == "alert" or "NOT PUNISHED" in full_result:
            actor = entry.user or guild.get_member(actor_id)
            if actor is not None:
                await self._trigger_auto_lockdown(
                    guild, actor, f"AntiNuke: {label} x{count} and attacker not removed"
                )

    # ------------------------------------------------------------------ rejoin invites

    async def _rejoin_enabled(self, guild_id):
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "CREATE TABLE IF NOT EXISTS antinuke_rejoin ("
                "guild_id INTEGER PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 1)"
            )
            cur = await db.execute("SELECT enabled FROM antinuke_rejoin WHERE guild_id=?", (guild_id,))
            row = await cur.fetchone()
            await db.commit()
        return True if row is None else bool(row[0])

    @staticmethod
    def _invite_channel(guild):
        me = guild.me
        if me is None:
            return None
        candidates = [guild.system_channel, guild.rules_channel, *guild.text_channels]
        for ch in candidates:
            if ch is not None and ch.permissions_for(me).create_instant_invite:
                return ch
        return None

    async def _send_rejoin(self, guild, user, why):
        """DM a fresh single-use invite. Returns True if the DM was delivered."""
        if user is None or user.bot:
            return False
        if not await self._rejoin_enabled(guild.id):
            return False
        channel = self._invite_channel(guild)
        if channel is None:
            log.warning("REJOIN_NO_CHANNEL guild=%s", guild.id)
            return False

        try:
            invite = await channel.create_invite(
                max_age=7 * 24 * 3600,
                max_uses=1,
                unique=True,
                reason=f"Sentinel Guard: rejoin invite for {user.id}",
            )
        except (discord.Forbidden, discord.HTTPException):
            log.warning("REJOIN_INVITE_FAILED guild=%s user=%s", guild.id, user.id)
            return False

        embed = discord.Embed(
            title=f"You can rejoin {guild.name}",
            description=(
                f"Reason: {why}.\n\n"
                f"Join again here: {invite.url}\n"
                "This link works once and expires in 7 days."
            ),
            color=discord.Color.blue(),
            timestamp=discord.utils.utcnow(),
        )
        if guild.icon:
            embed.set_thumbnail(url=guild.icon.url)
        embed.set_footer(text=f"Sentinel Guard | {guild.name}")

        delivered = False
        try:
            await user.send(embed=embed)
            delivered = True
        except (discord.Forbidden, discord.HTTPException):
            pass

        channel_id = await get_log_channel(guild.id)
        log_ch = guild.get_channel(channel_id) if channel_id else None
        if isinstance(log_ch, discord.TextChannel):
            status = "Rejoin invite sent by DM" if delivered else "Could not DM (DMs closed)"
            try:
                await log_ch.send(f"{status}: <@{user.id}> (`{user.id}`)")
            except (discord.Forbidden, discord.HTTPException):
                pass
        await add_security_log(
            guild.id, "rejoin_invite", f"{'sent' if delivered else 'dm failed'} to {user.id}", user.id
        )
        return delivered

    @commands.Cog.listener()
    async def on_member_unban(self, guild: discord.Guild, user: discord.User):
        await self._send_rejoin(guild, user, "you were unbanned")

    # ------------------------------------------------------------------ listener

    @commands.Cog.listener()
    async def on_audit_log_entry_create(self, entry: discord.AuditLogEntry):
        """Fires instantly with the real actor - no audit-log polling needed."""
        label = TRACKED.get(entry.action)
        guild = entry.guild
        actor_id = entry.user_id
        if label is None or guild is None or actor_id is None:
            return
        if self.bot.user and actor_id == self.bot.user.id:
            return

        cfg = await self.config(guild.id)
        if not cfg["enabled"]:
            return
        if await self._is_exempt(guild, actor_id):
            return

        mode = cfg["mode"] if cfg["mode"] in MODES else "ban"
        target_id = getattr(entry.target, "id", None)
        snapshot = self._snapshot(entry, label)
        key = (guild.id, actor_id)
        now = time.monotonic()
        since = now - self.punished.get(key, -1e9)

        # Attacker already dealt with: keep undoing whatever they still do.
        if mode != "alert" and since < PUNISHED_TTL:
            await self._cleanup(guild, [(label, target_id, snapshot)])
            if label == "bot_add" and target_id:
                await self._remove_bot(guild, target_id, mode, "Sentinel Guard: attacker added a bot")
            return
        if mode == "alert" and since < 30:
            return

        # 1. Dangerous permission grants are punished on the first strike.
        if label in ("role_update", "member_role_update"):
            note = await self._guard_permissions(entry, guild, label)
            if note is not None:
                async with self.locks[key]:
                    self.punished[key] = now
                await self._violation(guild, entry, cfg, mode, label, 1, [], note=note)
                return
        if label in NOT_COUNTED:
            return

        # 2. Unauthorized bot / prune: one strike.
        if label in INSTANT:
            async with self.locks[key]:
                self.punished[key] = now
            note = "Unauthorized bot added" if label == "bot_add" else "Member prune"
            await self._violation(
                guild, entry, cfg, mode, label, 1, [],
                note=note, bot_target=target_id if label == "bot_add" else None,
            )
            return

        # 3. Everything else: threshold within the time window.
        async with self.locks[key]:
            q = self.events[key]
            q.append((now, label, target_id, snapshot))
            while q and now - q[0][0] > cfg["window"]:
                q.popleft()
            count = len(q)
            log.info(
                "THRESHOLD_CHECK guild=%s actor=%s label=%s count=%s threshold=%s mode=%s",
                guild.id, actor_id, label, count, cfg["threshold"], mode,
            )
            if count < cfg["threshold"]:
                return
            self.punished[key] = now
            recent = list(q)
            q.clear()

        items = [(lbl, tid, snap) for _, lbl, tid, snap in recent]
        await self._violation(guild, entry, cfg, mode, label, count, items)

    @commands.hybrid_group(name="antinuke", invoke_without_command=True)
    @commands.guild_only()
    async def antinuke(self, ctx):
        await ctx.send("Use `/antinuke status`, `/antinuke enable|disable|toggle`, or `/antinuke config`.", ephemeral=ctx.interaction is not None)

    @antinuke.command(name="rejoin")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def rejoin(self, ctx, state: str = None):
        """Turn the DM rejoin invite (sent on unban) on or off."""
        ephemeral = ctx.interaction is not None
        if state is None or state.lower() not in ("on", "off"):
            current = await self._rejoin_enabled(ctx.guild.id)
            await ctx.send(
                f"Rejoin invites are **{'on' if current else 'off'}**. Use `/antinuke rejoin on|off`.",
                ephemeral=ephemeral,
            )
            return
        value = 1 if state.lower() == "on" else 0
        await self._rejoin_enabled(ctx.guild.id)  # makes sure the table exists
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "INSERT INTO antinuke_rejoin(guild_id, enabled) VALUES(?, ?) "
                "ON CONFLICT(guild_id) DO UPDATE SET enabled=excluded.enabled",
                (ctx.guild.id, value),
            )
            await db.commit()
        await ctx.send(
            f"Rejoin invites turned **{state.lower()}**.", ephemeral=ephemeral
        )

    @antinuke.command(name="features")
    @commands.guild_only()
    async def features(self, ctx):
        c = await self.config(ctx.guild.id)
        e = discord.Embed(
            title="Anti-Nuke Protections",
            description="\n".join(f"{emoji('success')} {item}" for item in FEATURES),
            color=discord.Color.green() if c["enabled"] else discord.Color.red(),
        )
        e.add_field(
            name="Current settings",
            value=f"Mode: `{c['mode']}` | Threshold: `{c['threshold']}` in `{c['window']}s`",
            inline=False,
        )
        await ctx.send(embed=e, ephemeral=ctx.interaction is not None)

    @antinuke.command(name="status")
    @commands.guild_only()
    async def status(self, ctx):
        c = await self.config(ctx.guild.id)
        e = discord.Embed(title="Anti-Nuke Status", color=discord.Color.green())
        e.add_field(name="Enabled", value=(f"{emoji('enabled')} Yes" if c["enabled"] else f"{emoji('disabled')} No"), inline=True)
        e.add_field(name="Threshold", value=str(c["threshold"]), inline=True)
        e.add_field(name="Window", value=f"{c['window']}s", inline=True)
        e.add_field(name="Alert Channel", value=f"<#{c['alert']}>" if c["alert"] else "Not configured", inline=False)
        e.add_field(name="Mode", value=c["mode"], inline=True)
        e.add_field(name="Punishment", value=MODES.get(c["mode"], c["mode"]), inline=False)
        if c["mode"] == "alert":
            e.add_field(
                name="Warning",
                value="Mode is `alert`: attackers are NOT removed. Run `/antinuke mode ban`.",
                inline=False,
            )
        me = ctx.guild.me
        if me is not None:
            above = [r.name for r in ctx.guild.roles if r > me.top_role and not r.is_default()]
            if above:
                e.add_field(
                    name="Role position",
                    value="Roles above the bot can not be stopped: " + ", ".join(above[:5]),
                    inline=False,
                )
        await ctx.send(embed=e, ephemeral=ctx.interaction is not None)

    @antinuke.command(name="mode")
    @commands.guild_only()
    async def mode(self, ctx, mode: str = None):
        """Choose what happens to an attacker: alert, strip, kick or ban."""
        if not await can_manage_security(ctx.guild, ctx.author.id):
            await ctx.send("Only the Server Owner or Extra Owners can change this.", ephemeral=ctx.interaction is not None)
            return
        if mode is None or mode.lower() not in MODES:
            lines = "\n".join(f"`{k}` - {v}" for k, v in MODES.items())
            await ctx.send("Usage: `/antinuke mode <alert|strip|kick|ban>`\n" + lines, ephemeral=ctx.interaction is not None)
            return
        mode = mode.lower()
        await self.config(ctx.guild.id)
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("UPDATE antinuke_config SET mode=? WHERE guild_id=?", (mode, ctx.guild.id))
            await db.commit()
        await add_security_log(ctx.guild.id, "antinuke_mode", f"Mode set to {mode}", ctx.author.id)
        await ctx.send(f"Anti-Nuke mode set to **{mode}**: {MODES[mode]}", ephemeral=ctx.interaction is not None)

    @antinuke.command(name="enable")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def enable(self, ctx):
        """Enable Anti-Nuke monitoring."""
        await self.config(ctx.guild.id)
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("UPDATE antinuke_config SET enabled=1 WHERE guild_id=?", (ctx.guild.id,))
            await db.commit()
        await add_security_log(ctx.guild.id, "antinuke_enabled", "Anti-Nuke monitoring enabled", ctx.author.id)
        await ctx.send(f"{emoji('enabled')} Anti-Nuke **enabled**. Watching channel/role/webhook/ban/kick activity.", ephemeral=ctx.interaction is not None)

    @antinuke.command(name="disable")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def disable(self, ctx):
        """Disable Anti-Nuke monitoring."""
        await self.config(ctx.guild.id)
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("UPDATE antinuke_config SET enabled=0 WHERE guild_id=?", (ctx.guild.id,))
            await db.commit()
        await add_security_log(ctx.guild.id, "antinuke_disabled", "Anti-Nuke monitoring disabled", ctx.author.id)
        await ctx.send(f"{emoji('disabled')} Anti-Nuke **disabled**. No monitoring active.", ephemeral=ctx.interaction is not None)

    @antinuke.command(name="toggle")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def toggle(self, ctx):
        """Toggle Anti-Nuke on/off."""
        c = await self.config(ctx.guild.id)
        new_state = not c["enabled"]
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("UPDATE antinuke_config SET enabled=? WHERE guild_id=?", (int(new_state), ctx.guild.id))
            await db.commit()
        action = "enabled" if new_state else "disabled"
        await add_security_log(ctx.guild.id, f"antinuke_{action}", f"Anti-Nuke {action} via toggle", ctx.author.id)
        await ctx.send(f"Anti-Nuke **{action}**.", ephemeral=ctx.interaction is not None)

    @antinuke.command(name="alertchannel")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def alertchannel(self, ctx, channel: discord.TextChannel = None):
        channel = channel or ctx.channel
        p = channel.permissions_for(ctx.guild.me)
        if not p.send_messages or not p.embed_links:
            await ctx.send("Bot needs Send Messages and Embed Links there.", ephemeral=ctx.interaction is not None)
            return
        await self.config(ctx.guild.id)
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "UPDATE antinuke_config SET alert_channel_id=? WHERE guild_id=?",
                (channel.id, ctx.guild.id),
            )
            await db.commit()
        await add_security_log(ctx.guild.id, "antinuke_alertchannel", f"Alert channel set to {channel.id}", ctx.author.id)
        await ctx.send(f"Alerts set to {channel.mention}.", ephemeral=ctx.interaction is not None)

    @antinuke.command(name="threshold")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def threshold(self, ctx, count: int, window_seconds: int):
        if not 2 <= count <= 20 or not 3 <= window_seconds <= 60:
            await ctx.send("Count must be 2-20; window 3-60 seconds.", ephemeral=ctx.interaction is not None)
            return
        await self.config(ctx.guild.id)
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "UPDATE antinuke_config SET threshold=?,window_seconds=? WHERE guild_id=?",
                (count, window_seconds, ctx.guild.id),
            )
            await db.commit()
        await add_security_log(ctx.guild.id, "antinuke_threshold", f"Threshold: {count}/{window_seconds}s", ctx.author.id)
        await ctx.send(f"Threshold set to {count} events / {window_seconds}s.", ephemeral=ctx.interaction is not None)

    @antinuke.command(name="whitelist-add")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def whitelist_add(self, ctx, member: discord.Member):
        await self.config(ctx.guild.id)
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "INSERT OR IGNORE INTO antinuke_whitelist(guild_id,user_id) VALUES(?,?)",
                (ctx.guild.id, member.id),
            )
            await db.commit()
        await add_security_log(ctx.guild.id, "antinuke_whitelist_add", f"Added {member.id}", ctx.author.id)
        await ctx.send(f"{member.mention} whitelisted.", ephemeral=ctx.interaction is not None)

    @antinuke.command(name="whitelist-remove")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def whitelist_remove(self, ctx, member: discord.Member):
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "DELETE FROM antinuke_whitelist WHERE guild_id=? AND user_id=?",
                (ctx.guild.id, member.id),
            )
            await db.commit()
        await add_security_log(ctx.guild.id, "antinuke_whitelist_remove", f"Removed {member.id}", ctx.author.id)
        await ctx.send(f"{member.mention} removed from whitelist.", ephemeral=ctx.interaction is not None)

    @antinuke.command(name="whitelist-list")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def whitelist_list(self, ctx):
        async with aiosqlite.connect(DB_PATH) as db:
            cur = await db.execute(
                "SELECT user_id FROM antinuke_whitelist WHERE guild_id=?", (ctx.guild.id,)
            )
            rows = await cur.fetchall()
        if not rows:
            await ctx.send("No whitelisted users.", ephemeral=ctx.interaction is not None)
            return
        desc = "\n".join(f"- <@{row[0]}> (`{row[0]}`)" for row in rows)
        e = discord.Embed(title="Anti-Nuke Whitelist", description=desc, color=discord.Color.blurple())
        await ctx.send(embed=e, ephemeral=ctx.interaction is not None)

    @antinuke.command(name="incidents")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def incidents(self, ctx, limit: int = 10):
        if not 1 <= limit <= 25:
            await ctx.send("Limit must be 1-25.", ephemeral=ctx.interaction is not None)
            return
        async with aiosqlite.connect(DB_PATH) as db:
            cur = await db.execute(
                "SELECT actor_id, action, event_count, details, created_at FROM antinuke_incidents WHERE guild_id=? ORDER BY id DESC LIMIT ?",
                (ctx.guild.id, limit),
            )
            rows = await cur.fetchall()
        if not rows:
            await ctx.send("No incidents recorded.", ephemeral=ctx.interaction is not None)
            return
        lines = []
        for actor_id, action, count, details, created_at in rows:
            actor = ctx.guild.get_member(actor_id) if actor_id else None
            actor_str = f"{actor.mention} (`{actor_id}`)" if actor else f"Unknown (`{actor_id}`)"
            lines.append(f"**{created_at}** - {actor_str} - {action} (x{count}): {details[:100]}")
        await ctx.send("\n".join(lines)[:1900], ephemeral=ctx.interaction is not None)


async def setup(bot):
    await bot.add_cog(AntiNuke(bot))
