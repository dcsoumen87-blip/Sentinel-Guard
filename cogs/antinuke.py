"""AntiNuke: detects destructive actions through the audit log, punishes the
person responsible and then repairs the damage.

Order of events for every attack
--------------------------------
1. Identify the actor from the audit log (not from guesses).
2. Exempt?  Server Owner, Extra Owners and the bot itself always; whitelisted
   members only for the actions they were granted.  Discord Administrator
   does NOT exempt anybody.
3. Threshold reached (or a one-strike action such as adding a bot):
   a) PUNISH first, using the configured mode (ban / kick / strip / alert).
      If the configured step is refused, the next one is tried
      (ban -> kick -> strip -> timeout) and the result is reported honestly.
   b) only then RECOVER: restore deleted channels/roles, remove what the
      attacker created, undo bans, revert edits (see core/recovery.py).
   c) log the incident, alert the staff, lock the server down if the attacker
      could not be removed.
4. Events that arrive later from the same attacker wait for step (a) to finish
   and are then reverted one by one.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Literal

import discord
from discord.ext import commands, tasks

from core import lockdown as lockdown_service
from core.emojis import e as emoji
from core.permissions import (
    bot_missing_permissions,
    can_manage_security,
    is_exempt,
    permission_for_action,
)
from core.recovery import (
    SNAPSHOT_INTERVAL,
    RecoveryOp,
    RecoveryService,
    fallback_from_entry,
)
from database.db import (
    add_security_log,
    ensure_guild,
    execute,
    fetchall,
    fetchone,
    get_log_channel,
)

log = logging.getLogger("sentinel_guard.antinuke")

# --------------------------------------------------------------------------
# What is watched
# --------------------------------------------------------------------------

A = discord.AuditLogAction

TRACKED: dict[Any, str] = {
    A.channel_create: "channel_create",
    A.channel_delete: "channel_delete",
    A.channel_update: "channel_update",
    A.overwrite_create: "channel_update",   # permission changes on a channel
    A.overwrite_update: "channel_update",
    A.overwrite_delete: "channel_update",
    A.role_create: "role_create",
    A.role_delete: "role_delete",
    A.role_update: "role_update",
    A.webhook_create: "webhook_create",
    A.webhook_update: "webhook_update",
    A.webhook_delete: "webhook_delete",
    A.emoji_delete: "emoji_delete",
    A.sticker_delete: "sticker_delete",
    A.integration_create: "integration_create",
    A.integration_update: "integration_update",
    A.integration_delete: "integration_delete",
    A.invite_create: "invite_create",
    A.guild_update: "guild_update",
    A.member_prune: "member_prune",
    A.bot_add: "bot_add",
    A.member_role_update: "member_role_update",
    A.ban: "member_ban",
    A.kick: "member_kick",
}

# One strike: the actor is punished immediately.
INSTANT = {"bot_add", "member_prune"}
# Never counted; only checked for dangerous permission grants.
NOT_COUNTED = {"member_role_update"}
# Changes made by trusted people: keep the recovery snapshot fresh.
STRUCTURAL = {
    "channel_create", "channel_delete", "channel_update",
    "role_create", "role_delete", "role_update", "guild_update",
}

DANGEROUS_PERMS = (
    "administrator",
    "manage_guild",
    "manage_roles",
    "manage_channels",
    "ban_members",
    "kick_members",
    "manage_webhooks",
)

MASS_MENTION_LIMIT = 15   # users + roles in one message

# Panic Mode: the first unauthorized action of these kinds is punished. Invites and
# mention spam stay threshold-based (ordinary members create invites all the time).
PANIC_THRESHOLD_ONLY = {"invite_create", "mass_mention"}
# Panic sweep: look this far back in the audit log, flag an actor with this many
# structural actions (one-strike actions always count); bans/kicks need the normal threshold.
SWEEP_MINUTES = 10
SWEEP_MIN_EVENTS = 2
SWEEP_SOFT = {"member_ban", "member_kick"}
SWEEP_IGNORED = {"invite_create"}

MODES = {
    "alert": "Alert + server lockdown only (the attacker is NOT removed)",
    "strip": "Remove the attacker's roles, then recover",
    "kick": "Kick the attacker, then recover",
    "ban": "Ban the attacker, then recover (recommended)",
}
# What is tried when the configured step is refused.
ESCALATION = {
    "ban": ("ban", "kick", "strip", "timeout"),
    "kick": ("kick", "strip", "timeout"),
    "strip": ("strip", "timeout"),
}

FEATURES = (
    "Channel create / delete / edit and channel permission changes",
    "Role create / delete / edit",
    "Mass ban, kick and prune",
    "Webhooks, integrations, emojis, stickers and invite abuse",
    "Server settings changes",
    "Mass @everyone / mention abuse",
    "Unauthorized bot add: bot removed, adder punished",
    "Dangerous permission grants: reverted and punished at once",
    "Punishment first (ban / kick), recovery right after",
    "Deleted channels and roles restored with permissions, position and category",
    "Attacker bot: whoever added it is punished too",
    "Server lockdown if the attacker cannot be removed (exact permissions restored later)",
    "Panic Mode: the first unauthorized action is punished and the audit log is swept",
    "Rejoin invite by DM for unbanned or attacker-kicked members",
    "Exempt: Server Owner and Extra Owners; whitelist only for granted actions",
)

PUNISHED_TTL = 300        # seconds after a punishment during which leftovers are reverted
FAILED_TTL = 60           # shorter when the attacker could not be removed
ALERT_ONLY_TTL = 30
CONFIG_TTL = 5.0
CONFIG_COLUMNS = {
    "enabled", "threshold", "window_seconds", "alert_channel_id", "mode", "recovery_enabled",
}


@dataclass
class Event:
    guild: discord.Guild
    actor_id: int
    label: str
    target_id: int | None = None
    entry: Any = None
    message: discord.Message | None = None
    ts: float = field(default_factory=time.monotonic)


@dataclass
class Incident:
    started: float
    mode: str
    done: asyncio.Event = field(default_factory=asyncio.Event)
    punished: bool = False
    ttl: float = PUNISHED_TTL


@dataclass
class Punishment:
    ok: bool
    action: str
    detail: str


class AntiNuke(commands.Cog):
    """Real-time protection against nuking, with punishment first and recovery after."""

    def __init__(self, bot: commands.Bot):
        self.bot = bot
        self.recovery = RecoveryService(bot)
        self.events: dict[tuple[int, int], deque] = defaultdict(deque)
        self.incidents: dict[tuple[int, int], Incident] = {}
        self.locks: dict[tuple[int, int], asyncio.Lock] = defaultdict(asyncio.Lock)
        self._config: dict[int, tuple[float, dict]] = {}

    # ------------------------------------------------------------------ lifecycle

    async def cog_load(self) -> None:
        self.snapshot_loop.start()
        self.cleanup_loop.start()

    async def cog_unload(self) -> None:
        self.snapshot_loop.cancel()
        self.cleanup_loop.cancel()

    @tasks.loop(seconds=SNAPSHOT_INTERVAL)
    async def snapshot_loop(self) -> None:
        await self.recovery.snapshot_all()

    @snapshot_loop.before_loop
    async def _before_snapshot(self) -> None:
        await self.bot.wait_until_ready()

    @tasks.loop(seconds=60)
    async def cleanup_loop(self) -> None:
        """Forget old state so memory cannot grow forever."""
        now = time.monotonic()
        for key, inc in list(self.incidents.items()):
            if now - inc.started > inc.ttl:
                del self.incidents[key]
        for key, queue in list(self.events.items()):
            if not queue or now - queue[-1][0] > 120:
                del self.events[key]
        for key in [k for k in self.locks if k not in self.events and k not in self.incidents]:
            if not self.locks[key].locked():
                del self.locks[key]

    @commands.Cog.listener()
    async def on_guild_join(self, guild: discord.Guild) -> None:
        try:
            await self.recovery.capture_snapshot(guild, "guild join")
        except Exception:
            log.exception("Snapshot on join failed")

    # --------------------------------------------------------------------- config

    async def config(self, guild_id: int) -> dict:
        cached = self._config.get(guild_id)
        now = time.monotonic()
        if cached and cached[0] > now:
            return cached[1]

        sql = (
            "SELECT enabled, threshold, window_seconds, alert_channel_id, mode, recovery_enabled "
            "FROM antinuke_config WHERE guild_id = ?"
        )
        row = await fetchone(sql, (guild_id,))
        if row is None:
            await ensure_guild(guild_id)
            row = await fetchone(sql, (guild_id,))
        mode = row["mode"] if row["mode"] in MODES else "ban"
        value = {
            "enabled": bool(row["enabled"]),
            "threshold": int(row["threshold"]),
            "window": int(row["window_seconds"]),
            "alert": row["alert_channel_id"],
            "mode": mode,
            "recovery": bool(row["recovery_enabled"]),
        }
        self._config[guild_id] = (now + CONFIG_TTL, value)
        return value

    async def _update_config(self, guild_id: int, **columns) -> None:
        unknown = set(columns) - CONFIG_COLUMNS
        if unknown:
            raise ValueError(f"unknown antinuke column(s): {sorted(unknown)}")
        await ensure_guild(guild_id)
        assignments = ", ".join(f"{name} = ?" for name in columns)
        await execute(
            f"UPDATE antinuke_config SET {assignments} WHERE guild_id = ?",
            (*columns.values(), guild_id),
        )
        self._config.pop(guild_id, None)

    # ------------------------------------------------------------------- logging

    async def _incident(self, guild_id, actor_id, action, count, details) -> None:
        await execute(
            "INSERT INTO antinuke_incidents (guild_id, actor_id, action, event_count, details) "
            "VALUES (?, ?, ?, ?, ?)",
            (guild_id, actor_id, action, count, details[:1500]),
        )
        await add_security_log(guild_id, action, details, actor_id)

    async def _alert(self, guild, cfg, ev: Event, count: int, punishment: Punishment | None,
                     summary: dict, note: str | None, lockdown: str | None) -> None:
        channel_id = cfg["alert"] or await get_log_channel(guild.id)
        channel = guild.get_channel(channel_id) if channel_id else None
        if not isinstance(channel, discord.TextChannel):
            log.warning("ALERT_NO_CHANNEL guild=%s actor=%s", guild.id, ev.actor_id)
            return

        failed = punishment is not None and not punishment.ok
        embed = discord.Embed(
            title=f"{emoji('incident')} AntiNuke | Attack detected",
            description=f"Destructive activity by <@{ev.actor_id}> (`{ev.actor_id}`).",
            color=discord.Color.red() if failed else discord.Color.orange(),
            timestamp=discord.utils.utcnow(),
        )
        embed.add_field(name="Trigger", value=f"`{ev.label}` x{count} in {cfg['window']}s", inline=True)
        embed.add_field(name="Mode", value=f"`{cfg['mode']}`", inline=True)
        if punishment is not None:
            icon = emoji("error") if failed else emoji("success")
            embed.add_field(
                name="Punishment",
                value=f"{icon} **{punishment.action}**: {punishment.detail}"[:1000],
                inline=False,
            )
        else:
            embed.add_field(name="Punishment", value=f"{emoji('warning')} Alert mode: nobody was removed.", inline=False)
        if summary and (summary.get("reverted") or summary.get("failed") or summary.get("irreversible")):
            embed.add_field(
                name="Recovery",
                value=(
                    f"{emoji('success')} Reverted: **{summary.get('reverted', 0)}**\n"
                    f"{emoji('error')} Failed: **{summary.get('failed', 0)}**\n"
                    f"{emoji('warning')} Cannot be undone: **{summary.get('irreversible', 0)}**"
                ),
                inline=False,
            )
        if note:
            embed.add_field(name="Details", value=note[:1000], inline=False)
        if lockdown:
            embed.add_field(name="Lockdown", value=lockdown[:500], inline=False)
        try:
            await channel.send(embed=embed)
        except discord.HTTPException as exc:
            log.error("ALERT_FAILED guild=%s error=%r", guild.id, exc)

    # ---------------------------------------------------------------- punishment

    async def _punish(self, guild: discord.Guild, actor_id: int, mode: str, reason: str) -> Punishment:
        """Execute the configured punishment, escalating if it is refused."""
        me = guild.me
        if me is None:
            return Punishment(False, "none", "the bot is not a member of this server")

        member = guild.get_member(actor_id)
        if member is not None and member.top_role >= me.top_role:
            return Punishment(
                False,
                "none",
                f"the attacker's highest role ({member.top_role.name}) is above or equal to mine. "
                "Drag the Sentinel bot role above it.",
            )

        problems: list[str] = []
        for step in ESCALATION.get(mode, ESCALATION["ban"]):
            try:
                detail = await self._run_step(step, guild, member, actor_id, reason)
            except discord.Forbidden:
                problems.append(f"{step} refused (missing permission)")
                continue
            except discord.HTTPException as exc:
                problems.append(f"{step} failed ({exc.status})")
                continue
            if detail is None:
                continue
            if problems:
                detail += f" Earlier steps failed: {'; '.join(problems)}."
            return Punishment(True, step, detail)

        log.error("PUNISHMENT_FAILED guild=%s actor=%s mode=%s problems=%s", guild.id, actor_id, mode, problems)
        return Punishment(False, "none", "; ".join(problems) or "no punishment step was possible")

    async def _run_step(self, step, guild, member, actor_id, reason) -> str | None:
        if step == "ban":
            await guild.ban(discord.Object(id=actor_id), reason=reason, delete_message_seconds=0)
            return "Banned."
        if step == "kick":
            if member is None:
                return "The attacker already left the server."
            await member.kick(reason=reason)
            return "Kicked."
        if step == "strip":
            if member is None:
                return None
            me = guild.me
            removable = [r for r in member.roles if not r.is_default() and not r.managed and r < me.top_role]
            if removable:
                await member.remove_roles(*removable, reason=reason)
                return f"Removed {len(removable)} role(s)."
            return None
        if step == "timeout":
            if member is None:
                return None
            await member.timeout(timedelta(days=28), reason=reason)
            return "Timed out for 28 days."
        return None

    async def _find_adder(self, guild, bot_id: int) -> int | None:
        try:
            async for item in guild.audit_logs(limit=100, action=discord.AuditLogAction.bot_add):
                if getattr(item.target, "id", None) == bot_id:
                    return item.user_id
        except discord.HTTPException:
            pass
        return None

    async def _remove_bot(self, guild, bot_id: int, mode: str, reason: str) -> str:
        member = guild.get_member(bot_id)
        try:
            if mode == "ban":
                await guild.ban(discord.Object(id=bot_id), reason=reason, delete_message_seconds=0)
                return "Unauthorized bot banned."
            if member is not None:
                await member.kick(reason=reason)
                return "Unauthorized bot kicked."
            return "Unauthorized bot already gone."
        except discord.HTTPException:
            return "COULD NOT remove the unauthorized bot (role hierarchy or permission)."

    # --------------------------------------------------------------- lockdown hook

    async def _lockdown(self, guild: discord.Guild, actor_id: int, reason: str) -> str:
        """Lock the server through the shared lockdown service."""
        try:
            result = await lockdown_service.engage(guild, actor_id, reason, automatic=True)
            return str(result)
        except Exception:
            log.exception("Lockdown service failed")
            return "Lockdown service failed; check the logs."

    # ---------------------------------------------------------------- recovery

    @staticmethod
    def _op(ev: Event) -> RecoveryOp | None:
        label = ev.label
        if label in ("channel_create", "role_create", "webhook_create", "member_ban"):
            return RecoveryOp(label, ev.target_id)
        if label in ("channel_delete", "role_delete"):
            fallback = fallback_from_entry(ev.entry, label) if ev.entry is not None else None
            return RecoveryOp(label, ev.target_id, fallback)
        if label in ("channel_update", "role_update"):
            return RecoveryOp(label, ev.target_id)
        if label == "guild_update":
            return RecoveryOp("guild_update", None)
        return None

    async def _revert_extras(self, guild, events: list[Event]) -> tuple[int, int]:
        """Things the recovery service does not handle. Returns (done, irreversible)."""
        done = irreversible = 0
        for ev in events:
            try:
                if ev.label == "member_kick" and ev.target_id:
                    user = self.bot.get_user(ev.target_id) or await self.bot.fetch_user(ev.target_id)
                    if await self._send_rejoin(guild, user, "you were removed by an attacker"):
                        done += 1
                elif ev.label == "mass_mention" and ev.message is not None:
                    await ev.message.delete()
                    done += 1
                elif ev.label == "invite_create" and ev.entry is not None and hasattr(ev.entry.target, "delete"):
                    await ev.entry.target.delete(reason="Sentinel Guard recovery (invite by attacker)")
                    done += 1
                else:
                    irreversible += 1
            except discord.HTTPException:
                irreversible += 1
        return done, irreversible

    async def _recover(self, guild, cfg, events: list[Event], actor_id: int) -> dict:
        summary = {"reverted": 0, "failed": 0, "irreversible": 0}
        if not cfg["recovery"] or not events:
            return summary
        ops, extras = [], []
        for ev in events:
            op = self._op(ev)
            (ops if op else extras).append(op or ev)
        if ops:
            result = await self.recovery.revert_many(guild, ops, actor_id)
            summary["reverted"] += result["reverted"]
            summary["failed"] += result["failed"]
        if extras:
            done, irreversible = await self._revert_extras(guild, extras)
            summary["reverted"] += done
            summary["irreversible"] += irreversible
        return summary

    # ------------------------------------------------------------ dangerous grants

    async def _guard_permissions(self, entry, guild, label, revert: bool = True) -> str | None:
        """Find a dangerous permission grant and (unless ``revert`` is False) undo it.

        Returns a note, or None if the change was harmless.
        """
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
            if revert and role is not None:
                try:
                    await role.edit(permissions=before, reason="Sentinel Guard: revert permission escalation")
                    note += " (reverted)"
                except discord.HTTPException:
                    note += " (COULD NOT revert)"
            return note

        if label == "member_role_update":
            bad = []
            for ref in getattr(entry.after, "roles", None) or []:
                role = guild.get_role(ref.id)
                if role is not None and not role.managed and any(
                    getattr(role.permissions, p) for p in DANGEROUS_PERMS
                ):
                    bad.append(role)
            if not bad:
                return None
            note = "Dangerous role(s) given: " + ", ".join(r.name for r in bad)
            member = guild.get_member(getattr(entry.target, "id", 0))
            if revert and member is not None:
                try:
                    await member.remove_roles(*bad, reason="Sentinel Guard: revert dangerous role grant")
                    note += " (removed again)"
                except discord.HTTPException:
                    note += " (COULD NOT remove)"
            return note
        return None

    # ----------------------------------------------------------------- the engine

    async def _handle(self, ev: Event) -> None:
        guild = ev.guild
        cfg = await self.config(guild.id)
        panic = await lockdown_service.is_panic(guild.id)
        if not cfg["enabled"] and not panic:   # Panic Mode works even if AntiNuke is switched off
            return

        permission = permission_for_action(ev.label)
        if await is_exempt(guild, ev.actor_id, permission):
            if ev.label in STRUCTURAL:
                self.recovery.schedule_snapshot(guild)
            return

        key = (guild.id, ev.actor_id)
        now = time.monotonic()

        # An attacker that was already dealt with: wait for the punishment, then undo.
        if self._active_incident(key, now) is not None:
            await self._late_event(ev, cfg)
            return

        # Dangerous permission grants: first strike, reverted on the spot.
        if ev.label in ("role_update", "member_role_update") and ev.entry is not None:
            note = await self._guard_permissions(ev.entry, guild, ev.label)
            if note is not None:
                incident = await self._begin(key, cfg, now)
                if incident is None:
                    await self._late_event(ev, cfg)
                else:
                    await self._violation(ev, cfg, 1, [], incident, note=note)
                return
        if ev.label in NOT_COUNTED:
            return

        # Unauthorized bot / prune: first strike.
        if ev.label in INSTANT:
            incident = await self._begin(key, cfg, now)
            if incident is None:
                await self._late_event(ev, cfg)
                return
            is_bot = ev.label == "bot_add"
            await self._violation(
                ev, cfg, 1, [ev], incident,
                note="Unauthorized bot added." if is_bot else "Members were pruned.",
                bot_target=ev.target_id if is_bot else None,
            )
            return

        # Panic Mode: zero tolerance, the first unauthorized action is punished.
        if panic and ev.label not in PANIC_THRESHOLD_ONLY:
            incident = await self._begin(key, cfg, now)
            if incident is None:
                await self._late_event(ev, cfg)
                return
            await self._violation(ev, cfg, 1, [ev], incident, note=f"Panic Mode: unauthorized {ev.label}.")
            return

        # Everything else: threshold inside the time window.
        async with self.locks[key]:
            if self._active_incident(key, now) is not None:
                incident = None
                late = True
            else:
                late = False
                queue = self.events[key]
                queue.append((now, ev))
                while queue and now - queue[0][0] > cfg["window"]:
                    queue.popleft()
                count = len(queue)
                log.info(
                    "THRESHOLD_CHECK guild=%s actor=%s label=%s count=%s threshold=%s mode=%s",
                    guild.id, ev.actor_id, ev.label, count, cfg["threshold"], cfg["mode"],
                )
                if count < cfg["threshold"]:
                    return
                batch = [item for _, item in queue]
                queue.clear()
                # Mark the attacker NOW: events that arrive meanwhile wait for the punishment.
                incident = Incident(
                    started=now, mode=cfg["mode"],
                    ttl=ALERT_ONLY_TTL if cfg["mode"] == "alert" else PUNISHED_TTL,
                )
                self.incidents[key] = incident
        if late:
            await self._late_event(ev, cfg)
            return
        await self._violation(ev, cfg, count, batch, incident)

    def _active_incident(self, key, now: float) -> Incident | None:
        incident = self.incidents.get(key)
        if incident is not None and now - incident.started < incident.ttl:
            return incident
        return None

    async def _begin(self, key, cfg: dict, now: float) -> Incident | None:
        """Register an incident for first-strike actions. None if one is already active."""
        async with self.locks[key]:
            if self._active_incident(key, now) is not None:
                return None
            incident = Incident(
                started=now, mode=cfg["mode"],
                ttl=ALERT_ONLY_TTL if cfg["mode"] == "alert" else PUNISHED_TTL,
            )
            self.incidents[key] = incident
            return incident

    async def _late_event(self, ev: Event, cfg: dict) -> None:
        """The attacker was already punished (or is being punished): undo what they still do."""
        incident = self.incidents.get((ev.guild.id, ev.actor_id))
        if incident is None or incident.mode == "alert":
            return
        await incident.done.wait()   # punishment always comes first
        await self._recover(ev.guild, cfg, [ev], ev.actor_id)
        if ev.label == "bot_add" and ev.target_id:
            await self._remove_bot(ev.guild, ev.target_id, cfg["mode"], "Sentinel Guard: attacker added a bot")

    async def _violation(self, ev: Event, cfg: dict, count: int, batch: list[Event],
                         incident: Incident, note: str | None = None,
                         bot_target: int | None = None) -> Punishment | None:
        guild, actor_id, mode = ev.guild, ev.actor_id, cfg["mode"]
        reason = f"Sentinel Guard AntiNuke: {ev.label} x{count} in {cfg['window']}s"

        # Keep the last good snapshots: the server is about to be damaged.
        self.recovery.pause_snapshots(guild.id)

        punishment: Punishment | None = None
        notes: list[str] = [note] if note else []

        # 1) PUNISH FIRST. Nothing is recovered until this has finished.
        try:
            if mode != "alert":
                punishment = await self._punish(guild, actor_id, mode, reason)
                incident.punished = punishment.ok
                if not punishment.ok:
                    incident.ttl = FAILED_TTL
        finally:
            incident.done.set()   # events waiting behind the punishment may now recover

        # 2) RECOVER (and the other follow-up jobs) at the same time.
        failed = punishment is not None and not punishment.ok
        jobs: dict[str, Any] = {}
        if mode != "alert":
            jobs["recover"] = self._recover(guild, cfg, batch, actor_id)
            if bot_target:
                jobs["bot"] = self._remove_bot(guild, bot_target, mode, reason)
            actor_member = guild.get_member(actor_id)
            if actor_member is not None and actor_member.bot:
                jobs["adder"] = self._punish_adder(guild, actor_id, mode)
        if mode == "alert" or failed:
            jobs["lockdown"] = self._lockdown(
                guild, actor_id, f"AntiNuke: {ev.label} x{count} and the attacker was not removed"
            )

        outcomes = dict(zip(jobs, await asyncio.gather(*jobs.values(), return_exceptions=True)))

        summary = {"reverted": 0, "failed": 0, "irreversible": 0}
        recovered = outcomes.get("recover")
        if isinstance(recovered, dict):
            summary = recovered
        elif isinstance(recovered, BaseException):
            log.error("Recovery crashed: %r", recovered)
            notes.append("Recovery crashed; check the bot logs.")
        for name in ("bot", "adder"):
            if name in outcomes:
                notes.append(str(outcomes[name]))
        lockdown_text = str(outcomes["lockdown"]) if "lockdown" in outcomes else None

        action = "alert only" if punishment is None else f"{punishment.action}: {punishment.detail}"
        details = " | ".join(
            part for part in (
                f"{count} x {ev.label} by {actor_id} in {cfg['window']}s",
                f"mode={mode}",
                f"punishment={action}",
                f"recovery={summary}",
                *notes,
            ) if part
        )
        try:
            await self._incident(guild.id, actor_id, "antinuke_triggered", count, details)
        except Exception:
            log.exception("Could not record incident")
        await self._alert(guild, cfg, ev, count, punishment, summary, " | ".join(notes) or None, lockdown_text)
        return punishment

    async def panic_sweep(self, guild: discord.Guild, requested_by: int, minutes: int = SWEEP_MINUTES) -> dict:
        """Look through the recent audit log for attackers that are still active.

        Used by ``panic on``. An actor is flagged when they are not exempt AND did
        at least SWEEP_MIN_EVENTS structural actions, or one one-strike action
        (bot add, prune, dangerous permission grant), or as many bans/kicks as the
        normal threshold. Flagged actors are punished and their damage recovered
        exactly like in a live attack.
        """
        cfg = await self.config(guild.id)
        since = discord.utils.utcnow() - timedelta(minutes=minutes)
        self.recovery.pause_snapshots(guild.id)

        per_actor: dict[int, list[Event]] = defaultdict(list)
        reviewed = 0
        async for entry in guild.audit_logs(limit=200, after=since, oldest_first=False):
            label = TRACKED.get(entry.action)
            actor_id = entry.user_id
            if label is None or label in SWEEP_IGNORED or actor_id is None:
                continue
            if self.bot.user and actor_id == self.bot.user.id:
                continue
            reviewed += 1
            per_actor[actor_id].append(
                Event(guild, actor_id, label, getattr(entry.target, "id", None), entry=entry)
            )

        flagged: list[tuple[int, list[Event], str]] = []
        for actor_id, events in per_actor.items():
            # exempt only for the actions they were granted
            events = [e for e in events if not await is_exempt(guild, actor_id, permission_for_action(e.label))]
            if not events:
                continue
            hard = [e for e in events if e.label not in SWEEP_SOFT]
            soft = [e for e in events if e.label in SWEEP_SOFT]
            reason = None
            dangerous = False
            for e in events:
                if e.label in ("role_update", "member_role_update") and await self._guard_permissions(
                    e.entry, guild, e.label, revert=False
                ):
                    dangerous = True
                    break
            if any(e.label in INSTANT for e in events):
                reason = "one-strike action (bot add or prune)"
            elif dangerous:
                reason = "dangerous permission grant"
            elif len(hard) >= SWEEP_MIN_EVENTS:
                reason = f"{len(hard)} structural actions"
            elif len(soft) >= cfg["threshold"]:
                reason = f"{len(soft)} bans/kicks"
            if reason:
                flagged.append((actor_id, [e for e in events if e.label not in NOT_COUNTED], reason))

        async def punish(actor_id: int, events: list[Event], reason: str) -> bool:
            key = (guild.id, actor_id)
            incident = await self._begin(key, cfg, time.monotonic())
            if incident is None:          # already being handled
                return False
            first = events[0]
            result = await self._violation(
                first, cfg, len(events), events, incident,
                note=f"Panic sweep: {reason} in the last {minutes} minutes.",
            )
            return bool(result and result.ok)

        outcomes = await asyncio.gather(*(punish(*item) for item in flagged), return_exceptions=True)
        for outcome in outcomes:
            if isinstance(outcome, BaseException):
                log.error("Panic sweep failed for one actor: %r", outcome)
        await add_security_log(
            guild.id, "panic_sweep", f"reviewed={reviewed} flagged={len(flagged)} by={requested_by}", requested_by
        )
        return {
            "minutes": minutes,
            "events": reviewed,
            "actors": len(flagged),
            "punished": sum(1 for o in outcomes if o is True),
        }

    async def _punish_adder(self, guild, bot_id: int, mode: str) -> str:
        adder_id = await self._find_adder(guild, bot_id)
        if not adder_id or adder_id == self.bot.user.id:
            return "Could not find who added the attacker bot."
        if await is_exempt(guild, adder_id, "bot_add"):
            return f"The attacker bot was added by a trusted member (<@{adder_id}>); not punished."
        result = await self._punish(guild, adder_id, mode, f"Added attacker bot {bot_id}")
        return f"Bot adder <@{adder_id}>: {result.action} - {result.detail}"

    # ------------------------------------------------------------------ listeners

    @commands.Cog.listener()
    async def on_audit_log_entry_create(self, entry: discord.AuditLogEntry) -> None:
        label = TRACKED.get(entry.action)
        guild = entry.guild
        actor_id = entry.user_id
        if label is None or guild is None or actor_id is None:
            return
        if self.bot.user and actor_id == self.bot.user.id:
            return
        try:
            await self._handle(
                Event(guild, actor_id, label, getattr(entry.target, "id", None), entry=entry)
            )
        except Exception:
            log.exception("AntiNuke failed on %s by %s in guild %s", label, actor_id, guild.id)

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        if message.guild is None or message.webhook_id is not None:
            return
        if self.bot.user and message.author.id == self.bot.user.id:
            return
        mentions = len(message.mentions) + len(message.role_mentions)
        if not (message.mention_everyone or mentions >= MASS_MENTION_LIMIT):
            return
        try:
            await self._handle(Event(message.guild, message.author.id, "mass_mention", message.id, message=message))
        except Exception:
            log.exception("AntiNuke failed on mass mention in guild %s", message.guild.id)

    @commands.Cog.listener()
    async def on_member_unban(self, guild: discord.Guild, user: discord.User) -> None:
        await self._send_rejoin(guild, user, "you were unbanned")

    # ------------------------------------------------------------- rejoin invites

    async def _rejoin_enabled(self, guild_id: int) -> bool:
        row = await fetchone("SELECT enabled FROM antinuke_rejoin WHERE guild_id = ?", (guild_id,))
        return True if row is None else bool(row[0])

    @staticmethod
    def _invite_channel(guild):
        me = guild.me
        if me is None:
            return None
        for channel in (guild.system_channel, guild.rules_channel, *guild.text_channels):
            if channel is not None and channel.permissions_for(me).create_instant_invite:
                return channel
        return None

    async def _send_rejoin(self, guild, user, why: str) -> bool:
        """DM a one-time invite. Returns True if the DM was delivered."""
        if user is None or user.bot or not await self._rejoin_enabled(guild.id):
            return False
        channel = self._invite_channel(guild)
        if channel is None:
            return False
        try:
            invite = await channel.create_invite(
                max_age=7 * 24 * 3600, max_uses=1, unique=True,
                reason=f"Sentinel Guard: rejoin invite for {user.id}",
            )
        except discord.HTTPException:
            return False

        embed = discord.Embed(
            title=f"You can rejoin {guild.name}",
            description=f"Reason: {why}.\n\nJoin again: {invite.url}\nThis link works once and expires in 7 days.",
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
        except discord.HTTPException:
            pass

        log_channel_id = await get_log_channel(guild.id)
        log_channel = guild.get_channel(log_channel_id) if log_channel_id else None
        if isinstance(log_channel, discord.TextChannel):
            status = "Rejoin invite sent by DM" if delivered else "Could not DM (DMs closed)"
            try:
                await log_channel.send(f"{status}: <@{user.id}> (`{user.id}`)")
            except discord.HTTPException:
                pass
        await add_security_log(guild.id, "rejoin_invite", f"{'sent' if delivered else 'dm failed'} to {user.id}", user.id)
        return delivered

    # ----------------------------------------------------------------- responses

    async def _reply(self, ctx, kind: str, title: str, text: str | None = None, fields=()) -> None:
        palette = {
            "success": (discord.Color.green(), emoji("success")),
            "error": (discord.Color.red(), emoji("error")),
            "warning": (discord.Color.gold(), emoji("warning")),
            "info": (discord.Color.blurple(), emoji("stats")),
        }
        color, icon = palette[kind]
        embed = discord.Embed(title=f"{icon} {title}", description=text, color=color, timestamp=discord.utils.utcnow())
        for name, value, inline in fields:
            embed.add_field(name=name, value=value, inline=inline)
        await ctx.send(embed=embed, ephemeral=ctx.interaction is not None)

    async def _allowed(self, ctx) -> bool:
        """Only the Server Owner and Extra Owners may use AntiNuke commands."""
        if ctx.guild is None:
            return False
        if await can_manage_security(ctx.guild, ctx.author.id):
            return True
        await add_security_log(ctx.guild.id, "unauthorized_command", f"{ctx.command.qualified_name} denied", ctx.author.id)
        await self._reply(
            ctx, "error", "Not authorized",
            "Only the Server Owner or an Extra Owner can use this command.",
        )
        return False

    # ------------------------------------------------------------------- commands

    @commands.hybrid_group(name="antinuke", invoke_without_command=True, description="Anti-nuke protection")
    @commands.guild_only()
    async def antinuke(self, ctx: commands.Context) -> None:
        """Show the AntiNuke commands."""
        p = ctx.clean_prefix
        lines = [
            f"`{p}antinuke status` - current settings and health check",
            f"`{p}antinuke features` - everything that is protected",
            f"`{p}antinuke enable` / `{p}antinuke disable`",
            f"`{p}antinuke mode <alert|strip|kick|ban>`",
            f"`{p}antinuke threshold <count> <seconds>`",
            f"`{p}antinuke alertchannel [channel]`",
            f"`{p}antinuke recovery <on|off>`",
            f"`{p}antinuke snapshot` - save a recovery snapshot now",
            f"`{p}antinuke rejoin <on|off>`",
            f"`{p}antinuke incidents [limit]`",
        ]
        await self._reply(ctx, "info", "Anti-Nuke", "\n".join(lines))

    @antinuke.command(name="features", description="List everything AntiNuke protects")
    @commands.guild_only()
    async def features(self, ctx: commands.Context) -> None:
        cfg = await self.config(ctx.guild.id)
        await self._reply(
            ctx, "info", "Anti-Nuke protections",
            "\n".join(f"{emoji('success')} {item}" for item in FEATURES),
            fields=[("Current settings", f"Mode `{cfg['mode']}` | `{cfg['threshold']}` events in `{cfg['window']}s`", False)],
        )

    @antinuke.command(name="status", description="Show AntiNuke settings and health")
    @commands.guild_only()
    async def status(self, ctx: commands.Context) -> None:
        if not await self._allowed(ctx):
            return
        guild, cfg = ctx.guild, await self.config(ctx.guild.id)
        on, off = emoji("enabled"), emoji("disabled")
        fields = [
            ("Protection", f"{on} On" if cfg["enabled"] else f"{off} Off", True),
            ("Mode", f"`{cfg['mode']}`", True),
            ("Threshold", f"{cfg['threshold']} in {cfg['window']}s", True),
            ("Recovery", f"{on} On" if cfg["recovery"] else f"{off} Off", True),
            ("Alert channel", f"<#{cfg['alert']}>" if cfg["alert"] else "Log channel / not set", True),
            ("Punishment", MODES[cfg["mode"]], False),
        ]
        lock_state = await lockdown_service.status(guild)
        fields.append(("Panic Mode", f"{on} On" if lock_state["panic"]["active"] else f"{off} Off", True))
        fields.append(("Lockdown", f"{emoji('locked') or chr(0x1F512)} Locked" if lock_state["lockdown"]["active"] else "Off", True))
        snapshot = await self.recovery.latest_snapshot(guild.id)
        if snapshot:
            stamp = int(snapshot.get("taken_at", 0))
            fields.append(("Latest recovery snapshot",
                           f"<t:{stamp}:R> - {len(snapshot['channels'])} channels, {len(snapshot['roles'])} roles", False))
        else:
            fields.append(("Latest recovery snapshot", f"{emoji('warning')} None yet. Run `antinuke snapshot`.", False))

        problems = []
        if cfg["mode"] == "alert":
            problems.append("Mode is `alert`: attackers are not removed. Use `antinuke mode ban`.")
        missing = bot_missing_permissions(
            guild, "ban_members", "kick_members", "manage_roles", "manage_channels", "view_audit_log",
            "moderate_members", "manage_webhooks", "create_instant_invite",
        )
        if missing:
            problems.append("The bot is missing: " + ", ".join(f"`{m}`" for m in missing))
        me = guild.me
        if me is not None:
            above = [r.name for r in guild.roles if r > me.top_role and not r.is_default()]
            if above:
                problems.append("Roles above the bot cannot be punished: " + ", ".join(above[:5]))
        kind = "warning" if problems else "success"
        if problems:
            fields.append(("Problems found", "\n".join(f"{emoji('warning')} {p}" for p in problems)[:1000], False))
        await self._reply(ctx, kind, "Anti-Nuke status", None, fields)

    @antinuke.command(name="enable", description="Turn AntiNuke on")
    @commands.guild_only()
    async def enable(self, ctx: commands.Context) -> None:
        if not await self._allowed(ctx):
            return
        await self._update_config(ctx.guild.id, enabled=1)
        await add_security_log(ctx.guild.id, "antinuke_enabled", "", ctx.author.id)
        await self._reply(ctx, "success", "Anti-Nuke enabled", f"{emoji('enabled')} Protection is **ON**.")

    @antinuke.command(name="disable", description="Turn AntiNuke off")
    @commands.guild_only()
    async def disable(self, ctx: commands.Context) -> None:
        if not await self._allowed(ctx):
            return
        await self._update_config(ctx.guild.id, enabled=0)
        await add_security_log(ctx.guild.id, "antinuke_disabled", "", ctx.author.id)
        await self._reply(ctx, "warning", "Anti-Nuke disabled", f"{emoji('disabled')} Protection is **OFF**. The server is not protected.")

    @antinuke.command(name="mode", description="Choose the punishment: alert, strip, kick or ban")
    @commands.guild_only()
    async def mode(self, ctx: commands.Context, mode: Literal["alert", "strip", "kick", "ban"]) -> None:
        if not await self._allowed(ctx):
            return
        await self._update_config(ctx.guild.id, mode=mode)
        await add_security_log(ctx.guild.id, "antinuke_mode", mode, ctx.author.id)
        kind = "warning" if mode == "alert" else "success"
        await self._reply(ctx, kind, "Punishment mode updated", f"Mode is now `{mode}`.\n{MODES[mode]}")

    @antinuke.command(name="threshold", description="How many actions in how many seconds trigger a punishment")
    @commands.guild_only()
    async def threshold(self, ctx: commands.Context, count: int, window_seconds: int) -> None:
        if not await self._allowed(ctx):
            return
        if not 2 <= count <= 20 or not 3 <= window_seconds <= 60:
            await self._reply(ctx, "error", "Invalid values", "Count must be 2-20 and the window 3-60 seconds.")
            return
        await self._update_config(ctx.guild.id, threshold=count, window_seconds=window_seconds)
        await add_security_log(ctx.guild.id, "antinuke_threshold", f"{count}/{window_seconds}s", ctx.author.id)
        await self._reply(ctx, "success", "Threshold updated", f"`{count}` actions within `{window_seconds}` seconds trigger a punishment.")

    @antinuke.command(name="alertchannel", description="Where AntiNuke alerts are posted")
    @commands.guild_only()
    async def alertchannel(self, ctx: commands.Context, channel: discord.TextChannel | None = None) -> None:
        if not await self._allowed(ctx):
            return
        channel = channel or ctx.channel
        perms = channel.permissions_for(ctx.guild.me)
        if not (perms.view_channel and perms.send_messages and perms.embed_links):
            await self._reply(ctx, "error", "Cannot use that channel", "The bot needs View Channel, Send Messages and Embed Links there.")
            return
        await self._update_config(ctx.guild.id, alert_channel_id=channel.id)
        await add_security_log(ctx.guild.id, "antinuke_alertchannel", str(channel.id), ctx.author.id)
        await self._reply(ctx, "success", "Alert channel set", f"Alerts will be posted in {channel.mention}.")

    @antinuke.command(name="recovery", description="Turn automatic recovery on or off")
    @commands.guild_only()
    async def recovery(self, ctx: commands.Context, state: Literal["on", "off"]) -> None:
        if not await self._allowed(ctx):
            return
        await self._update_config(ctx.guild.id, recovery_enabled=1 if state == "on" else 0)
        await add_security_log(ctx.guild.id, "antinuke_recovery", state, ctx.author.id)
        if state == "on":
            await self._reply(ctx, "success", "Recovery enabled", f"{emoji('enabled')} Damage is repaired automatically after a punishment.")
        else:
            await self._reply(ctx, "warning", "Recovery disabled", f"{emoji('disabled')} Attackers are punished but damage is NOT repaired.")

    @antinuke.command(name="snapshot", description="Save a recovery snapshot of the server now")
    @commands.guild_only()
    async def snapshot(self, ctx: commands.Context) -> None:
        if not await self._allowed(ctx):
            return
        await ctx.defer(ephemeral=ctx.interaction is not None)
        saved = await self.recovery.capture_snapshot(ctx.guild, f"manual by {ctx.author.id}", force=True)
        data = await self.recovery.latest_snapshot(ctx.guild.id)
        if saved and data:
            await add_security_log(ctx.guild.id, "snapshot_manual", "", ctx.author.id)
            await self._reply(
                ctx, "success", "Snapshot saved",
                f"{len(data['channels'])} channels and {len(data['roles'])} roles are now recoverable.",
            )
        else:
            await self._reply(ctx, "error", "Snapshot failed", "Nothing was saved. Check the bot logs.")

    @antinuke.command(name="rejoin", description="Send a rejoin invite by DM when someone is unbanned")
    @commands.guild_only()
    async def rejoin(self, ctx: commands.Context, state: Literal["on", "off"]) -> None:
        if not await self._allowed(ctx):
            return
        await execute(
            "INSERT INTO antinuke_rejoin (guild_id, enabled) VALUES (?, ?) "
            "ON CONFLICT(guild_id) DO UPDATE SET enabled = excluded.enabled",
            (ctx.guild.id, 1 if state == "on" else 0),
        )
        await add_security_log(ctx.guild.id, "antinuke_rejoin", state, ctx.author.id)
        await self._reply(ctx, "success", "Rejoin invites", f"Rejoin invites are now **{state}**.")

    @antinuke.command(name="incidents", description="Recent AntiNuke incidents")
    @commands.guild_only()
    async def incidents(self, ctx: commands.Context, limit: int = 10) -> None:
        if not await self._allowed(ctx):
            return
        if not 1 <= limit <= 15:
            await self._reply(ctx, "error", "Invalid limit", "Choose a number from 1 to 15.")
            return
        rows = await fetchall(
            "SELECT actor_id, action, event_count, details, created_at FROM antinuke_incidents "
            "WHERE guild_id = ? ORDER BY id DESC LIMIT ?",
            (ctx.guild.id, limit),
        )
        if not rows:
            await self._reply(ctx, "info", "No incidents", "Nothing has been recorded yet.")
            return
        lines = [
            f"**{row['created_at']}** <@{row['actor_id']}> `{row['action']}` x{row['event_count']}\n{str(row['details'])[:140]}"
            for row in rows
        ]
        await self._reply(ctx, "info", "Recent incidents", "\n\n".join(lines)[:4000])


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(AntiNuke(bot))
