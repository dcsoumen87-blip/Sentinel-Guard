# 🛡️ Sentinel Guard — Level 7 Security Architecture

A defensive Discord security bot project using Python, `discord.py`, SQLite/`aiosqlite`, and `.env` secrets. Security rules are hard-coded in Python; SQLite persists guild configuration, security events, whitelist records, warnings, and recovery snapshots metadata where implemented.

> **Status honesty:** this is a feature-rich architecture build, not an independently audited enterprise product. Python syntax compilation is not the same as live Discord integration testing. Test in a private server first.

## Included in this build
- Slash + prefix hybrid command framework and premium-style interactive Help dashboard.
- Idempotent `/security_setup`: creates Sentinel Developer/Owner/Admin/Moderator/Trusted/Member roles, `Sentinel Security` category, `#sentinel-logs`, and assigns the basic role to existing/new human members where permissions allow.
- `/devroleclaim`: only the exact `DEVELOPER_ID` in `.env` can explicitly enable Administrator on `Sentinel Developer` and claim it. Keep the bot's top role above it. This is intentionally high privilege.
- Anti-Nuke monitoring for channel create/delete with audit evidence and alerts; join-spike Anti-Raid alerts; heuristic AutoMod; moderation commands.
- `/recovery_status`: database/backup/setup drift health report.
- `/recovery_backup`: consistent SQLite snapshot using SQLite's backup API.
- Startup recovery check (`PRAGMA quick_check`) and automatic local snapshot. Keeps up to 10 newest local snapshots.
- Ubuntu EC2 systemd example, structured logging, and environment-based secrets.

## Recovery scope and limits
- Restart recovery reopens the persistent SQLite state and checks database integrity at startup.
- Backups are local snapshots in `$DATA_DIR/backups`; copy them to a separate host/storage location for disaster recovery.
- The bot does **not** automatically overwrite a possibly damaged live database. Inspect and restore deliberately after stopping the bot and preserving a copy of the damaged file.
- Deleted Discord channels/messages cannot be recreated exactly without prior saved configuration/content. Nuke recovery is not equivalent to database restart recovery.
- The current version does not yet implement every planned Level 7 feature: full Anti-Nuke audit-event coverage, durable event counters, full verification-based Raid Mode, complete tempban/unban/warning management, resumable large-server role assignment, automated off-host backup, and full integration/load tests.

## Install and configure
1. Upload the ZIP contents to the private GitHub repository. **Do not upload `.env` or a bot token.**
2. Use Python 3.13/3.14 only after verifying all dependencies on the selected host.
3. Install dependencies: `python -m pip install -r requirements.txt`
4. Copy `.env.example` to `.env`, then set `DISCORD_TOKEN`, numeric `DEVELOPER_ID`, `DEFAULT_PREFIX`, and `DATA_DIR`.
5. In Discord Developer Portal enable **Server Members Intent** and **Message Content Intent** (the bot uses member join and message-based features).
6. Invite with required permissions: View Audit Log, Manage Roles, Manage Channels, Manage Messages, Moderate Members, Kick/Ban Members, Send Messages, Embed Links, Read Message History. Keep the bot's role above all roles it needs to manage.
7. Run `python main.py` and check logs. In a private test server run `/security_setup`, `/recovery_status`, and `/recovery_backup`.
8. Run `/devroleclaim` only if you deliberately want the verified developer account's role to have Administrator permission.

## EC2 notes
- Use a dedicated non-root Linux user and persistent `$DATA_DIR` (example `/opt/sentinel-guard/data`).
- Restrict filesystem permissions; keep `.env` outside Git and readable only by the service user.
- Review `deploy/sentinel-guard.service`, set the correct paths/user, then enable systemd restart-on-failure.
- Verify backups and restore procedure on a separate test copy. Monitor AWS costs and disk usage.

## Defensive policy
The current Anti-Nuke/Anti-Raid behavior is alert/evidence-first. It does not mass-ban users or destructively alter a server automatically. A bot's ability to ban/manage roles depends on Discord permissions and role hierarchy. Account age and heuristics are signals, not proof.

## Developer System Monitor

Install dependencies with `pip install -r requirements.txt`. The `psutil` package is used for host metrics.

Developer-only prefix commands (the examples use `!`; use the configured guild prefix if changed):

- `!devhelp` — developer command list
- `!devsystem` — CPU model/usage/cores, host RAM, process RSS/CPU, disk, network counters, OS, Python, discord.py, SQLite size, gateway latency and restart count
- `!devcpu`, `!devram`, `!devdisk`, `!devnetwork` — focused resource reports
- `!devhealth`, `!devinfo`, `!devstats`, `!devuptime`, `!devversion`, `!devservers`, `!devsetup`, `!devrecovery`, `!devbackup`, `!devlogs`
- `!devroleclaim` — privileged role claim. For safety, this build requires the configured developer to also be the server owner; Discord role hierarchy and Manage Roles permissions still apply.
- `!devreload <extension>` — reloads only allow-listed extensions.

`DEVELOPER_ID` must be a numeric Discord user ID in `.env`. Metrics refer to the machine hosting the bot (such as the EC2 instance), not the Android phone. CPU model reporting may be unavailable in some containers/virtual machines. Network figures are cumulative host counters, not per-bot traffic. Maintenance toggle is intentionally reported as not implemented rather than pretending to change state.
