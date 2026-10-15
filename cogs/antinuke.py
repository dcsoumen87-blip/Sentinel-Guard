import asyncio, logging, time
from collections import defaultdict, deque
import discord, aiosqlite
from discord.ext import commands
from config import DB_PATH
from database.db import add_security_log

log = logging.getLogger("sentinel_guard.antinuke")
class AntiNuke(commands.Cog):
    def __init__(self, bot):
        self.bot=bot; self.events=defaultdict(deque); self.cooldowns={}; self.processed={}; self.locks=defaultdict(asyncio.Lock)

    async def config(self,gid):
        async with aiosqlite.connect(DB_PATH) as db:
            cur=await db.execute("SELECT enabled,threshold,window_seconds,alert_channel_id,mode FROM antinuke_config WHERE guild_id=?",(gid,))
            r=await cur.fetchone()
            if r:return {"enabled":bool(r[0]),"threshold":r[1],"window":r[2],"alert":r[3],"mode":r[4]}
            await db.execute("INSERT OR IGNORE INTO antinuke_config(guild_id) VALUES(?)",(gid,)); await db.commit()
        return {"enabled":True,"threshold":4,"window":10,"alert":None,"mode":"alert"}

    async def incident(self,gid,actor,action,count,details):
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("INSERT INTO antinuke_incidents(guild_id,actor_id,action,event_count,details) VALUES(?,?,?,?,?)",(gid,actor,action,count,details[:1500])); await db.commit()
        await add_security_log(gid,action,details,actor)

    async def whitelisted(self,gid,uid):
        async with aiosqlite.connect(DB_PATH) as db:
            cur=await db.execute("SELECT 1 FROM antinuke_whitelist WHERE guild_id=? AND user_id=?",(gid,uid))
            return await cur.fetchone() is not None

    async def find_actor(self,guild,channel_id,audit_action):
        for attempt in range(5):
            try:
                async for entry in guild.audit_logs(limit=25,action=audit_action):
                    if getattr(entry.target,"id",None)!=channel_id: continue
                    age=(discord.utils.utcnow()-entry.created_at).total_seconds()
                    if not -2<=age<=30: continue
                    key=(guild.id,entry.id)
                    if key in self.processed: return None,None
                    self.processed[key]=time.monotonic()
                    return entry.user,entry
            except discord.Forbidden:
                log.error("AUDIT_FORBIDDEN guild=%s: grant View Audit Log",guild.id); return None,None
            except discord.HTTPException as exc:
                log.warning("AUDIT_HTTP_ERROR guild=%s attempt=%s error=%r",guild.id,attempt+1,exc)
            if attempt<4: await asyncio.sleep(.7)
        log.warning("AUDIT_ACTOR_UNKNOWN guild=%s channel=%s",guild.id,channel_id)
        return None,None

    async def alert(self,guild,cfg,actor,label,count,channel_name):
        if not cfg["alert"]:
            log.warning("ALERT_NOT_CONFIGURED guild=%s actor=%s count=%s",guild.id,actor.id,count); return
        ch=guild.get_channel(cfg["alert"])
        if not isinstance(ch,discord.TextChannel):
            log.error("ALERT_CHANNEL_MISSING guild=%s id=%s",guild.id,cfg["alert"]); return
        e=discord.Embed(title="🚨 Sentinel Guard | Anti-Nuke Alert",description="Rapid channel activity reached the configured threshold.",color=discord.Color.red(),timestamp=discord.utils.utcnow())
        e.add_field(name="Actor",value=f"{actor.mention} (`{actor.id}`)",inline=False)
        e.add_field(name="Activity",value=label,inline=True); e.add_field(name="Events",value=f"{count} in {cfg['window']} seconds",inline=True)
        e.add_field(name="Channel",value=f"`{channel_name[:100]}`",inline=False)
        try:
            await ch.send(embed=e); log.warning("ALERT_SENT guild=%s actor=%s count=%s",guild.id,actor.id,count)
        except discord.Forbidden: log.error("ALERT_FORBIDDEN guild=%s channel=%s",guild.id,ch.id)
        except discord.HTTPException as exc: log.error("ALERT_HTTP_ERROR guild=%s error=%r",guild.id,exc)

    async def process(self,ch,label,audit_action):
        g=ch.guild; log.info("CHANNEL_EVENT guild=%s id=%s action=%s",g.id,ch.id,label)
        cfg=await self.config(g.id)
        if not cfg["enabled"]: return
        actor,entry=await self.find_actor(g,ch.id,audit_action)
        if actor is None or entry is None:
            await self.incident(g.id,None,"actor_unverified",1,f"Actor unverified for {label}, channel={ch.id}")
            return
        if self.bot.user and actor.id==self.bot.user.id: return
        if await self.whitelisted(g.id,actor.id): return
        now=time.monotonic(); key=(g.id,actor.id)
        async with self.locks[key]:
            q=self.events[key]; q.append((now,label))
            while q and now-q[0][0]>cfg["window"]: q.popleft()
            count=len(q)
            log.info("THRESHOLD_CHECK guild=%s actor=%s count=%s threshold=%s",g.id,actor.id,count,cfg["threshold"])
            if count<cfg["threshold"] or now-self.cooldowns.get(key,0)<30:return
            self.cooldowns[key]=now
        await self.incident(g.id,actor.id,"channel_activity_threshold",count,f"{count} channel events by {actor.id} within {cfg['window']} seconds")
        await self.alert(g,cfg,actor,label,count,ch.name)
        # Safe default: alert-only. No automated punishment in this build.

    @commands.Cog.listener()
    async def on_guild_channel_create(self,ch): await self.process(ch,"channel_create",discord.AuditLogAction.channel_create)
    @commands.Cog.listener()
    async def on_guild_channel_delete(self,ch): await self.process(ch,"channel_delete",discord.AuditLogAction.channel_delete)

    @commands.hybrid_group(name="antinuke",invoke_without_command=True)
    @commands.guild_only()
    async def antinuke(self,ctx): await ctx.send("Use `/antinuke status`.",ephemeral=ctx.interaction is not None)

    @antinuke.command(name="status")
    @commands.guild_only()
    async def status(self,ctx):
        c=await self.config(ctx.guild.id); e=discord.Embed(title="🛡️ Anti-Nuke Status",color=discord.Color.green())
        e.add_field(name="Enabled",value=str(c["enabled"]),inline=True); e.add_field(name="Threshold",value=str(c["threshold"]),inline=True)
        e.add_field(name="Window",value=f"{c['window']}s",inline=True); e.add_field(name="Alerts",value=f"<#{c['alert']}>" if c["alert"] else "Not configured",inline=False)
        await ctx.send(embed=e,ephemeral=ctx.interaction is not None)

    @antinuke.command(name="setup")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def setup(self,ctx):
        await self.config(ctx.guild.id)
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("UPDATE antinuke_config SET enabled=1 WHERE guild_id=?",(ctx.guild.id,)); await db.commit()
        await ctx.send("✅ Monitoring enabled. Alert-only response.",ephemeral=ctx.interaction is not None)

    @antinuke.command(name="alertchannel")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def alertchannel(self,ctx,channel:discord.TextChannel=None):
        channel=channel or ctx.channel; p=channel.permissions_for(ctx.guild.me)
        if not p.send_messages or not p.embed_links:
            await ctx.send("Bot needs Send Messages and Embed Links there.",ephemeral=ctx.interaction is not None); return
        await self.config(ctx.guild.id)
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("UPDATE antinuke_config SET alert_channel_id=? WHERE guild_id=?",(channel.id,ctx.guild.id)); await db.commit()
        await ctx.send(f"✅ Alerts set to {channel.mention}.",ephemeral=ctx.interaction is not None)

    @antinuke.command(name="threshold")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def threshold(self,ctx,count:int,window_seconds:int):
        if not 2<=count<=20 or not 3<=window_seconds<=60:
            await ctx.send("Count must be 2–20; window 3–60 seconds.",ephemeral=ctx.interaction is not None); return
        await self.config(ctx.guild.id)
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("UPDATE antinuke_config SET threshold=?,window_seconds=? WHERE guild_id=?",(count,window_seconds,ctx.guild.id)); await db.commit()
        await ctx.send(f"✅ Threshold set to {count} / {window_seconds}s.",ephemeral=ctx.interaction is not None)

    @antinuke.command(name="whitelist-add")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def whitelist_add(self,ctx,member:discord.Member):
        await self.config(ctx.guild.id)
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("INSERT OR IGNORE INTO antinuke_whitelist(guild_id,user_id) VALUES(?,?)",(ctx.guild.id,member.id)); await db.commit()
        await ctx.send(f"✅ {member.mention} whitelisted.",ephemeral=ctx.interaction is not None)

    @antinuke.command(name="whitelist-remove")
    @commands.guild_only()
    @commands.has_guild_permissions(manage_guild=True)
    async def whitelist_remove(self,ctx,member:discord.Member):
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("DELETE FROM antinuke_whitelist WHERE guild_id=? AND user_id=?",(ctx.guild.id,member.id)); await db.commit()
        await ctx.send(f"✅ {member.mention} removed from whitelist.",ephemeral=ctx.interaction is not None)

async def setup(bot): await bot.add_cog(AntiNuke(bot))
