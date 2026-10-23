import json, os, sqlite3, threading, time, urllib.request
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI
from fastapi.responses import FileResponse

LOG = os.environ.get("COWRIE_LOG", "/home/cowrie/cowrie/var/log/cowrie/cowrie.json")
DB = os.environ.get("DASH_DB", "/opt/dash/dash.db")
HERE = os.path.dirname(os.path.abspath(__file__))
KEEP = {"cowrie.session.connect", "cowrie.login.success", "cowrie.login.failed",
        "cowrie.command.input", "cowrie.client.kex"}
LOGIN = "eventid IN ('cowrie.login.success','cowrie.login.failed')"


def db():
    c = sqlite3.connect(DB, timeout=30)
    c.row_factory = sqlite3.Row
    return c


def init():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS events(ts TEXT, session TEXT, ip TEXT, eventid TEXT,
        username TEXT, password TEXT, input TEXT, hassh TEXT);
    CREATE INDEX IF NOT EXISTS ev_ts ON events(ts);
    CREATE INDEX IF NOT EXISTS ev_ip ON events(ip);
    CREATE TABLE IF NOT EXISTS geo(ip TEXT PRIMARY KEY, lat REAL, lon REAL, country TEXT);
    CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);""")
    c.commit()
    c.close()


def ingest():
    c = db()
    row = c.execute("SELECT v FROM meta WHERE k='offset'").fetchone()
    off = int(row["v"]) if row else 0
    try:
        if os.path.getsize(LOG) < off:  # log rotated
            off = 0
        with open(LOG, "rb") as f:
            f.seek(off)
            data = f.read()
    except OSError:
        c.close()
        return
    end = data.rfind(b"\n")
    if end >= 0:
        rows = []
        for line in data[:end].splitlines():
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("eventid") in KEEP:
                rows.append((e.get("timestamp"), e.get("session"), e.get("src_ip"), e["eventid"],
                             e.get("username"), e.get("password"),
                             (e.get("input") or "")[:300] or None, e.get("hassh")))
        c.executemany("INSERT INTO events VALUES (?,?,?,?,?,?,?,?)", rows)
        c.execute("INSERT OR REPLACE INTO meta VALUES ('offset', ?)", (str(off + end + 1),))
        c.commit()
    c.close()


def geolocate():
    c = db()
    ips = [r[0] for r in c.execute(
        "SELECT DISTINCT ip FROM events WHERE ip NOT IN (SELECT ip FROM geo) LIMIT 100")]
    if ips:
        body = json.dumps([{"query": ip, "fields": "status,query,lat,lon,country"} for ip in ips]).encode()
        try:
            req = urllib.request.Request("http://ip-api.com/batch", body,
                                         {"Content-Type": "application/json"})
            res = json.load(urllib.request.urlopen(req, timeout=20))
        except Exception:
            res = []
        for r in res:
            ok = r.get("status") == "success"
            c.execute("INSERT OR REPLACE INTO geo VALUES (?,?,?,?)",
                      (r.get("query"), r.get("lat") if ok else None,
                       r.get("lon") if ok else None, r.get("country") if ok else None))
        c.commit()
    c.close()


def worker():
    n = 0
    while True:
        try:
            ingest()
            if n % 3 == 0:  # ip-api free tier allows 15 batch calls/min
                geolocate()
        except Exception as e:
            print("worker error:", e)
        n += 1
        time.sleep(5)


@asynccontextmanager
async def lifespan(app):
    init()
    threading.Thread(target=worker, daemon=True).start()
    yield


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)


@app.get("/")
def index():
    return FileResponse(os.path.join(HERE, "index.html"))


@app.get("/api/summary")
def summary():
    c = db()
    q = lambda s, *a: [dict(r) for r in c.execute(s, a)]
    since = (datetime.now(timezone.utc) - timedelta(hours=48)).strftime("%Y-%m-%dT%H")
    top = lambda col: q(f"SELECT {col} AS k, COUNT(*) AS n FROM events WHERE {LOGIN} "
                        f"AND {col} IS NOT NULL GROUP BY {col} ORDER BY n DESC LIMIT 10")
    out = {
        "totals": dict(c.execute(
            f"SELECT COUNT(*) AS attempts, COUNT(DISTINCT ip) AS ips, "
            f"(SELECT COUNT(*) FROM events WHERE eventid='cowrie.command.input') AS commands "
            f"FROM events WHERE {LOGIN}").fetchone()),
        "hourly": q(f"SELECT substr(ts,1,13) AS k, COUNT(*) AS n FROM events "
                    f"WHERE {LOGIN} AND ts >= ? GROUP BY k ORDER BY k", since),
        "users": top("username"),
        "passwords": top("password"),
        "countries": q(f"SELECT g.country AS k, COUNT(*) AS n FROM events e JOIN geo g ON g.ip=e.ip "
                       f"WHERE e.{LOGIN} AND g.country IS NOT NULL GROUP BY g.country "
                       f"ORDER BY n DESC LIMIT 10"),
        "commands": q("SELECT substr(input,1,90) AS k, COUNT(*) AS n FROM events "
                      "WHERE eventid='cowrie.command.input' GROUP BY k ORDER BY n DESC LIMIT 10"),
        "tools": q("SELECT hassh AS k, COUNT(DISTINCT ip) AS ips, COUNT(*) AS n FROM events "
                   "WHERE eventid='cowrie.client.kex' AND hassh IS NOT NULL "
                   "GROUP BY hassh ORDER BY n DESC LIMIT 8"),
        "map": q(f"SELECT e.ip, g.lat, g.lon, g.country, COUNT(*) AS n FROM events e "
                 f"JOIN geo g ON g.ip=e.ip WHERE g.lat IS NOT NULL AND e.{LOGIN} GROUP BY e.ip"),
        "recent": q(f"SELECT e.ts, e.ip, e.username, e.password, g.country FROM events e "
                    f"LEFT JOIN geo g ON g.ip=e.ip WHERE e.{LOGIN} ORDER BY e.ts DESC LIMIT 20"),
    }
    c.close()
    return out
@app.get("/api/live")
def live(after: int = 0):
    c = db()

    latest = c.execute(
        "SELECT COALESCE(MAX(rowid), 0) FROM events"
    ).fetchone()[0]

    rows = [dict(r) for r in c.execute("""
        SELECT
            e.rowid AS id,
            e.ts,
            e.ip,
            e.eventid,
            e.username,
            g.country,
            g.lat,
            g.lon
        FROM events e
        LEFT JOIN geo g ON e.ip = g.ip
        WHERE e.rowid > ?
          AND e.eventid IN (
              'cowrie.session.connect',
              'cowrie.login.failed',
              'cowrie.login.success'
          )
        ORDER BY e.rowid ASC
        LIMIT 100
    """, (max(0, after),))]

    c.close()
    return {"latest": latest, "events": rows}

# IP Investigation API

from fastapi import Query
from fastapi.responses import JSONResponse
import ipaddress

@app.get("/api/ips")
def search_ips(
    search: str = Query(default="", max_length=100),
    limit: int = Query(default=50, ge=1, le=200)
):
    c = db()
    try:
        rows = c.execute("""
            SELECT e.ip,
                   COALESCE(g.country, 'Unknown') AS country,
                   COUNT(*) AS events,
                   SUM(CASE WHEN e.eventid IN (
                       'cowrie.login.success',
                       'cowrie.login.failed'
                   ) THEN 1 ELSE 0 END) AS attempts,
                   MAX(e.ts) AS last_seen
            FROM events e
            LEFT JOIN geo g ON g.ip = e.ip
            WHERE e.ip IS NOT NULL
              AND (e.ip LIKE ? OR g.country LIKE ?)
            GROUP BY e.ip
            ORDER BY attempts DESC, events DESC
            LIMIT ?
        """, (f"%{search}%", f"%{search}%", limit)).fetchall()

        return {"ips": [dict(r) for r in rows]}
    finally:
        c.close()


@app.get("/api/ip/{ip}")
def investigate_ip(ip: str):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return JSONResponse(
            {"error": "Invalid IP address"},
            status_code=400
        )

    c = db()
    try:
        geo = c.execute(
            "SELECT * FROM geo WHERE ip = ?", (ip,)
        ).fetchone()

        events = c.execute("""
            SELECT ts, session, eventid,
                   username, password, input, hassh
            FROM events
            WHERE ip = ?
            ORDER BY ts DESC, rowid DESC
            LIMIT 500
        """, (ip,)).fetchall()

        return {
            "ip": ip,
            "geo": dict(geo) if geo else None,
            "events": [dict(r) for r in events]
        }
    finally:
        c.close()
