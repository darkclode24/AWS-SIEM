"""
cowrie-dashboard-exporter

Runs hourly (EventBridge schedule). Reads Cowrie events from CloudWatch Logs
Insights, geolocates source IPs via ip-api.com, and writes three public
JSON documents to an S3 bucket that fronts the static attack dashboard:

  meta.json     - { first_data_date, generated_at }  (drives the range picker)
  live.json     - rich last-24h view (globe points, top lists, recent ticker)
  archive.json  - compact per-day aggregates, all-time (default + custom ranges)

Environment variables:
  COWRIE_LOG_GROUP   CloudWatch log group to query      (default /honeypot/cowrie)
  DASHBOARD_BUCKET   S3 bucket that stores the JSON      (required)
  GEOIP_ENABLED      "true"/"false" kill-switch for geo  (default true)
  GEOIP_ENDPOINT     ip-api batch endpoint               (default http://ip-api.com/batch)

Invoking with {"backfill": ["2026-07-29", ...]} rebuilds those UTC day
buckets in archive.json instead of running the normal hourly export.
"""

import json
import os
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta

import boto3

logs = boto3.client("logs")
s3 = boto3.client("s3")

LOG_GROUP = os.environ.get("COWRIE_LOG_GROUP", "/honeypot/cowrie")
BUCKET = os.environ.get("DASHBOARD_BUCKET", "")
GEOIP_ENABLED = os.environ.get("GEOIP_ENABLED", "true").lower() == "true"
GEOIP_ENDPOINT = os.environ.get("GEOIP_ENDPOINT", "http://ip-api.com/batch")

LIVE_WINDOW_HOURS = 24
GEOIP_MAX_IPS = 300
GEOIP_BATCH = 100
QUERY_POLL_INTERVAL = 1.0
QUERY_TIMEOUT = 50  # seconds, keep under the Lambda timeout


# --------------------------------------------------------------------------
# CloudWatch Logs Insights helpers
# --------------------------------------------------------------------------

def run_query(query, start_dt, end_dt):
    """Run a Logs Insights query and return rows as list[dict]."""
    start = int(start_dt.timestamp())
    end = int(end_dt.timestamp())
    query_id = logs.start_query(
        logGroupName=LOG_GROUP,
        startTime=start,
        endTime=end,
        queryString=query,
    )["queryId"]

    deadline = time.time() + QUERY_TIMEOUT
    while True:
        resp = logs.get_query_results(queryId=query_id)
        status = resp.get("status")
        if status == "Complete":
            return [
                {item["field"]: item.get("value", "") for item in row}
                for row in resp.get("results", [])
            ]
        if status in ("Failed", "Cancelled", "Timeout"):
            raise RuntimeError(f"Logs Insights query {status}: {query_id}")
        if time.time() > deadline:
            raise RuntimeError(f"Logs Insights query timed out: {query_id}")
        time.sleep(QUERY_POLL_INTERVAL)


def first_data_date():
    """Earliest event timestamp in the log group (ISO date), or None."""
    rows = run_query(
        "stats min(@timestamp) as first_ts",
        datetime.now(timezone.utc) - timedelta(days=3650),
        datetime.now(timezone.utc),
    )
    if not rows or "first_ts" not in rows[0]:
        return None
    raw = str(rows[0]["first_ts"]).strip()
    # Logs Insights may return epoch millis or a "YYYY-MM-DD HH:MM:SS.mmm" string.
    try:
        ts = float(raw) / 1000.0
        return datetime.fromtimestamp(ts, tz=timezone.utc).date().isoformat()
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(raw, fmt).date().isoformat()
        except ValueError:
            continue
    return raw[:10] if len(raw) >= 10 else None


# --------------------------------------------------------------------------
# GeoIP (ip-api.com batch)
# --------------------------------------------------------------------------

def geolocate(ips):
    """Return {ip: {country, code, lat, lon}} for a list of IPs."""
    if not GEOIP_ENABLED or not ips:
        return {}
    result = {}
    ips = ips[:GEOIP_MAX_IPS]
    for i in range(0, len(ips), GEOIP_BATCH):
        chunk = ips[i:i + GEOIP_BATCH]
        body = json.dumps(chunk).encode("utf-8")
        url = GEOIP_ENDPOINT + "?fields=status,query,country,countryCode,lat,lon"
        req = urllib.request.Request(
            url, data=body, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, ValueError, TimeoutError):
            continue
        for item in data:
            if item.get("status") != "success":
                continue
            result[item["query"]] = {
                "country": item.get("country", ""),
                "code": item.get("countryCode", ""),
                "lat": item.get("lat"),
                "lon": item.get("lon"),
            }
    return result


# --------------------------------------------------------------------------
# S3 helpers
# --------------------------------------------------------------------------

def put_json(key, obj):
    s3.put_object(
        Bucket=BUCKET,
        Key=key,
        Body=json.dumps(obj).encode("utf-8"),
        ContentType="application/json",
        CacheControl="max-age=60",
    )


def get_json(key):
    try:
        resp = s3.get_object(Bucket=BUCKET, Key=key)
        return json.loads(resp["Body"].read().decode("utf-8"))
    except Exception:
        return None


# --------------------------------------------------------------------------
# Query strings
# --------------------------------------------------------------------------

def display_name(field, value):
    """Uploaded file names land as cowrie storage paths; show the basename."""
    if field == "outfile" and value:
        return value.rsplit("/", 1)[-1]
    return value


Q_TOTALS_TIMELINE = """
filter ispresent(eventid)
| stats
    sum(eventid = "cowrie.session.connect") as connections,
    sum(eventid = "cowrie.login.failed" or eventid = "cowrie.login.success") as auth,
    sum(eventid = "cowrie.command.input") as commands,
    sum(eventid = "cowrie.session.file_download") as downloads,
    sum(eventid = "cowrie.session.file_upload") as uploads,
    count_distinct(src_ip) as unique_ips,
    count_distinct(session) as unique_sessions
  by bin(1h) as t
| sort t asc
"""

Q_TOP_IPS = """
filter ispresent(src_ip)
| stats count(*) as count by src_ip
| sort count desc
| limit 25
"""

Q_TOP_FIELD = {
    "usernames": 'filter ispresent(username) | filter eventid = "cowrie.login.failed" or eventid = "cowrie.login.success" | stats count(*) as count by username | sort count desc | limit 10',
    "passwords": 'filter ispresent(password) | filter eventid = "cowrie.login.failed" or eventid = "cowrie.login.success" | stats count(*) as count by password | sort count desc | limit 10',
    "commands":  'filter eventid = "cowrie.command.input" | filter ispresent(input) | stats count(*) as count by input | sort count desc | limit 15',
    "downloads": 'filter eventid = "cowrie.session.file_download" | filter ispresent(url) | stats count(*) as count by url | sort count desc | limit 10',
    "uploads":   'filter eventid = "cowrie.session.file_upload" | filter ispresent(outfile) | stats count(*) as count by outfile | sort count desc | limit 10',
}

Q_RECENT = """
fields @timestamp, eventid, src_ip, username, password, input
| filter eventid = "cowrie.login.failed"
      or eventid = "cowrie.login.success"
      or eventid = "cowrie.command.input"
      or eventid = "cowrie.session.file_download"
      or eventid = "cowrie.session.file_upload"
| sort @timestamp desc
| limit 20
"""

Q_DAY_COUNTRIES = """
filter ispresent(src_ip)
| stats count(*) as count by src_ip
| sort count desc
| limit 60
"""

Q_DAY_FIELD = {
    "usernames": 'filter ispresent(username) | filter eventid = "cowrie.login.failed" or eventid = "cowrie.login.success" | stats count(*) as count by username | sort count desc | limit 10',
    "commands":  'filter eventid = "cowrie.command.input" | filter ispresent(input) | stats count(*) as count by input | sort count desc | limit 10',
    "downloads": 'filter eventid = "cowrie.session.file_download" | filter ispresent(url) | stats count(*) as count by url | sort count desc | limit 10',
    "uploads":   'filter eventid = "cowrie.session.file_upload" | filter ispresent(outfile) | stats count(*) as count by outfile | sort count desc | limit 10',
}

DAY_LIST_FIELDS = {
    "usernames": ("username", "usernames"),
    "commands": ("input", "top_commands"),
    "downloads": ("url", "downloads_top"),
    "uploads": ("outfile", "uploads_top"),
}


# --------------------------------------------------------------------------
# Build live.json (last 24h, rich)
# --------------------------------------------------------------------------

def build_live(now):
    start = now - timedelta(hours=LIVE_WINDOW_HOURS)

    timeline_rows = run_query(Q_TOTALS_TIMELINE, start, now)
    totals = {
        "connections": 0, "auth_attempts": 0, "commands": 0,
        "downloads": 0, "uploads": 0, "unique_ips": 0, "unique_sessions": 0,
    }
    timeline = []
    for r in timeline_rows:
        t = r.get("t", "")
        conn = int(float(r.get("connections", 0) or 0))
        auth = int(float(r.get("auth", 0) or 0))
        timeline.append({"t": t, "connections": conn, "auth": auth})
        totals["connections"] += conn
        totals["auth_attempts"] += auth
        totals["commands"] += int(float(r.get("commands", 0) or 0))
        totals["downloads"] += int(float(r.get("downloads", 0) or 0))
        totals["uploads"] += int(float(r.get("uploads", 0) or 0))
        totals["unique_ips"] = max(totals["unique_ips"], int(float(r.get("unique_ips", 0) or 0)))
        totals["unique_sessions"] = max(totals["unique_sessions"], int(float(r.get("unique_sessions", 0) or 0)))

    # Top IPs + geo
    ip_rows = run_query(Q_TOP_IPS, start, now)
    ips = [r["src_ip"] for r in ip_rows if r.get("src_ip")]
    geo = geolocate(ips)

    top_ips = []
    for r in ip_rows[:10]:
        ip = r.get("src_ip", "")
        top_ips.append({
            "ip": ip,
            "country": geo.get(ip, {}).get("code", ""),
            "count": int(float(r.get("count", 0) or 0)),
        })

    # Aggregate geo points by (rounded lat,lon)
    ip_counts = {r.get("src_ip", ""): int(float(r.get("count", 0) or 0)) for r in ip_rows}
    point_map = {}
    country_map = {}
    for ip, g in geo.items():
        if g.get("lat") is None or g.get("lon") is None:
            continue
        key = (round(g["lat"], 1), round(g["lon"], 1))
        pt = point_map.setdefault(key, {"lat": key[0], "lon": key[1], "count": 0, "country": g.get("code", "")})
        cnt = ip_counts.get(ip, 1)
        pt["count"] += cnt
        c = g.get("country", "")
        code = g.get("code", "")
        if code:
            ck = (c, code)
            country_map[ck] = country_map.get(ck, 0) + cnt
    geo_points = sorted(point_map.values(), key=lambda x: -x["count"])[:300]
    top_countries = [
        {"country": c, "code": code, "count": n}
        for (c, code), n in sorted(country_map.items(), key=lambda x: -x[1])[:10]
    ]

    def top_list(key, field):
        rows = run_query(Q_TOP_FIELD[key], start, now)
        return [
            {field: display_name(field, r.get(field, "")),
             "count": int(float(r.get("count", 0) or 0))}
            for r in rows if r.get(field)
        ]

    recent_rows = run_query(Q_RECENT, start, now)
    recent = []
    for r in recent_rows:
        detail = ""
        if r.get("input"):
            detail = r["input"]
        elif r.get("username") or r.get("password"):
            detail = f"{r.get('username','')}/{r.get('password','')}"
        recent.append({
            "time": r.get("@timestamp", ""),
            "ip": r.get("src_ip", ""),
            "country": geo.get(r.get("src_ip", ""), {}).get("code", ""),
            "event": r.get("eventid", "").replace("cowrie.", ""),
            "detail": detail,
        })

    return {
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "window": "24h",
        "totals": totals,
        "top_countries": top_countries,
        "top_ips": top_ips,
        "top_usernames": top_list("usernames", "username"),
        "top_passwords": top_list("passwords", "password"),
        "top_commands": top_list("commands", "input"),
        "top_downloads": top_list("downloads", "url"),
        "top_uploads": top_list("uploads", "outfile"),
        "recent_attacks": recent,
        "geo_points": geo_points,
        "timeline": timeline,
    }


# --------------------------------------------------------------------------
# Build today's archive day-bucket and merge into archive.json
# --------------------------------------------------------------------------

def build_day_bucket(start, end, label):
    ip_rows = run_query(Q_DAY_COUNTRIES, start, end)
    ips = [r["src_ip"] for r in ip_rows if r.get("src_ip")]
    geo = geolocate(ips)

    countries = {}
    geo_pts = {}
    ips = {}
    for r in ip_rows:
        ip = r.get("src_ip", "")
        cnt = int(float(r.get("count", 0) or 0))
        g = geo.get(ip)
        if not g:
            continue
        code = g.get("code", "")
        if code:
            countries[code] = countries.get(code, 0) + cnt
        if g.get("lat") is not None and g.get("lon") is not None:
            key = (round(g["lat"], 1), round(g["lon"], 1))
            pt = geo_pts.get(key)
            if not pt:
                pt = geo_pts[key] = {"count": 0, "by_country": {}}
            pt["count"] += cnt
            if code:
                pt["by_country"][code] = pt["by_country"].get(code, 0) + cnt
        ips[ip] = {"count": cnt, "country": code or ""}

    # totals for the day from the timeline query
    timeline_rows = run_query(Q_TOTALS_TIMELINE, start, end)
    bucket = {
        "date": label,
        # scalar daily totals
        "connections": 0, "auth": 0, "unique_ips": 0,
        "commands": 0, "downloads": 0, "uploads": 0,
        # per-day top lists (maps of value -> count)
        "countries": dict(sorted(countries.items(), key=lambda x: -x[1])[:15]),
        "usernames": {}, "top_commands": {}, "downloads_top": {}, "uploads_top": {},
        "ips": dict(sorted(ips.items(), key=lambda x: -x[1]["count"])[:25]),
        "geo": [{"lat": k[0], "lon": k[1], "count": v["count"],
                 "country": max(v["by_country"].items(), key=lambda x: x[1])[0] if v["by_country"] else ""}
                for k, v in sorted(geo_pts.items(), key=lambda x: -x[1]["count"])[:60]],
    }
    for r in timeline_rows:
        bucket["connections"] += int(float(r.get("connections", 0) or 0))
        bucket["auth"] += int(float(r.get("auth", 0) or 0))
        bucket["commands"] += int(float(r.get("commands", 0) or 0))
        bucket["downloads"] += int(float(r.get("downloads", 0) or 0))
        bucket["uploads"] += int(float(r.get("uploads", 0) or 0))
        bucket["unique_ips"] = max(bucket["unique_ips"], int(float(r.get("unique_ips", 0) or 0)))

    for field, (key, out_field) in DAY_LIST_FIELDS.items():
        rows = run_query(Q_DAY_FIELD[field], start, end)
        bucket[out_field] = {
            display_name(key, r.get(key, "")): int(float(r.get("count", 0) or 0))
            for r in rows if r.get(key)
        }

    return bucket


def build_day_bucket_for_date(date_str):
    """Rebuild a full day bucket for an arbitrary UTC date (YYYY-MM-DD)."""
    start = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return build_day_bucket(start, start + timedelta(days=1), date_str)


def merge_archive(existing, day_bucket, fallback_first_date):
    if not existing:
        existing = {"first_data_date": day_bucket["date"], "days": []}
    days = {d["date"]: d for d in existing.get("days", [])}
    days[day_bucket["date"]] = day_bucket
    ordered = [days[k] for k in sorted(days.keys())]
    first = existing.get("first_data_date") or fallback_first_date or day_bucket["date"]
    return {"first_data_date": first, "days": ordered}


# --------------------------------------------------------------------------
# Backfill: rebuild day buckets for past UTC dates on demand
# --------------------------------------------------------------------------

def backfill(dates, now):
    archive = get_json("archive.json")
    fallback_first = archive.get("first_data_date") if archive else None
    if not fallback_first:
        fallback_first = first_data_date() or dates[0]
    for date_str in dates:
        day_bucket = build_day_bucket_for_date(date_str)
        archive = merge_archive(archive, day_bucket, fallback_first)
    put_json("archive.json", archive)
    meta = {
        "first_data_date": archive["first_data_date"],
        "generated_at": now.isoformat().replace("+00:00", "Z"),
    }
    put_json("meta.json", meta)
    return {"status": "ok", "backfilled": dates, "days": len(archive["days"])}


# --------------------------------------------------------------------------
# Handler
# --------------------------------------------------------------------------

def lambda_handler(event, context):
    if not BUCKET:
        raise RuntimeError("DASHBOARD_BUCKET env var is not set")

    now = datetime.now(timezone.utc)

    if isinstance(event, dict) and event.get("backfill"):
        return backfill(event["backfill"], now)

    live = build_live(now)
    day_bucket = build_day_bucket(now - timedelta(hours=LIVE_WINDOW_HOURS), now, now.date().isoformat())

    existing_archive = get_json("archive.json")
    fallback_first = existing_archive.get("first_data_date") if existing_archive else None
    if not fallback_first:
        fallback_first = first_data_date() or day_bucket["date"]

    archive = merge_archive(existing_archive, day_bucket, fallback_first)
    meta = {
        "first_data_date": archive["first_data_date"],
        "generated_at": live["generated_at"],
    }

    put_json("live.json", live)
    put_json("archive.json", archive)
    put_json("meta.json", meta)

    return {
        "status": "ok",
        "generated_at": live["generated_at"],
        "first_data_date": archive["first_data_date"],
        "days": len(archive["days"]),
        "live_connections": live["totals"]["connections"],
    }
