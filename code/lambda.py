"""
cowrie-detector

Alert delivery: Telegram Bot API. Two ingestion paths:

  1. CloudWatch Logs subscription filter - high-confidence Cowrie events
     (successful login, file upload, file download). One Telegram message
     per event with source country flag, IP, and event details.
  2. EventBridge "Scheduled Query Completed" - credential-guessing burst.
     Deduped per src_ip in DynamoDB so the 5-minute schedule with a
     20-minute lookback does not re-alert the same attacker (25-minute
     suppress window; DynamoDB TTL cleans the table).

Environment variables:
  TELEGRAM_SECRET       JSON {"bot_token": "...", "chat_id": "..."}
                        (Secrets Manager dynamic reference)
  DEDUP_TABLE           DynamoDB table for burst dedup
  EXPECTED_ACCOUNT_ID   reject events from other accounts
  EXPECTED_REGION       reject events from other Regions
  COWRIE_LOG_GROUP      validate source log group (default /honeypot/cowrie)
  CREDENTIAL_QUERY_ARN  accept only this scheduled query
  HONEYPOT_SENSOR_ALIAS sensor label (default cowrie-sensor-01)
  GEOIP_ENABLED         "false" disables ip-api.com lookups (default true)
  GEOIP_ENDPOINT        ip-api batch endpoint
"""

import base64
import gzip
import hashlib
import html
import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

import boto3

logs = boto3.client("logs")
ddb = boto3.client("dynamodb")
secrets = boto3.client("secretsmanager")


def load_telegram_config():
    """TELEGRAM_SECRET holds secret JSON directly, or a secret ID to fetch."""
    raw = os.environ.get("TELEGRAM_SECRET", "")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        pass
    if raw:
        try:
            resp = secrets.get_secret_value(SecretId=raw)
            return json.loads(resp["SecretString"])
        except Exception:
            pass
    return {}


_telegram = load_telegram_config()
BOT_TOKEN = _telegram.get("bot_token", "")
CHAT_ID = str(_telegram.get("chat_id", ""))
DEDUP_TABLE = os.environ.get("DEDUP_TABLE", "")
EXPECTED_ACCOUNT_ID = os.environ.get("EXPECTED_ACCOUNT_ID", "")
EXPECTED_REGION = os.environ.get("EXPECTED_REGION", "")
LOG_GROUP = os.environ.get("COWRIE_LOG_GROUP", "/honeypot/cowrie")
CREDENTIAL_QUERY_ARN = os.environ.get("CREDENTIAL_QUERY_ARN", "")
SENSOR_ALIAS = os.environ.get("HONEYPOT_SENSOR_ALIAS", "cowrie-sensor-01")
GEOIP_ENABLED = os.environ.get("GEOIP_ENABLED", "true").lower() == "true"
GEOIP_ENDPOINT = os.environ.get("GEOIP_ENDPOINT", "http://ip-api.com/batch")
QUERY_MARKER = "CREDENTIAL_GUESSING_BURST"

MAX_ROWS_IN_ALERT = 20
SUPPRESS_SECONDS = 1500  # 25 minutes, longer than the 20-minute lookback
HIGH_CONFIDENCE_EVENTS = {
    "cowrie.login.success": ("COWRIE_EMULATED_AUTH_ACCEPTED", "HIGH"),
    "cowrie.session.file_upload": ("COWRIE_FILE_UPLOADED", "HIGH"),
    "cowrie.session.file_download": ("COWRIE_URL_PAYLOAD_DOWNLOADED", "HIGH"),
}


WIB = timezone(timedelta(hours=7), "WIB")


def wib_time(value=None):
    """Format ISO string, epoch seconds, or epoch millis as WIB text."""
    if value is None:
        dt = datetime.now(WIB)
    elif isinstance(value, (int, float)):
        ts = float(value) / 1000 if value > 1e12 else float(value)
        dt = datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(WIB)
    else:
        text = str(value).strip()
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(WIB)
        except ValueError:
            return text
    return dt.strftime("%Y-%m-%d %H:%M:%S WIB")


def build_alert_id(*parts):
    material = "|".join(str(part) for part in parts if part is not None)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def flag_emoji(code):
    if not code or len(code) != 2:
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper())


def send_telegram(text):
    if not BOT_TOKEN or not CHAT_ID:
        raise RuntimeError("TELEGRAM_SECRET is missing bot_token or chat_id")
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    body = json.dumps(
        {
            "chat_id": CHAT_ID,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}
    )
    last_error = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read().decode("utf-8"))
            return result["result"]["message_id"]
        except (urllib.error.URLError, ValueError, KeyError, TimeoutError) as exc:
            last_error = exc
            time.sleep(1 + attempt)
    raise RuntimeError(f"Telegram send failed: {last_error}")


def geolocate(ips):
    """Return {ip: {"country": str, "code": str}} via ip-api.com batch."""
    if not GEOIP_ENABLED or not ips:
        return {}
    unique = list(dict.fromkeys(ip for ip in ips if ip))
    if not unique:
        return {}
    body = json.dumps(unique).encode("utf-8")
    req = urllib.request.Request(
        GEOIP_ENDPOINT + "?fields=status,query,country,countryCode",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, ValueError, TimeoutError):
        return {}
    result = {}
    for item in data:
        if item.get("status") == "success":
            result[item["query"]] = {
                "country": item.get("country", ""),
                "code": item.get("countryCode", ""),
            }
    return result


def geo_text(geo, ip=""):
    flag = flag_emoji(geo.get("code", "")) or "\U0001F3F3\uFE0F"
    name = html.escape(geo.get("country") or "Unknown")
    text = f"{flag} {name}"
    if ip:
        text += f" \u00B7 <code>{html.escape(ip)}</code>"
    return text


def already_alerted(ips):
    """Return the set of src_ips still inside the suppress window."""
    if not DEDUP_TABLE or not ips:
        return set()
    keys = [{"alert_key": {"S": f"{QUERY_MARKER}|{ip}"}} for ip in ips]
    seen = set()
    now = int(time.time())
    for i in range(0, len(keys), 100):  # BatchGetItem limit is 100 keys
        resp = ddb.batch_get_item(
            RequestItems={DEDUP_TABLE: {"Keys": keys[i:i + 100]}}
        )
        for item in resp.get("Responses", {}).get(DEDUP_TABLE, []):
            # DynamoDB TTL deletion is lazy; treat expired items as unseen.
            expires = int(item.get("expires_at", {}).get("N", "0"))
            if expires > now:
                seen.add(item["alert_key"]["S"].split("|", 1)[1])
    return seen


def mark_alerted(ips):
    if not DEDUP_TABLE or not ips:
        return
    expires = str(int(time.time()) + SUPPRESS_SECONDS)
    requests = [
        {
            "PutRequest": {
                "Item": {
                    "alert_key": {"S": f"{QUERY_MARKER}|{ip}"},
                    "expires_at": {"N": expires},
                }
            }
        }
        for ip in ips
    ]
    for i in range(0, len(requests), 25):  # BatchWriteItem limit is 25 items
        ddb.batch_write_item(RequestItems={DEDUP_TABLE: requests[i:i + 25]})


def rows_to_dicts(results):
    return [
        {item["field"]: item.get("value", "") for item in row}
        for row in results
    ]


def decode_subscription_event(event):
    try:
        compressed = base64.b64decode(event["awslogs"]["data"])
        return json.loads(gzip.decompress(compressed).decode("utf-8"))
    except (KeyError, TypeError, ValueError, OSError) as exc:
        raise ValueError("Invalid CloudWatch Logs subscription event") from exc


def log_event_to_json(log_event):
    message = log_event.get("message", "")
    try:
        parsed = json.loads(message)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def is_expected_source(owner, log_group):
    if EXPECTED_ACCOUNT_ID and owner != EXPECTED_ACCOUNT_ID:
        return False
    if log_group != LOG_GROUP:
        return False
    return True


def build_subscription_message(cowrie_event, detection, severity, geo, event_time, alert_id):
    esc = html.escape
    lines = [
        f"\U0001F534 <b>{detection}</b>",
        f"<i>{severity} \u00B7 {esc(SENSOR_ALIAS)}</i>",
        "",
    ]
    src_ip = cowrie_event.get("src_ip", "")
    if src_ip:
        lines.append(geo_text(geo.get(src_ip, {}), src_ip))
    event_id = cowrie_event.get("eventid", "")
    if event_id == "cowrie.login.success":
        lines.append(
            f"user: <code>{esc(cowrie_event.get('username', ''))}</code>"
            f" \u00B7 pass: <code>{esc(cowrie_event.get('password', ''))}</code>"
        )
    elif event_id == "cowrie.session.file_upload":
        name = cowrie_event.get("filename") or cowrie_event.get("outfile", "")
        lines.append(f"file: <code>{esc(name.rsplit('/', 1)[-1])}</code>")
    elif event_id == "cowrie.session.file_download":
        lines.append(f"url: <code>{esc(cowrie_event.get('url', ''))}</code>")
    if cowrie_event.get("shasum"):
        lines.append(f"sha256: <code>{esc(cowrie_event['shasum'])}</code>")
    lines.append(f"time: {esc(event_time)}")
    lines.append(f"alert: <code>{esc(alert_id)}</code>")
    return "\n".join(lines)


def process_subscription_event(event):
    envelope = decode_subscription_event(event)

    if envelope.get("messageType") == "CONTROL_MESSAGE":
        return {"alerted": False, "reason": "CloudWatch Logs control message ignored"}

    if envelope.get("messageType") != "DATA_MESSAGE":
        return {
            "alerted": False,
            "reason": f"Unsupported CloudWatch Logs message type: {envelope.get('messageType', 'unknown')}",
        }

    owner = envelope.get("owner", "")
    log_group = envelope.get("logGroup", "")
    log_stream = envelope.get("logStream", "")
    if not is_expected_source(owner, log_group):
        return {"alerted": False, "reason": "Unexpected log source"}

    entries = []
    for log_event in envelope.get("logEvents", []):
        cowrie_event = log_event_to_json(log_event)
        mapping = HIGH_CONFIDENCE_EVENTS.get(cowrie_event.get("eventid", ""))
        if mapping:
            entries.append((log_event, cowrie_event, mapping))

    if not entries:
        return {"alerted": False, "reason": "No matching Cowrie events"}

    geo = geolocate([e[1].get("src_ip", "") for e in entries])

    results = []
    for log_event, cowrie_event, mapping in entries:
        detection, severity = mapping
        event_time = wib_time(cowrie_event.get("timestamp") or log_event.get("timestamp"))
        alert_id = build_alert_id(owner, log_group, log_stream, log_event.get("id"), cowrie_event.get("eventid"), event_time)
        message_id = send_telegram(
            build_subscription_message(cowrie_event, detection, severity, geo, event_time, alert_id)
        )
        results.append(
            {
                "alerted": True,
                "alert_id": alert_id,
                "detection": detection,
                "message_id": message_id,
            }
        )

    if len(results) == 1:
        return results[0]
    return {"alerted": True, "alerts": results, "count": len(results)}


def build_burst_message(new_rows, geo, event_time, alert_id):
    esc = html.escape
    lines = [
        f"\U0001F7E1 <b>{QUERY_MARKER}</b>",
        f"<i>MEDIUM \u00B7 {esc(SENSOR_ALIAS)}</i>",
        "",
    ]
    flags = []
    for row in new_rows:
        flag = flag_emoji(geo.get(row["src_ip"], {}).get("code", ""))
        if flag and flag not in flags:
            flags.append(flag)
    lines.append("countries : " + (" ".join(flags) if flags else "\U0001F3F3\uFE0F"))
    lines.append("")
    for row in new_rows[:MAX_ROWS_IN_ALERT]:
        lines.append(
            f"<code>{esc(row['src_ip'])}</code> \u2014 "
            f"{esc(row.get('attempts', '?'))} attempts \u00B7 "
            f"{esc(row.get('usernames', '?'))} users \u00B7 "
            f"{esc(row.get('sessions', '?'))} sessions"
        )
    if len(new_rows) > MAX_ROWS_IN_ALERT:
        lines.append(f"... and {len(new_rows) - MAX_ROWS_IN_ALERT} more")
    lines.append("")
    lines.append(f"time: {esc(event_time)}")
    lines.append(f"alert: <code>{esc(alert_id)}</code>")
    return "\n".join(lines)


def process_scheduled_query_event(event):
    detail = event.get("detail", {})
    if detail.get("status") != "Complete":
        return {"alerted": False, "reason": "Query did not complete"}

    resources = event.get("resources", [])
    if CREDENTIAL_QUERY_ARN:
        if CREDENTIAL_QUERY_ARN not in resources:
            return {"alerted": False, "reason": "Unexpected scheduled query ARN"}
    else:
        return {"alerted": False, "reason": "CREDENTIAL_QUERY_ARN is not configured"}

    if EXPECTED_ACCOUNT_ID and event.get("account") != EXPECTED_ACCOUNT_ID:
        return {"alerted": False, "reason": "Unexpected account ID"}
    if EXPECTED_REGION and event.get("region") != EXPECTED_REGION:
        return {"alerted": False, "reason": "Unexpected Region"}

    query_id = detail.get("queryId")
    if not query_id:
        raise ValueError("Scheduled-query event did not contain queryId")

    response = logs.get_query_results(queryId=query_id)
    if response.get("status") != "Complete":
        return {
            "alerted": False,
            "reason": f"Query result status is {response.get('status', 'unknown')}",
        }

    rows = rows_to_dicts(response.get("results", []))
    if not rows:
        return {"alerted": False, "reason": "Query returned no detections"}

    if rows[0].get("detection", "") != QUERY_MARKER:
        return {"alerted": False, "reason": "Unexpected scheduled query marker"}

    alert_id = build_alert_id(event.get("id"), query_id, QUERY_MARKER, event.get("time"))

    ips = [row.get("src_ip", "") for row in rows if row.get("src_ip")]
    geo = geolocate(ips)
    seen = already_alerted(ips)
    new_rows = [row for row in rows if row.get("src_ip") not in seen]

    if not new_rows:
        return {
            "alerted": False,
            "reason": "All burst sources already alerted recently",
            "alert_id": alert_id,
            "suppressed": len(rows),
        }

    event_time = wib_time(event.get("time"))
    message_id = send_telegram(build_burst_message(new_rows, geo, event_time, alert_id))
    mark_alerted([row["src_ip"] for row in new_rows])
    return {
        "alerted": True,
        "alert_id": alert_id,
        "message_id": message_id,
        "new_ips": len(new_rows),
        "suppressed": len(rows) - len(new_rows),
    }


def lambda_handler(event, context):
    if isinstance(event, dict) and "awslogs" in event:
        return process_subscription_event(event)

    source = event.get("source")
    detail_type = event.get("detail-type")

    if source == "aws.logs" and detail_type == "Scheduled Query Completed":
        return process_scheduled_query_event(event)

    return {"alerted": False, "reason": "Unsupported event type"}
