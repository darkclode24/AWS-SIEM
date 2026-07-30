import base64
import gzip
import hashlib
import json
import os
from datetime import datetime, timezone

import boto3

logs = boto3.client("logs")
sns = boto3.client("sns")

TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
EXPECTED_ACCOUNT_ID = os.environ.get("EXPECTED_ACCOUNT_ID", "")
EXPECTED_REGION = os.environ.get("EXPECTED_REGION", "")
LOG_GROUP = os.environ.get("COWRIE_LOG_GROUP", "/honeypot/cowrie")
CREDENTIAL_QUERY_ARN = os.environ.get("CREDENTIAL_QUERY_ARN", "")
SENSOR_ALIAS = os.environ.get("HONEYPOT_SENSOR_ALIAS", "cowrie-sensor-01")
QUERY_MARKER = "CREDENTIAL_GUESSING_BURST"

MAX_ROWS_IN_ALERT = 20
HIGH_CONFIDENCE_EVENTS = {
    "cowrie.login.success": ("COWRIE_EMULATED_AUTH_ACCEPTED", "HIGH"),
    "cowrie.session.file_upload": ("COWRIE_FILE_UPLOADED", "HIGH"),
    "cowrie.session.file_download": ("COWRIE_URL_PAYLOAD_DOWNLOADED", "HIGH"),
}


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_event_time(value):
    if isinstance(value, str) and value.strip():
        return value
    if isinstance(value, (int, float)):
        return (
            datetime.fromtimestamp(value / 1000, tz=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
    return utc_now_iso()


def publish(subject, payload):
    response = sns.publish(
        TopicArn=TOPIC_ARN,
        Subject=subject[:100],
        Message=json.dumps(payload, indent=2, default=str),
    )
    return response["MessageId"]


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


def build_alert_id(*parts):
    material = "|".join(str(part) for part in parts if part is not None)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def is_expected_source(owner, log_group):
    if EXPECTED_ACCOUNT_ID and owner != EXPECTED_ACCOUNT_ID:
        return False
    if log_group != LOG_GROUP:
        return False
    return True


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

    results = []
    for log_event in envelope.get("logEvents", []):
        cowrie_event = log_event_to_json(log_event)
        event_id = cowrie_event.get("eventid", "")
        mapping = HIGH_CONFIDENCE_EVENTS.get(event_id)
        if not mapping:
            continue

        detection, severity = mapping
        event_time = normalize_event_time(cowrie_event.get("timestamp") or log_event.get("timestamp"))
        alert_id = build_alert_id(owner, log_group, log_stream, log_event.get("id"), event_id, event_time)
        payload = {
            "alert_id": alert_id,
            "detection": detection,
            "severity": severity,
            "event_time": event_time,
            "sensor": SENSOR_ALIAS,
            "count": 1,
            "log_event_id": log_event.get("id"),
        }
        if cowrie_event.get("shasum"):
            payload["sha256"] = cowrie_event["shasum"]

        message_id = publish(f"{severity}: {detection}", payload)
        results.append(
            {
                "alerted": True,
                "alert_id": alert_id,
                "detection": detection,
                "message_id": message_id,
            }
        )

    if not results:
        return {"alerted": False, "reason": "No matching Cowrie events"}
    if len(results) == 1:
        return results[0]
    return {"alerted": True, "alerts": results, "count": len(results)}


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

    detection = rows[0].get("detection", "")
    if detection != QUERY_MARKER:
        return {"alerted": False, "reason": "Unexpected scheduled query marker"}

    alert_id = build_alert_id(event.get("id"), query_id, detection, event.get("time"))
    payload = {
        "alert_id": alert_id,
        "detection": detection,
        "severity": "MEDIUM",
        "event_time": event.get("time") or utc_now_iso(),
        "sensor": SENSOR_ALIAS,
        "count": len(rows),
        "statistics": detail.get("statistics", {}),
    }

    message_id = publish("MEDIUM: Cowrie CREDENTIAL_GUESSING_BURST", payload)
    return {"alerted": True, "alert_id": alert_id, "message_id": message_id}


def lambda_handler(event, context):
    if isinstance(event, dict) and "awslogs" in event:
        return process_subscription_event(event)

    source = event.get("source")
    detail_type = event.get("detail-type")

    if source == "aws.logs" and detail_type == "Scheduled Query Completed":
        return process_scheduled_query_event(event)

    return {"alerted": False, "reason": "Unsupported event type"}
