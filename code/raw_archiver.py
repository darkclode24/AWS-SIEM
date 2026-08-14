"""
cowrie-raw-archiver

Subscribed to /honeypot/cowrie via a CloudWatch Logs subscription filter.
Copies every raw Cowrie log event to a private, versioned S3 bucket as gzipped
JSON, partitioned by UTC date. Pure passthrough: no detection, no filtering.

Object layout: raw/yyyy/MM/dd/<uuid>.json.gz

Environment variables:
  ARCHIVE_BUCKET   S3 bucket that stores the raw events   (required)
"""

import base64
import gzip
import io
import json
import os
import uuid
from datetime import datetime, timezone

import boto3

s3 = boto3.client("s3")
BUCKET = os.environ.get("ARCHIVE_BUCKET", "")


def decode_subscription_event(event):
    """Unwrap the base64 + gzip CloudWatch Logs subscription envelope."""
    compressed = base64.b64decode(event["awslogs"]["data"])
    return json.loads(gzip.decompress(compressed).decode("utf-8"))


def log_event_to_json(log_event):
    message = log_event.get("message", "")
    try:
        parsed = json.loads(message)
    except (json.JSONDecodeError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def day_prefix(now):
    return "{:04d}/{:02d}/{:02d}".format(now.year, now.month, now.day)


def lambda_handler(event, context):
    if not BUCKET:
        raise RuntimeError("ARCHIVE_BUCKET env var is not set")

    envelope = decode_subscription_event(event)
    if envelope.get("messageType") != "DATA_MESSAGE":
        return {"written": 0, "reason": "ignored non-data message"}

    now = datetime.now(timezone.utc)
    key = "raw/{}/{}.json.gz".format(day_prefix(now), uuid.uuid4().hex)

    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        for log_event in envelope.get("logEvents", []):
            cowrie = log_event_to_json(log_event)
            if cowrie:
                gz.write((json.dumps(cowrie) + "\n").encode("utf-8"))

    s3.put_object(
        Bucket=BUCKET,
        Key=key,
        Body=buf.getvalue(),
        ContentType="application/json",
        ContentEncoding="gzip",
    )
    return {"written": len(envelope.get("logEvents", [])), "key": key}