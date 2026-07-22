import json
import os
import time

import boto3

logs = boto3.client("logs")
sns = boto3.client("sns")

TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
LOG_GROUP = os.environ.get("COWRIE_LOG_GROUP", "/honeypot/cowrie")
ENRICHMENT_LOOKBACK_SECONDS = 300
ENRICHMENT_POLL_INTERVAL = 1
ENRICHMENT_POLL_ATTEMPTS = 10
MAX_ROWS_IN_ALERT = 20


def rows_to_dicts(results):
    return [
        {item["field"]: item.get("value", "") for item in row}
        for row in results
    ]


def publish(subject, payload):
    response = sns.publish(
        TopicArn=TOPIC_ARN,
        Subject=subject[:100],
        Message=json.dumps(payload, indent=2, default=str),
    )
    return response["messageId"]


def run_file_transfer_enrichment_query():
    query = '''fields "FILE_TRANSFER" as detection,
       @timestamp,
       eventid,
       src_ip,
       session,
       url,
       filename,
       outfile,
       shasum
| filter eventid = "cowrie.session.file_upload"
    or eventid = "cowrie.session.file_download"
| sort @timestamp desc
| limit 20'''
    now = int(time.time())
    started = logs.start_query(
        logGroupName=LOG_GROUP,
        startTime=now - ENRICHMENT_LOOKBACK_SECONDS,
        endTime=now,
        queryString=query,
    )
    query_id = started["queryId"]

    for _ in range(ENRICHMENT_POLL_ATTEMPTS):
        results = logs.get_query_results(queryId=query_id)
        if results.get("status") in ("Complete", "Failed", "Cancelled"):
            break
        time.sleep(ENRICHMENT_POLL_INTERVAL)
    return results


def lambda_handler(event, context):
    source = event.get("source")
    detail_type = event.get("detail-type")
    detail = event.get("detail", {})

    if source == "aws.cloudwatch" and detail_type == "CloudWatch Alarm State Change":
        state = detail.get("state", {})
        if state.get("value") != "ALARM":
            return {"alerted": False, "reason": "Alarm is not in ALARM state"}

        alarm_name = detail.get("alarmName", "unknown")

        if alarm_name == "cowrie-login-success":
            payload = {
                "detection": "HONEYPOT_LOGIN_SUCCESS",
                "severity": "HIGH",
                "alarm": alarm_name,
                "time": event.get("time"),
                "region": event.get("region"),
                "reason": state.get("reason", ""),
                "next_step": (
                    "Open CloudWatch Logs Insights and investigate recent "
                    "cowrie.login.success events."
                ),
            }
            message_id = publish("HIGH: Cowrie successful login", payload)
            return {"alerted": True, "message_id": message_id}

        if alarm_name == "cowrie-file-transfer":
            enrichment = run_file_transfer_enrichment_query()
            rows = rows_to_dicts(enrichment.get("results", []))
            if rows:
                next_step = (
                    "Review the session, transfer metadata, and SHA-256 "
                    "value. Do not execute the captured file."
                )
            else:
                next_step = (
                    "Open CloudWatch Logs Insights and investigate recent "
                    "cowrie.session.file_upload and "
                    "cowrie.session.file_download events."
                )
            payload = {
                "detection": "FILE_TRANSFER",
                "severity": "HIGH",
                "alarm": alarm_name,
                "time": event.get("time"),
                "region": event.get("region"),
                "reason": state.get("reason", ""),
                "matched_rows": len(rows),
                "results": rows[:MAX_ROWS_IN_ALERT],
                "next_step": next_step,
            }
            message_id = publish("HIGH: Cowrie file transfer", payload)
            return {
                "alerted": True,
                "message_id": message_id,
                "enriched": bool(rows),
            }

        return {"alerted": False, "reason": f"Unhandled alarm: {alarm_name}"}

    if source == "aws.logs" and detail_type == "Scheduled Query Completed":
        if detail.get("status") != "Complete":
            return {"alerted": False, "reason": "Query did not complete"}

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

        detection = rows[0].get("detection", "COWRIE_DETECTION")
        severity_by_detection = {
            "CREDENTIAL_GUESSING_BURST": "MEDIUM",
            "FILE_TRANSFER": "HIGH",
        }
        next_step_by_detection = {
            "CREDENTIAL_GUESSING_BURST": (
                "Review authentication events for the source IP, then pivot "
                "on its session identifiers in the private log group."
            ),
            "FILE_TRANSFER": (
                "Review the session, transfer metadata, and SHA-256 value. "
                "Do not execute the captured file."
            ),
        }
        severity = severity_by_detection.get(detection, "MEDIUM")

        payload = {
            "detection": detection,
            "severity": severity,
            "time": event.get("time"),
            "region": event.get("region"),
            "matched_rows": len(rows),
            "results": rows[:MAX_ROWS_IN_ALERT],
            "statistics": detail.get("statistics", {}),
            "next_step": next_step_by_detection.get(
                detection,
                "Pivot on src_ip and session in the private log group.",
            ),
        }
        message_id = publish(f"{severity}: Cowrie {detection}", payload)
        return {"alerted": True, "message_id": message_id}

    return {"alerted": False, "reason": "Unsupported event type"}
