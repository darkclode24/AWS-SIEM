import json
import os

import boto3

logs = boto3.client("logs")
sns = boto3.client("sns")

TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
MAX_ROWS_IN_ALERT = 20


def rows_to_dicts(results):
    return [
        {item["field"]: item.get("value", "") for item in row}
        for row in results
    ]


def publish(subject, payload):
    response = sns.publish(
        TopicArn=TOPIC_ARN,
        Subject=subject[:99],
        Message=json.dumps(payload, indent=2, default=str),
    )
    return response["MessageId"]


def lambda_handler(event, context):
    source = event.get("source")
    detail_type = event.get("detail-type")
    detail = event.get("detail", {})

    if source == "aws.cloudwatch" and detail_type == "CloudWatch Alarm State Change":
        state = detail.get("state", {})
        if state.get("value") != "ALARM":
            return {"alerted": False, "reason": "Alarm is not in ALARM state"}

        payload = {
            "detection": "HONEYPOT_LOGIN_SUCCESS",
            "severity": "HIGH",
            "alarm": detail.get("alarmName", "unknown"),
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
        payload = {
            "detection": detection,
            "severity": "MEDIUM",
            "time": event.get("time"),
            "region": event.get("region"),
            "matched_rows": len(rows),
            "results": rows[:MAX_ROWS_IN_ALERT],
            "statistics": detail.get("statistics", {}),
            "next_step": "Pivot on src_ip and session in the private log group.",
        }
        message_id = publish(f"Cowrie alert: {detection}", payload)
        return {"alerted": True, "message_id": message_id}

    return {"alerted": False, "reason": "Unsupported event type"}