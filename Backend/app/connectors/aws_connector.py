"""
aws_connector.py

Connects to real AWS CloudTrail, normalizes events, runs them through
the Rule Engine, and saves Logs (+ Alerts where flagged) to the database.

Run it directly: python -m app.connectors.aws_connector
"""

import boto3
import uuid
import json
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime, timedelta, timezone
from app.processors.rule_engine import RuleEngine
from app.db.database import SessionLocal
from app.models.logs import Log
from app.models.alert import Alert


def get_cloudtrail_client():
    """
    Creates a boto3 CloudTrail client using whatever credentials
    are currently active (CloudGoat-Admin, via 'aws configure').
    """
    return boto3.client("cloudtrail")


def get_one_cloudtrail_event():
    """
    Calls CloudTrail's lookup_events API and returns the single most
    recent event from Event History.
    """
    client = get_cloudtrail_client()

    try:
        response = client.lookup_events(MaxResults=1)
    except NoCredentialsError:
        print("No AWS credentials found. Run 'aws configure' first.")
        return None
    except ClientError as e:
        print(f"AWS rejected the request: {e}")
        return None

    events = response.get("Events", [])
    if not events:
        print("Call succeeded, but no events came back. "
              "Check region — CloudTrail Event History is per-region.")
        return None

    return events[0]


def get_recent_cloudtrail_events(lookback_minutes=15, max_results=20):
    """
    Pulls all CloudTrail events from the last `lookback_minutes` minutes,
    instead of just the single newest one.
    """
    client = get_cloudtrail_client()

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(minutes=lookback_minutes)

    try:
        response = client.lookup_events(
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=max_results,
        )
    except ClientError as e:
        print(f"AWS rejected the request: {e}")
        return []

    return response.get("Events", [])


def normalize_event(raw_event):
    """
    Converts a raw AWS CloudTrail event into the exact shape your
    Log model (app/models/logs.py) expects.
    """
    detail = {}
    raw_json = raw_event.get("CloudTrailEvent")
    if raw_json:
        try:
            detail = json.loads(raw_json)
        except (json.JSONDecodeError, TypeError):
            detail = {}

    resources = raw_event.get("Resources", [])
    resource_str = ", ".join(
        r.get("ResourceName", "") for r in resources if r.get("ResourceName")
    ) or None

    return {
        "cloud": "AWS",
        "provider": "aws",
        "event_source": raw_event.get("EventSource"),
        "event_name": raw_event.get("EventName"),
        "event_category": detail.get("eventCategory"),
        "user": raw_event.get("Username"),
        "source_ip": detail.get("sourceIPAddress"),
        "region": detail.get("awsRegion"),
        "resource": resource_str,
        "outcome": "Failed" if detail.get("errorCode") else "Success",
        "error_code": detail.get("errorCode"),
        "timestamp": str(raw_event.get("EventTime")),
        "raw_log": raw_json,
    }


# Maps real AWS CloudTrail EventName -> the semantic event_type keys
# your RuleEngine's rulebook already understands. Anything NOT in this
# map is treated as routine -- saved as a Log only, never sent to the
# Rule Engine, never becomes an Alert.
AWS_EVENT_NAME_TO_RULE_TYPE = {
    "AuthorizeSecurityGroupIngress": "security_group_change",
    "RevokeSecurityGroupIngress":    "security_group_change",
    "PutUserPolicy":                 "iam_policy_change",
    "AttachUserPolicy":              "iam_policy_change",
    "PutRolePolicy":                 "iam_policy_change",
    "CreatePolicyVersion":           "iam_policy_change",
    "StopLogging":                   "cloudtrail_disabled",
    "DeleteTrail":                   "cloudtrail_disabled",
    "DeleteFlowLogs":                "vpc_flow_logs_deleted",
    "DeleteDetector":                "guardduty_disabled",
    "ScheduleKeyDeletion":           "kms_key_deletion",
    "RunInstances":                  "ec2_instance_started",
    "ConsoleLogin":                  "console_login_success",  # root override below
}


def get_rule_event_type(raw_event):
    """
    Decides which semantic event_type (if any) from RuleEngine's rulebook
    this raw AWS event maps to. Returns None for routine/unmapped events.
    """
    event_name = raw_event.get("EventName")

    if event_name == "ConsoleLogin":
        detail = {}
        raw_json = raw_event.get("CloudTrailEvent")
        if raw_json:
            try:
                detail = json.loads(raw_json)
            except (json.JSONDecodeError, TypeError):
                detail = {}
        if detail.get("userIdentity", {}).get("type") == "Root":
            return "root_account_login"
        return "console_login_success"

    return AWS_EVENT_NAME_TO_RULE_TYPE.get(event_name)


def process_aws_event(raw_event, db):
    """
    Takes ONE raw CloudTrail event and an already-open database session,
    and runs the full pipeline: dedup check -> normalize -> rule mapping
    -> evaluate -> save.

    Both the Log and the Alert (if one is created) get created_at set to
    the REAL AWS event time (raw_event['EventTime']), not the moment we
    happened to save it. This keeps displayed times, sort order, and any
    future trend charts consistent with when things actually happened in
    AWS -- not when a sync button was clicked.

    Returns:
        (Log, Alert | None) if newly saved
        (None, None) if this event was already saved before (duplicate)
    """
    source_event_id = raw_event.get("EventId")

    if source_event_id:
        existing = db.query(Log).filter(Log.source_event_id == source_event_id).first()
        if existing:
            return None, None

    normalized = normalize_event(raw_event)
    rule_type = get_rule_event_type(raw_event)
    event_time = raw_event.get("EventTime")  # real AWS event time, tz-aware datetime

    alert_data = None
    if rule_type:
        alert_data = RuleEngine.evaluate_event(
            provider="aws",
            event_type=rule_type,
            event_data={
                "resource": normalized["resource"],
                "user": normalized["user"],
                "ip_address": normalized["source_ip"],
                "timestamp": normalized["timestamp"],
            }
        )

    log = Log(
        log_id=str(uuid.uuid4()),
        alert_id=None,
        cloud=normalized["cloud"],
        provider=normalized["provider"],
        event_source=normalized["event_source"],
        event_name=normalized["event_name"],
        event_category=normalized["event_category"],
        user=normalized["user"],
        source_ip=normalized["source_ip"],
        region=normalized["region"],
        resource=normalized["resource"],
        outcome=normalized["outcome"],
        error_code=normalized["error_code"],
        timestamp=normalized["timestamp"],
        raw_log=normalized["raw_log"],
        source_event_id=source_event_id,
        created_at=event_time,
    )
    db.add(log)
    db.flush()

    alert = None
    if alert_data:
        alert = Alert(
            cloud=normalized["cloud"],
            provider=normalized["provider"],
            severity=alert_data["severity"],
            title=alert_data["title"],
            description=alert_data["description"],
            resource=alert_data["resource"],
            log_id=log.log_id,
            created_at=event_time,
        )
        db.add(alert)
        db.flush()

        log.alert_id = alert.id

    return log, alert


if __name__ == "__main__":
    events = get_recent_cloudtrail_events(lookback_minutes=15)

    if not events:
        print("No events found in the last 15 minutes.")
    else:
        print(f"Retrieved {len(events)} event(s):\n")
        db = SessionLocal()
        try:
            for raw in events:
                log, alert = process_aws_event(raw, db)
                if log is None:
                    continue  # already saved before, skip
                db.commit()

                if alert:
                    print(f"SAVED ALERT ({alert.severity.upper()}): "
                          f"{alert.title}  |  log_id={log.log_id}  alert_id={alert.id}")
                else:
                    print(f"saved log only:          {log.event_name}  |  log_id={log.log_id}")
        except Exception as e:
            db.rollback()
            print(f"Failed to process events: {e}")
        finally:
            db.close()