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
from app.models.resource import Resource


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


def get_recent_cloudtrail_events(lookback_minutes=15, max_results=50):
    """
    Pulls ALL CloudTrail events from the last `lookback_minutes` minutes,
    paginating through multiple pages if there are more than max_results
    events in the window (AWS caps each single call at 50).

    Capped at 10 pages (500 events) per call as a safety limit, so a
    very noisy window can't turn one sync into an unbounded loop.
    """
    client = get_cloudtrail_client()

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(minutes=lookback_minutes)

    all_events = []
    next_token = None
    max_pages = 10

    for _ in range(max_pages):
        kwargs = {
            "StartTime": start_time,
            "EndTime": end_time,
            "MaxResults": max_results,
        }
        if next_token:
            kwargs["NextToken"] = next_token

        try:
            response = client.lookup_events(**kwargs)
        except ClientError as e:
            print(f"AWS rejected the request: {e}")
            break

        all_events.extend(response.get("Events", []))
        next_token = response.get("NextToken")

        if not next_token:
            break

    return all_events

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
    "StopInstances":                 "ec2_instance_stopped",
    "ConsoleLogin":                  "console_login_success",  # root override below
    "CreateBucket":                  "s3_bucket_created",
    "PutBucketPolicy":               "s3_bucket_policy_change",  # public-principal check happens in get_rule_event_type
}
# Event sources and exact event names that are AWS/Console background
# noise -- automatic telemetry, never something a real person did.
# These still get saved as Logs (nothing is thrown away), just flagged
# so the frontend can hide them by default.
SYSTEM_NOISE_EVENT_SOURCES = {
    "resource-explorer-2.amazonaws.com",
}

SYSTEM_NOISE_EVENT_NAMES = {
    "GetAccountColor",
    "GetAccountPlanState",
    "GetCostAndUsage",
    "GetCostForecast",
    "ListManagedNotificationEvents",
    "DescribeEventAggregates",
    "ListEnrollmentStatuses",
    "ListDelegatedAdministrators",
    "DescribeOrganization",
    "LookupEvents",       # our own tool checking CloudTrail -- always self-noise
    "GetCallerIdentity",  # "who am I" checks -- never security-relevant
    "AssumeRole",         # covers resource-explorer-2's background AssumeRole too
    
    "ListDetectors",
    "ListResources",

}

def is_system_noise_event(raw_event):
    """
    Returns True if this event is automatic AWS/Console background
    telemetry rather than real user or API activity.
    """
    event_source = raw_event.get("EventSource", "")
    event_name = raw_event.get("EventName", "")

    # Never treat these as noise, even if AWS marks them read-only --
    # our rule engine specifically cares about them.
    if event_name in AWS_EVENT_NAME_TO_RULE_TYPE:
        return False
    if _is_permission_denied(raw_event):
        return False

    if event_source in SYSTEM_NOISE_EVENT_SOURCES:
        return True
    if event_name in SYSTEM_NOISE_EVENT_NAMES:
        return True

    # Generalized signal: almost every "just looking" Describe/List/Get
    # call AWS makes is marked read-only in CloudTrail. The AWS Console
    # fires dozens of these automatically just from opening a page --
    # none of it was a deliberate action. Rather than naming every
    # possible Describe/List/Get call one by one, treat any read-only
    # call as noise unless explicitly exempted above.
    detail = {}
    raw_json = raw_event.get("CloudTrailEvent")
    if raw_json:
        try:
            detail = json.loads(raw_json)
        except (json.JSONDecodeError, TypeError):
            detail = {}
    if detail.get("readOnly") is True:
        return True

    return False
# Error codes CloudTrail uses when a call was denied for lack of
# permissions. Checked BEFORE the specific-event-name mapping below,
# so ANY denied action becomes an alert -- without needing every
# possible action name enumerated one by one.
PERMISSION_DENIED_ERROR_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedAccess",
    "UnauthorizedOperation",
    "Client.UnauthorizedOperation",
    "AuthorizationError",
}


def _is_permission_denied(raw_event):
    """
    Returns True if this event's errorCode indicates the call was
    denied due to insufficient permissions.
    """
    detail = {}
    raw_json = raw_event.get("CloudTrailEvent")
    if raw_json:
        try:
            detail = json.loads(raw_json)
        except (json.JSONDecodeError, TypeError):
            return False
    return detail.get("errorCode") in PERMISSION_DENIED_ERROR_CODES

def get_rule_event_type(raw_event):
    """
    Decides which semantic event_type (if any) from RuleEngine's rulebook
    this raw AWS event maps to. Returns None for routine/unmapped events.
    """
    event_name = raw_event.get("EventName")

    # Checked before the specific-name mapping: a denied action is
    # security-relevant regardless of WHICH action it was denied on.
    if _is_permission_denied(raw_event):
        return "unauthorized_api_call"

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

    if event_name == "PutBucketPolicy":
        return "s3_bucket_public" if _bucket_policy_is_public(raw_event) else None

    return AWS_EVENT_NAME_TO_RULE_TYPE.get(event_name)


def _bucket_policy_is_public(raw_event):
    """
    Parses a PutBucketPolicy event's policy document and returns True if
    any statement grants access to "*" (everyone) or {"AWS": "*"} --
    the two common shapes of a fully public S3 bucket policy.

    Returns False (not public, or unparseable) if the policy can't be
    found or read -- fails safe by NOT alerting rather than guessing.
    """
    detail = {}
    raw_json = raw_event.get("CloudTrailEvent")
    if raw_json:
        try:
            detail = json.loads(raw_json)
        except (json.JSONDecodeError, TypeError):
            return False

    request_params = detail.get("requestParameters", {})
    policy = request_params.get("bucketPolicy")

    if not policy:
        return False

    # bucketPolicy can come through as a dict already, or as a JSON string
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except (json.JSONDecodeError, TypeError):
            return False

    for statement in policy.get("Statement", []):
        principal = statement.get("Principal")
        if principal == "*":
            return True
        if isinstance(principal, dict) and principal.get("AWS") == "*":
            return True

    return False

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
        is_system_noise=is_system_noise_event(raw_event),
        source="real",
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
            source="real",
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

def get_ec2_client():
    """boto3 EC2 client, uses whatever credentials are active."""
    return boto3.client("ec2")


def get_s3_client():
    """boto3 S3 client, uses whatever credentials are active."""
    return boto3.client("s3")


def get_iam_client():
    """boto3 IAM client, uses whatever credentials are active."""
    return boto3.client("iam")


def discover_ec2_instances():
    """
    Fetches all EC2 instances (any state) via describe_instances and
    normalizes each into the shape the Resource model expects.
    """
    client = get_ec2_client()
    resources = []

    try:
        response = client.describe_instances()
    except ClientError as e:
        print(f"AWS rejected the EC2 describe_instances request: {e}")
        return resources

    for reservation in response.get("Reservations", []):
        for instance in reservation.get("Instances", []):
            instance_id = instance.get("InstanceId")
            if not instance_id:
                continue

            name = None
            for tag in instance.get("Tags", []):
                if tag.get("Key") == "Name":
                    name = tag.get("Value")
                    break

            resources.append({
                "resource_id": instance_id,
                "cloud": "AWS",
                "provider": "aws",
                "type": "vm",
                "name": name or instance_id,
                "region": instance.get("Placement", {}).get("AvailabilityZone", "")[:-1] or None,
                "status": instance.get("State", {}).get("Name"),
                "raw_metadata": instance,
            })

    return resources


def discover_s3_buckets():
    """
    Fetches all S3 buckets via list_buckets and normalizes each into
    the shape the Resource model expects. S3 is a global service, so
    there's no per-region call needed here.
    """
    client = get_s3_client()
    resources = []

    try:
        response = client.list_buckets()
    except ClientError as e:
        print(f"AWS rejected the S3 list_buckets request: {e}")
        return resources

    for bucket in response.get("Buckets", []):
        bucket_name = bucket.get("Name")
        if not bucket_name:
            continue

        resources.append({
            "resource_id": bucket_name,
            "cloud": "AWS",
            "provider": "aws",
            "type": "storage",
            "name": bucket_name,
            "region": None,  # requires a separate get_bucket_location call per bucket; skip for now
            "status": "active",
            "raw_metadata": {"creation_date": str(bucket.get("CreationDate"))},
        })

    return resources


def discover_iam_users():
    """
    Fetches all IAM users via list_users and normalizes each into the
    shape the Resource model expects. IAM is also a global service.
    """
    client = get_iam_client()
    resources = []

    try:
        response = client.list_users()
    except ClientError as e:
        print(f"AWS rejected the IAM list_users request: {e}")
        return resources

    for user in response.get("Users", []):
        user_name = user.get("UserName")
        if not user_name:
            continue

        resources.append({
            "resource_id": user.get("Arn", user_name),
            "cloud": "AWS",
            "provider": "aws",
            "type": "iam_user",
            "name": user_name,
            "region": None,
            "status": "active",
            "raw_metadata": {
                "created": str(user.get("CreateDate")),
                "path": user.get("Path"),
            },
        })

    return resources


def discover_all_aws_resources():
    """
    Runs all three discovery functions and returns one combined list.
    """
    resources = []
    resources.extend(discover_ec2_instances())
    resources.extend(discover_s3_buckets())
    resources.extend(discover_iam_users())
    return resources

def save_discovered_resources(resources, db):
    """
    Takes a list of normalized resource dicts (from discover_all_aws_resources
    or any single discover_* function) and upserts them into the resources
    table, keyed on resource_id.

    Existing resources get their mutable fields refreshed (status, name,
    region, raw_metadata, last_synced_at). New resources get inserted.

    Returns (created_count, updated_count).
    """
    created = 0
    updated = 0
    now = datetime.now(timezone.utc)

    for r in resources:
        existing = db.query(Resource).filter(
            Resource.resource_id == r["resource_id"]
        ).first()

        raw_metadata_json = json.dumps(r["raw_metadata"], default=str)

        if existing:
            existing.name = r["name"]
            existing.region = r["region"]
            existing.status = r["status"]
            existing.raw_metadata = raw_metadata_json
            existing.last_synced_at = now
            updated += 1
        else:
            new_resource = Resource(
                resource_id=r["resource_id"],
                cloud=r["cloud"],
                provider=r["provider"],
                type=r["type"],
                name=r["name"],
                region=r["region"],
                status=r["status"],
                raw_metadata=raw_metadata_json,
                source="real",
                created_at=now,
                last_synced_at=now,
            )
            db.add(new_resource)
            created += 1

    db.flush()
    return created, updated

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
            
# IAM user console logins get recorded in a region chosen by a browser
# cookie, NOT necessarily the account's default region -- confirmed via
# AWS docs and real testing (see session log). These are the regions
# AWS is known to route console logins to.
CONSOLE_LOGIN_ADDITIONAL_REGIONS = ["us-east-2", "eu-north-1", "ap-southeast-2"]


def get_cloudtrail_client_for_region(region_name):
    """
    Same as get_cloudtrail_client(), but pinned to a specific region --
    needed because ConsoleLogin events can land in a region other than
    the account default.
    """
    return boto3.client("cloudtrail", region_name=region_name)


def get_console_login_events_from_additional_regions(lookback_minutes=15, max_results=20):
    """
    Checks CONSOLE_LOGIN_ADDITIONAL_REGIONS specifically for ConsoleLogin
    events, since the primary region poll (get_recent_cloudtrail_events)
    misses these entirely. Only fetches ConsoleLogin events here -- not
    a full second sync -- to keep this cheap and targeted.
    """
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(minutes=lookback_minutes)

    all_events = []

    for region in CONSOLE_LOGIN_ADDITIONAL_REGIONS:
        try:
            client = get_cloudtrail_client_for_region(region)
            response = client.lookup_events(
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=max_results,
                LookupAttributes=[
                    {"AttributeKey": "EventName", "AttributeValue": "ConsoleLogin"}
                ],
            )
            all_events.extend(response.get("Events", []))
        except ClientError as e:
            print(f"AWS rejected the ConsoleLogin lookup in {region}: {e}")
            continue

    return all_events