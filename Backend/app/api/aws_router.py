"""
AWS Sync API Endpoint
Lets the running backend (not just a manual script) pull real CloudTrail
events and run them through the same normalize -> rule engine -> save
pipeline the standalone connector script uses.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.connectors.aws_connector import get_recent_cloudtrail_events, process_aws_event, discover_all_aws_resources, save_discovered_resources, get_console_login_events_from_additional_regions
router = APIRouter()


@router.post("/aws/sync")
def sync_aws_events(lookback_minutes: int = 15, db: Session = Depends(get_db)):
    """
    Pulls real AWS CloudTrail events from the last `lookback_minutes`
    minutes and saves Logs (+ Alerts where flagged) to the database.

    Also checks a fixed set of additional regions for ConsoleLogin
    events specifically, since IAM console logins can land in a region
    other than the account default (see CONSOLE_LOGIN_ADDITIONAL_REGIONS).
    """
    events = get_recent_cloudtrail_events(lookback_minutes=lookback_minutes)
    console_login_events = get_console_login_events_from_additional_regions(lookback_minutes=lookback_minutes)
    events = events + console_login_events
    
    logs_saved = 0
    alerts_created = 0
    results = []

    for raw in events:
        log, alert = process_aws_event(raw, db)
        
        if log is None:
            continue  # already saved before, skip
        db.commit()

        logs_saved += 1
        if alert:
            alerts_created += 1
            results.append({
                "event_name": log.event_name,
                "alert_created": True,
                "severity": alert.severity,
                "title": alert.title,
                "log_id": log.log_id,
                "alert_id": alert.id,
            })
        else:
            results.append({
                "event_name": log.event_name,
                "alert_created": False,
                "log_id": log.log_id,
            })

    return {
        "success": True,
        "events_retrieved": len(events),
        "logs_saved": logs_saved,
        "alerts_created": alerts_created,
        "results": results,
    }


@router.post("/aws/sync-resources")
def sync_aws_resources(db: Session = Depends(get_db)):
    """
    Discovers real AWS resources (EC2 instances, S3 buckets, IAM users)
    and upserts them into the resources table.
    """
    resources = discover_all_aws_resources()

    created, updated = save_discovered_resources(resources, db)
    db.commit()

    return {
        "success": True,
        "resources_found": len(resources),
        "created": created,
        "updated": updated,
    }