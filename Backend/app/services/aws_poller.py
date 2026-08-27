"""
AWS Polling Service
Runs process_aws_event on a schedule so real AWS data flows in
automatically, without anyone manually calling /aws/sync.
"""
from apscheduler.schedulers.background import BackgroundScheduler
from app.db.database import SessionLocal
from app.connectors.aws_connector import get_recent_cloudtrail_events, process_aws_event

scheduler = BackgroundScheduler()


def poll_aws_events():
    """
    One polling cycle: fetch recent CloudTrail events, save new ones.
    Wrapped in try/except so one bad AWS API call doesn't kill the
    entire background scheduler -- it just tries again next cycle.
    """
    try:
        events = get_recent_cloudtrail_events(lookback_minutes=15)
        db = SessionLocal()
        try:
            new_count = 0
            for raw in events:
                log, alert = process_aws_event(raw, db)
                if log is None:
                    continue
                db.commit()
                new_count += 1
            print(f"[aws_poller] cycle complete: {new_count} new event(s) saved")
        except Exception as e:
            db.rollback()
            print(f"[aws_poller] error during processing: {e}")
        finally:
            db.close()
    except Exception as e:
        print(f"[aws_poller] failed to fetch events: {e}")


def start_polling():
    """
    Registers the polling job and starts the scheduler.
    Called once, when the FastAPI app starts up.
    """
    scheduler.add_job(
        poll_aws_events,
        trigger="interval",
        minutes=5,
        id="aws_poll_job",
        replace_existing=True,
        max_instances=1,  # don't let a slow cycle overlap with the next one
    )
    scheduler.start()
    print("[aws_poller] scheduler started, polling every 5 minutes")