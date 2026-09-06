"""
One-time backfill: re-evaluate is_system_noise on every existing Log row
using the CURRENT noise logic (including the new readOnly check).

Existing rows were saved under older, narrower noise rules, so console
background noise from earlier syncs is still marked as real activity.
This re-runs the check against what's already stored and updates the flag.

Run once from the Backend directory:  python backfill_noise.py
"""
import json
from app.db.database import SessionLocal
from app.models.logs import Log
from app.connectors.aws_connector import (
    SYSTEM_NOISE_EVENT_SOURCES,
    SYSTEM_NOISE_EVENT_NAMES,
    AWS_EVENT_NAME_TO_RULE_TYPE,
    PERMISSION_DENIED_ERROR_CODES,
)


def should_be_noise(log):
    """
    Mirrors is_system_noise_event(), but reads from a saved Log row
    instead of a raw CloudTrail event dict.
    """
    # Exemptions first -- same order as the live logic
    if log.event_name in AWS_EVENT_NAME_TO_RULE_TYPE:
        return False
    if log.error_code in PERMISSION_DENIED_ERROR_CODES:
        return False

    if log.event_source in SYSTEM_NOISE_EVENT_SOURCES:
        return True
    if log.event_name in SYSTEM_NOISE_EVENT_NAMES:
        return True

    # readOnly lives inside the stored raw_log JSON
    if log.raw_log:
        try:
            detail = json.loads(log.raw_log)
            if detail.get("readOnly") is True:
                return True
        except (json.JSONDecodeError, TypeError):
            pass

    return False


if __name__ == "__main__":
    db = SessionLocal()
    changed = 0
    unchanged = 0

    try:
        logs = db.query(Log).all()
        print(f"Checking {len(logs)} log rows...\n")

        for log in logs:
            correct_value = should_be_noise(log)
            if log.is_system_noise != correct_value:
                log.is_system_noise = correct_value
                changed += 1
            else:
                unchanged += 1

        db.commit()
        print(f"Updated:   {changed}")
        print(f"Unchanged: {unchanged}")
        print("\nBackfill complete.")
    except Exception as e:
        db.rollback()
        print(f"Backfill failed, nothing was changed: {e}")
    finally:
        db.close()