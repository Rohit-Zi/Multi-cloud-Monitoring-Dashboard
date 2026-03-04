"""
Log API Routes
Endpoints to fetch logs linked to alerts
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.models.logs import Log
from app.models.alert import Alert

router = APIRouter()


# ─────────────────────────────────────────────────────────────────────────────
# GET /alerts/{alert_id}/logs
# Fetch all logs for a specific alert
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/alerts/{alert_id}/logs")
def get_logs_for_alert(alert_id: str, db: Session = Depends(get_db)):
    """
    Get all logs linked to a specific alert.
    Called when user clicks on an alert in the dashboard.
    """
    # Check alert exists
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")

    # Fetch logs for this alert
    logs = db.query(Log).filter(Log.alert_id == alert_id).all()

    if not logs:
        return {
            "alert_id":   alert_id,
            "total_logs": 0,
            "message":    "No logs found for this alert",
            "logs":       []
        }

    return {
        "alert_id":     alert_id,
        "alert_title":  alert.title,
        "alert_severity": alert.severity,
        "total_logs":   len(logs),
        "logs":         [log.to_dict() for log in logs]
    }


# ─────────────────────────────────────────────────────────────────────────────
# GET /logs/{log_id}
# Fetch a single log by ID (with full raw_log JSON)
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/logs/{log_id}")
def get_log_by_id(log_id: str, db: Session = Depends(get_db)):
    """
    Get a specific log by log_id.
    Returns the full raw log JSON for detailed view.
    """
    log = db.query(Log).filter(Log.log_id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail=f"Log '{log_id}' not found")

    return {
        "success": True,
        "log": log.to_dict()
    }


# ─────────────────────────────────────────────────────────────────────────────
# GET /logs
# Fetch all logs (with optional filters)
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/logs")
def get_all_logs(
    cloud: str = None,
    provider: str = None,
    outcome: str = None,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """
    Get all logs with optional filters.
    Query params: ?cloud=AWS&outcome=Success&limit=20
    """
    query = db.query(Log)

    if cloud:
        query = query.filter(Log.cloud == cloud.upper())
    if provider:
        query = query.filter(Log.provider == provider.lower())
    if outcome:
        query = query.filter(Log.outcome == outcome)

    logs = query.order_by(Log.created_at.desc()).limit(limit).all()

    return {
        "total_logs": len(logs),
        "filters_applied": {
            "cloud":    cloud,
            "provider": provider,
            "outcome":  outcome,
            "limit":    limit
        },
        "logs": [log.to_dict() for log in logs]
    }


# ─────────────────────────────────────────────────────────────────────────────
# DELETE /logs/{log_id}
# Delete a specific log
# ─────────────────────────────────────────────────────────────────────────────
@router.delete("/logs/{log_id}")
def delete_log(log_id: str, db: Session = Depends(get_db)):
    """
    Delete a specific log by ID.
    """
    log = db.query(Log).filter(Log.log_id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail=f"Log '{log_id}' not found")

    db.delete(log)
    db.commit()

    return {
        "success": True,
        "message": f"Log '{log_id}' deleted successfully"
    }