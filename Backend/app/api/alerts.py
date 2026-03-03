from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.models.alert import Alert
from app.processors.severity_normalizer import SeverityNormalizer
from app.processors.rule_engine import RuleEngine

router = APIRouter()


@router.post("/alerts")
def create_alert(cloud: str, provider: str, severity: str, title: str, description: str = None, db: Session = Depends(get_db)):
    
    normalized_severity = SeverityNormalizer.normalize(provider, severity)

    new_alert = Alert(
        cloud=cloud,
        provider=provider,
        severity=normalized_severity,
        title=title,
        description=description
    )

    db.add(new_alert)
    db.commit()
    db.refresh(new_alert)

    return new_alert
    
@router.get("/alerts")
def get_alerts(db: Session = Depends(get_db)):
    alerts = db.query(Alert).order_by(Alert.created_at.desc()).all()
    return alerts

@router.post("/alerts/evaluate")
def evaluate_and_create_alert(
    provider: str, 
    event_type: str, 
    event_data: dict,
    db: Session = Depends(get_db)
):
    """
    Evaluate an event through rule engine and create alert if rules match
    """
    # Evaluate event against rules
    alert_data = RuleEngine.evaluate_event(provider, event_type, event_data)
    
    if not alert_data:
        return {"message": "Event does not match any security rules", "alert_created": False}
    
    # Normalize severity
    normalized_severity = SeverityNormalizer.normalize(
        alert_data["provider"], 
        alert_data["severity"]
    )
    
    # Create alert
    new_alert = Alert(
        cloud=provider.upper(),
        provider=provider.lower(),
        severity=normalized_severity,
        title=alert_data["title"],
        description=f"{alert_data['description']} | User: {alert_data['user']} | Resource: {alert_data['resource']}"
    )
    
    db.add(new_alert)
    db.commit()
    db.refresh(new_alert)
    
    return {
        "message": "Alert created based on security rules",
        "alert_created": True,
        "alert": new_alert
    }
@router.get("/alerts/{alert_id}")
def get_alert_by_id(alert_id: str, db: Session = Depends(get_db)):
    """Get a specific alert by ID"""
    from fastapi import HTTPException
    
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@router.get("/alerts/stats/summary")
def get_alert_statistics(db: Session = Depends(get_db)):
    """Get alert statistics for dashboard"""
    all_alerts = db.query(Alert).all()
    
    return {
        "total_alerts": len(all_alerts),
        "critical_alerts": len([a for a in all_alerts if a.severity == "high"]),
        "high_alerts": len([a for a in all_alerts if a.severity == "high"]),
        "medium_alerts": len([a for a in all_alerts if a.severity == "medium"]),
        "low_alerts": len([a for a in all_alerts if a.severity == "low"]),
        "open_alerts": len([a for a in all_alerts if a.status == "open" or a.status == "detected"]),
        "investigating": len([a for a in all_alerts if a.status == "investigating"]),
        "resolved": len([a for a in all_alerts if a.status == "resolved"]),
        "by_provider": {
            "aws": len([a for a in all_alerts if a.provider == "aws"]),
            "azure": len([a for a in all_alerts if a.provider == "azure"]),
            "gcp": len([a for a in all_alerts if a.provider == "gcp"])
        }
    }


