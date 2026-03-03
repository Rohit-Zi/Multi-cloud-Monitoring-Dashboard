"""
CloudTrail Simulator API Endpoints
Trigger security event simulations manually or automatically
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from app.db.database import get_db
from app.models.alert import Alert
from app.services.cloudtrail_simulator import CloudTrailSimulator
from app.processors.rule_engine import RuleEngine
from app.processors.severity_normalizer import SeverityNormalizer
import threading
import time

router = APIRouter()

# Global simulator instance
simulator = CloudTrailSimulator()

@router.get("/simulator/events")
def list_available_events():
    """
    Get list of all available simulation scenarios
    """
    all_events = simulator.get_all_event_names()
    
    return {
        "total_scenarios": len(all_events),
        "critical_events": simulator.get_event_by_severity("critical"),
        "high_events": simulator.get_event_by_severity("high"),
        "medium_events": simulator.get_event_by_severity("medium"),
        "low_events": simulator.get_event_by_severity("low"),
        "all_events": all_events
    }

@router.post("/simulator/trigger/random")
def trigger_random_event(db: Session = Depends(get_db)):
    """
    Trigger a single random security event
    Perfect for manual testing
    """
    # Generate random event
    event = simulator.generate_random_event()
    
    # Evaluate through rule engine
    alert_data = RuleEngine.evaluate_event(
        event["provider"],
        event["event_type"],
        event["event_data"]
    )
    
    if not alert_data:
        return {
            "success": False,
            "message": "Event did not match any security rules",
            "event_type": event["event_type"],
            "alert_created": False
        }
    
    # Normalize severity
    normalized_severity = SeverityNormalizer.normalize(
        alert_data["provider"],
        alert_data["severity"]
    )
    
    # Create alert
    new_alert = Alert(
        cloud=event["provider"].upper(),
        provider=event["provider"],
        severity=normalized_severity,
        title=alert_data["title"],
        description=f"{alert_data['description']} | User: {alert_data.get('user', 'Unknown')} | Resource: {alert_data.get('resource', 'Unknown')}"
    )
    
    db.add(new_alert)
    db.commit()
    db.refresh(new_alert)
    
    return {
        "success": True,
        "message": "Security alert created from simulated event",
        "alert_created": True,
        "event_type": event["event_type"],
        "alert": {
            "id": new_alert.id,
            "title": new_alert.title,
            "severity": new_alert.severity,
            "provider": new_alert.provider,
            "status": new_alert.status,
            "created_at": new_alert.created_at.isoformat()
        }
    }

@router.post("/simulator/trigger/specific")
def trigger_specific_event(event_name: str, db: Session = Depends(get_db)):
    """
    Trigger a specific security event by name
    Use GET /simulator/events to see available event names
    """
   # Get event types from RuleEngine instead
    provider_rules = RuleEngine.SECURITY_RULES.get("aws", {})
    event_names = [
        event_type
        for event_type, rule in provider_rules.items()
        if rule["severity"] == severity and rule.get("alert", False)
    ]
    if not event_names:
        raise HTTPException(
            status_code=404,
            detail=f"Event '{event_name}' not found. Use GET /simulator/events to see available events."
    )
    
    # Evaluate through rule engine
    alert_data = RuleEngine.evaluate_event(
        event["provider"],
        event["event_type"],
        event["event_data"]
    )
    
    if not alert_data:
        return {
            "success": False,
            "message": "Event did not match any security rules",
            "event_name": event_name,
            "alert_created": False
        }
    
    # Normalize severity
    normalized_severity = SeverityNormalizer.normalize(
        alert_data["provider"],
        alert_data["severity"]
    )
    
    # Create alert
    new_alert = Alert(
        cloud=event["provider"].upper(),
        provider=event["provider"],
        severity=normalized_severity,
        title=alert_data["title"],
        description=f"{alert_data['description']} | User: {alert_data.get('user', 'Unknown')} | Resource: {alert_data.get('resource', 'Unknown')}"
    )
    
    db.add(new_alert)
    db.commit()
    db.refresh(new_alert)
    
    return {
        "success": True,
        "message": f"Security alert created from '{event_name}'",
        "alert_created": True,
        "event_name": event_name,
        "alert": {
            "id": new_alert.id,
            "title": new_alert.title,
            "severity": new_alert.severity,
            "provider": new_alert.provider,
            "status": new_alert.status,
            "created_at": new_alert.created_at.isoformat()
        }
    }

@router.post("/simulator/trigger/batch")
def trigger_batch_events(count: int = 5, db: Session = Depends(get_db)):
    """
    Trigger multiple random events at once
    Great for populating dashboard with test data
    """
    if count > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 events per batch")
    
    results = []
    alerts_created = 0
    
    for i in range(count):
        # Generate random event
        event = simulator.generate_random_event()
        
        # Evaluate through rule engine
        alert_data = RuleEngine.evaluate_event(
            event["provider"],
            event["event_type"],
            event["event_data"]
        )
        
        if not alert_data:
            results.append({
                "event_number": i + 1,
                "alert_created": False,
                "event_type": event["event_type"]
            })
            continue
        
        # Normalize severity
        normalized_severity = SeverityNormalizer.normalize(
            alert_data["provider"],
            alert_data["severity"]
        )
        
        # Create alert
        new_alert = Alert(
            cloud=event["provider"].upper(),
            provider=event["provider"],
            severity=normalized_severity,
            title=alert_data["title"],
            description=f"{alert_data['description']} | User: {alert_data.get('user', 'Unknown')} | Resource: {alert_data.get('resource', 'Unknown')}"
        )
        
        db.add(new_alert)
        db.commit()
        db.refresh(new_alert)
        
        alerts_created += 1
        results.append({
            "event_number": i + 1,
            "alert_created": True,
            "alert_id": new_alert.id,
            "title": new_alert.title,
            "severity": new_alert.severity
        })
    
    return {
        "success": True,
        "total_events": count,
        "alerts_created": alerts_created,
        "results": results
    }

@router.post("/simulator/trigger/severity")
def trigger_by_severity(severity: str, count: int = 3, db: Session = Depends(get_db)):
    """
    Trigger events of specific severity level
    Severity options: critical, high, medium
    """
    valid_severities = ["critical", "high", "medium", "low"]
    if severity not in valid_severities:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid severity. Choose from: {', '.join(valid_severities)}"
        )
    
    # Get events matching severity
    event_names = simulator.get_event_by_severity(severity)
    
    if not event_names:
        raise HTTPException(
            status_code=404,
            detail=f"No events found with severity '{severity}'"
        )
    
    results = []
    alerts_created = 0
    
    for i in range(min(count, len(event_names))):
        event_name = event_names[i % len(event_names)]
        
        # Generate specific event
        event = simulator.generate_specific_event(event_name)
        
        # Evaluate through rule engine
        alert_data = RuleEngine.evaluate_event(
            event["provider"],
            event["event_type"],
            event["event_data"]
        )
        
        if not alert_data:
            continue
        
        # Normalize severity
        normalized_severity = SeverityNormalizer.normalize(
            alert_data["provider"],
            alert_data["severity"]
        )
        
        # Create alert
        new_alert = Alert(
            cloud=event["provider"].upper(),
            provider=event["provider"],
            severity=normalized_severity,
            title=alert_data["title"],
            description=f"{alert_data['description']} | User: {alert_data.get('user', 'Unknown')} | Resource: {alert_data.get('resource', 'Unknown')}"
        )
        
        db.add(new_alert)
        db.commit()
        db.refresh(new_alert)
        
        alerts_created += 1
        results.append({
            "event_name": event_name,
            "alert_id": new_alert.id,
            "title": new_alert.title,
            "severity": new_alert.severity
        })
    
    return {
        "success": True,
        "severity_requested": severity,
        "alerts_created": alerts_created,
        "results": results
    }

@router.get("/simulator/history")
def get_simulation_history():
    """
    Get history of all simulated events in current session
    """
    return {
        "total_events_simulated": len(simulator.event_history),
        "history": simulator.event_history[-20:]  # Last 20 events
    }

@router.delete("/simulator/history")
def clear_simulation_history():
    """
    Clear simulation history
    """
    simulator.event_history.clear()
    return {
        "success": True,
        "message": "Simulation history cleared"
    }
