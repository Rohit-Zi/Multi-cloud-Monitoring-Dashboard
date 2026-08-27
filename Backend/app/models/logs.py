"""
Log Model - Stores generated logs linked to alerts
Each alert has one or more logs associated with it
"""
from sqlalchemy import Column, String, DateTime, Text
from app.db.database import Base
from datetime import datetime
import uuid


class Log(Base):
    __tablename__ = "logs"

    log_id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))

    alert_id = Column(String, nullable=True)  

    cloud = Column(String, nullable=False)
    provider = Column(String, nullable=False)

    event_source = Column(String, nullable=True)
    event_name = Column(String, nullable=True)
    event_category = Column(String, nullable=True)

    user = Column(String, nullable=True)
    source_ip = Column(String, nullable=True)
    region = Column(String, nullable=True)
    resource = Column(String, nullable=True)

    outcome = Column(String, nullable=True)
    error_code = Column(String, nullable=True)

    timestamp = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    raw_log = Column(Text, nullable=True)

    # NEW: the source system's own unique event ID (e.g. CloudTrail's EventId).
    # Nullable because simulator-generated logs have no real source event.
    # Unique so the database itself refuses a duplicate insert, even if our
    # own dedup check somehow gets bypassed -- belt and suspenders.
    source_event_id = Column(String, nullable=True, unique=True)

    def to_dict(self):
        return {
            "log_id": self.log_id,
            "alert_id": self.alert_id,
            "cloud": self.cloud,
            "provider": self.provider,
            "event_source": self.event_source,
            "event_name": self.event_name,
            "event_category": self.event_category,
            "user": self.user,
            "source_ip": self.source_ip,
            "region": self.region,
            "resource": self.resource,
            "outcome": self.outcome,
            "error_code": self.error_code,
            "timestamp": self.timestamp,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "raw_log": self.raw_log,
            "source_event_id": self.source_event_id,
        }