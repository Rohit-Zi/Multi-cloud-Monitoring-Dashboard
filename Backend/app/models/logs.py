"""
Log Model - Stores generated logs linked to alerts
Each alert has one or more logs associated with it
"""
from sqlalchemy import Column, String, DateTime, Text
from sqlalchemy.orm import relationship
from app.db.database import Base
from datetime import datetime
import uuid


class Log(Base):
    __tablename__ = "logs"

    log_id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))

    alert_id = Column(String, nullable=False)  # FK to alerts.id

    cloud = Column(String, nullable=False)          # AWS / Azure / GCP / OCI / Cloudflare
    provider = Column(String, nullable=False)        # aws / azure / gcp / oci / cloudflare

    event_source = Column(String, nullable=True)     # iam.amazonaws.com / Microsoft.Authorization
    event_name = Column(String, nullable=True)       # root_account_login / DeleteDetector
    event_category = Column(String, nullable=True)   # Authentication / Configuration / DataAccess

    user = Column(String, nullable=True)             # who triggered the event
    source_ip = Column(String, nullable=True)        # IP address of the caller
    region = Column(String, nullable=True)           # cloud region
    resource = Column(String, nullable=True)         # affected resource ARN/ID

    outcome = Column(String, nullable=True)          # Success / Failed / Unknown
    error_code = Column(String, nullable=True)       # AccessDenied / NoSuchBucket etc

    timestamp = Column(String, nullable=True)        # when event occurred
    created_at = Column(DateTime, default=datetime.utcnow)

    raw_log = Column(Text, nullable=True)            # complete fake cloud log as JSON string

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
            "raw_log": self.raw_log
        }