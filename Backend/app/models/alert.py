import uuid
from sqlalchemy import Column, String, DateTime, Text
from sqlalchemy.sql import func
from app.db.database import Base
from datetime import datetime, timezone


class Alert(Base):
    __tablename__ = "alerts"

    id          = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    cloud       = Column(String, nullable=False)
    severity    = Column(String, nullable=False) 
    title       = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    created_at  = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    status      = Column(String, default="detected")  # detected, open, investigating, mitigated, resolved, archived
    provider    = Column(String, nullable=False)       # aws, azure, gcp, oci, cloudflare

    log_id      = Column(String, nullable=True)      # FK to logs.log_id, can be null if alert created without log (e.g. manual alert)