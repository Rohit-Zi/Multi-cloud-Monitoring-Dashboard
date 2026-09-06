"""
Resource Model - Stores real cloud resource inventory (EC2 instances,
S3 buckets, IAM users, etc.) discovered via cloud provider APIs.

Distinct from Alert.resource (a plain string name attached to an alert) --
this is the actual inventory: one row per real resource, refreshed on
each sync/poll cycle, independent of whether that resource ever triggered
an alert.
"""
from sqlalchemy import Column, String, DateTime, Text
from app.db.database import Base
from datetime import datetime, timezone
import uuid


class Resource(Base):
    __tablename__ = "resources"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))

    # The resource's own ID from the cloud provider (e.g. "i-0abc123",
    # "my-bucket-name", "arn:aws:iam::...:user/dev"). This is what we
    # de-dupe/upsert on -- NOT our internal `id` above.
    resource_id = Column(String, nullable=False, unique=True)

    cloud = Column(String, nullable=False)      # "AWS", "Azure", "GCP" (display)
    provider = Column(String, nullable=False)   # "aws", "azure", "gcp" (lowercase, for filtering)

    type = Column(String, nullable=False)       # "vm", "storage", "iam_user", etc.
    name = Column(String, nullable=True)        # human-friendly name, if one exists
    region = Column(String, nullable=True)
    status = Column(String, nullable=True)      # "running", "stopped", "active", etc.

    # Full raw metadata from the provider API, stored as a JSON string.
    # Lets the frontend detail view show everything without us having to
    # predict every field we'll ever want up front.
    raw_metadata = Column(Text, nullable=True)

    source = Column(String, default="real")     # matches Log/Alert pattern -- real vs simulated

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_synced_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id": self.id,
            "resource_id": self.resource_id,
            "cloud": self.cloud,
            "provider": self.provider,
            "type": self.type,
            "name": self.name,
            "region": self.region,
            "status": self.status,
            "raw_metadata": self.raw_metadata,
            "source": self.source,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_synced_at": self.last_synced_at.isoformat() if self.last_synced_at else None,
        }