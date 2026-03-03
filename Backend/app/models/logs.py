from sqlalchemy import Column, String, ForeignKey
from app.db.database import Base


class Log(Base):
    __tablename__ = "logs"
    log_id = Column(String, primary_key=True)
    alert_id = Column(String, ForeignKey("alerts.id"))