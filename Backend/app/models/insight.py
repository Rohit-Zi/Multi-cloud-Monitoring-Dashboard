from sqlalchemy import Column, String, ForeignKey, Text
from app.db.database import Base



class Insight(Base):
    __tablename__ = "insights"
    insight_id = Column(String, primary_key=True)
    alert_id = Column(String, ForeignKey("alerts.id"))
    description = Column(Text)