from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.db.database import engine
from app.models import alert
from app.api import alerts
from app.models import alert, user, logs, insight
from app.api import alerts, simulator
from app.api.log_router import router as log_router
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    swagger_ui_parameters={
        "docExpansion": "none",   # collapse endpoints
        "defaultModelsExpandDepth": -1  # hide schema models
    }
   
)
app.include_router(log_router)

alert.Base.metadata.create_all(bind=engine)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(alerts.router)
app.include_router(simulator.router)


@app.get("/")
def root():
    return {
        "status": "running",
        "message": "Backend is alive"
    }
