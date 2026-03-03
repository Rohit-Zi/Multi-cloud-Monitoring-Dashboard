import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    PROJECT_NAME: str = "Multi-Cloud Security Backend"
    VERSION: str = "1.0.0"

    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "sqlite:///./multicloud_backend.db"
    )

    SECRET_KEY: str = os.getenv(
        "SECRET_KEY",
        "supersecretkey"
    )


settings = Settings()
