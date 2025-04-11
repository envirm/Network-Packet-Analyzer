import os
from pydantic import BaseSettings


class Settings(BaseSettings):
    # Basic App Config
    APP_NAME: str = "FastAPI Security Monitoring System"
    DEBUG: bool = True
    VERSION: str = "1.0.0"

    # Firewall file
    FIREWALL_STATE_FILE: str = "firewall_state.json"

    # CORS
    ALLOWED_ORIGINS: list[str] = ["*"]  # You can restrict this in production

    # Logging
    LOG_LEVEL: str = "INFO"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
