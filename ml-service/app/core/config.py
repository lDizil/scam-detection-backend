from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    API_V1_PREFIX: str = "/api/v1"
    PROJECT_NAME: str = "Scam Detection ML Service"
    VERSION: str = "1.0.0"

    MODEL_NAME: str = "RUSpam/spam_deberta_v4"
    MODEL_CACHE_DIR: str = "./models_cache"
    MAX_LENGTH: int = 128

    PHISHING_THRESHOLD: float = 0.5

    CUSTOM_MODEL_PATH: Optional[str] = None

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
