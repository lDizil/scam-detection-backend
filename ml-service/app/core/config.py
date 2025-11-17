"""
Конфигурация ML сервиса
"""

from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Настройки приложения"""

    # API настройки
    API_V1_PREFIX: str = "/api/v1"
    PROJECT_NAME: str = "Scam Detection ML Service"
    VERSION: str = "1.0.0"

    # Модель
    MODEL_NAME: str = "ealvaradob/bert-finetuned-phishing"
    MODEL_CACHE_DIR: str = "./models_cache"
    MAX_LENGTH: int = 512

    # Пороги для классификации
    PHISHING_THRESHOLD: float = 0.5  # Порог для определения фишинга

    # Опционально: путь к локальной дообученной модели
    CUSTOM_MODEL_PATH: Optional[str] = None

    # Training настройки
    TRAINING_DATA_PATH: str = "./training/data"
    TRAINED_MODELS_PATH: str = "./training/models"

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
