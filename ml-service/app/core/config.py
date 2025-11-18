from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    API_V1_PREFIX: str = "/api/v1"
    PROJECT_NAME: str = "Scam Detection ML Service"
    VERSION: str = "1.0.0"

    # RUSpam/spam_deberta_v4 - специализированная модель для русского спама
    # Обучена на русских SMS/emails, точность >95%
    MODEL_NAME: str = "RUSpam/spam_deberta_v4"
    MODEL_CACHE_DIR: str = "./models_cache"
    MAX_LENGTH: int = 128

    # Порог для классификации (0.95 = 95% уверенности)
    # Модель переобучена, поэтому ставим высокий порог
    PHISHING_THRESHOLD: float = 0.95

    # Опциональная модель-переводчик (backwards compatibility)
    # Если в контейнере остался код с переводчиком, наличие этого
    # поля предотвратит AttributeError при старой версии кода.
    TRANSLATOR_MODEL: Optional[str] = None

    CUSTOM_MODEL_PATH: Optional[str] = None

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
