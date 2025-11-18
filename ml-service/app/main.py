"""
Главный файл FastAPI приложения
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging

from app.core.config import settings
from app.api.endpoints import router
from app.services.model_service import model_service

# Настройка логирования
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Управление жизненным циклом приложения"""
    logger.info("🚀 Запуск ML сервиса...")
    try:
        await model_service.load_model()
        logger.info("✅ ML сервис готов к работе!")
    except Exception as e:
        logger.error(f"❌ Ошибка при загрузке модели: {e}")
        raise

    yield

    logger.info("🛑 Остановка ML сервиса...")


# Создаем FastAPI приложение
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="""
    ## ML сервис для детекции мошеннических текстов
    
    ### Архитектура модели:
    - **Базовая модель**: BERT (Bidirectional Encoder Representations from Transformers)
    - **Дообученная модель**: ealvaradob/bert-finetuned-phishing
    - **Задача**: Бинарная классификация (phishing vs legitimate)
    
    ### Что детектирует:
    ✅ Фишинговые сообщения от поддельных банков и сервисов  
    ✅ Срочные запросы личных данных (пароли, карты, коды)  
    ✅ Подозрительные ссылки и призывы к действию  
    ✅ Манипуляции через страх или жадность  
    ✅ Запросы на перевод денег под различными предлогами  
    
    ### Endpoints:
    - `GET /health` - Проверка статуса сервиса
    - `POST /api/v1/analyze/text` - Анализ одного текста
    - `POST /api/v1/analyze/batch` - Пакетный анализ текстов
    
    ### Возможности дообучения:
    Сервис поддерживает загрузку кастомных дообученных моделей через переменную окружения `CUSTOM_MODEL_PATH`
    """,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:8080",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix=settings.API_V1_PREFIX, tags=["ML Analysis"])


@app.get("/", tags=["Root"])
async def root():
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "running",
        "model_loaded": model_service.model_loaded,
        "docs": "/docs",
    }
