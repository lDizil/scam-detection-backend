from fastapi import APIRouter, HTTPException, status
from time import time
import logging

from app.models.schemas import (
    TextAnalysisRequest,
    TextAnalysisResponse,
    BatchTextAnalysisRequest,
    BatchTextAnalysisResponse,
    HealthResponse,
    ErrorResponse,
    PredictionResult,
)
from app.services.model_service import model_service
from app.core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Проверка здоровья сервиса",
    description="Возвращает статус сервиса и информацию о загруженной модели",
)
async def health_check():
    return HealthResponse(
        status="healthy" if model_service.model_loaded else "unhealthy",
        model_loaded=model_service.model_loaded,
        model_name=settings.CUSTOM_MODEL_PATH or settings.MODEL_NAME,
        version=settings.VERSION,
    )


@router.post(
    "/analyze/text",
    response_model=TextAnalysisResponse,
    responses={
        200: {"description": "Успешный анализ текста"},
        500: {"model": ErrorResponse, "description": "Ошибка при анализе"},
    },
    summary="Анализ текста на мошенничество",
    description="""
    Анализирует текст и определяет, является ли он фишинговым/мошенническим.
    
    **Что детектит модель:**
    - Фишинговые сообщения (поддельные банки, сервисы)
    - Срочные запросы личных данных (пароли, номера карт)
    - Подозрительные ссылки и призывы к действию
    - Манипуляции через страх ("аккаунт заблокирован") или жадность ("вы выиграли приз")
    - Запросы на перевод денег под предлогами
    
    **Примеры мошеннических текстов:**
    - "Срочно! Ваш аккаунт заблокирован. Перейдите по ссылке для разблокировки"
    - "Вы выиграли 1000000 рублей! Переведите 500р для получения приза"
    - "Ваша карта заблокирована. Подтвердите данные по ссылке"
    """,
)
async def analyze_text(request: TextAnalysisRequest):
    if not model_service.model_loaded:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Model not loaded"
        )

    try:
        start_time = time()
        prediction = await model_service.predict(request.text)
        processing_time = time() - start_time

        logger.info(
            f"Анализ текста завершен: label={prediction['label']}, "
            f"confidence={prediction['confidence']:.3f}, "
            f"time={processing_time:.3f}s"
        )

        return TextAnalysisResponse(
            success=True,
            prediction=PredictionResult(**prediction),
            processing_time=processing_time,
        )

    except Exception as e:
        logger.error(f"Ошибка при анализе текста: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )


@router.post(
    "/analyze/batch",
    response_model=BatchTextAnalysisResponse,
    responses={
        200: {"description": "Успешный пакетный анализ"},
        500: {"model": ErrorResponse, "description": "Ошибка при анализе"},
    },
    summary="Пакетный анализ текстов",
    description="Анализирует несколько текстов за один запрос (до 100 текстов)",
)
async def analyze_batch(request: BatchTextAnalysisRequest):
    if not model_service.model_loaded:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Model not loaded"
        )

    try:
        start_time = time()
        predictions = await model_service.predict_batch(request.texts)
        processing_time = time() - start_time

        logger.info(
            f"Пакетный анализ завершен: {len(predictions)} текстов, "
            f"time={processing_time:.3f}s"
        )

        return BatchTextAnalysisResponse(
            success=True,
            predictions=[PredictionResult(**pred) for pred in predictions],
            processing_time=processing_time,
        )

    except Exception as e:
        logger.error(f"Ошибка при пакетном анализе: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )
