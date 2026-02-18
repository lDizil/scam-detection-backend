import logging
from time import time

from fastapi import APIRouter, File, HTTPException, UploadFile, status

from app.core.config import settings
from app.models.schemas import (
    BatchTextAnalysisRequest,
    BatchTextAnalysisResponse,
    ErrorResponse,
    HealthResponse,
    ImageAnalysisResponse,
    PredictionResult,
    TextAnalysisRequest,
    TextAnalysisResponse,
    VideoAnalysisResponse,
)
from app.services.image_service import image_service
from app.services.model_service import model_service
from app.services.video_service import video_service

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
        status="healthy"
        if model_service.model_loaded and image_service.loaded and video_service.loaded
        else "unhealthy",
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
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


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
            f"Пакетный анализ завершен: {len(predictions)} текстов, time={processing_time:.3f}s"
        )

        return BatchTextAnalysisResponse(
            success=True,
            predictions=[PredictionResult(**pred) for pred in predictions],
            processing_time=processing_time,
        )

    except Exception as e:
        logger.error(f"Ошибка при пакетном анализе: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post(
    "/analyze/image",
    response_model=ImageAnalysisResponse,
    responses={
        200: {"description": "Успешный анализ изображения"},
        400: {"model": ErrorResponse, "description": "Неверный формат файла"},
        500: {"model": ErrorResponse, "description": "Ошибка при анализе"},
    },
    summary="Анализ изображения на мошенничество",
    description="""
    Извлекает текст из изображения (OCR) и анализирует его на предмет мошенничества.

    **Что детектит:**
    - Скриншоты поддельных банковских уведомлений
    - Фейковые QR-коды с просьбами оплаты
    - Объявления о "выигрышах" с реквизитами
    - Мошеннические рекламные баннеры
    - Фишинговые формы ввода данных

    **Поддерживаемые форматы:** JPG, JPEG, PNG, BMP, TIFF
    """,
)
async def analyze_image(file: UploadFile = File(...)):
    if not model_service.model_loaded or not image_service.loaded:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Models not loaded",
        )

    allowed_types = ["image/jpeg", "image/jpg", "image/png", "image/bmp", "image/tiff"]
    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Неподдерживаемый формат файла. Поддерживаются: {', '.join(allowed_types)}",
        )

    try:
        start_time = time()

        image_bytes = await file.read()

        logger.info(f"Извлечение текста из изображения {file.filename}...")
        extracted_text = await image_service.extract_text_from_image(image_bytes)

        if not extracted_text:
            return ImageAnalysisResponse(
                success=True,
                extracted_text="",
                prediction=PredictionResult(label="legitimate", confidence=0.0, is_scam=False),
                processing_time=time() - start_time,
                message="Текст не обнаружен на изображении",
            )

        logger.info(f"Анализ извлеченного текста: {extracted_text[:100]}...")
        prediction = await model_service.predict(extracted_text)

        processing_time = time() - start_time

        logger.info(
            f"Анализ изображения завершен: extracted_chars={len(extracted_text)}, "
            f"label={prediction['label']}, confidence={prediction['confidence']:.3f}, "
            f"time={processing_time:.3f}s"
        )

        return ImageAnalysisResponse(
            success=True,
            extracted_text=extracted_text,
            prediction=PredictionResult(**prediction),
            processing_time=processing_time,
        )

    except Exception as e:
        logger.error(f"Ошибка при анализе изображения: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post(
    "/analyze/video",
    response_model=VideoAnalysisResponse,
    responses={
        200: {"description": "Успешный анализ видео"},
        400: {
            "model": ErrorResponse,
            "description": "Неверный формат или превышен лимит",
        },
        500: {"model": ErrorResponse, "description": "Ошибка при анализе"},
    },
    summary="Анализ видео на мошенничество",
    description="""
    Извлекает аудио из видео, транскрибирует речь через Whisper и анализирует текст.

    **Что детектит:**
    - Видеозвонки от "службы безопасности банка"
    - Записи с просьбами перевести деньги
    - Видеоинструкции по "выводу выигрыша"
    - Голосовые сообщения с манипуляциями

    **Ограничения:**
    - Максимальный размер: 50MB
    - Максимальная длительность: 5 минут

    **Поддерживаемые форматы:** MP4, AVI, MOV, MKV, WEBM
    """,
)
async def analyze_video(file: UploadFile = File(...)):
    if not model_service.model_loaded or not video_service.loaded:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Models not loaded",
        )

    allowed_types = [
        "video/mp4",
        "video/avi",
        "video/quicktime",
        "video/x-msvideo",
        "video/x-matroska",
        "video/webm",
    ]
    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Неподдерживаемый формат. Поддерживаются: MP4, AVI, MOV, MKV, WEBM",
        )

    try:
        start_time = time()

        video_bytes = await file.read()

        logger.info(
            f"Транскрибация видео {file.filename} ({len(video_bytes) / 1024 / 1024:.1f}MB)..."
        )

        transcription_result = await video_service.transcribe_video(video_bytes, file.filename)
        transcription = transcription_result["transcription"]
        duration = transcription_result["duration"]
        language = transcription_result["language"]

        if not transcription:
            return VideoAnalysisResponse(
                success=True,
                transcription="",
                duration=duration,
                language=language,
                prediction=PredictionResult(label="legitimate", confidence=0.0, is_scam=False),
                processing_time=time() - start_time,
                message="Речь не обнаружена в видео",
            )

        logger.info(f"Анализ транскрипции: {transcription[:100]}...")
        prediction = await model_service.predict(transcription)

        processing_time = time() - start_time

        logger.info(
            f"Анализ видео завершен: duration={duration:.1f}s, chars={len(transcription)}, "
            f"label={prediction['label']}, confidence={prediction['confidence']:.3f}, "
            f"time={processing_time:.3f}s"
        )

        return VideoAnalysisResponse(
            success=True,
            transcription=transcription,
            duration=duration,
            language=language,
            prediction=PredictionResult(**prediction),
            processing_time=processing_time,
        )

    except ValueError as e:
        logger.warning(f"Ошибка валидации видео: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Ошибка при анализе видео: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
