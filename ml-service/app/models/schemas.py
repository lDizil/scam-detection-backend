from pydantic import BaseModel, Field
from typing import Optional, List


class TextAnalysisRequest(BaseModel):
    text: str = Field(
        ..., min_length=1, max_length=5000, description="Текст для анализа"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "text": "Срочно! Ваш аккаунт заблокирован. Перейдите по ссылке для разблокировки"
            }
        }


class PredictionResult(BaseModel):
    label: str = Field(..., description="Метка класса (phishing/legitimate)")
    confidence: float = Field(..., ge=0, le=1, description="Уверенность модели (0-1)")
    is_scam: bool = Field(..., description="Является ли текст мошенническим")

    class Config:
        json_schema_extra = {
            "example": {"label": "phishing", "confidence": 0.95, "is_scam": True}
        }


class TextAnalysisResponse(BaseModel):
    success: bool = Field(..., description="Успешность операции")
    prediction: PredictionResult = Field(..., description="Результат предсказания")
    processing_time: float = Field(..., description="Время обработки в секундах")

    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "prediction": {
                    "label": "phishing",
                    "confidence": 0.95,
                    "is_scam": True,
                },
                "processing_time": 0.234,
            }
        }


class BatchTextAnalysisRequest(BaseModel):
    texts: List[str] = Field(
        ..., min_length=1, max_length=100, description="Список текстов для анализа"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "texts": [
                    "Вы выиграли 1000000 рублей! Переведите 500р для получения приза",
                    "Привет, как дела? Созвонимся завтра?",
                ]
            }
        }


class BatchTextAnalysisResponse(BaseModel):
    success: bool = Field(..., description="Успешность операции")
    predictions: List[PredictionResult] = Field(..., description="Список результатов")
    processing_time: float = Field(..., description="Общее время обработки")

    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "predictions": [
                    {"label": "phishing", "confidence": 0.98, "is_scam": True},
                    {"label": "legitimate", "confidence": 0.92, "is_scam": False},
                ],
                "processing_time": 0.456,
            }
        }


class HealthResponse(BaseModel):
    status: str = Field(..., description="Статус сервиса")
    model_loaded: bool = Field(..., description="Загружена ли модель")
    model_name: str = Field(..., description="Название используемой модели")
    version: str = Field(..., description="Версия сервиса")

    class Config:
        json_schema_extra = {
            "example": {
                "status": "healthy",
                "model_loaded": True,
                "model_name": "ealvaradob/bert-finetuned-phishing",
                "version": "1.0.0",
            }
        }


class ErrorResponse(BaseModel):
    success: bool = Field(False, description="Успешность операции")
    error: str = Field(..., description="Описание ошибки")

    class Config:
        json_schema_extra = {"example": {"success": False, "error": "Model not loaded"}}
