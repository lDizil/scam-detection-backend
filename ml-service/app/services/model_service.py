import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from typing import Dict, List, Tuple
import logging

from app.core.config import settings

logger = logging.getLogger(__name__)


class ModelService:
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.device = None
        self.model_loaded = False

    async def load_model(self):
        try:
            logger.info("Начинаю загрузку модели...")

            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            logger.info(f"Используется устройство: {self.device}")

            if self.device.type == "cpu":
                torch.set_num_threads(4)
                logger.info("CPU режим: ограничено 4 потока")

            model_path = settings.CUSTOM_MODEL_PATH or settings.MODEL_NAME

            logger.info(f"Загрузка токенизатора из {model_path}...")
            self.tokenizer = AutoTokenizer.from_pretrained(
                model_path, cache_dir=settings.MODEL_CACHE_DIR, local_files_only=False
            )

            logger.info(f"Загрузка модели из {model_path} (оптимизация памяти)...")
            self.model = AutoModelForSequenceClassification.from_pretrained(
                model_path,
                cache_dir=settings.MODEL_CACHE_DIR,
                torch_dtype=torch.float32,
                low_cpu_mem_usage=True,
                local_files_only=False,
            )

            logger.info("Перенос модели на устройство...")
            self.model.to(self.device)
            self.model.eval()

            import gc

            gc.collect()
            if torch.cuda.is_available():
                torch.cuda.empty_cache()

            self.model_loaded = True
            logger.info("Модель успешно загружена!")

        except Exception as e:
            logger.error(f"Ошибка при загрузке модели: {e}")
            self.model_loaded = False
            raise

    def _preprocess(self, text: str) -> Dict:
        inputs = self.tokenizer(
            text,
            padding=True,
            truncation=True,
            max_length=settings.MAX_LENGTH,
            return_tensors="pt",
        )

        inputs = {key: val.to(self.device) for key, val in inputs.items()}
        return inputs

    def _postprocess(self, outputs) -> Tuple[str, float, bool]:
        logits = outputs.logits
        probabilities = torch.nn.functional.softmax(logits, dim=-1)
        predicted_class = torch.argmax(probabilities, dim=-1).item()
        confidence = probabilities[0][predicted_class].item()

        label = "phishing" if predicted_class == 1 else "legitimate"
        is_scam = predicted_class == 1 and confidence >= settings.PHISHING_THRESHOLD

        return label, confidence, is_scam

    async def predict(self, text: str) -> Dict:
        if not self.model_loaded:
            raise RuntimeError("Model not loaded")

        try:
            inputs = self._preprocess(text)

            with torch.no_grad():
                outputs = self.model(**inputs)

            label, confidence, is_scam = self._postprocess(outputs)

            return {"label": label, "confidence": confidence, "is_scam": is_scam}

        except Exception as e:
            logger.error(f"Ошибка при предсказании: {e}")
            raise

    async def predict_batch(self, texts: List[str]) -> List[Dict]:
        if not self.model_loaded:
            raise RuntimeError("Model not loaded")

        try:
            inputs = self.tokenizer(
                texts,
                padding=True,
                truncation=True,
                max_length=settings.MAX_LENGTH,
                return_tensors="pt",
            )

            inputs = {key: val.to(self.device) for key, val in inputs.items()}

            with torch.no_grad():
                outputs = self.model(**inputs)

            logits = outputs.logits
            probabilities = torch.nn.functional.softmax(logits, dim=-1)
            predicted_classes = torch.argmax(probabilities, dim=-1)

            results = []
            for i in range(len(texts)):
                predicted_class = predicted_classes[i].item()
                confidence = probabilities[i][predicted_class].item()
                label = "phishing" if predicted_class == 1 else "legitimate"
                is_scam = (
                    predicted_class == 1 and confidence >= settings.PHISHING_THRESHOLD
                )

                results.append(
                    {"label": label, "confidence": confidence, "is_scam": is_scam}
                )

            return results

        except Exception as e:
            logger.error(f"Ошибка при батч-предсказании: {e}")
            raise


model_service = ModelService()
