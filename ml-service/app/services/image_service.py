import easyocr
import logging
from typing import Optional
from PIL import Image
import io
import numpy as np
import re

logger = logging.getLogger(__name__)


class ImageService:
    def __init__(self):
        self.reader: Optional[easyocr.Reader] = None
        self.loaded = False

    async def load_reader(self):
        try:
            logger.info("Загрузка EasyOCR для русского и английского языков...")
            self.reader = easyocr.Reader(["ru", "en"], gpu=False, verbose=False)
            self.loaded = True
            logger.info("EasyOCR успешно загружен!")
        except Exception as e:
            logger.error(f"Ошибка при загрузке EasyOCR: {e}")
            self.loaded = False
            raise

    def _clean_ocr_text(self, text: str) -> str:

        text = re.sub(r"\[\d{1,2}:\d{2}(?::\d{2})?\]", "", text)
        text = re.sub(
            r"(?:^|\n)\d{3}\s\d{3}-\d{2}-\d{2}:\s*", " ", text, flags=re.MULTILINE
        )

        text = re.sub(r"\s+", " ", text)

        return text.strip()

    async def extract_text_from_image(self, image_bytes: bytes) -> str:
        if not self.loaded:
            raise RuntimeError("EasyOCR не загружен")

        try:
            image = Image.open(io.BytesIO(image_bytes))

            if image.mode == "RGBA":
                image = image.convert("RGB")

            image_array = np.array(image)

            result = self.reader.readtext(image_array, detail=0, paragraph=True)

            extracted_text = " ".join(result).strip()

            if extracted_text:
                extracted_text = self._clean_ocr_text(extracted_text)

            logger.info(f"Извлечено {len(extracted_text)} символов из изображения")

            if not extracted_text:
                logger.warning("Текст не обнаружен на изображении")
                return ""

            return extracted_text

        except Exception as e:
            logger.error(f"Ошибка при извлечении текста из изображения: {e}")
            raise


image_service = ImageService()
