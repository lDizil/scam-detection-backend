import whisper
import logging
import tempfile
import os
from typing import Optional
import ffmpeg

logger = logging.getLogger(__name__)

# Лимиты для видео
MAX_VIDEO_SIZE_MB = 50
MAX_VIDEO_DURATION_SEC = 300


class VideoService:
    def __init__(self):
        self.model: Optional[whisper.Whisper] = None
        self.loaded = False

    async def load_model(self):
        try:
            logger.info("Загрузка Whisper модели (small)...")
            self.model = whisper.load_model("small")
            self.loaded = True
            logger.info("Whisper модель успешно загружена!")
        except Exception as e:
            logger.error(f"Ошибка при загрузке Whisper: {e}")
            self.loaded = False
            raise

    def _extract_audio(self, video_path: str, audio_path: str) -> bool:
        try:
            (
                ffmpeg.input(video_path)
                .output(audio_path, acodec="pcm_s16le", ac=1, ar="16000")
                .overwrite_output()
                .run(quiet=True)
            )
            return True
        except ffmpeg.Error as e:
            logger.error(f"Ошибка извлечения аудио: {e}")
            return False

    def _get_video_duration(self, video_path: str) -> float:
        try:
            probe = ffmpeg.probe(video_path)
            duration = float(probe["format"]["duration"])
            return duration
        except Exception as e:
            logger.error(f"Ошибка получения длительности: {e}")
            return 0

    async def transcribe_video(self, video_bytes: bytes, filename: str) -> dict:
        """
        Транскрибирует аудио из видео.

        Returns:
            dict: {
                "transcription": str,
                "duration": float,
                "language": str
            }
        """
        if not self.loaded:
            raise RuntimeError("Whisper модель не загружена")

        size_mb = len(video_bytes) / (1024 * 1024)
        if size_mb > MAX_VIDEO_SIZE_MB:
            raise ValueError(
                f"Размер видео {size_mb:.1f}MB превышает лимит {MAX_VIDEO_SIZE_MB}MB"
            )

        with tempfile.TemporaryDirectory() as temp_dir:
            video_path = os.path.join(temp_dir, filename)
            audio_path = os.path.join(temp_dir, "audio.wav")

            with open(video_path, "wb") as f:
                f.write(video_bytes)

            duration = self._get_video_duration(video_path)
            if duration > MAX_VIDEO_DURATION_SEC:
                raise ValueError(
                    f"Длительность видео {duration:.0f}с превышает лимит {MAX_VIDEO_DURATION_SEC}с (5 минут)"
                )

            logger.info(f"Извлечение аудио из {filename}...")
            if not self._extract_audio(video_path, audio_path):
                raise RuntimeError("Не удалось извлечь аудио из видео")

            logger.info("Транскрибация аудио через Whisper...")
            result = self.model.transcribe(audio_path, language="ru", task="transcribe")

            transcription = result["text"].strip()
            detected_language = result.get("language", "ru")

            logger.info(
                f"Транскрибировано {len(transcription)} символов, язык: {detected_language}"
            )

            return {
                "transcription": transcription,
                "duration": duration,
                "language": detected_language,
            }


video_service = VideoService()
