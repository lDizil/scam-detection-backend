FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ffmpeg \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    || (sleep 5 && apt-get update && apt-get install -y --no-install-recommends curl ffmpeg ca-certificates && rm -rf /var/lib/apt/lists/*)

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1

COPY requirements.txt .

RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install --system --no-cache setuptools && \
    uv pip install --system --no-cache \
    torch==2.5.1+cpu --index-url https://download.pytorch.org/whl/cpu && \
    uv pip install --system --no-cache --no-build-isolation openai-whisper==20240930 && \
    uv pip install --system --no-cache --index-strategy unsafe-best-match -r requirements.txt

COPY ./app ./app

RUN mkdir -p /app/models_cache

RUN python -c "import whisper; whisper.load_model('small', download_root='/root/.cache/whisper')" || echo "Whisper model download skipped"

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]