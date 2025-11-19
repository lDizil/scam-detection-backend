# ML Service для детекции мошенничества

Python FastAPI сервис для анализа текстов на предмет мошенничества и фишинга.

## Архитектура

```
ml-service/
├── app/
│   ├── api/
│   │   └── endpoints.py          # API endpoints
│   ├── core/
│   │   └── config.py             # Конфигурация
│   ├── models/
│   │   └── schemas.py            # Pydantic схемы
│   ├── services/
│   │   └── model_service.py      # ML модель и инференс
│   └── main.py                   # FastAPI приложение
├── Dockerfile
├── requirements.txt
└── .env.example
```

## Модель

### Базовая модель: `ealvaradob/bert-finetuned-phishing`

**Архитектура:**

- **BERT** (Bidirectional Encoder Representations from Transformers)
- 12 слоев трансформеров
- 110M параметров
- Максимальная длина последовательности: 512 токенов

**Обучение:**

- Предобучена на огромном корпусе текстов (Wikipedia, BookCorpus)
- Дообучена на датасете фишинговых сообщений
- Бинарная классификация: phishing (1) vs legitimate (0)

**Что детектирует:**

- Фишинговые сообщения от поддельных банков и сервисов
- Срочные запросы личных данных (пароли, карты, CVV коды)
- Подозрительные ссылки и призывы к действию
- Манипуляции через страх ("аккаунт заблокирован", "подозрительная активность")
- Манипуляции через жадность ("вы выиграли приз", "получите миллион")
- Запросы на перевод денег под различными предлогами

**Что НЕ детектирует:**

- Токсичность и оскорбления (нужна другая модель)
- Грамматические ошибки
- Общий стиль текста

### Как работает инференс

1. **Токенизация**: Текст разбивается на токены (слова/подслова)
2. **Энкодинг**: Токены конвертируются в числовые ID
3. **Padding/Truncation**: Короткие тексты дополняются, длинные обрезаются до 512 токенов
4. **Forward Pass**: Текст проходит через 12 слоев BERT
5. **Classification Head**: Финальный слой выдает логиты для 2 классов
6. **Softmax**: Логиты конвертируются в вероятности
7. **Prediction**: Выбирается класс с максимальной вероятностью

## Быстрый старт

### 1. Установка зависимостей

```bash
cd ml-service
pip install -r requirements.txt
```

### 2. Настройка окружения

```bash
cp .env.example .env
```

### 3. Запуск сервиса

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Сервис будет доступен:

- API: http://localhost:8000
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

### 4. Запуск в Docker

```bash
docker build -t scam-detection-ml .
docker run -p 8000:8000 scam-detection-ml
```

## API Endpoints

### `GET /health`

Проверка здоровья сервиса

**Response:**

```json
{
  "status": "healthy",
  "model_loaded": true,
  "model_name": "ealvaradob/bert-finetuned-phishing",
  "version": "1.0.0"
}
```

### `POST /api/v1/analyze/text`

Анализ одного текста

**Request:**

```json
{
  "text": "Срочно! Ваш аккаунт заблокирован. Перейдите по ссылке для разблокировки"
}
```

**Response:**

```json
{
  "success": true,
  "prediction": {
    "label": "phishing",
    "confidence": 0.95,
    "is_scam": true
  },
  "processing_time": 0.234
}
```

### `POST /api/v1/analyze/batch`

Пакетный анализ текстов (до 100 за раз)

**Request:**

```json
{
  "texts": [
    "Вы выиграли 1000000 рублей! Переведите 500р для получения приза",
    "Привет, как дела? Созвонимся завтра?"
  ]
}
```

**Response:**

```json
{
  "success": true,
  "predictions": [
    {
      "label": "phishing",
      "confidence": 0.98,
      "is_scam": true
    },
    {
      "label": "legitimate",
      "confidence": 0.92,
      "is_scam": false
    }
  ],
  "processing_time": 0.456
}
```

## Конфигурация

Все настройки в `.env`:

```env
MODEL_NAME=ealvaradob/bert-finetuned-phishing
MODEL_CACHE_DIR=./models_cache
MAX_LENGTH=512
PHISHING_THRESHOLD=0.5
```

## Тестирование

Примеры запросов через curl:

```bash
# Health check
curl http://localhost:8000/health

# Анализ текста
curl -X POST http://localhost:8000/api/v1/analyze/text \
  -H "Content-Type: application/json" \
  -d '{"text": "Срочно! Ваш аккаунт заблокирован"}'

# Пакетный анализ
curl -X POST http://localhost:8000/api/v1/analyze/batch \
  -H "Content-Type: application/json" \
  -d '{"texts": ["Вы выиграли приз", "Привет, как дела?"]}'
```

## Производительность

**Железо:**

- CPU: ~0.2-0.5s на текст
- GPU (CUDA): ~0.05-0.1s на текст

**Оптимизация:**

- Используйте batch endpoints для нескольких текстов
- Модель загружается один раз при старте

## Интеграция с Go Backend

Пример вызова из Go:

```go
type MLRequest struct {
    Text string `json:"text"`
}

type MLResponse struct {
    Success    bool `json:"success"`
    Prediction struct {
        Label      string  `json:"label"`
        Confidence float64 `json:"confidence"`
        IsScam     bool    `json:"is_scam"`
    } `json:"prediction"`
}

func AnalyzeText(text string) (*MLResponse, error) {
    reqBody, _ := json.Marshal(MLRequest{Text: text})

    resp, err := http.Post(
        "http://ml-service:8000/api/v1/analyze/text",
        "application/json",
        bytes.NewBuffer(reqBody),
    )
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var result MLResponse
    json.NewDecoder(resp.Body).Decode(&result)
    return &result, nil
}
```

## Лицензия

MIT
