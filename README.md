# Scam Detection Backend

REST API для определения мошеннического контента с использованием машинного обучения.

## Оглавление

- [Быстрый старт](#быстрый-старт)
- [Архитектура](#архитектура)
- [Технологии](#технологии)
- [API Endpoints](#api-endpoints)
- [ML Модель](#ml-модель)
- [Примеры использования](#примеры-использования)
- [Документация](#документация)
- [Безопасность](#безопасность)
- [Разработка](#разработка)

## Быстрый старт

### Docker Compose (рекомендуется)

```bash
# Клонировать репозиторий
git clone https://github.com/lDizil/scam-detection-backend.git
cd scam-detection-backend

# Запустить все сервисы
docker-compose up --build
```

**Готово!** Сервисы доступны:

- Backend API: http://localhost:8080
- Swagger UI: http://localhost:8080/swagger/index.html
- ML Service: http://localhost:8000
- ML Docs: http://localhost:8000/docs

### Первый запуск

**Важно:** ML Service при первом запуске скачивает модель (~440MB). Это займет 2-5 минут.

```bash
# Проверить статус
curl http://localhost:8000/health

# Должен вернуть:
# {"status": "healthy", "model_loaded": true, ...}
```

Полная инструкция: **[QUICKSTART.md](QUICKSTART.md)**

## Архitecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Client                               │
│               (Browser / Mobile App / API)                   │
└───────────────────────┬─────────────────────────────────────┘
                        │ HTTP/HTTPS
                        ▼
┌─────────────────────────────────────────────────────────────┐
│                   Go Backend (Port 8080)                     │
│  ┌──────────────────────────────────────────────────────┐   │
│  │   JWT Authentication (HttpOnly cookies)           │   │
│  │   User Management (Register/Login/Profile)        │   │
│  │   Argon2 Password Hashing                         │   │
│  │   Session Management (DB-backed)                  │   │
│  │   Auth Middleware                                 │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │     ML Client                                        │   │
│  │     → Proxy requests to ML Service                  │   │
│  └──────────────────────────────────────────────────────┘   │
└───────────┬───────────────────────────┬─────────────────────┘
            │                           │
            ▼                           ▼
┌─────────────────────┐    ┌────────────────────────────────┐
│   PostgreSQL 16     │    │  Python ML Service (Port 8000) │
│                     │    │  ┌──────────────────────────┐  │
│  • Users            │    │  │   BERT Model             │  │
│  • Sessions         │    │  │  (phishing detection)    │  │
│  • Refresh Tokens   │    │  └──────────────────────────┘  │
│                     │    │  ┌──────────────────────────┐  │
└─────────────────────┘    │  │  FastAPI Endpoints       │  │
                           │  │  • /analyze/text         │  │
                           │  │  • /analyze/batch        │  │
                           │  │  • /health               │  │
                           │  └──────────────────────────┘  │
                           └────────────────────────────────┘
```

### Компоненты:

**Backend (Go):**

- JWT аутентификация + сессии
- Управление пользователями
- API gateway для ML сервиса
- Swagger документация

**ML Service (Python):**

- FastAPI + BERT модель
- Детекция фишинга и мошенничества
- Поддержка дообучения
- Батч-обработка текстов

**Database (PostgreSQL):**

- Хранение пользователей
- Управление сессиями
- Refresh токены

## Технологии

**Backend:**

- Go 1.23 + Gin
- PostgreSQL 16
- JWT (HttpOnly cookies)
- Argon2 (хеширование паролей)
- Swagger UI
- Docker

**ML Service:**

- Python 3.11 + FastAPI
- PyTorch + Transformers
- BERT (ealvaradob/bert-finetuned-phishing)
- Docker

## Быстрый старт

```bash
# Запуск всех сервисов (Backend + PostgreSQL + ML Service)
docker-compose up --build
```

**Сервисы:**

- Backend API: http://localhost:8080
- Swagger UI: http://localhost:8080/swagger/index.html
- ML Service API: http://localhost:8000
- ML Service Docs: http://localhost:8000/docs
- PostgreSQL: localhost:5432

## Локальный запуск

```bash
# Запустить только PostgreSQL
docker-compose up postgres -d

# Backend (терминал 1)
go run ./cmd/server/main.go

# ML Service (терминал 2)
cd ml-service
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## API Endpoints

**Публичные:**

- `POST /api/v1/auth/register` - регистрация
- `POST /api/v1/auth/login` - вход (username или email)
- `POST /api/v1/auth/logout` - выход
- `POST /api/v1/auth/refresh` - обновить токены

**Защищённые (требуется JWT):**

- `GET /api/v1/profile` - получить профиль
- `PUT /api/v1/profile` - обновить профиль
- `DELETE /api/v1/account` - удалить аккаунт

**ML Analysis (защищённые):**

- `POST /api/v1/analysis/text` - анализ текста на мошенничество
- `POST /api/v1/analysis/batch` - пакетный анализ текстов
- `GET /api/v1/analysis/health` - статус ML сервиса

**Примеры:**

```bash
# Анализ текста (нужен JWT токен)
curl -X POST http://localhost:8080/api/v1/analysis/text \
  -H "Content-Type: application/json" \
  -H "Cookie: access_token=YOUR_TOKEN" \
  -d '{"text": "Срочно! Ваш аккаунт заблокирован. Перейдите по ссылке"}'

# Response:
# {
#   "success": true,
#   "prediction": {
#     "label": "phishing",
#     "confidence": 0.95,
#     "is_scam": true
#   },
#   "processing_time": 0.234
# }
```

## Переменные окружения

**Backend (.env):**

```env
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=password
DB_NAME=fraud_detection

SERVER_PORT=8080
SERVER_MODE=debug

JWT_SECRET=your-secret-key
JWT_ACCESS_DURATION=1h
JWT_REFRESH_DURATION=168h

# URL ML сервиса
ML_SERVICE_URL=http://localhost:8000
```

**ML Service (ml-service/.env):**

```env
MODEL_NAME=ealvaradob/bert-finetuned-phishing
MODEL_CACHE_DIR=./models_cache
PHISHING_THRESHOLD=0.5
# Опционально: путь к дообученной модели
# CUSTOM_MODEL_PATH=./training/models/my_model
```

## Структура

```
cmd/server/            - точка входа Backend
internal/
  ├── api/             - handlers, middleware, routes
  ├── config/          - конфигурация
  ├── crypto/          - Argon2 хеширование
  ├── jwt/             - JWT утилиты
  ├── mlclient/        - клиент для ML сервиса
  ├── models/          - модели данных
  ├── repository/      - работа с БД
  └── services/        - бизнес-логика

ml-service/            - ML сервис (Python)
  ├── app/
  │   ├── api/         - FastAPI endpoints
  │   ├── core/        - конфигурация
  │   ├── models/      - Pydantic схемы
  │   ├── services/    - ML модель и инференс
  │   └── main.py      - FastAPI приложение
  └── training/        - скрипты для дообучения модели
      ├── data/        - датасеты
      ├── models/      - дообученные модели
      └── train.py     - скрипт обучения
```

## ML Модель

**Модель:** `ealvaradob/bert-finetuned-phishing`

**Что детектирует:**

- Фишинговые сообщения от поддельных банков
- Срочные запросы личных данных (карты, пароли, CVV)
- Манипуляции через страх ("аккаунт заблокирован")
- Манипуляции через жадность ("вы выиграли приз")
- Подозрительные ссылки и призывы к действию

**Примеры мошеннических текстов:**

- "Срочно! Ваш аккаунт заблокирован. Перейдите по ссылке"
- "Вы выиграли 1000000 рублей! Переведите 500р для получения"
- "Подтвердите данные карты по ссылке"

**Дообучение:**

Вы можете дообучить модель на своих данных:

1. Подготовьте CSV файл:

```csv
text,label
"Срочно! Ваш аккаунт заблокирован",1
"Привет, как дела?",0
```

2. Положите данные в `ml-service/training/data/`

3. Запустите обучение:

```bash
cd ml-service
python training/train.py
```

4. Обновите `.env` с путем к новой модели

Подробнее: [ml-service/README.md](ml-service/README.md)

## Примеры использования

### Быстрый тест через curl

```bash
# 1. Регистрация
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{"username":"test","email":"test@test.com","password":"Test123!"}'

# 2. Вход
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -b cookies.txt -c cookies.txt \
  -d '{"username":"test","password":"Test123!"}'

# 3. Анализ мошеннического текста
curl -X POST http://localhost:8080/api/v1/analysis/text \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"text":"Срочно! Ваш аккаунт заблокирован"}'

# Response:
# {
#   "success": true,
#   "prediction": {
#     "label": "phishing",
#     "confidence": 0.9765,
#     "is_scam": true
#   },
#   "processing_time": 0.234
# }
```

### Python пример

```python
import requests

session = requests.Session()
BASE_URL = "http://localhost:8080/api/v1"

# Вход
session.post(f"{BASE_URL}/auth/login", json={
    "username": "test",
    "password": "Test123!"
})

# Анализ текста
result = session.post(f"{BASE_URL}/analysis/text", json={
    "text": "Вы выиграли миллион! Переведите 500р"
}).json()

print(f"Is Scam: {result['prediction']['is_scam']}")
print(f"Confidence: {result['prediction']['confidence']:.2%}")
```

### JavaScript пример

```javascript
// Вход
await fetch("http://localhost:8080/api/v1/auth/login", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  credentials: "include",
  body: JSON.stringify({ username: "test", password: "Test123!" }),
});

// Анализ
const result = await fetch("http://localhost:8080/api/v1/analysis/text", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  credentials: "include",
  body: JSON.stringify({ text: "Срочно! Аккаунт заблокирован" }),
}).then((r) => r.json());

console.log(result.prediction); // {label: "phishing", confidence: 0.97, is_scam: true}
```

## Документация

- **[Быстрый старт](QUICKSTART.md)** - Подробная инструкция по запуску
- **[ML Service](ml-service/README.md)** - Документация ML сервиса
- **[Архитектура модели](ml-service/ARCHITECTURE.md)** - Как работает BERT
- **[Дообучение](ml-service/training/README.md)** - Инструкция по fine-tuning

### API Документация

- **Swagger UI:** http://localhost:8080/swagger/index.html
- **ML Service Docs:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

## Безопасность

### Аутентификация и авторизация

**Argon2id хеширование паролей**

- Memory: 64MB
- Iterations: 3
- Parallelism: 2
- Salt: 16 bytes (уникальный для каждого пользователя)

**JWT токены в HttpOnly cookies**

- Access token: 1 час (короткий срок для безопасности)
- Refresh token: 7 дней (хранится в БД, можно отозвать)
- Защита от XSS атак (JavaScript не может прочитать)
- Secure flag в production (только HTTPS)

**Session Management**

- Refresh токены хешируются (SHA256) в БД
- Проверка на повторное использование refresh токена
- Logout отзывает токены из БД
- Возможность LogoutAllDevices (отозвать все сессии пользователя)

**Middleware защита**

- Все `/api/v1/analysis/*` endpoint'ы требуют JWT
- Валидация токена на каждом запросе
- Проверка активности сессии в БД

### CORS

Настроен для frontend'а:

```go
AllowOrigins: []string{
    "http://localhost:3000",  // React
    "http://localhost:5173",  // Vite
}
AllowCredentials: true  // Для cookies
```

### Best Practices

- Используйте `credentials: 'include'` в fetch для отправки cookies
- Меняйте `JWT_SECRET` в production
- Используйте HTTPS в production
- Регулярно обновляйте зависимости

## Разработка

### Локальный запуск для разработки

```bash
# Terminal 1: PostgreSQL
docker-compose up postgres -d

# Terminal 2: Backend
go run ./cmd/server/main.go

# Terminal 3: ML Service
cd ml-service
python -m venv venv
source venv/bin/activate  # или .\venv\Scripts\Activate.ps1 на Windows
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### Обновление Swagger документации

```bash
# После изменений в handlers
swag init -g cmd/server/main.go -o ./docs
```

### Миграции БД

Используем GORM AutoMigrate:

```go
db.AutoMigrate(&models.User{}, &models.Session{})
```

Для production рекомендуется использовать [golang-migrate](https://github.com/golang-migrate/migrate).

### Тестирование

```bash
# Backend тесты
go test ./...

# ML Service тесты
cd ml-service
pytest
```

### Структура проекта

```
scam-detection-backend/
├── cmd/
│   └── server/
│       └── main.go              # Entry point
├── internal/
│   ├── api/
│   │   ├── handlers/            # HTTP handlers
│   │   ├── middleware/          # Auth middleware
│   │   └── routers/             # Route setup
│   ├── config/                  # Configuration
│   ├── crypto/                  # Argon2 hashing
│   ├── jwt/                     # JWT utilities
│   ├── mlclient/                # ML service client
│   ├── models/                  # Data models
│   ├── repository/              # Database layer
│   └── services/                # Business logic
├── ml-service/
│   ├── app/
│   │   ├── api/                 # FastAPI endpoints
│   │   ├── core/                # Config
│   │   ├── models/              # Pydantic schemas
│   │   ├── services/            # ML model service
│   │   └── main.py              # FastAPI app
│   └── training/
│       ├── data/                # Training datasets
│       ├── models/              # Fine-tuned models
│       └── train.py             # Training script
├── docs/                        # Swagger docs
├── docker-compose.yml
├── Dockerfile
├── go.mod
├── .env
├── README.md
├── QUICKSTART.md
└── EXAMPLES.md
```

## Contributing

Pull requests приветствуются! Для больших изменений сначала откройте issue.

## License

MIT

## Contact

- GitHub: [@lDizil](https://github.com/lDizil)
- Repository: [scam-detection-backend](https://github.com/lDizil/scam-detection-backend)

## Star

Если проект вам помог, поставьте звездочку

---

**Made with ❤️ using Go, Python, and BERT**
