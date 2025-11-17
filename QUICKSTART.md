# Быстрый запуск проекта

## Вариант 1: Docker Compose (рекомендуется)

Все сервисы в Docker контейнерах:

```bash
# Запуск всех сервисов
docker-compose up --build

# Или в фоновом режиме
docker-compose up --build -d

# Проверка логов
docker-compose logs -f

# Остановка
docker-compose down
```

**Что запускается:**

- PostgreSQL (порт 5432)
- Go Backend (порт 8080)
- Python ML Service (порт 8000)

**URLs:**

- Backend API: http://localhost:8080
- Backend Swagger: http://localhost:8080/swagger/index.html
- ML Service API: http://localhost:8000
- ML Service Docs: http://localhost:8000/docs

## Вариант 2: Локальный запуск (для разработки)

### Шаг 1: PostgreSQL в Docker

```bash
docker-compose up postgres -d
```

### Шаг 2: Backend (терминал 1)

```bash
# Установка зависимостей (первый раз)
go mod download

# Запуск
go run ./cmd/server/main.go
```

### Шаг 3: ML Service (терминал 2)

```bash
cd ml-service

# Создать виртуальное окружение (первый раз)
python -m venv venv

# Активировать
# Windows PowerShell:
.\venv\Scripts\Activate.ps1
# Windows CMD:
.\venv\Scripts\activate.bat
# Linux/Mac:
source venv/bin/activate

# Установить зависимости (первый раз)
pip install -r requirements.txt

# Запуск
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Первый запуск: Что происходит?

### Backend (Go)

1. Подключается к PostgreSQL
2. Выполняет миграции (создает таблицы users, user_sessions)
3. Запускает HTTP сервер на порту 8080
4. Генерирует Swagger документацию

### ML Service (Python)

1. **Загружает модель BERT** (первый раз скачивается ~440MB)
2. Кеширует модель в `ml-service/models_cache/`
3. Загружает модель в память (занимает ~1GB RAM)
4. Запускает FastAPI сервер на порту 8000

**Важно:** Первый запуск ML сервиса займет 2-5 минут на скачивание модели!

## Проверка работоспособности

### 1. Проверить Backend

```bash
curl http://localhost:8080/health
```

Ожидается:

```json
{ "status": "ok", "database": "connected" }
```

### 2. Проверить ML Service

```bash
curl http://localhost:8000/health
```

Ожидается:

```json
{
  "status": "healthy",
  "model_loaded": true,
  "model_name": "ealvaradob/bert-finetuned-phishing",
  "version": "1.0.0"
}
```

### 3. Полный тест

```bash
# Регистрация
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "Test123!"
  }'

# Вход
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -b cookies.txt -c cookies.txt \
  -d '{
    "username": "testuser",
    "password": "Test123!"
  }'

# Анализ текста
curl -X POST http://localhost:8080/api/v1/analysis/text \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "text": "Срочно! Ваш аккаунт заблокирован"
  }'
```

Ожидается результат с `"is_scam": true`

## Частые проблемы

### 1. ML Service не загружается

**Проблема:** Нехватка памяти  
**Решение:** Модель требует минимум 2GB RAM

**Проблема:** Долгая загрузка модели  
**Решение:** Первый запуск скачивает ~440MB, подождите 2-5 минут

**Проблема:** Ошибка импорта torch/transformers  
**Решение:**

```bash
cd ml-service
pip install --upgrade torch transformers
```

### 2. Backend не подключается к PostgreSQL

**Проблема:** Connection refused  
**Решение:** Убедитесь, что PostgreSQL запущен:

```bash
docker-compose up postgres -d
docker-compose ps
```

### 3. CORS ошибки во фронтенде

**Проблема:** Frontend на порту 3000 не может обращаться к API  
**Решение:** CORS уже настроен для портов 3000, 5173. Используйте `credentials: 'include'` в fetch

### 4. JWT токены не сохраняются

**Проблема:** Токены в HttpOnly cookies, недоступны из JavaScript  
**Решение:** Это нормально! Используйте `credentials: 'include'` в fetch:

```javascript
fetch("http://localhost:8080/api/v1/profile", {
  credentials: "include",
});
```

## Остановка сервисов

### Docker Compose

```bash
# Остановить и удалить контейнеры
docker-compose down

# Остановить, удалить контейнеры и volumes (БД будет очищена!)
docker-compose down -v
```

### Локальный запуск

```bash
# Просто Ctrl+C в каждом терминале
```

## Дообучение модели

Если нужно дообучить модель на своих данных:

```bash
cd ml-service

# 1. Подготовить данные
# Создать ml-service/training/data/train.csv
# Создать ml-service/training/data/test.csv

# Формат CSV:
# text,label
# "Срочно! Ваш аккаунт заблокирован",1
# "Привет, как дела?",0

# 2. Запустить обучение
python training/train.py

# 3. Модель сохранится в training/models/my_finetuned_model

# 4. Обновить .env
echo "CUSTOM_MODEL_PATH=./training/models/my_finetuned_model" >> .env

# 5. Перезапустить ML сервис
```

Подробнее: [ml-service/training/README.md](ml-service/training/README.md)

## Полезные ссылки

- [Backend Swagger UI](http://localhost:8080/swagger/index.html)
- [ML Service Docs](http://localhost:8000/docs)
- [ML Service README](ml-service/README.md)

## Требования

**Для Docker Compose:**

- Docker Desktop
- 4GB RAM (рекомендуется 8GB)
- 5GB свободного места

**Для локального запуска:**

- Go 1.23+
- Python 3.11+
- PostgreSQL 16
- 4GB RAM (рекомендуется 8GB)
