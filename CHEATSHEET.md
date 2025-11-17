# Шпаргалка команд

## Запуск проекта

```bash
# Docker Compose (все сервисы)
docker-compose up --build              # С билдом
docker-compose up -d                   # В фоне
docker-compose down                    # Остановить
docker-compose down -v                 # Остановить + удалить volumes

# Только PostgreSQL
docker-compose up postgres -d

# Логи
docker-compose logs -f                 # Все сервисы
docker-compose logs -f backend         # Только backend
docker-compose logs -f ml-service      # Только ML
```

## Backend (Go)

```bash
# Запуск
go run ./cmd/server/main.go

# Билд
go build -o server ./cmd/server

# Тесты
go test ./...

# Обновить зависимости
go mod tidy

# Swagger
swag init -g cmd/server/main.go -o ./docs
```

## ML Service (Python)

```bash
cd ml-service

# Виртуальное окружение
python -m venv venv
.\venv\Scripts\Activate.ps1            # Windows PowerShell
.\venv\Scripts\activate.bat            # Windows CMD
source venv/bin/activate               # Linux/Mac

# Установка зависимостей
pip install -r requirements.txt

# Запуск
uvicorn app.main:app --reload
uvicorn app.main:app --host 0.0.0.0 --port 8000

# Дообучение модели
python training/train.py
```

## Тестирование API

```bash
# Health checks
curl http://localhost:8080/health
curl http://localhost:8000/health

# Регистрация
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{"username":"test","email":"test@test.com","password":"Test123!"}'

# Вход
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -b cookies.txt -c cookies.txt \
  -d '{"username":"test","password":"Test123!"}'

# Профиль
curl http://localhost:8080/api/v1/profile -b cookies.txt

# Анализ текста
curl -X POST http://localhost:8080/api/v1/analysis/text \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"text":"Срочно! Ваш аккаунт заблокирован"}'

# Батч-анализ
curl -X POST http://localhost:8080/api/v1/analysis/batch \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"texts":["Текст 1","Текст 2","Текст 3"]}'

# Прямой запрос к ML сервису
curl -X POST http://localhost:8000/api/v1/analyze/text \
  -H "Content-Type: application/json" \
  -d '{"text":"Вы выиграли миллион!"}'
```

## База данных

```bash
# Подключиться к PostgreSQL
docker exec -it scam-detection-db psql -U postgres -d fraud_detection

# SQL команды
\dt                                    # Список таблиц
SELECT * FROM users;                   # Все пользователи
SELECT * FROM user_sessions;           # Все сессии
\q                                     # Выход
```

## Docker команды

```bash
# Статус контейнеров
docker-compose ps

# Рестарт сервиса
docker-compose restart backend
docker-compose restart ml-service

# Пересборка конкретного сервиса
docker-compose build backend
docker-compose build ml-service

# Войти в контейнер
docker exec -it scam-detection-backend sh
docker exec -it scam-detection-ml sh

# Очистка
docker system prune                    # Удалить неиспользуемое
docker volume prune                    # Удалить volumes
docker-compose down --rmi all          # Удалить images
```

## Полезные файлы

```bash
# Логи
tail -f logs/backend.log
tail -f logs/ml-service.log

# Конфигурация
cat .env
cat ml-service/.env

# Проверить порты
netstat -an | findstr "8080"          # Windows
netstat -an | grep "8080"             # Linux/Mac
lsof -i :8080                          # Mac/Linux
```

## Отладка

```bash
# Проверить, что сервисы запущены
curl http://localhost:8080/health
curl http://localhost:8000/health

# Проверить статус ML модели
curl http://localhost:8000/health | jq '.model_loaded'

# Проверить соединение между сервисами
docker exec -it scam-detection-backend curl http://ml-service:8000/health

# Проверить переменные окружения
docker exec -it scam-detection-backend env | grep ML_SERVICE_URL
docker exec -it scam-detection-ml env | grep MODEL_NAME
```

## Примеры текстов для тестирования

```bash
# Мошенничество (должно быть is_scam: true)
"Срочно! Ваш аккаунт заблокирован. Перейдите по ссылке"
"Вы выиграли 1000000 рублей! Переведите 500р для получения"
"Служба безопасности банка. Назовите CVV код"
"Ваша карта заблокирована. Подтвердите данные по ссылке"
"Техподдержка VK. Для восстановления отправьте код"

# Легитимные тексты (должно быть is_scam: false)
"Привет! Как дела? Созвонимся завтра?"
"Ваш заказ №12345 отправлен. Трек-номер: ABC123"
"Напоминание: встреча завтра в 15:00"
"Спасибо за покупку! Ждем вас снова"
"Доброе утро! Отличного дня!"
```

## URLs

```bash
# Backend
http://localhost:8080                  # API
http://localhost:8080/swagger/index.html  # Swagger UI
http://localhost:8080/health           # Health check

# ML Service
http://localhost:8000                  # API
http://localhost:8000/docs             # FastAPI Docs
http://localhost:8000/redoc            # ReDoc
http://localhost:8000/health           # Health check
http://localhost:8000/api/v1/analyze/text  # Анализ текста

# PostgreSQL
localhost:5432                         # Подключение
Database: fraud_detection
Username: postgres
Password: password
```

## Настройка

```bash
# Backend
.env                                   # Конфигурация

# ML Service
ml-service/.env                        # Конфигурация
ml-service/models_cache/               # Кеш моделей (автосоздается)
ml-service/training/data/              # Данные для обучения
ml-service/training/models/            # Дообученные модели

# Docker
docker-compose.yml                     # Orchestration
Dockerfile                             # Backend image
ml-service/Dockerfile                  # ML Service image
```

## Дообучение модели

```bash
# 1. Подготовить данные
# Создать ml-service/training/data/train.csv и test.csv
# Формат: text,label

# 2. Запустить обучение
cd ml-service
python training/train.py

# 3. Модель сохранится в training/models/my_finetuned_model

# 4. Обновить .env
echo "CUSTOM_MODEL_PATH=./training/models/my_finetuned_model" >> .env

# 5. Перезапустить
docker-compose restart ml-service
```

## Частые проблемы

```bash
# ML Service не загружается
docker-compose logs ml-service
# Возможно: нехватка памяти (нужно 2GB+)

# Backend не подключается к ML
docker-compose ps
# Проверить, запущен ли ml-service

# Порт занят
netstat -ano | findstr ":8080"         # Windows
lsof -ti:8080 | xargs kill -9          # Mac/Linux

# JWT токены не работают
# Проверить: используется ли credentials: 'include' в fetch
# Проверить: правильно ли настроен CORS
```

## Мониторинг

```bash
# Статус сервисов
docker-compose ps

# Использование ресурсов
docker stats

# Размер images
docker images

# Размер volumes
docker volume ls
```

## Обновление зависимостей

```bash
# Go
go get -u ./...
go mod tidy

# Python
cd ml-service
pip install --upgrade -r requirements.txt
pip freeze > requirements.txt
```

## Очистка

```bash
# Остановить все
docker-compose down

# Удалить volumes (БД будет очищена!)
docker-compose down -v

# Удалить images
docker-compose down --rmi all

# Очистить кеш моделей
rm -rf ml-service/models_cache/*       # Linux/Mac
rmdir /s ml-service\models_cache       # Windows

# Очистить __pycache__
find . -type d -name __pycache__ -exec rm -rf {} +  # Linux/Mac
```
