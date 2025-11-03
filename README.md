# Scam Detection Backend

REST API для определения мошеннического контента.

## Технологии

- Go 1.24 + Gin
- PostgreSQL 16
- JWT (HttpOnly cookies)
- Argon2 (хеширование паролей)
- Swagger UI
- Docker

## Быстрый старт

```bash
docker-compose up --build
```

API: http://localhost:8080  
Swagger: http://localhost:8080/swagger/index.html

## Локальный запуск

```bash
docker-compose up postgres -d
go run ./cmd/server/main.go
```

## API Endpoints

**Публичные:**

- `POST /api/v1/auth/register` - регистрация
- `POST /api/v1/auth/login` - вход
- `POST /api/v1/auth/logout` - выход
- `POST /api/v1/auth/refresh` - обновить токены

**Защищённые (требуется JWT):**

- `GET /api/v1/profile` - получить профиль
- `PUT /api/v1/profile` - обновить профиль
- `DELETE /api/v1/account` - удалить аккаунт

## Переменные окружения

```env
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=password
DB_NAME=fraud_detection

SERVER_PORT=8080
SERVER_MODE=debug

JWT_SECRET=your-secret-key
JWT_ACCESS_DURATION=15m
JWT_REFRESH_DURATION=7d
```

## Структура

```
cmd/server/          - точка входа
internal/
  ├── api/           - handlers, middleware, routes
  ├── config/        - конфигурация
  ├── crypto/        - Argon2 хеширование
  ├── jwt/           - JWT утилиты
  ├── models/        - модели данных
  ├── repository/    - работа с БД
  └── services/      - бизнес-логика
```

## Безопасность

- Пароли хешируются Argon2id
- JWT токены в HttpOnly cookies (защита от XSS)
- Refresh токены хранятся в БД (можно отозвать)
- Проверка на повторное использование refresh токена
- Middleware для защиты роутов

## Сборка

```bash
go build -o server ./cmd/server
```

## Swagger документация

Регенерация после изменений:

```bash
swag init -g cmd/server/main.go -o ./docs
```
