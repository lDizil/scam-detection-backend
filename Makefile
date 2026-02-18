.PHONY: help build up down restart logs clean test lint format

# Цвета для вывода
GREEN  := \033[0;32m
YELLOW := \033[0;33m
NC     := \033[0m # No Color

help: ## Показать эту справку
	@echo "$(GREEN)Доступные команды:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-15s$(NC) %s\n", $$1, $$2}'

build: ## Собрать все Docker образы
	docker-compose build

up: ## Запустить все сервисы
	docker-compose up -d

down: ## Остановить все сервисы
	docker-compose down

restart: down up ## Перезапустить все сервисы

logs: ## Показать логи всех сервисов
	docker-compose logs -f

logs-backend: ## Показать логи backend
	docker-compose logs -f backend

logs-ml: ## Показать логи ML service
	docker-compose logs -f ml-service

clean: ## Очистить volumes и остановить сервисы
	docker-compose down -v
	docker system prune -f

clean-all: ## Удалить все (включая образы)
	docker-compose down -v --rmi all
	docker system prune -af

test-backend: ## Запустить тесты backend
	go test -v -race -coverprofile=coverage.out ./...

test-ml: ## Запустить тесты ML service
	cd ml-service && pytest -v --cov=app

lint-backend: ## Запустить линтер для backend
	go vet ./...
	gofmt -l .
	staticcheck ./...

lint-ml: ## Запустить линтер для ML service
	cd ml-service && python -m ruff check app/

format-backend: ## Отформатировать код backend
	gofmt -w .

format-ml: ## Отформатировать код ML service
	cd ml-service && python -m ruff format app/

lint: lint-backend lint-ml ## Запустить все линтеры

format: format-backend format-ml ## Отформатировать весь код

dev: ## Запустить в режиме разработки
	docker-compose up

ps: ## Показать статус контейнеров
	docker-compose ps

health: ## Проверить здоровье сервисов
	@echo "$(YELLOW)Проверка здоровья сервисов...$(NC)"
	@curl -s http://localhost/health || echo "$(RED)Nginx не отвечает$(NC)"
	@curl -s http://localhost:8080/health || echo "$(RED)Backend не отвечает$(NC)"
	@curl -s http://localhost:8000/health || echo "$(RED)ML Service не отвечает$(NC)"

migrate: ## Запустить миграции БД
	docker-compose exec backend /server migrate

shell-backend: ## Открыть shell в backend контейнере
	docker-compose exec backend sh

shell-ml: ## Открыть shell в ML service контейнере
	docker-compose exec ml-service sh

db-shell: ## Подключиться к PostgreSQL
	docker-compose exec postgres psql -U postgres -d fraud_detection

init: ## Инициализировать проект (первый запуск)
	@echo "$(GREEN)Инициализация проекта...$(NC)"
	@if [ ! -f .env ]; then \
		echo "$(YELLOW)Копирование .env.example в .env...$(NC)"; \
		cp .env.example .env; \
		echo "$(YELLOW)Отредактируйте .env файл перед запуском!$(NC)"; \
	fi
	@echo "$(GREEN)Сборка образов...$(NC)"
	$(MAKE) build
	@echo "$(GREEN)Запуск сервисов...$(NC)"
	$(MAKE) up
	@echo "$(GREEN)Проект готов!$(NC)"
