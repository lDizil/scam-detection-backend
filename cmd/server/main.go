package main

import (
	"log"
	"scam-detection-backend/internal/config"
	"scam-detection-backend/internal/models"
)

func main() {
	cfg := config.Load()

	db, err := config.Connect(&cfg.Database)
	if err != nil {
		log.Fatal("Не удалось подключиться к БД:", err)
	}

	if err := db.AutoMigrate(&models.User{}, &models.Check{}); err != nil {
		log.Fatal("Ошибка миграций:", err)
	}
}
