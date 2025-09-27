package config

import (
	"fmt"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func Connect(d *DatabaseConfig) (*gorm.DB, error) {
	dsn := d.DSN()

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		return nil, fmt.Errorf("не удалось подключиться к БД: %w", err)
	}

	fmt.Printf("Успешное подключение к базе данных %s:%s\n",
		d.Host, d.Port)

	return db, nil
}
