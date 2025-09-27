package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	Database DatabaseConfig
	Server   ServerConfig
}

type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Name     string
}

type ServerConfig struct {
	Port string
	Mode string
}

func getEnv(key, defaultValue string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultValue
}

func Load() *Config {
	godotenv.Load()

	host := getEnv("DB_HOST", "localhost")
	port := getEnv("DB_PORT", "5432")
	user := getEnv("DB_USER", "postgres")
	password := getEnv("DB_PASSWORD", "password123")
	name := getEnv("DB_NAME", "scamdetection")

	serverPort := getEnv("SERVER_PORT", "8080")
	serverMode := getEnv("SERVER_MODE", "debug")

	config := &Config{
		Database: DatabaseConfig{
			Host:     host,
			Port:     port,
			User:     user,
			Password: password,
			Name:     name,
		},
		Server: ServerConfig{
			Port: serverPort,
			Mode: serverMode,
		},
	}

	return config
}

func (d *DatabaseConfig) DSN() string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		d.Host, d.Port, d.User, d.Password, d.Name)
}
