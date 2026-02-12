package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	Database DatabaseConfig
	Server   ServerConfig
	JWT      JWTConfig
	URLhaus  URLhausConfig
	MinIO    MinIOConfig
}

type MinIOConfig struct {
	Endpoint  string
	AccessKey string
	SecretKey string
	Bucket    string
	UseSSL    bool
}

type URLhausConfig struct {
	AuthKey string
}

type JWTConfig struct {
	Secret               string
	AccessTokenDuration  string
	RefreshTokenDuration string
}

type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Name     string
}

type ServerConfig struct {
	Port    string
	Mode    string
	BaseURL string
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
	baseURL := getEnv("BASE_URL", "http://localhost:8080")

	jwtSecret := getEnv("JWT_SECRET", "your-secret-key-change-in-production")
	accessDuration := getEnv("JWT_ACCESS_DURATION", "60m")
	refreshDuration := getEnv("JWT_REFRESH_DURATION", "168h")

	urlhausAuthKey := getEnv("URLHAUS_AUTH_KEY", "")

	minioEndpoint := getEnv("MINIO_ENDPOINT", "localhost:9000")
	minioAccessKey := getEnv("MINIO_ACCESS_KEY", "minioadmin")
	minioSecretKey := getEnv("MINIO_SECRET_KEY", "minioadmin123")
	minioBucket := getEnv("MINIO_BUCKET", "scam-images")
	minioUseSSL := getEnv("MINIO_USE_SSL", "false") == "true"

	config := &Config{
		Database: DatabaseConfig{
			Host:     host,
			Port:     port,
			User:     user,
			Password: password,
			Name:     name,
		},
		Server: ServerConfig{
			Port:    serverPort,
			Mode:    serverMode,
			BaseURL: baseURL,
		},
		JWT: JWTConfig{
			Secret:               jwtSecret,
			AccessTokenDuration:  accessDuration,
			RefreshTokenDuration: refreshDuration,
		},
		URLhaus: URLhausConfig{
			AuthKey: urlhausAuthKey,
		},
		MinIO: MinIOConfig{
			Endpoint:  minioEndpoint,
			AccessKey: minioAccessKey,
			SecretKey: minioSecretKey,
			Bucket:    minioBucket,
			UseSSL:    minioUseSSL,
		},
	}

	return config
}

func (d *DatabaseConfig) DSN() string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		d.Host, d.Port, d.User, d.Password, d.Name)
}
