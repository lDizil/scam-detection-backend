package main

import (
	"fmt"
	"log"
	routes "scam-detection-backend/internal/api/routers"
	"scam-detection-backend/internal/config"
	"scam-detection-backend/internal/models"
	"scam-detection-backend/internal/repository"
	"scam-detection-backend/internal/services"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	_ "scam-detection-backend/docs"
)

// @title           Scam Detection API
// @version         1.0
// @description     API для системы детекции скама
// @termsOfService  http://swagger.io/terms/

// @contact.name   API Support
// @contact.email  support@example.com

// @license.name  Apache 2.0
// @license.url   http://www.apache.org/licenses/LICENSE-2.0.html

// @host      localhost:8080
// @BasePath  /api/v1

// @securityDefinitions.apikey CookieAuth
// @in cookie
// @name access_token
// @description JWT токен в HttpOnly cookie

func main() {
	cfg := config.Load()

	db, err := config.Connect(&cfg.Database)
	if err != nil {
		log.Fatal("Не удалось подключиться к БД:", err)
	}

	if err := db.AutoMigrate(&models.User{}, &models.Check{}, &models.CheckDetail{}, &models.UserSessions{}); err != nil {
		log.Fatal("Ошибка миграций:", err)
	}

	userRepo := repository.NewUserRepository(db)
	sessionRepo := repository.NewSessionRepository(db)

	userService := services.NewUserService(userRepo)

	sessionService, err := services.NewSessionService(
		sessionRepo,
		cfg.JWT.Secret,
		cfg.JWT.AccessTokenDuration,
		cfg.JWT.RefreshTokenDuration,
	)
	if err != nil {
		log.Fatal("Не удалось создать session service:", err)
	}

	authService := services.NewAuthService(userRepo, sessionService)

	if cfg.Server.Mode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000", "http://localhost:5173"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept"},
		AllowCredentials: true,
		MaxAge:           12 * 3600,
	}))

	routes.SetupRoutes(r, db, authService, userService)

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	addr := fmt.Sprintf(":%s", cfg.Server.Port)
	if err := r.Run(addr); err != nil {
		log.Fatal("Не удалось запустить сервер:", err)
	}
}
