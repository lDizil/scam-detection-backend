package routes

import (
	"scam-detection-backend/internal/api/handlers"
	"scam-detection-backend/internal/api/middleware"
	"scam-detection-backend/internal/repository"
	"scam-detection-backend/internal/services"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func SetupRoutes(r *gin.Engine, db *gorm.DB, authService *services.AuthService, userService services.UserService) {
	authHandler := handlers.NewAuthHandler(authService, userService)
	userHandler := handlers.NewUserHandler(userService)

	checkRepo := repository.NewCheckRepository(db)
	analysisHandler := handlers.NewAnalysisHandler(checkRepo)

	api := r.Group("/api/v1")
	{
		auth := api.Group("/auth")
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
			auth.POST("/logout", authHandler.Logout)
			auth.POST("/refresh", authHandler.RefreshToken)
		}

		analysisPublic := api.Group("/analysis")
		{
			analysisPublic.GET("/health", analysisHandler.MLHealthCheck)
		}

		analysis := api.Group("/analysis")
		analysis.Use(middleware.AuthMiddleware(authService))
		{
			analysis.POST("/text", analysisHandler.AnalyzeText)
			analysis.POST("/batch", analysisHandler.AnalyzeBatch)
			analysis.GET("/history", analysisHandler.GetCheckHistory)
			analysis.DELETE("/history/:id", analysisHandler.DeleteCheck)
			analysis.GET("/stats", analysisHandler.GetStats)
		}

		protected := api.Group("")
		protected.Use(middleware.AuthMiddleware(authService))
		{
			protected.GET("/profile", authHandler.GetProfile)
			protected.PUT("/profile", userHandler.UpdateProfile)
			protected.DELETE("/account", userHandler.DeleteAccount)
		}
	}
}
