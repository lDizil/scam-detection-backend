package routes

import (
	"scam-detection-backend/internal/api/handlers"
	"scam-detection-backend/internal/api/middleware"
	"scam-detection-backend/internal/config"
	"scam-detection-backend/internal/models"
	"scam-detection-backend/internal/repository"
	"scam-detection-backend/internal/services"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func SetupRoutes(r *gin.Engine, db *gorm.DB, authService *services.AuthService, userService services.UserService, cfg *config.Config) {
	authHandler := handlers.NewAuthHandler(authService, userService)
	userHandler := handlers.NewUserHandler(userService)
	adminHandler := handlers.NewAdminHandler(userService)

	checkRepo := repository.NewCheckRepository(db)
	analysisHandler := handlers.NewAnalysisHandler(checkRepo, cfg)

	seoHandler := handlers.NewSEOHandler(cfg.Server.BaseURL)

	r.GET("/sitemap.xml", seoHandler.Sitemap)
	r.GET("/robots.txt", seoHandler.Robots)

	api := r.Group("/api/v1")
	{
		auth := api.Group("/auth")
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
			auth.POST("/refresh", authHandler.RefreshToken)
		}

		authProtected := api.Group("/auth")
		authProtected.Use(middleware.AuthMiddleware(authService))
		{
			authProtected.POST("/logout", authHandler.Logout)
		}

		analysisPublic := api.Group("/analysis")
		{
			analysisPublic.GET("/health", analysisHandler.MLHealthCheck)
		}

		api.GET("/structured-data", seoHandler.StructuredData)
		api.GET("/health/structured-data", seoHandler.HealthStructuredData)

		api.GET("/files/*filepath", analysisHandler.GetFile)

		analysis := api.Group("/analysis")
		analysis.Use(middleware.AuthMiddleware(authService))
		analysis.Use(middleware.RequireRole(userService, models.RoleUser, models.RoleModerator, models.RoleAdmin))
		{
			analysis.POST("/text", analysisHandler.AnalyzeText)
			analysis.POST("/batch", analysisHandler.AnalyzeBatch)
			analysis.POST("/url", analysisHandler.AnalyzeURL)
			analysis.POST("/image", analysisHandler.AnalyzeImage)
			analysis.POST("/video", analysisHandler.AnalyzeVideo)
			analysis.GET("/history", analysisHandler.GetCheckHistory)
			analysis.DELETE("/history/:id", analysisHandler.DeleteCheck)
			analysis.GET("/stats", analysisHandler.GetStats)
		}

		moderatorAnalysis := api.Group("/analysis")
		moderatorAnalysis.Use(middleware.AuthMiddleware(authService))
		moderatorAnalysis.Use(middleware.RequireRole(userService, models.RoleModerator, models.RoleAdmin))
		{
			moderatorAnalysis.GET("/all", analysisHandler.GetAllChecks)
			moderatorAnalysis.GET("/global-stats", analysisHandler.GetGlobalStats)
		}

		adminUsers := api.Group("/admin/users")
		adminUsers.Use(middleware.AuthMiddleware(authService))
		adminUsers.Use(middleware.RequireRole(userService, models.RoleAdmin))
		{
			adminUsers.GET("", adminHandler.GetAllUsers)
			adminUsers.GET("/:id", adminHandler.GetUserByID)
			adminUsers.PUT("/:id/role", adminHandler.UpdateUserRole)
			adminUsers.PUT("/:id/status", adminHandler.ToggleUserStatus)
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
