package routes

import (
	"scam-detection-backend/internal/api/handlers"
	"scam-detection-backend/internal/api/middleware"
	"scam-detection-backend/internal/services"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(r *gin.Engine, authService *services.AuthService, userService services.UserService) {
	authHandler := handlers.NewAuthHandler(authService, userService)
	userHandler := handlers.NewUserHandler(userService)

	api := r.Group("/api/v1")
	{
		auth := api.Group("/auth")
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
			auth.POST("/logout", authHandler.Logout)
			auth.POST("/refresh", authHandler.RefreshToken)
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
