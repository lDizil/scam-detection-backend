package middleware

import (
	"net/http"
	"scam-detection-backend/internal/services"

	"github.com/gin-gonic/gin"
)

const (
	UserIDKey = "userID"
)

func AuthMiddleware(authService *services.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		accessToken, err := c.Cookie("access_token")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "токен не найден"})
			c.Abort()
			return
		}

		userID, err := authService.ValidateToken(accessToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "невалидный токен"})
			c.Abort()
			return
		}

		c.Set(UserIDKey, userID)
		c.Next()
	}
}

func GetUserID(c *gin.Context) (uint, bool) {
	userID, exists := c.Get(UserIDKey)
	if !exists {
		return 0, false
	}
	id, ok := userID.(uint)
	return id, ok
}
