package middleware

import (
	"net/http"
	"scam-detection-backend/internal/models"
	"scam-detection-backend/internal/services"

	"github.com/gin-gonic/gin"
)

const (
	UserIDKey   = "userID"
	UserRoleKey = "userRole"
	UserKey     = "user"
)

func AuthMiddleware(authService *services.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Пропускаем OPTIONS запросы (CORS preflight)
		if c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

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

func RequireRole(userService services.UserService, allowedRoles ...models.Role) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Пропускаем OPTIONS запросы (CORS preflight)
		if c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		userID, exists := GetUserID(c)
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "пользователь не аутентифицирован"})
			c.Abort()
			return
		}

		user, err := userService.GetByID(userID)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "пользователь не найден"})
			c.Abort()
			return
		}

		if !user.IsActive {
			c.JSON(http.StatusForbidden, gin.H{"error": "учётная запись заблокирована"})
			c.Abort()
			return
		}

		hasRole := false
		for _, role := range allowedRoles {
			if user.Role == role {
				hasRole = true
				break
			}
		}

		if !hasRole {
			c.JSON(http.StatusForbidden, gin.H{"error": "недостаточно прав доступа"})
			c.Abort()
			return
		}

		c.Set(UserRoleKey, user.Role)
		c.Set(UserKey, user)
		c.Next()
	}
}

func GetUserRole(c *gin.Context) (models.Role, bool) {
	role, exists := c.Get(UserRoleKey)
	if !exists {
		return "", false
	}
	r, ok := role.(models.Role)
	return r, ok
}

func GetUser(c *gin.Context) (*models.User, bool) {
	user, exists := c.Get(UserKey)
	if !exists {
		return nil, false
	}
	u, ok := user.(*models.User)
	return u, ok
}
