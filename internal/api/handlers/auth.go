package handlers

import (
	"net/http"
	"scam-detection-backend/internal/api/middleware"
	"scam-detection-backend/internal/models"
	"scam-detection-backend/internal/services"
	"time"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	authService *services.AuthService
	userService services.UserService
}

func NewAuthHandler(authService *services.AuthService, userService services.UserService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		userService: userService,
	}
}

type RegisterRequest struct {
	Username string  `json:"username" binding:"required,min=3"`
	Email    *string `json:"email" binding:"omitempty,email"`
	Password string  `json:"password" binding:"required,min=6"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type AuthResponse struct {
	User         *models.User `json:"user"`
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
}

// Register godoc
// @Summary      Регистрация нового пользователя
// @Description  Создаёт нового пользователя и возвращает JWT токены в cookies
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body RegisterRequest true "Данные для регистрации"
// @Success      201 {object} AuthResponse
// @Failure      400 {object} map[string]string
// @Router       /auth/register [post]
func (h *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	createReq := &models.CreateUserRequest{
		Username: req.Username,
		Email:    req.Email,
		Password: req.Password,
	}

	user, tokens, err := h.authService.Register(c.Request.Context(), createReq)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.setTokenCookies(c, tokens)

	c.JSON(http.StatusCreated, AuthResponse{
		User:         user,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	})
}

// Login godoc
// @Summary      Вход в систему
// @Description  Аутентификация пользователя и возврат JWT токенов в cookies
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body LoginRequest true "Логин и пароль"
// @Success      200 {object} AuthResponse
// @Failure      401 {object} map[string]string
// @Router       /auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, tokens, err := h.authService.Login(c.Request.Context(), req.Username, req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	h.setTokenCookies(c, tokens)

	c.JSON(http.StatusOK, AuthResponse{
		User:         user,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	})
}

// Logout godoc
// @Summary      Выход из системы
// @Description  Удаляет все сессии пользователя и очищает cookies
// @Tags         auth
// @Produce      json
// @Success      200 {object} map[string]string
// @Router       /auth/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if exists {
		h.authService.LogoutAllDevices(c.Request.Context(), userID)
	}

	c.SetCookie(
		"access_token",
		"",
		-1,
		"/",
		"",
		false,
		true,
	)
	c.SetCookie(
		"refresh_token",
		"",
		-1,
		"/",
		"",
		false,
		true,
	)

	c.JSON(http.StatusOK, gin.H{"message": "успешный выход"})
}

// RefreshToken godoc
// @Summary      Обновление токенов
// @Description  Обновляет access и refresh токены используя refresh токен из cookie
// @Tags         auth
// @Produce      json
// @Success      200 {object} map[string]string
// @Failure      401 {object} map[string]string
// @Router       /auth/refresh [post]
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh токен не найден"})
		return
	}

	tokens, err := h.authService.RefreshToken(c.Request.Context(), refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	h.setTokenCookies(c, tokens)

	c.JSON(http.StatusOK, gin.H{
		"message":       "токены обновлены",
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
	})
}

// GetProfile godoc
// @Summary      Получить профиль текущего пользователя
// @Description  Возвращает данные авторизованного пользователя
// @Tags         user
// @Produce      json
// @Security     CookieAuth
// @Success      200 {object} models.User
// @Failure      401 {object} map[string]string
// @Failure      404 {object} map[string]string
// @Router       /profile [get]
func (h *AuthHandler) GetProfile(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "пользователь не найден"})
		return
	}

	user, err := h.userService.GetByID(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "пользователь не найден"})
		return
	}

	c.JSON(http.StatusOK, user)
}

func (h *AuthHandler) setTokenCookies(c *gin.Context, tokens *models.TokenPair) {
	accessMaxAge := int(time.Until(tokens.AccessExpiry).Seconds())
	refreshMaxAge := int(time.Until(tokens.RefreshExpry).Seconds())

	c.SetCookie(
		"access_token",
		tokens.AccessToken,
		accessMaxAge,
		"/",
		"",
		false,
		true,
	)

	c.SetCookie(
		"refresh_token",
		tokens.RefreshToken,
		refreshMaxAge,
		"/",
		"",
		false,
		true,
	)
}
