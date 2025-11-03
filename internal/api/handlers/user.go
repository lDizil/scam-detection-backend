package handlers

import (
	"net/http"
	"scam-detection-backend/internal/api/middleware"
	"scam-detection-backend/internal/models"
	"scam-detection-backend/internal/services"

	"github.com/gin-gonic/gin"
)

type UserHandler struct {
	userService services.UserService
}

func NewUserHandler(userService services.UserService) *UserHandler {
	return &UserHandler{
		userService: userService,
	}
}

type UpdateProfileRequest struct {
	Username *string `json:"username,omitempty" binding:"omitempty,min=3"`
	Email    *string `json:"email,omitempty" binding:"omitempty,email"`
}

// UpdateProfile godoc
// @Summary      Обновить профиль
// @Description  Обновляет username и/или email текущего пользователя
// @Tags         user
// @Accept       json
// @Produce      json
// @Security     CookieAuth
// @Param        request body UpdateProfileRequest true "Данные для обновления"
// @Success      200 {object} models.User
// @Failure      400 {object} map[string]string
// @Failure      401 {object} map[string]string
// @Router       /profile [put]
func (h *UserHandler) UpdateProfile(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "пользователь не найден"})
		return
	}

	var req UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updateReq := &models.UpdateUserRequest{
		Username: req.Username,
		Email:    req.Email,
	}

	if err := h.userService.Update(userID, updateReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.userService.GetByID(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "не удалось получить обновлённого пользователя"})
		return
	}

	c.JSON(http.StatusOK, user)
}

// DeleteAccount godoc
// @Summary      Удалить аккаунт
// @Description  Полностью удаляет аккаунт текущего пользователя
// @Tags         user
// @Produce      json
// @Security     CookieAuth
// @Success      200 {object} map[string]string
// @Failure      401 {object} map[string]string
// @Failure      500 {object} map[string]string
// @Router       /account [delete]
func (h *UserHandler) DeleteAccount(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "пользователь не найден"})
		return
	}

	if err := h.userService.Delete(userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "не удалось удалить аккаунт"})
		return
	}

	c.SetCookie("access_token", "", -1, "/", "", false, true)
	c.SetCookie("refresh_token", "", -1, "/", "", false, true)

	c.JSON(http.StatusOK, gin.H{"message": "аккаунт успешно удалён"})
}
