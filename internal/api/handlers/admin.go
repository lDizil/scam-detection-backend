package handlers

import (
	"errors"
	"net/http"
	"scam-detection-backend/internal/models"
	"scam-detection-backend/internal/services"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type AdminHandler struct {
	userService services.UserService
}

func NewAdminHandler(userService services.UserService) *AdminHandler {
	return &AdminHandler{
		userService: userService,
	}
}

type GetUsersResponse struct {
	Users []models.User `json:"users"`
	Total int64         `json:"total"`
	Page  int           `json:"page"`
	Limit int           `json:"limit"`
}

type UpdateRoleRequest struct {
	Role models.Role `json:"role" binding:"required"`
}

type ToggleUserStatusRequest struct {
	IsActive *bool `json:"is_active" binding:"required"`
}

// GetAllUsers godoc
// @Summary      Получить список всех пользователей (только admin)
// @Description  Возвращает список всех пользователей с пагинацией. Доступно только администраторам.
// @Tags         admin
// @Accept       json
// @Produce      json
// @Param        page query int false "Номер страницы" default(1)
// @Param        limit query int false "Количество на странице" default(20)
// @Success      200 {object} GetUsersResponse
// @Failure      403 {object} map[string]string
// @Failure      500 {object} map[string]string
// @Security     CookieAuth
// @Router       /admin/users [get]
func (h *AdminHandler) GetAllUsers(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))

	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}

	offset := (page - 1) * limit

	users, total, err := h.userService.GetAllUsers(limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get users"})
		return
	}

	c.JSON(http.StatusOK, GetUsersResponse{
		Users: users,
		Total: total,
		Page:  page,
		Limit: limit,
	})
}

// UpdateUserRole godoc
// @Summary      Изменить роль пользователя (только admin)
// @Description  Изменяет роль указанного пользователя. Доступно только администраторам.
// @Tags         admin
// @Accept       json
// @Produce      json
// @Param        id path int true "ID пользователя"
// @Param        request body UpdateRoleRequest true "Новая роль"
// @Success      200 {object} map[string]interface{}
// @Failure      400 {object} map[string]string
// @Failure      403 {object} map[string]string
// @Failure      500 {object} map[string]string
// @Security     CookieAuth
// @Router       /admin/users/{id}/role [put]
func (h *AdminHandler) UpdateUserRole(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var req UpdateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !req.Role.IsValid() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid role"})
		return
	}

	if err := h.userService.UpdateUserRole(uint(userID), req.Role); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user role"})
		return
	}

	user, err := h.userService.GetByID(uint(userID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User updated but failed to fetch"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Role updated successfully", "user": user})
}

// ToggleUserStatus godoc
// @Summary      Заблокировать/разблокировать пользователя (только admin)
// @Description  Изменяет статус активности пользователя. Доступно только администраторам.
// @Tags         admin
// @Accept       json
// @Produce      json
// @Param        id path int true "ID пользователя"
// @Param        request body ToggleUserStatusRequest true "Статус активности"
// @Success      200 {object} map[string]interface{}
// @Failure      400 {object} map[string]string
// @Failure      403 {object} map[string]string
// @Failure      500 {object} map[string]string
// @Security     CookieAuth
// @Router       /admin/users/{id}/status [put]
func (h *AdminHandler) ToggleUserStatus(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var req ToggleUserStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.userService.ToggleUserActiveStatus(uint(userID), *req.IsActive); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user status"})
		return
	}

	user, err := h.userService.GetByID(uint(userID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User updated but failed to fetch"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User status updated successfully", "user": user})
}

// GetUserByID godoc
// @Summary      Получить информацию о пользователе (только admin)
// @Description  Возвращает детальную информацию о пользователе по ID. Доступно только администраторам.
// @Tags         admin
// @Accept       json
// @Produce      json
// @Param        id path int true "ID пользователя"
// @Success      200 {object} models.User
// @Failure      400 {object} map[string]string
// @Failure      403 {object} map[string]string
// @Failure      404 {object} map[string]string
// @Security     CookieAuth
// @Router       /admin/users/{id} [get]
func (h *AdminHandler) GetUserByID(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	user, err := h.userService.GetByID(uint(userID))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, user)
}
