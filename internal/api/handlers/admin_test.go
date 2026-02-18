package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"scam-detection-backend/internal/api/middleware"
	"scam-detection-backend/internal/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (s *TestServer) setupAdminRoutes() {
	adminHandler := NewAdminHandler(s.userService)

	adminGroup := s.router.Group("/admin")
	adminGroup.Use(middleware.AuthMiddleware(s.authService))
	adminGroup.Use(middleware.RequireRole(s.userService, models.RoleAdmin))
	{
		adminGroup.GET("/users", adminHandler.GetAllUsers)
		adminGroup.GET("/users/:id", adminHandler.GetUserByID)
		adminGroup.PUT("/users/:id/role", adminHandler.UpdateUserRole)
		adminGroup.PUT("/users/:id/status", adminHandler.ToggleUserStatus)
	}
}

func (s *TestServer) createAdminUser(t *testing.T, username, password string) *models.User {
	user := s.createTestUser(t, username, password)

	err := s.db.Model(&models.User{}).Where("id = ?", user.ID).Update("role", models.RoleAdmin).Error
	require.NoError(t, err)

	user.Role = models.RoleAdmin
	return user
}

func TestAdmin_GetAllUsers_Success(t *testing.T) {
	server := setupTestServer(t)
	server.setupAdminRoutes()

	admin := server.createAdminUser(t, "admin", "password123")
	token := server.createTestToken(t, admin.ID)

	server.createTestUser(t, "user1", "password123")
	server.createTestUser(t, "user2", "password123")

	req := httptest.NewRequest("GET", "/admin/users?limit=10&offset=0", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Contains(t, response, "users")
	assert.Contains(t, response, "total")

	total := response["total"].(float64)
	assert.GreaterOrEqual(t, total, float64(3))
}

func TestAdmin_GetAllUsers_Forbidden(t *testing.T) {
	server := setupTestServer(t)
	server.setupAdminRoutes()

	user := server.createTestUser(t, "regularuser", "password123")
	token := server.createTestToken(t, user.ID)

	req := httptest.NewRequest("GET", "/admin/users?limit=10&offset=0", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestAdmin_GetUserByID_Success(t *testing.T) {
	server := setupTestServer(t)
	server.setupAdminRoutes()

	admin := server.createAdminUser(t, "admin2", "password123")
	token := server.createTestToken(t, admin.ID)

	targetUser := server.createTestUser(t, "targetuser", "password123")

	req := httptest.NewRequest("GET", fmt.Sprintf("/admin/users/%d", targetUser.ID), nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var user models.User
	err := json.Unmarshal(w.Body.Bytes(), &user)
	assert.NoError(t, err)
	assert.Equal(t, "targetuser", user.Username)
}

func TestAdmin_GetUserByID_NotFound(t *testing.T) {
	server := setupTestServer(t)
	server.setupAdminRoutes()

	admin := server.createAdminUser(t, "admin3", "password123")
	token := server.createTestToken(t, admin.ID)

	req := httptest.NewRequest("GET", "/admin/users/99999", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAdmin_UpdateUserRole_Success(t *testing.T) {
	server := setupTestServer(t)
	server.setupAdminRoutes()

	admin := server.createAdminUser(t, "admin4", "password123")
	token := server.createTestToken(t, admin.ID)

	targetUser := server.createTestUser(t, "promoteuser", "password123")

	payload := map[string]interface{}{
		"role": "admin",
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("PUT", fmt.Sprintf("/admin/users/%d/role", targetUser.ID), bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var updatedUser models.User
	err := server.db.First(&updatedUser, targetUser.ID).Error
	assert.NoError(t, err)
	assert.Equal(t, models.RoleAdmin, updatedUser.Role)
}

func TestAdmin_UpdateUserRole_InvalidRole(t *testing.T) {
	server := setupTestServer(t)
	server.setupAdminRoutes()

	admin := server.createAdminUser(t, "admin5", "password123")
	token := server.createTestToken(t, admin.ID)

	targetUser := server.createTestUser(t, "user5", "password123")

	payload := map[string]interface{}{
		"role": "superadmin",
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("PUT", fmt.Sprintf("/admin/users/%d/role", targetUser.ID), bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdmin_ToggleUserStatus_Success(t *testing.T) {
	server := setupTestServer(t)
	server.setupAdminRoutes()

	admin := server.createAdminUser(t, "admin6", "password123")
	token := server.createTestToken(t, admin.ID)

	targetUser := server.createTestUser(t, "blockuser", "password123")

	isActive := false
	payload := map[string]interface{}{
		"is_active": &isActive,
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("PUT", fmt.Sprintf("/admin/users/%d/status", targetUser.ID), bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var updatedUser models.User
	err := server.db.First(&updatedUser, targetUser.ID).Error
	assert.NoError(t, err)
	assert.False(t, updatedUser.IsActive)
}

func TestAdmin_ToggleUserStatus_NotFound(t *testing.T) {
	server := setupTestServer(t)
	server.setupAdminRoutes()

	admin := server.createAdminUser(t, "admin7", "password123")
	token := server.createTestToken(t, admin.ID)

	isActive := false
	payload := map[string]interface{}{
		"is_active": &isActive,
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("PUT", "/admin/users/99999/status", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}
