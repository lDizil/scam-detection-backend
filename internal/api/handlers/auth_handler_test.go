package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"scam-detection-backend/internal/api/middleware"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestAuthLogout_WithValidToken(t *testing.T) {
	server := setupTestServer(t)
	server.setupAuthRoutes()

	user := server.createTestUser(t, "logoutuser", "password123")
	token := server.createTestToken(t, user.ID)

	req := httptest.NewRequest("POST", "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "message")
}

func TestAuthLogout_WithoutToken(t *testing.T) {
	server := setupTestServer(t)
	server.setupAuthRoutes()

	req := httptest.NewRequest("POST", "/auth/logout", nil)

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthRefreshToken_NoCookie(t *testing.T) {
	server := setupTestServer(t)
	server.setupAuthRoutes()

	req := httptest.NewRequest("POST", "/auth/refresh", nil)

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestAuthRefreshToken_InvalidToken(t *testing.T) {
	server := setupTestServer(t)
	server.setupAuthRoutes()

	req := httptest.NewRequest("POST", "/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "invalid.token.value"})

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthRefreshToken_ValidToken(t *testing.T) {
	server := setupTestServer(t)
	server.setupAuthRoutes()

	user := server.createTestUser(t, "refreshuser", "password123")
	tokens, err := server.sessionSvc.GenerateSession(context.TODO(), user.ID)
	assert.NoError(t, err)

	req := httptest.NewRequest("POST", "/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: tokens.RefreshToken})

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "access_token")
	assert.Contains(t, response, "refresh_token")
}

func TestAuthGetProfile_Success(t *testing.T) {
	server := setupTestServer(t)
	authHandler := NewAuthHandler(server.authService, server.userService)
	server.router.GET("/profile", middleware.AuthMiddleware(server.authService), authHandler.GetProfile)

	user := server.createTestUser(t, "profilegetuser", "password123")
	token := server.createTestToken(t, user.ID)

	req := httptest.NewRequest("GET", "/profile", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "profilegetuser", response["username"])
}

func TestAuthGetProfile_Unauthorized(t *testing.T) {
	router := gin.New()
	authHandler := NewAuthHandler(nil, nil)
	router.GET("/profile", authHandler.GetProfile)

	req := httptest.NewRequest("GET", "/profile", nil)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
