package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"scam-detection-backend/internal/api/middleware"
	"scam-detection-backend/internal/crypto"
	"scam-detection-backend/internal/models"
	"scam-detection-backend/internal/repository"
	"scam-detection-backend/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type TestServer struct {
	router      *gin.Engine
	db          *gorm.DB
	authService *services.AuthService
	userService services.UserService
	sessionSvc  services.SessionService
}

func setupTestServer(t *testing.T) *TestServer {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.User{}, &models.UserSessions{})
	require.NoError(t, err)

	userRepo := repository.NewUserRepository(db)
	sessionRepo := repository.NewSessionRepository(db)

	sessionService, err := services.NewSessionService(sessionRepo, "test-secret", "1h", "24h")
	require.NoError(t, err)

	authService := services.NewAuthService(userRepo, sessionService)
	userService := services.NewUserService(userRepo)

	router := gin.New()

	return &TestServer{
		router:      router,
		db:          db,
		authService: authService,
		userService: userService,
		sessionSvc:  sessionService,
	}
}

func (s *TestServer) setupAuthRoutes() {
	authHandler := NewAuthHandler(s.authService, s.userService)

	authGroup := s.router.Group("/auth")
	{
		authGroup.POST("/register", authHandler.Register)
		authGroup.POST("/login", authHandler.Login)
		authGroup.POST("/logout", middleware.AuthMiddleware(s.authService), authHandler.Logout)
		authGroup.POST("/refresh", authHandler.RefreshToken)
	}
}

func (s *TestServer) setupUserRoutes() {
	userHandler := NewUserHandler(s.userService)

	s.router.PUT("/profile", middleware.AuthMiddleware(s.authService), userHandler.UpdateProfile)
	s.router.DELETE("/account", middleware.AuthMiddleware(s.authService), userHandler.DeleteAccount)
}

func (s *TestServer) createTestUser(t *testing.T, username, password string) *models.User {
	hashedPassword, err := crypto.HashPassword(password)
	require.NoError(t, err)

	email := username + "@test.com"
	user := &models.User{
		Username:     username,
		Email:        &email,
		PasswordHash: hashedPassword,
		Role:         models.RoleUser,
		IsActive:     true,
	}

	err = s.db.Create(user).Error
	require.NoError(t, err)

	return user
}

func (s *TestServer) createTestToken(t *testing.T, userID uint) string {
	tokens, err := s.sessionSvc.GenerateSession(context.TODO(), userID)
	require.NoError(t, err)
	return tokens.AccessToken
}

func TestAuthRegister_Success(t *testing.T) {
	server := setupTestServer(t)
	server.setupAuthRoutes()

	payload := map[string]interface{}{
		"username": "newuser",
		"email":    "newuser@test.com",
		"password": "password123",
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/auth/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Contains(t, response, "user")
	assert.Contains(t, response, "access_token")
	assert.Contains(t, response, "refresh_token")

	user := response["user"].(map[string]interface{})
	assert.Equal(t, "newuser", user["username"])
}

func TestAuthRegister_ValidationError(t *testing.T) {
	server := setupTestServer(t)
	server.setupAuthRoutes()

	payload := map[string]interface{}{
		"username": "ab",
		"password": "12345",
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/auth/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestAuthRegister_DuplicateUsername(t *testing.T) {
	server := setupTestServer(t)
	server.setupAuthRoutes()

	server.createTestUser(t, "existinguser", "password123")

	payload := map[string]interface{}{
		"username": "existinguser",
		"email":    "another@test.com",
		"password": "password123",
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/auth/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
}

func TestAuthLogin_Success(t *testing.T) {
	server := setupTestServer(t)
	server.setupAuthRoutes()

	server.createTestUser(t, "loginuser", "password123")

	payload := map[string]interface{}{
		"username": "loginuser",
		"password": "password123",
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Contains(t, response, "user")
	assert.Contains(t, response, "access_token")
	assert.Contains(t, response, "refresh_token")
}

func TestAuthLogin_InvalidCredentials(t *testing.T) {
	server := setupTestServer(t)
	server.setupAuthRoutes()

	server.createTestUser(t, "loginuser2", "password123")

	payload := map[string]interface{}{
		"username": "loginuser2",
		"password": "wrongpassword",
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthLogin_UserNotFound(t *testing.T) {
	server := setupTestServer(t)
	server.setupAuthRoutes()

	payload := map[string]interface{}{
		"username": "nonexistent",
		"password": "password123",
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserUpdateProfile_Success(t *testing.T) {
	server := setupTestServer(t)
	server.setupUserRoutes()

	user := server.createTestUser(t, "profileuser", "password123")
	token := server.createTestToken(t, user.ID)

	newUsername := "updatedusername"
	payload := map[string]interface{}{
		"username": newUsername,
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("PUT", "/profile", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response models.User
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "updatedusername", response.Username)
}

func TestUserUpdateProfile_Unauthorized(t *testing.T) {
	server := setupTestServer(t)
	server.setupUserRoutes()

	payload := map[string]interface{}{
		"username": "whatever",
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("PUT", "/profile", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserUpdateProfile_InvalidData(t *testing.T) {
	server := setupTestServer(t)
	server.setupUserRoutes()

	user := server.createTestUser(t, "valuser", "password123")
	token := server.createTestToken(t, user.ID)

	payload := map[string]interface{}{
		"username": "ab",
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("PUT", "/profile", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserDeleteAccount_Success(t *testing.T) {
	server := setupTestServer(t)
	server.setupUserRoutes()

	user := server.createTestUser(t, "deleteuser", "password123")
	token := server.createTestToken(t, user.ID)

	req := httptest.NewRequest("DELETE", "/account", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var dbUser models.User
	err := server.db.First(&dbUser, user.ID).Error
	assert.Error(t, err)
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
}

func TestUserDeleteAccount_Unauthorized(t *testing.T) {
	server := setupTestServer(t)
	server.setupUserRoutes()

	req := httptest.NewRequest("DELETE", "/account", nil)

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
