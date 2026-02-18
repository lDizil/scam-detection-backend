package e2e_tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"scam-detection-backend/internal/api/handlers"
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

type E2ETestServer struct {
	router      *gin.Engine
	db          *gorm.DB
	authService *services.AuthService
	userService services.UserService
	sessionSvc  services.SessionService
}

func setupE2EServer(t *testing.T) *E2ETestServer {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.User{}, &models.UserSessions{}, &models.Check{}, &models.CheckDetail{})
	require.NoError(t, err)

	userRepo := repository.NewUserRepository(db)
	sessionRepo := repository.NewSessionRepository(db)

	sessionService, err := services.NewSessionService(sessionRepo, "e2e-test-secret", "1h", "24h")
	require.NoError(t, err)

	authService := services.NewAuthService(userRepo, sessionService)
	userService := services.NewUserService(userRepo)

	router := gin.New()

	authHandler := handlers.NewAuthHandler(authService, userService)
	userHandler := handlers.NewUserHandler(userService)
	adminHandler := handlers.NewAdminHandler(userService)

	authGroup := router.Group("/auth")
	{
		authGroup.POST("/register", authHandler.Register)
		authGroup.POST("/login", authHandler.Login)
		authGroup.POST("/logout", middleware.AuthMiddleware(authService), authHandler.Logout)
		authGroup.POST("/refresh", authHandler.RefreshToken)
	}

	userGroup := router.Group("")
	userGroup.Use(middleware.AuthMiddleware(authService))
	{
		userGroup.PUT("/profile", userHandler.UpdateProfile)
		userGroup.DELETE("/account", userHandler.DeleteAccount)
	}

	adminGroup := router.Group("/admin")
	adminGroup.Use(middleware.AuthMiddleware(authService))
	adminGroup.Use(middleware.RequireRole(userService, models.RoleAdmin))
	{
		adminGroup.GET("/users", adminHandler.GetAllUsers)
		adminGroup.GET("/users/:id", adminHandler.GetUserByID)
		adminGroup.PUT("/users/:id/role", adminHandler.UpdateUserRole)
		adminGroup.PUT("/users/:id/status", adminHandler.ToggleUserStatus)
	}

	return &E2ETestServer{
		router:      router,
		db:          db,
		authService: authService,
		userService: userService,
		sessionSvc:  sessionService,
	}
}

func TestE2E_UserRegistrationLoginFlow(t *testing.T) {
	server := setupE2EServer(t)

	registerPayload := map[string]interface{}{
		"username": "e2euser",
		"email":    "e2e@test.com",
		"password": "securepass123",
	}

	body, _ := json.Marshal(registerPayload)
	req := httptest.NewRequest("POST", "/auth/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var registerResponse map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &registerResponse)
	assert.NoError(t, err)
	assert.Contains(t, registerResponse, "access_token")

	loginPayload := map[string]interface{}{
		"username": "e2euser",
		"password": "securepass123",
	}

	body, _ = json.Marshal(loginPayload)
	req = httptest.NewRequest("POST", "/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w = httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var loginResponse map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &loginResponse)
	assert.NoError(t, err)
	assert.Contains(t, loginResponse, "user")
	assert.Contains(t, loginResponse, "access_token")
	assert.Contains(t, loginResponse, "refresh_token")
}

func TestE2E_UserProfileUpdateFlow(t *testing.T) {
	server := setupE2EServer(t)

	registerPayload := map[string]interface{}{
		"username": "profileuser",
		"email":    "profile@test.com",
		"password": "password123",
	}

	body, _ := json.Marshal(registerPayload)
	req := httptest.NewRequest("POST", "/auth/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var registerResponse map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &registerResponse)
	assert.NoError(t, err)

	accessToken := registerResponse["access_token"].(string)

	updatePayload := map[string]interface{}{
		"username": "updatedprofileuser",
		"email":    "updated@test.com",
	}

	body, _ = json.Marshal(updatePayload)
	req = httptest.NewRequest("PUT", "/profile", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "access_token", Value: accessToken})

	w = httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var updateResponse models.User
	err = json.Unmarshal(w.Body.Bytes(), &updateResponse)
	assert.NoError(t, err)
	assert.Equal(t, "updatedprofileuser", updateResponse.Username)
	assert.Equal(t, "updated@test.com", *updateResponse.Email)
}

func TestE2E_AdminUserManagementFlow(t *testing.T) {
	server := setupE2EServer(t)

	hashedPassword, _ := crypto.HashPassword("adminpass123")
	adminEmail := "admin@test.com"
	admin := &models.User{
		Username:     "adminuser",
		Email:        &adminEmail,
		PasswordHash: hashedPassword,
		Role:         models.RoleAdmin,
		IsActive:     true,
	}
	err := server.db.Create(admin).Error
	require.NoError(t, err)

	loginPayload := map[string]interface{}{
		"username": "adminuser",
		"password": "adminpass123",
	}

	body, _ := json.Marshal(loginPayload)
	req := httptest.NewRequest("POST", "/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var loginResponse map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &loginResponse)
	assert.NoError(t, err)

	adminToken := loginResponse["access_token"].(string)

	registerPayload := map[string]interface{}{
		"username": "regularuser",
		"email":    "regular@test.com",
		"password": "userpass123",
	}

	body, _ = json.Marshal(registerPayload)
	req = httptest.NewRequest("POST", "/auth/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w = httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var user models.User
	err = server.db.Where("username = ?", "regularuser").First(&user).Error
	require.NoError(t, err)

	req = httptest.NewRequest("GET", "/admin/users?limit=10&offset=0", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: adminToken})

	w = httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	rolePayload := map[string]interface{}{
		"role": "admin",
	}

	body, _ = json.Marshal(rolePayload)
	req = httptest.NewRequest("PUT", "/admin/users/"+string(rune(user.ID+48))+"/role", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "access_token", Value: adminToken})

	w = httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestE2E_UnauthorizedAccessDenied(t *testing.T) {
	server := setupE2EServer(t)

	req := httptest.NewRequest("PUT", "/profile", nil)

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	req = httptest.NewRequest("GET", "/admin/users", nil)

	w = httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestE2E_RoleBasedAccessControl(t *testing.T) {
	server := setupE2EServer(t)

	registerPayload := map[string]interface{}{
		"username": "normaluser",
		"email":    "normal@test.com",
		"password": "password123",
	}

	body, _ := json.Marshal(registerPayload)
	req := httptest.NewRequest("POST", "/auth/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var registerResponse map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &registerResponse)
	assert.NoError(t, err)

	userToken := registerResponse["access_token"].(string)

	req = httptest.NewRequest("GET", "/admin/users", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: userToken})

	w = httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestE2E_AccountDeletionFlow(t *testing.T) {
	server := setupE2EServer(t)

	registerPayload := map[string]interface{}{
		"username": "deleteuser",
		"email":    "delete@test.com",
		"password": "password123",
	}

	body, _ := json.Marshal(registerPayload)
	req := httptest.NewRequest("POST", "/auth/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var registerResponse map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &registerResponse)
	assert.NoError(t, err)

	accessToken := registerResponse["access_token"].(string)
	userID := uint(registerResponse["user"].(map[string]interface{})["id"].(float64))

	req = httptest.NewRequest("DELETE", "/account", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: accessToken})

	w = httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var deletedUser models.User
	err = server.db.First(&deletedUser, userID).Error
	assert.Error(t, err)
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
}
