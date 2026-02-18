package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

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

type middlewareTestEnv struct {
	router      *gin.Engine
	db          *gorm.DB
	authService *services.AuthService
	userService services.UserService
	sessionSvc  services.SessionService
}

func setupMiddlewareTestEnv(t *testing.T) *middlewareTestEnv {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.User{}, &models.UserSessions{})
	require.NoError(t, err)

	userRepo := repository.NewUserRepository(db)
	sessionRepo := repository.NewSessionRepository(db)

	sessionService, err := services.NewSessionService(sessionRepo, "mw-test-secret", "1h", "24h")
	require.NoError(t, err)

	authService := services.NewAuthService(userRepo, sessionService)
	userService := services.NewUserService(userRepo)

	return &middlewareTestEnv{
		router:      gin.New(),
		db:          db,
		authService: authService,
		userService: userService,
		sessionSvc:  sessionService,
	}
}

func (env *middlewareTestEnv) createUser(t *testing.T, username string, role models.Role, active bool) *models.User {
	hashed, err := crypto.HashPassword("password")
	require.NoError(t, err)

	email := username + "@test.com"
	user := &models.User{
		Username:     username,
		Email:        &email,
		PasswordHash: hashed,
		Role:         role,
		IsActive:     true,
	}
	require.NoError(t, env.db.Create(user).Error)

	if !active {
		require.NoError(t, env.db.Model(user).Update("is_active", false).Error)
		user.IsActive = false
	}
	return user
}

func (env *middlewareTestEnv) generateToken(t *testing.T, userID uint) string {
	tokens, err := env.sessionSvc.GenerateSession(context.TODO(), userID)
	require.NoError(t, err)
	return tokens.AccessToken
}

// --- AuthMiddleware tests ---

func TestAuthMiddleware_ValidToken(t *testing.T) {
	env := setupMiddlewareTestEnv(t)

	env.router.GET("/protected", AuthMiddleware(env.authService), func(c *gin.Context) {
		userID, ok := GetUserID(c)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "no user id"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"user_id": userID})
	})

	user := env.createUser(t, "validtokenuser", models.RoleUser, true)
	token := env.generateToken(t, user.ID)

	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthMiddleware_NoToken(t *testing.T) {
	env := setupMiddlewareTestEnv(t)

	env.router.GET("/protected", AuthMiddleware(env.authService), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	env := setupMiddlewareTestEnv(t)

	env.router.GET("/protected", AuthMiddleware(env.authService), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "bad.token.value"})
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_OptionsPassthrough(t *testing.T) {
	env := setupMiddlewareTestEnv(t)

	env.router.OPTIONS("/protected", AuthMiddleware(env.authService), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest("OPTIONS", "/protected", nil)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// --- GetUserID tests ---

func TestGetUserID_Present(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set(UserIDKey, uint(42))

	id, ok := GetUserID(c)
	assert.True(t, ok)
	assert.Equal(t, uint(42), id)
}

func TestGetUserID_Missing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	_, ok := GetUserID(c)
	assert.False(t, ok)
}

// --- RequireRole tests ---

func TestRequireRole_Allowed(t *testing.T) {
	env := setupMiddlewareTestEnv(t)

	env.router.GET("/admin", AuthMiddleware(env.authService), RequireRole(env.userService, models.RoleAdmin), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	user := env.createUser(t, "adminroleuser", models.RoleAdmin, true)
	token := env.generateToken(t, user.ID)

	req := httptest.NewRequest("GET", "/admin", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireRole_Forbidden(t *testing.T) {
	env := setupMiddlewareTestEnv(t)

	env.router.GET("/admin", AuthMiddleware(env.authService), RequireRole(env.userService, models.RoleAdmin), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	user := env.createUser(t, "regularlroleruser", models.RoleUser, true)
	token := env.generateToken(t, user.ID)

	req := httptest.NewRequest("GET", "/admin", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequireRole_InactiveUser(t *testing.T) {
	env := setupMiddlewareTestEnv(t)

	env.router.GET("/admin", AuthMiddleware(env.authService), RequireRole(env.userService, models.RoleAdmin), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	user := env.createUser(t, "inactiveuserr", models.RoleAdmin, false)
	token := env.generateToken(t, user.ID)

	req := httptest.NewRequest("GET", "/admin", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// --- GetUserRole / GetUser tests ---

func TestGetUserRole_Present(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set(UserRoleKey, models.RoleAdmin)

	role, ok := GetUserRole(c)
	assert.True(t, ok)
	assert.Equal(t, models.RoleAdmin, role)
}

func TestGetUserRole_Missing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	_, ok := GetUserRole(c)
	assert.False(t, ok)
}

func TestGetUser_Present(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	user := &models.User{Username: "testuser"}
	c.Set(UserKey, user)

	u, ok := GetUser(c)
	assert.True(t, ok)
	assert.Equal(t, "testuser", u.Username)
}

func TestGetUser_Missing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	_, ok := GetUser(c)
	assert.False(t, ok)
}
