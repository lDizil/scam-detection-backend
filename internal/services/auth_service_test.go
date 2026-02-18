package services

import (
	"context"
	"errors"
	"testing"

	"scam-detection-backend/internal/crypto"
	"scam-detection-backend/internal/models"
	repomocks "scam-detection-backend/internal/repository/mocks"
	svcmocks "scam-detection-backend/internal/services/mocks"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestAuthService_Register_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := repomocks.NewMockUserRepository(ctrl)
	mockSession := svcmocks.NewMockSessionService(ctrl)
	svc := NewAuthService(mockUserRepo, mockSession)

	email := "user@test.com"
	req := &models.CreateUserRequest{
		Username: "newuser",
		Email:    &email,
		Password: "password123",
	}

	mockUserRepo.EXPECT().GetByUsername("newuser").Return(nil, gorm.ErrRecordNotFound)
	mockUserRepo.EXPECT().GetByEmail(email).Return(nil, gorm.ErrRecordNotFound)
	mockUserRepo.EXPECT().Create(gomock.Any()).Return(nil)
	mockSession.EXPECT().GenerateSession(gomock.Any(), gomock.Any()).Return(&models.TokenPair{
		AccessToken:  "access",
		RefreshToken: "refresh",
	}, nil)

	user, tokens, err := svc.Register(context.TODO(), req)

	require.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, "access", tokens.AccessToken)
}

func TestAuthService_Register_UserAlreadyExists(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := repomocks.NewMockUserRepository(ctrl)
	mockSession := svcmocks.NewMockSessionService(ctrl)
	svc := NewAuthService(mockUserRepo, mockSession)

	mockUserRepo.EXPECT().GetByUsername("existing").Return(&models.User{Username: "existing"}, nil)

	_, _, err := svc.Register(context.TODO(), &models.CreateUserRequest{
		Username: "existing",
		Password: "pass123",
	})

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrUserAlreadyExists)
}

func TestAuthService_Register_EmailAlreadyExists(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := repomocks.NewMockUserRepository(ctrl)
	mockSession := svcmocks.NewMockSessionService(ctrl)
	svc := NewAuthService(mockUserRepo, mockSession)

	email := "taken@test.com"
	mockUserRepo.EXPECT().GetByUsername("newuser").Return(nil, gorm.ErrRecordNotFound)
	mockUserRepo.EXPECT().GetByEmail(email).Return(&models.User{}, nil)

	_, _, err := svc.Register(context.TODO(), &models.CreateUserRequest{
		Username: "newuser",
		Email:    &email,
		Password: "pass123",
	})

	assert.ErrorIs(t, err, ErrUserAlreadyExists)
}

func TestAuthService_Login_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := repomocks.NewMockUserRepository(ctrl)
	mockSession := svcmocks.NewMockSessionService(ctrl)
	svc := NewAuthService(mockUserRepo, mockSession)

	hashedPass, err := hashTestPassword("password123")
	require.NoError(t, err)

	user := &models.User{ID: 1, Username: "loginuser", PasswordHash: hashedPass, IsActive: true}
	mockUserRepo.EXPECT().GetByUsernameOrEmail("loginuser").Return(user, nil)
	mockSession.EXPECT().CleanupExpiredSessions(gomock.Any()).Return(int64(0), nil)
	mockSession.EXPECT().GenerateSession(gomock.Any(), uint(1)).Return(&models.TokenPair{
		AccessToken:  "access",
		RefreshToken: "refresh",
	}, nil)

	resultUser, tokens, err := svc.Login(context.TODO(), "loginuser", "password123")

	require.NoError(t, err)
	assert.Equal(t, "loginuser", resultUser.Username)
	assert.Equal(t, "access", tokens.AccessToken)
}

func TestAuthService_Login_UserNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := repomocks.NewMockUserRepository(ctrl)
	mockSession := svcmocks.NewMockSessionService(ctrl)
	svc := NewAuthService(mockUserRepo, mockSession)

	mockUserRepo.EXPECT().GetByUsernameOrEmail("unknown").Return(nil, gorm.ErrRecordNotFound)

	_, _, err := svc.Login(context.TODO(), "unknown", "pass")

	assert.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestAuthService_Login_WrongPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := repomocks.NewMockUserRepository(ctrl)
	mockSession := svcmocks.NewMockSessionService(ctrl)
	svc := NewAuthService(mockUserRepo, mockSession)

	hashedPass, err := hashTestPassword("correctpass")
	require.NoError(t, err)

	user := &models.User{ID: 1, Username: "user", PasswordHash: hashedPass, IsActive: true}
	mockUserRepo.EXPECT().GetByUsernameOrEmail("user").Return(user, nil)

	_, _, err = svc.Login(context.TODO(), "user", "wrongpass")

	assert.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestAuthService_Login_InactiveUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := repomocks.NewMockUserRepository(ctrl)
	mockSession := svcmocks.NewMockSessionService(ctrl)
	svc := NewAuthService(mockUserRepo, mockSession)

	user := &models.User{ID: 1, Username: "inactive", PasswordHash: "hash", IsActive: false}
	mockUserRepo.EXPECT().GetByUsernameOrEmail("inactive").Return(user, nil)

	_, _, err := svc.Login(context.TODO(), "inactive", "pass")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "деактивирован")
}

func TestAuthService_ValidateToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := repomocks.NewMockUserRepository(ctrl)
	mockSession := svcmocks.NewMockSessionService(ctrl)
	svc := NewAuthService(mockUserRepo, mockSession)

	mockSession.EXPECT().ValidateAccessToken("token123").Return(uint(42), nil)

	id, err := svc.ValidateToken("token123")

	assert.NoError(t, err)
	assert.Equal(t, uint(42), id)
}

func TestAuthService_ValidateToken_Invalid(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := repomocks.NewMockUserRepository(ctrl)
	mockSession := svcmocks.NewMockSessionService(ctrl)
	svc := NewAuthService(mockUserRepo, mockSession)

	mockSession.EXPECT().ValidateAccessToken("badtoken").Return(uint(0), errors.New("invalid"))

	_, err := svc.ValidateToken("badtoken")

	assert.Error(t, err)
}

func TestAuthService_RefreshToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := repomocks.NewMockUserRepository(ctrl)
	mockSession := svcmocks.NewMockSessionService(ctrl)
	svc := NewAuthService(mockUserRepo, mockSession)

	mockSession.EXPECT().RefreshSession(gomock.Any(), "refresh123").Return(&models.TokenPair{
		AccessToken:  "newaccess",
		RefreshToken: "newrefresh",
	}, nil)

	tokens, err := svc.RefreshToken(context.TODO(), "refresh123")

	assert.NoError(t, err)
	assert.Equal(t, "newaccess", tokens.AccessToken)
}

func TestAuthService_LogoutAllDevices(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := repomocks.NewMockUserRepository(ctrl)
	mockSession := svcmocks.NewMockSessionService(ctrl)
	svc := NewAuthService(mockUserRepo, mockSession)

	mockSession.EXPECT().InvalidateAllUserSessions(gomock.Any(), uint(1)).Return(nil)

	err := svc.LogoutAllDevices(context.TODO(), 1)

	assert.NoError(t, err)
}

func hashTestPassword(password string) (string, error) {
	return crypto.HashPassword(password)
}
