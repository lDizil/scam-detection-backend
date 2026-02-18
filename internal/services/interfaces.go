//go:generate mockgen -source=interfaces.go -destination=mocks/mock_service.go -package=mocks

package services

import (
	"context"
	"scam-detection-backend/internal/models"
)

type UserService interface {
	GetByID(id uint) (*models.User, error)
	Update(id uint, data *models.UpdateUserRequest) error
	Delete(id uint) error
	GetAllUsers(limit, offset int) ([]models.User, int64, error)
	UpdateUserRole(id uint, role models.Role) error
	ToggleUserActiveStatus(id uint, isActive bool) error
}

type SessionService interface {
	GenerateSession(ctx context.Context, userID uint) (*models.TokenPair, error)
	ValidateAccessToken(token string) (userId uint, err error)
	GetUserIDFromToken(token string) (userId uint, err error)
	RefreshSession(ctx context.Context, refreshToken string) (*models.TokenPair, error)
	InvalidateAllUserSessions(ctx context.Context, userId uint) error
	InvalidateSession(ctx context.Context, sessionId uint) error
	CleanupExpiredSessions(ctx context.Context) (int64, error)
}
