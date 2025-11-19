package repository

import (
	"context"
	"scam-detection-backend/internal/models"
	"time"
)

type UserRepository interface {
	Create(user *models.User) error
	CreateUser(user *models.User) error
	GetByID(id uint) (*models.User, error)
	GetByUsername(username string) (*models.User, error)
	GetByEmail(email string) (*models.User, error)
	GetByUsernameOrEmail(login string) (*models.User, error)
	Update(id uint, data *models.UpdateUserRequest) error
	Delete(id uint) error
}

type CheckRepository interface {
	CreateCheck(check *models.Check) error
	GetCheckByID(id uint) (*models.Check, error)
	GetChecksByUserID(userID uint, limit, offset int) ([]models.Check, int64, error)
	UpdateCheckStatus(id uint, status string, dangerScore float64, dangerLevel string, processingTime int) error
	AddCheckDetail(detail *models.CheckDetail) error
	GetCheckDetails(checkID uint) ([]models.CheckDetail, error)
	DeleteCheck(id uint, userID uint) error
	GetUserStats(userID uint) (map[string]interface{}, error)
}

type SessionRepository interface {
	Create(ctx context.Context, s *models.UserSessions) error
	GetActiveByHash(ctx context.Context, hash string, now time.Time) (*models.UserSessions, error)
	MarkUsed(ctx context.Context, id uint, usedAt time.Time) error
	InvalidateAllByUser(ctx context.Context, userID uint) error
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
}
