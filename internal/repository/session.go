package repository

import (
	"context"
	"scam-detection-backend/internal/models"
	"time"

	"gorm.io/gorm"
)

type sessionRepository struct {
	db *gorm.DB
}

func NewSessionRepository(db *gorm.DB) SessionRepository {
	return &sessionRepository{
		db: db,
	}
}

func (r *sessionRepository) Create(ctx context.Context, s *models.UserSessions) error {

}
func (r *sessionRepository) GetActiveByHash(ctx context.Context, hash string, now time.Time) (*models.UserSessions, error) {

}
func (r *sessionRepository) MarkUsed(ctx context.Context, id uint, usedAt time.Time) error {

}
func (r *sessionRepository) InvalidateAllByUser(ctx context.Context, userID uint) error {

}
func (r *sessionRepository) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {

}
