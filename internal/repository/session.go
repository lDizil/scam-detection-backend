package repository

import (
	"context"
	"errors"
	"fmt"
	"log"
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
	if s == nil {
		return gorm.ErrInvalidData
	}

	err := r.db.WithContext(ctx).Create(s).Error
	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return gorm.ErrDuplicatedKey
		}

		return fmt.Errorf("failed to create session: %w", err)
	}

	return nil
}

func (r *sessionRepository) GetActiveByHash(ctx context.Context, hash string, now time.Time) (*models.UserSessions, error) {
	if hash == "" {
		return nil, gorm.ErrInvalidData
	}

	var session models.UserSessions

	err := r.db.Where("token_hash = ? AND expires_at > ? AND used_at IS NULL", hash, now).First(&session).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, gorm.ErrRecordNotFound
		}
		return nil, fmt.Errorf("failed to get session by hash: %w", err)
	}

	return &session, nil
}

func (r *sessionRepository) MarkUsed(ctx context.Context, id uint, usedAt time.Time) error {
	if id == 0 {
		return gorm.ErrInvalidData
	}

	var session models.UserSessions
	err := r.db.Where("ID = ? AND used_at IS NULL", id).First(&session).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return gorm.ErrRecordNotFound
		}
		return fmt.Errorf("failed to find session: %w", err)
	}

	session.UsedAt = &usedAt
	err = r.db.Save(&session).Error
	if err != nil {
		return fmt.Errorf("failed to mark session used: %w", err)
	}

	return nil
}

func (r *sessionRepository) InvalidateAllByUser(ctx context.Context, userID uint) error {
	if userID == 0 {
		return gorm.ErrInvalidData
	}

	result := r.db.Where("user_id = ?", userID).Delete(&models.UserSessions{})
	err := result.Error
	rowsAffected := result.RowsAffected

	if err != nil {
		return fmt.Errorf("failed to invalidate all user sessions: %w", err)
	}

	if rowsAffected == 0 {
		log.Printf("InvalidateAllByUser: no user sessions found to delete")
	}

	return nil
}

func (r *sessionRepository) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	result := r.db.WithContext(ctx).Where("expires_at <= ?", now).Delete(&models.UserSessions{})

	if result.Error != nil {
		return 0, fmt.Errorf("failed to delete expires user session: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		log.Printf("DeleteExpired: no expired sessions found to delete")
	}

	return result.RowsAffected, nil
}
