package repository

import (
	"context"
	"testing"
	"time"

	"scam-detection-backend/internal/models"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func setupSessionTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.UserSessions{})
	require.NoError(t, err)

	return db
}

func TestSessionRepo_Create_Success(t *testing.T) {
	db := setupSessionTestDB(t)
	repo := NewSessionRepository(db)

	session := &models.UserSessions{
		UserId:    1,
		TokenHash: "test-hash",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err := repo.Create(context.Background(), session)

	assert.NoError(t, err)
	assert.NotZero(t, session.ID)
}

func TestSessionRepo_GetActiveByHash_Success(t *testing.T) {
	db := setupSessionTestDB(t)
	repo := NewSessionRepository(db)

	session := &models.UserSessions{
		UserId:    1,
		TokenHash: "test-hash-123",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err := repo.Create(context.Background(), session)
	require.NoError(t, err)

	found, err := repo.GetActiveByHash(context.Background(), "test-hash-123", time.Now())

	assert.NoError(t, err)
	assert.NotNil(t, found)
	assert.Equal(t, session.ID, found.ID)
	assert.Equal(t, uint(1), found.UserId)
}

func TestSessionRepo_GetActiveByHash_Expired(t *testing.T) {
	db := setupSessionTestDB(t)
	repo := NewSessionRepository(db)

	session := &models.UserSessions{
		UserId:    1,
		TokenHash: "expired-hash",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}

	err := repo.Create(context.Background(), session)
	require.NoError(t, err)

	found, err := repo.GetActiveByHash(context.Background(), "expired-hash", time.Now())

	assert.Error(t, err)
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	assert.Nil(t, found)
}

func TestSessionRepo_GetActiveByHash_NotFound(t *testing.T) {
	db := setupSessionTestDB(t)
	repo := NewSessionRepository(db)

	found, err := repo.GetActiveByHash(context.Background(), "nonexistent-hash", time.Now())

	assert.Error(t, err)
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	assert.Nil(t, found)
}

func TestSessionRepo_MarkUsed_Success(t *testing.T) {
	db := setupSessionTestDB(t)
	repo := NewSessionRepository(db)

	session := &models.UserSessions{
		UserId:    1,
		TokenHash: "hash-to-use",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err := repo.Create(context.Background(), session)
	require.NoError(t, err)

	usedAt := time.Now()
	err = repo.MarkUsed(context.Background(), session.ID, usedAt)

	assert.NoError(t, err)

	var updated models.UserSessions
	err = db.First(&updated, session.ID).Error
	assert.NoError(t, err)
	assert.NotNil(t, updated.UsedAt)
}

func TestSessionRepo_InvalidateAllByUser_Success(t *testing.T) {
	db := setupSessionTestDB(t)
	repo := NewSessionRepository(db)

	sessions := []*models.UserSessions{
		{
			UserId:    1,
			TokenHash: "hash1",
			ExpiresAt: time.Now().Add(24 * time.Hour),
		},
		{
			UserId:    1,
			TokenHash: "hash2",
			ExpiresAt: time.Now().Add(24 * time.Hour),
		},
	}

	for _, s := range sessions {
		err := repo.Create(context.Background(), s)
		require.NoError(t, err)
	}

	err := repo.InvalidateAllByUser(context.Background(), 1)

	assert.NoError(t, err)

	var count int64
	db.Model(&models.UserSessions{}).Where("user_id = ? AND revoked_at IS NULL", 1).Count(&count)
	assert.Equal(t, int64(0), count)
}

func TestSessionRepo_DeleteExpired_Success(t *testing.T) {
	db := setupSessionTestDB(t)
	repo := NewSessionRepository(db)

	expiredSession := &models.UserSessions{
		UserId:    1,
		TokenHash: "expired-hash",
		ExpiresAt: time.Now().Add(-48 * time.Hour),
	}

	activeSession := &models.UserSessions{
		UserId:    1,
		TokenHash: "active-hash",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err := repo.Create(context.Background(), expiredSession)
	require.NoError(t, err)

	err = repo.Create(context.Background(), activeSession)
	require.NoError(t, err)

	deleted, err := repo.DeleteExpired(context.Background(), time.Now())

	assert.NoError(t, err)
	assert.Equal(t, int64(1), deleted)

	var count int64
	db.Model(&models.UserSessions{}).Count(&count)
	assert.Equal(t, int64(1), count)
}
