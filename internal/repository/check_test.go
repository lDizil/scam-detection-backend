package repository

import (
	"testing"

	"scam-detection-backend/internal/models"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func setupCheckTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	err = db.AutoMigrate(&models.User{}, &models.Check{}, &models.CheckDetail{})
	require.NoError(t, err)
	return db
}

func createTestUser(t *testing.T, db *gorm.DB) *models.User {
	email := "checkuser@test.com"
	user := &models.User{
		Username:     "checkuser",
		Email:        &email,
		PasswordHash: "hash",
		Role:         models.RoleUser,
		IsActive:     true,
	}
	err := db.Create(user).Error
	require.NoError(t, err)
	return user
}

func TestCheckRepo_CreateCheck(t *testing.T) {
	db := setupCheckTestDB(t)
	repo := NewCheckRepository(db)
	user := createTestUser(t, db)

	check := &models.Check{
		Title:       "test url",
		ContentType: "url",
		Content:     "http://example.com",
		CheckType:   "text",
		Status:      "processing",
		UserID:      user.ID,
	}

	err := repo.CreateCheck(check)

	assert.NoError(t, err)
	assert.NotZero(t, check.ID)
}

func TestCheckRepo_GetCheckByID(t *testing.T) {
	db := setupCheckTestDB(t)
	repo := NewCheckRepository(db)
	user := createTestUser(t, db)

	check := &models.Check{
		Title:       "test url",
		ContentType: "url",
		Content:     "http://example.com",
		CheckType:   "text",
		Status:      "done",
		UserID:      user.ID,
	}
	err := repo.CreateCheck(check)
	require.NoError(t, err)

	found, err := repo.GetCheckByID(check.ID)

	assert.NoError(t, err)
	assert.Equal(t, check.ID, found.ID)
	assert.Equal(t, "test url", found.Title)
}

func TestCheckRepo_GetCheckByID_NotFound(t *testing.T) {
	db := setupCheckTestDB(t)
	repo := NewCheckRepository(db)

	found, err := repo.GetCheckByID(99999)

	assert.Error(t, err)
	assert.Nil(t, found)
}

func TestCheckRepo_GetChecksByUserID(t *testing.T) {
	db := setupCheckTestDB(t)
	repo := NewCheckRepository(db)
	user := createTestUser(t, db)

	for i := 0; i < 3; i++ {
		check := &models.Check{
			Title:       "check",
			ContentType: "url",
			Content:     "http://example.com",
			Status:      "done",
			UserID:      user.ID,
		}
		err := repo.CreateCheck(check)
		require.NoError(t, err)
	}

	checks, total, err := repo.GetChecksByUserID(user.ID, 10, 0)

	assert.NoError(t, err)
	assert.Equal(t, int64(3), total)
	assert.Len(t, checks, 3)
}

func TestCheckRepo_GetChecksByUserID_Pagination(t *testing.T) {
	db := setupCheckTestDB(t)
	repo := NewCheckRepository(db)
	user := createTestUser(t, db)

	for i := 0; i < 5; i++ {
		check := &models.Check{
			Title:       "check",
			ContentType: "url",
			Content:     "http://example.com",
			Status:      "done",
			UserID:      user.ID,
		}
		err := repo.CreateCheck(check)
		require.NoError(t, err)
	}

	checks, total, err := repo.GetChecksByUserID(user.ID, 2, 0)

	assert.NoError(t, err)
	assert.Equal(t, int64(5), total)
	assert.Len(t, checks, 2)
}

func TestCheckRepo_GetAllChecks(t *testing.T) {
	db := setupCheckTestDB(t)
	repo := NewCheckRepository(db)
	user := createTestUser(t, db)

	for i := 0; i < 3; i++ {
		check := &models.Check{
			Title:       "check",
			ContentType: "url",
			Content:     "http://example.com",
			Status:      "done",
			UserID:      user.ID,
		}
		err := repo.CreateCheck(check)
		require.NoError(t, err)
	}

	checks, total, err := repo.GetAllChecks(10, 0)

	assert.NoError(t, err)
	assert.Equal(t, int64(3), total)
	assert.Len(t, checks, 3)
}

func TestCheckRepo_UpdateCheckStatus(t *testing.T) {
	db := setupCheckTestDB(t)
	repo := NewCheckRepository(db)
	user := createTestUser(t, db)

	check := &models.Check{
		Title:       "test",
		ContentType: "url",
		Content:     "http://example.com",
		Status:      "processing",
		UserID:      user.ID,
	}
	err := repo.CreateCheck(check)
	require.NoError(t, err)

	err = repo.UpdateCheckStatus(check.ID, "done", 0.85, "high", 120)

	assert.NoError(t, err)

	updated, err := repo.GetCheckByID(check.ID)
	assert.NoError(t, err)
	assert.Equal(t, "done", updated.Status)
	assert.Equal(t, 0.85, updated.DangerScore)
	assert.Equal(t, "high", updated.DangerLevel)
	assert.Equal(t, 120, updated.ProcessingTime)
}

func TestCheckRepo_AddCheckDetail(t *testing.T) {
	db := setupCheckTestDB(t)
	repo := NewCheckRepository(db)
	user := createTestUser(t, db)

	check := &models.Check{
		Title:       "test",
		ContentType: "url",
		Content:     "http://example.com",
		Status:      "done",
		UserID:      user.ID,
	}
	err := repo.CreateCheck(check)
	require.NoError(t, err)

	detail := &models.CheckDetail{
		CheckID:         check.ID,
		FeatureName:     "ssl_certificate",
		FeatureValue:    "false",
		ConfidenceScore: 0.9,
	}

	err = repo.AddCheckDetail(detail)

	assert.NoError(t, err)
	assert.NotZero(t, detail.ID)
}

func TestCheckRepo_GetCheckDetails(t *testing.T) {
	db := setupCheckTestDB(t)
	repo := NewCheckRepository(db)
	user := createTestUser(t, db)

	check := &models.Check{
		Title:       "test",
		ContentType: "url",
		Content:     "http://example.com",
		Status:      "done",
		UserID:      user.ID,
	}
	err := repo.CreateCheck(check)
	require.NoError(t, err)

	details := []*models.CheckDetail{
		{CheckID: check.ID, FeatureName: "feature1", FeatureValue: "val1", ConfidenceScore: 0.8},
		{CheckID: check.ID, FeatureName: "feature2", FeatureValue: "val2", ConfidenceScore: 0.6},
	}
	for _, d := range details {
		err = repo.AddCheckDetail(d)
		require.NoError(t, err)
	}

	found, err := repo.GetCheckDetails(check.ID)

	assert.NoError(t, err)
	assert.Len(t, found, 2)
}

func TestCheckRepo_GetCheckDetails_Empty(t *testing.T) {
	db := setupCheckTestDB(t)
	repo := NewCheckRepository(db)

	found, err := repo.GetCheckDetails(99999)

	assert.NoError(t, err)
	assert.Empty(t, found)
}

func TestCheckRepo_DeleteCheck(t *testing.T) {
	db := setupCheckTestDB(t)
	repo := NewCheckRepository(db)
	user := createTestUser(t, db)

	check := &models.Check{
		Title:       "to delete",
		ContentType: "url",
		Content:     "http://example.com",
		Status:      "done",
		UserID:      user.ID,
	}
	err := repo.CreateCheck(check)
	require.NoError(t, err)

	detail := &models.CheckDetail{
		CheckID:         check.ID,
		FeatureName:     "feature",
		FeatureValue:    "value",
		ConfidenceScore: 0.5,
	}
	err = repo.AddCheckDetail(detail)
	require.NoError(t, err)

	err = repo.DeleteCheck(check.ID, user.ID)

	assert.NoError(t, err)

	_, err = repo.GetCheckByID(check.ID)
	assert.Error(t, err)
}

func TestCheckRepo_GetUserStats(t *testing.T) {
	db := setupCheckTestDB(t)
	repo := NewCheckRepository(db)
	user := createTestUser(t, db)

	checks := []*models.Check{
		{Title: "c1", ContentType: "url", Content: "http://a.com", Status: "done", UserID: user.ID, DangerLevel: "low", DangerScore: 0.1, ProcessingTime: 100},
		{Title: "c2", ContentType: "url", Content: "http://b.com", Status: "done", UserID: user.ID, DangerLevel: "medium", DangerScore: 0.5, ProcessingTime: 200},
		{Title: "c3", ContentType: "url", Content: "http://c.com", Status: "done", UserID: user.ID, DangerLevel: "high", DangerScore: 0.9, ProcessingTime: 300},
		{Title: "c4", ContentType: "url", Content: "http://d.com", Status: "done", UserID: user.ID, DangerLevel: "critical", DangerScore: 1.0, ProcessingTime: 400},
	}
	for _, c := range checks {
		err := repo.CreateCheck(c)
		require.NoError(t, err)
	}

	stats, err := repo.GetUserStats(user.ID)

	assert.NoError(t, err)
	assert.Equal(t, int64(4), stats["total_analyses"])
	assert.Equal(t, 1, stats["safe_count"])
	assert.Equal(t, 1, stats["suspicious_count"])
	assert.Equal(t, 2, stats["dangerous_count"])
}

func TestCheckRepo_GetUserStats_Empty(t *testing.T) {
	db := setupCheckTestDB(t)
	repo := NewCheckRepository(db)

	stats, err := repo.GetUserStats(99999)

	assert.NoError(t, err)
	assert.Equal(t, int64(0), stats["total_analyses"])
}

func TestCheckRepo_GetGlobalStats(t *testing.T) {
	db := setupCheckTestDB(t)
	repo := NewCheckRepository(db)
	user := createTestUser(t, db)

	checks := []*models.Check{
		{Title: "c1", ContentType: "url", Content: "http://a.com", Status: "done", UserID: user.ID, DangerLevel: "low", DangerScore: 0.1, ProcessingTime: 100},
		{Title: "c2", ContentType: "url", Content: "http://b.com", Status: "done", UserID: user.ID, DangerLevel: "medium", DangerScore: 0.5, ProcessingTime: 200},
		{Title: "c3", ContentType: "url", Content: "http://c.com", Status: "done", UserID: user.ID, DangerLevel: "critical", DangerScore: 0.95, ProcessingTime: 300},
	}
	for _, c := range checks {
		err := repo.CreateCheck(c)
		require.NoError(t, err)
	}

	stats, err := repo.GetGlobalStats()

	assert.NoError(t, err)
	assert.Equal(t, int64(3), stats["total_analyses"])
	assert.Equal(t, int64(1), stats["total_users"])
	assert.Equal(t, 1, stats["safe_count"])
	assert.Equal(t, 1, stats["suspicious_count"])
	assert.Equal(t, 1, stats["dangerous_count"])
}

func TestCheckRepo_GetGlobalStats_Empty(t *testing.T) {
	db := setupCheckTestDB(t)
	repo := NewCheckRepository(db)

	stats, err := repo.GetGlobalStats()

	assert.NoError(t, err)
	assert.Equal(t, int64(0), stats["total_analyses"])
}
