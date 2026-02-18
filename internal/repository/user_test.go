package repository

import (
	"fmt"
	"testing"

	"scam-detection-backend/internal/models"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err, "failed to connect to test database")

	err = db.AutoMigrate(&models.User{})
	require.NoError(t, err, "failed to migrate test database")

	return db
}

func stringPtr(s string) *string {
	return &s
}

func TestUserRepo_Create(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &models.User{
		Username:     "testuser",
		Email:        stringPtr("test@example.com"),
		PasswordHash: "hashed_password",
		Role:         models.RoleUser,
		IsActive:     true,
	}

	err := repo.Create(user)

	assert.NoError(t, err)
	assert.NotZero(t, user.ID, "ID должен быть присвоен после создания")

	var foundUser models.User
	err = db.First(&foundUser, user.ID).Error
	assert.NoError(t, err)
	assert.Equal(t, "testuser", foundUser.Username)
	assert.Equal(t, "test@example.com", *foundUser.Email)
}

func TestUserRepo_Create_ErrDuplicatedKey(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &models.User{
		Username:     "testuser",
		Email:        stringPtr("test@example.com"),
		PasswordHash: "hashed_password",
		Role:         models.RoleUser,
		IsActive:     true,
	}

	err := repo.Create(user)
	require.NoError(t, err)

	user2 := &models.User{
		Username:     "testuser",
		Email:        stringPtr("other@example.com"),
		PasswordHash: "hashed_password",
		Role:         models.RoleUser,
		IsActive:     true,
	}

	err = repo.Create(user2)

	assert.Error(t, err, "должна быть ошибка при дублировании username")
	assert.Contains(t, err.Error(), "UNIQUE constraint failed", "ошибка должна содержать информацию о нарушении UNIQUE")

	var count int64
	db.Model(&models.User{}).Count(&count)
	assert.Equal(t, int64(1), count, "в БД должен быть только 1 пользователь")
}

func TestUserRepo_GetByID(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &models.User{
		Username:     "testuser",
		Email:        stringPtr("test@example.com"),
		PasswordHash: "hashed_password",
		Role:         models.RoleUser,
		IsActive:     true,
	}

	err := repo.Create(user)
	require.NoError(t, err)

	findUser, err := repo.GetByID(user.ID)

	assert.NoError(t, err)
	assert.NotNil(t, findUser)
	assert.Equal(t, user.Username, findUser.Username)
	assert.Equal(t, user.Email, findUser.Email)
	assert.Equal(t, user.PasswordHash, findUser.PasswordHash)
	assert.Equal(t, user.IsActive, findUser.IsActive)
}

func TestUserRepo_GetByID_NotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	findUser, err := repo.GetByID(99999)

	assert.Error(t, err)
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	assert.Nil(t, findUser)
}

func TestUserRepo_GetByUsername(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &models.User{
		Username:     "uniqueuser",
		Email:        stringPtr("unique@test.com"),
		PasswordHash: "hash123",
		Role:         models.RoleUser,
		IsActive:     true,
	}

	err := repo.Create(user)
	require.NoError(t, err)

	foundUser, err := repo.GetByUsername("uniqueuser")

	assert.NoError(t, err)
	assert.NotNil(t, foundUser)
	assert.Equal(t, user.ID, foundUser.ID)
	assert.Equal(t, "uniqueuser", foundUser.Username)
}

func TestUserRepo_GetByUsername_NotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	foundUser, err := repo.GetByUsername("nonexistent")

	assert.Error(t, err)
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	assert.Nil(t, foundUser)
}

func TestUserRepo_GetByEmail(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &models.User{
		Username:     "emailuser",
		Email:        stringPtr("find@email.com"),
		PasswordHash: "hash456",
		Role:         models.RoleUser,
		IsActive:     true,
	}

	err := repo.Create(user)
	require.NoError(t, err)

	foundUser, err := repo.GetByEmail("find@email.com")

	assert.NoError(t, err)
	assert.NotNil(t, foundUser)
	assert.Equal(t, user.ID, foundUser.ID)
	assert.Equal(t, "find@email.com", *foundUser.Email)
}

func TestUserRepo_GetByEmail_NotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	foundUser, err := repo.GetByEmail("nonexistent@test.com")

	assert.Error(t, err)
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	assert.Nil(t, foundUser)
}

func TestUserRepo_GetByUsernameOrEmail_WithUsername(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &models.User{
		Username:     "loginuser",
		Email:        stringPtr("login@test.com"),
		PasswordHash: "hash789",
		Role:         models.RoleUser,
		IsActive:     true,
	}

	err := repo.Create(user)
	require.NoError(t, err)

	foundUser, err := repo.GetByUsernameOrEmail("loginuser")

	assert.NoError(t, err)
	assert.NotNil(t, foundUser)
	assert.Equal(t, user.ID, foundUser.ID)
}

func TestUserRepo_GetByUsernameOrEmail_WithEmail(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &models.User{
		Username:     "emaillogin",
		Email:        stringPtr("emaillogin@test.com"),
		PasswordHash: "hash000",
		Role:         models.RoleUser,
		IsActive:     true,
	}

	err := repo.Create(user)
	require.NoError(t, err)

	foundUser, err := repo.GetByUsernameOrEmail("emaillogin@test.com")

	assert.NoError(t, err)
	assert.NotNil(t, foundUser)
	assert.Equal(t, user.ID, foundUser.ID)
}

func TestUserRepo_GetByUsernameOrEmail_NotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	foundUser, err := repo.GetByUsernameOrEmail("doesnotexist")

	assert.Error(t, err)
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	assert.Nil(t, foundUser)
}

func TestUserRepo_Update(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &models.User{
		Username:     "oldusername",
		Email:        stringPtr("old@email.com"),
		PasswordHash: "hash",
		Role:         models.RoleUser,
		IsActive:     true,
	}

	err := repo.Create(user)
	require.NoError(t, err)

	newUsername := "newusername"
	newEmail := "new@email.com"
	updateData := &models.UpdateUserRequest{
		Username: &newUsername,
		Email:    &newEmail,
	}

	err = repo.Update(user.ID, updateData)

	assert.NoError(t, err)

	updatedUser, err := repo.GetByID(user.ID)
	assert.NoError(t, err)
	assert.Equal(t, "newusername", updatedUser.Username)
	assert.Equal(t, "new@email.com", *updatedUser.Email)
}

func TestUserRepo_Update_OnlyUsername(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &models.User{
		Username:     "user1",
		Email:        stringPtr("user1@test.com"),
		PasswordHash: "hash",
		Role:         models.RoleUser,
		IsActive:     true,
	}

	err := repo.Create(user)
	require.NoError(t, err)

	newUsername := "user1updated"
	updateData := &models.UpdateUserRequest{
		Username: &newUsername,
	}

	err = repo.Update(user.ID, updateData)

	assert.NoError(t, err)

	updatedUser, err := repo.GetByID(user.ID)
	assert.NoError(t, err)
	assert.Equal(t, "user1updated", updatedUser.Username)
	assert.Equal(t, "user1@test.com", *updatedUser.Email)
}

func TestUserRepo_Update_NotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	newUsername := "whatever"
	updateData := &models.UpdateUserRequest{
		Username: &newUsername,
	}

	err := repo.Update(99999, updateData)

	assert.Error(t, err)
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
}

func TestUserRepo_Update_EmptyData(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &models.User{
		Username:     "user2",
		Email:        stringPtr("user2@test.com"),
		PasswordHash: "hash",
		Role:         models.RoleUser,
		IsActive:     true,
	}

	err := repo.Create(user)
	require.NoError(t, err)

	updateData := &models.UpdateUserRequest{}

	err = repo.Update(user.ID, updateData)

	assert.Error(t, err)
	assert.ErrorIs(t, err, gorm.ErrInvalidData)
}

func TestUserRepo_Delete(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &models.User{
		Username:     "deleteuser",
		Email:        stringPtr("delete@test.com"),
		PasswordHash: "hash",
		Role:         models.RoleUser,
		IsActive:     true,
	}

	err := repo.Create(user)
	require.NoError(t, err)

	err = repo.Delete(user.ID)

	assert.NoError(t, err)

	foundUser, err := repo.GetByID(user.ID)
	assert.Error(t, err)
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	assert.Nil(t, foundUser)
}

func TestUserRepo_Delete_NotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	err := repo.Delete(99999)

	assert.Error(t, err)
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
}

func TestUserRepo_GetAll(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	for i := 1; i <= 5; i++ {
		user := &models.User{
			Username:     fmt.Sprintf("user%d", i),
			Email:        stringPtr(fmt.Sprintf("user%d@test.com", i)),
			PasswordHash: "hash",
			Role:         models.RoleUser,
			IsActive:     true,
		}
		err := repo.Create(user)
		require.NoError(t, err)
	}

	users, total, err := repo.GetAll(10, 0)

	assert.NoError(t, err)
	assert.Equal(t, int64(5), total)
	assert.Len(t, users, 5)
}

func TestUserRepo_GetAll_WithPagination(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	for i := 1; i <= 10; i++ {
		user := &models.User{
			Username:     fmt.Sprintf("puser%d", i),
			Email:        stringPtr(fmt.Sprintf("puser%d@test.com", i)),
			PasswordHash: "hash",
			Role:         models.RoleUser,
			IsActive:     true,
		}
		err := repo.Create(user)
		require.NoError(t, err)
	}

	users, total, err := repo.GetAll(3, 0)

	assert.NoError(t, err)
	assert.Equal(t, int64(10), total)
	assert.Len(t, users, 3)

	users2, total2, err := repo.GetAll(3, 3)

	assert.NoError(t, err)
	assert.Equal(t, int64(10), total2)
	assert.Len(t, users2, 3)
	assert.NotEqual(t, users[0].ID, users2[0].ID)
}

func TestUserRepo_UpdateRole(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &models.User{
		Username:     "roleuser",
		Email:        stringPtr("role@test.com"),
		PasswordHash: "hash",
		Role:         models.RoleUser,
		IsActive:     true,
	}

	err := repo.Create(user)
	require.NoError(t, err)

	err = repo.UpdateRole(user.ID, models.RoleAdmin)

	assert.NoError(t, err)

	updatedUser, err := repo.GetByID(user.ID)
	assert.NoError(t, err)
	assert.Equal(t, models.RoleAdmin, updatedUser.Role)
}

func TestUserRepo_UpdateRole_NotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	err := repo.UpdateRole(99999, models.RoleAdmin)

	assert.Error(t, err)
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
}

func TestUserRepo_UpdateActiveStatus(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &models.User{
		Username:     "activeuser",
		Email:        stringPtr("active@test.com"),
		PasswordHash: "hash",
		Role:         models.RoleUser,
		IsActive:     true,
	}

	err := repo.Create(user)
	require.NoError(t, err)

	err = repo.UpdateActiveStatus(user.ID, false)

	assert.NoError(t, err)

	updatedUser, err := repo.GetByID(user.ID)
	assert.NoError(t, err)
	assert.False(t, updatedUser.IsActive)
}

func TestUserRepo_UpdateActiveStatus_NotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	err := repo.UpdateActiveStatus(99999, false)

	assert.Error(t, err)
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
}

func TestUserRepo_Create_NilUser(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	err := repo.Create(nil)

	assert.Error(t, err)
	assert.ErrorIs(t, err, gorm.ErrInvalidData)
}
