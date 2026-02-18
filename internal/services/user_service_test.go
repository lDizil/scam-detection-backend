package services

import (
	"testing"

	"scam-detection-backend/internal/models"
	"scam-detection-backend/internal/repository/mocks"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func TestUserService_GetByID_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	service := NewUserService(mockRepo)

	expectedUser := &models.User{
		ID:       1,
		Username: "testuser",
		Role:     models.RoleUser,
		IsActive: true,
	}

	mockRepo.EXPECT().
		GetByID(uint(1)).
		Return(expectedUser, nil).
		Times(1)

	user, err := service.GetByID(1)

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, uint(1), user.ID)
	assert.Equal(t, "testuser", user.Username)
}

func TestUserService_GetByID_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	service := NewUserService(mockRepo)

	mockRepo.EXPECT().
		GetByID(uint(999)).
		Return(nil, gorm.ErrRecordNotFound).
		Times(1)

	user, err := service.GetByID(999)

	assert.Error(t, err)
	assert.Nil(t, user)
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
}

func TestUserService_Update_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	service := NewUserService(mockRepo)

	username := "updated"
	updateData := &models.UpdateUserRequest{
		Username: &username,
	}

	mockRepo.EXPECT().
		Update(uint(1), updateData).
		Return(nil).
		Times(1)

	err := service.Update(1, updateData)

	assert.NoError(t, err)
}

func TestUserService_Update_Error(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	service := NewUserService(mockRepo)

	updateData := &models.UpdateUserRequest{}

	mockRepo.EXPECT().
		Update(uint(1), updateData).
		Return(gorm.ErrInvalidData).
		Times(1)

	err := service.Update(1, updateData)

	assert.Error(t, err)
	assert.ErrorIs(t, err, gorm.ErrInvalidData)
}

func TestUserService_Delete_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	service := NewUserService(mockRepo)

	mockRepo.EXPECT().
		Delete(uint(1)).
		Return(nil).
		Times(1)

	err := service.Delete(1)

	assert.NoError(t, err)
}

func TestUserService_Delete_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	service := NewUserService(mockRepo)

	mockRepo.EXPECT().
		Delete(uint(999)).
		Return(gorm.ErrRecordNotFound).
		Times(1)

	err := service.Delete(999)

	assert.Error(t, err)
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
}

func TestUserService_GetAllUsers_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	service := NewUserService(mockRepo)

	expectedUsers := []models.User{
		{ID: 1, Username: "user1", Role: models.RoleUser},
		{ID: 2, Username: "user2", Role: models.RoleUser},
	}

	mockRepo.EXPECT().
		GetAll(10, 0).
		Return(expectedUsers, int64(2), nil).
		Times(1)

	users, total, err := service.GetAllUsers(10, 0)

	assert.NoError(t, err)
	assert.Len(t, users, 2)
	assert.Equal(t, int64(2), total)
}

func TestUserService_UpdateUserRole_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	service := NewUserService(mockRepo)

	mockRepo.EXPECT().
		UpdateRole(uint(1), models.RoleAdmin).
		Return(nil).
		Times(1)

	err := service.UpdateUserRole(1, models.RoleAdmin)

	assert.NoError(t, err)
}

func TestUserService_UpdateUserRole_InvalidRole(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	service := NewUserService(mockRepo)

	err := service.UpdateUserRole(1, models.Role("invalid"))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid role")
}

func TestUserService_ToggleUserActiveStatus_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	service := NewUserService(mockRepo)

	mockRepo.EXPECT().
		UpdateActiveStatus(uint(1), false).
		Return(nil).
		Times(1)

	err := service.ToggleUserActiveStatus(1, false)

	assert.NoError(t, err)
}
