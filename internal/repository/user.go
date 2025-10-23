package repository

import (
	"errors"
	"fmt"
	"scam-detection-backend/internal/models"

	"gorm.io/gorm"
)

type userRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) CreateUser(user *models.User) error {
	if user == nil {
		return gorm.ErrInvalidData
	}

	err := r.db.Create(user).Error

	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return gorm.ErrDuplicatedKey
		}
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

func (r *userRepository) GetByID(id uint) (*models.User, error) {
	var user models.User

	err := r.db.First(&user, id).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, gorm.ErrRecordNotFound
		}
		return nil, fmt.Errorf("failed to get user by id: %w", err)
	}

	return &user, nil
}

func (r *userRepository) GetByUsernameOrEmail(login string) (*models.User, error) {
	var user models.User

	err := r.db.Where("username = ? OR email = ?", login, login).First(&user).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, gorm.ErrRecordNotFound
		}
		return nil, fmt.Errorf("failed to get user by username or email: %w", err)
	}

	return &user, nil
}

func (r *userRepository) Update(id uint, data *models.UpdateUserRequest) error {
	updates := make(map[string]interface{})

	if data.Username != nil {
		updates["username"] = *data.Username
	}
	if data.Email != nil {
		updates["email"] = *data.Email
	}

	if len(updates) == 0 {
		return gorm.ErrInvalidData
	}

	result := r.db.Model(&models.User{}).Where("id = ?", id).Updates(updates)

	if result.Error != nil {
		return fmt.Errorf("faile to update user: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	return nil
}

func (r *userRepository) Delete(id uint) error {
	result := r.db.Delete(&models.User{}, id)

	if result.Error != nil {
		return fmt.Errorf("faile to delete user: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}
