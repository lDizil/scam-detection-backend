package repository

import (
	"errors"
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
		return ErrInvalidData
	}

	err := r.db.Create(user).Error

	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return ErrUserAlreadyExists
		}
		return ErrDatabaseError
	}

	return nil
}

func (r *userRepository) GetByID(id uint) (*models.User, error) {
	var user models.User

	err := r.db.First(&user, id).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, ErrDatabaseError
	}

	return &user, nil
}

func (r *userRepository) GetByUsernameOrEmail(login string) (*models.User, error) {
	var user models.User

	err := r.db.Where("username = ? OR email = ?", login, login).First(&user).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, ErrDatabaseError
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
		return ErrInvalidData
	}

	result := r.db.Model(&models.User{}).Where("id = ?", id).Updates(updates)

	if result.Error != nil {
		return ErrDatabaseError
	}

	if result.RowsAffected == 0 {
		return ErrUserNotFound
	}

	return nil
}

func (r *userRepository) Delete(id uint) error {
	result := r.db.Delete(&models.User{}, id)

	if result.Error != nil {
		return ErrDatabaseError
	}

	if result.RowsAffected == 0 {
		return ErrUserNotFound
	}
	return nil
}
