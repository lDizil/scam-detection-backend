package repository

import "scam-detection-backend/internal/models"

type UserRepository interface {
	CreateUser(user *models.User) error
	GetByID(id uint) (*models.User, error)
	GetByUsernameOrEmail(login string) (*models.User, error)
	Update(id uint, data *models.UpdateUserRequest) error
	Delete(id uint) error
}

type CheckRepository interface {
}
