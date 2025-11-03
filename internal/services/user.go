package services

import (
	"scam-detection-backend/internal/models"
	"scam-detection-backend/internal/repository"
)

type userService struct {
	userRepo repository.UserRepository
}

func NewUserService(userRepo repository.UserRepository) *userService {
	return &userService{
		userRepo: userRepo,
	}
}

func (s *userService) GetByID(id uint) (*models.User, error) {
	return s.userRepo.GetByID(id)
}

func (s *userService) Update(id uint, data *models.UpdateUserRequest) error {
	return s.userRepo.Update(id, data)
}

func (s *userService) Delete(id uint) error {
	return s.userRepo.Delete(id)
}
