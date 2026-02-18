package services

import (
	"fmt"
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

func (s *userService) GetAllUsers(limit, offset int) ([]models.User, int64, error) {
	return s.userRepo.GetAll(limit, offset)
}

func (s *userService) UpdateUserRole(id uint, role models.Role) error {
	if !role.IsValid() {
		return fmt.Errorf("invalid role: %s", role)
	}
	return s.userRepo.UpdateRole(id, role)
}

func (s *userService) ToggleUserActiveStatus(id uint, isActive bool) error {
	return s.userRepo.UpdateActiveStatus(id, isActive)
}
