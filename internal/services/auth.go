package services

import (
	"context"
	"errors"
	"scam-detection-backend/internal/crypto"
	"scam-detection-backend/internal/models"
	"scam-detection-backend/internal/repository"
)

var (
	ErrInvalidCredentials = errors.New("неверные учётные данные")
	ErrUserAlreadyExists  = errors.New("пользователь уже существует")
)

type AuthService struct {
	userRepo       repository.UserRepository
	sessionService SessionService
}

func NewAuthService(userRepo repository.UserRepository, sessionService SessionService) *AuthService {
	return &AuthService{
		userRepo:       userRepo,
		sessionService: sessionService,
	}
}

func (s *AuthService) Register(ctx context.Context, req *models.CreateUserRequest) (*models.User, *models.TokenPair, error) {
	existing, _ := s.userRepo.GetByUsername(req.Username)
	if existing != nil {
		return nil, nil, ErrUserAlreadyExists
	}

	if req.Email != nil {
		existing, _ = s.userRepo.GetByEmail(*req.Email)
		if existing != nil {
			return nil, nil, ErrUserAlreadyExists
		}
	}

	hashedPassword, err := crypto.HashPassword(req.Password)
	if err != nil {
		return nil, nil, err
	}

	user := &models.User{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: hashedPassword,
		IsActive:     true,
	}

	if err := s.userRepo.Create(user); err != nil {
		return nil, nil, err
	}

	tokens, err := s.sessionService.GenerateSession(ctx, user.ID)
	if err != nil {
		return nil, nil, err
	}

	return user, tokens, nil
}

func (s *AuthService) Login(ctx context.Context, username, password string) (*models.User, *models.TokenPair, error) {
	user, err := s.userRepo.GetByUsernameOrEmail(username)
	if err != nil {
		return nil, nil, ErrInvalidCredentials
	}

	if !user.IsActive {
		return nil, nil, errors.New("аккаунт деактивирован")
	}

	match, err := crypto.ComparePasswordAndHash(password, user.PasswordHash)
	if err != nil || !match {
		return nil, nil, ErrInvalidCredentials
	}

	tokens, err := s.sessionService.GenerateSession(ctx, user.ID)
	if err != nil {
		return nil, nil, err
	}

	return user, tokens, nil
}

func (s *AuthService) ValidateToken(token string) (uint, error) {
	return s.sessionService.ValidateAccessToken(token)
}

func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (*models.TokenPair, error) {
	return s.sessionService.RefreshSession(ctx, refreshToken)
}

func (s *AuthService) LogoutAllDevices(ctx context.Context, userID uint) error {
	return s.sessionService.InvalidateAllUserSessions(ctx, userID)
}
