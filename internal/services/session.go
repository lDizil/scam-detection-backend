package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"scam-detection-backend/internal/jwt"
	"scam-detection-backend/internal/models"
	"scam-detection-backend/internal/repository"
	"time"
)

var (
	ErrSessionNotFound = errors.New("сессия не найдена")
	ErrSessionExpired  = errors.New("сессия истекла")
	ErrSessionUsed     = errors.New("сессия уже использована")
)

type sessionService struct {
	sessionRepo   repository.SessionRepository
	jwtSecret     string
	accessExpiry  time.Duration
	refreshExpiry time.Duration
}

func NewSessionService(
	sessionRepo repository.SessionRepository,
	jwtSecret, accessDur, refreshDur string,
) (*sessionService, error) {
	accessExpiry, err := time.ParseDuration(accessDur)
	if err != nil {
		return nil, err
	}

	refreshExpiry, err := time.ParseDuration(refreshDur)
	if err != nil {
		return nil, err
	}

	return &sessionService{
		sessionRepo:   sessionRepo,
		jwtSecret:     jwtSecret,
		accessExpiry:  accessExpiry,
		refreshExpiry: refreshExpiry,
	}, nil
}

func (s *sessionService) GenerateSession(ctx context.Context, userID uint) (*models.TokenPair, error) {
	now := time.Now()
	accessExpiry := now.Add(s.accessExpiry)
	refreshExpiry := now.Add(s.refreshExpiry)

	accessToken, err := jwt.GenerateJWT(userID, accessExpiry, s.jwtSecret)
	if err != nil {
		return nil, err
	}

	refreshToken, err := jwt.GenerateJWT(userID, refreshExpiry, s.jwtSecret)
	if err != nil {
		return nil, err
	}

	tokenHash := hashToken(refreshToken)

	session := &models.UserSessions{
		UserId:    userID,
		TokenHash: tokenHash,
		ExpiresAt: refreshExpiry,
		CreatedAt: now,
	}

	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return nil, err
	}

	return &models.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		AccessExpiry: accessExpiry,
		RefreshExpry: refreshExpiry,
	}, nil
}

func (s *sessionService) ValidateAccessToken(token string) (uint, error) {
	claims, err := jwt.ValidateJWT(token, s.jwtSecret)
	if err != nil {
		return 0, err
	}
	return claims.UserID, nil
}

func (s *sessionService) GetUserIDFromToken(token string) (uint, error) {
	claims, err := jwt.ValidateJWT(token, s.jwtSecret)
	if err != nil {
		return 0, err
	}
	return claims.UserID, nil
}

func (s *sessionService) RefreshSession(ctx context.Context, refreshToken string) (*models.TokenPair, error) {
	claims, err := jwt.ValidateJWT(refreshToken, s.jwtSecret)
	if err != nil {
		return nil, err
	}

	tokenHash := hashToken(refreshToken)
	now := time.Now()

	session, err := s.sessionRepo.GetActiveByHash(ctx, tokenHash, now)
	if err != nil {
		return nil, ErrSessionNotFound
	}

	if session.UsedAt != nil {
		return nil, ErrSessionUsed
	}

	if session.ExpiresAt.Before(now) {
		return nil, ErrSessionExpired
	}

	if err := s.sessionRepo.MarkUsed(ctx, session.ID, now); err != nil {
		return nil, err
	}

	return s.GenerateSession(ctx, claims.UserID)
}

func (s *sessionService) InvalidateAllUserSessions(ctx context.Context, userID uint) error {
	return s.sessionRepo.InvalidateAllByUser(ctx, userID)
}

func (s *sessionService) InvalidateSession(ctx context.Context, sessionID uint) error {
	now := time.Now()
	return s.sessionRepo.MarkUsed(ctx, sessionID, now)
}

func (s *sessionService) CleanupExpiredSessions(ctx context.Context) (int64, error) {
	now := time.Now()
	return s.sessionRepo.DeleteExpired(ctx, now)
}

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
