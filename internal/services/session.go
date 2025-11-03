package services

type sessionService struct {
	
}

func GenerateSession(ctx context.Context, userID uint) (*models.TokenPair, error) {

}
ValidateAccessToken(token string) (userId uint, err error)
RefreshSession(ctx context.Context, refreshToken string) (*models.TokenPair, error)
InvalidateAllUserSessions(ctx context.Context, userId uint) error
InvalidateSession(ctx context.Context, sessionId uint) error
CleanupExpiredSessions(ctx context.Context) (int64, error)
