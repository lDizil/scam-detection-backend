package jwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSecret = "test-secret-key-for-testing"

func TestGenerateJWT_Success(t *testing.T) {
	expiry := time.Now().Add(1 * time.Hour)
	token, err := GenerateJWT(42, expiry, testSecret)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestValidateJWT_ValidToken(t *testing.T) {
	expiry := time.Now().Add(1 * time.Hour)
	token, err := GenerateJWT(42, expiry, testSecret)
	require.NoError(t, err)

	claims, err := ValidateJWT(token, testSecret)
	require.NoError(t, err)
	assert.Equal(t, uint(42), claims.UserID)
}

func TestValidateJWT_ExpiredToken(t *testing.T) {
	expiry := time.Now().Add(-1 * time.Hour)
	token, err := GenerateJWT(1, expiry, testSecret)
	require.NoError(t, err)

	_, err = ValidateJWT(token, testSecret)
	assert.Error(t, err)
}

func TestValidateJWT_WrongSecret(t *testing.T) {
	expiry := time.Now().Add(1 * time.Hour)
	token, err := GenerateJWT(1, expiry, testSecret)
	require.NoError(t, err)

	_, err = ValidateJWT(token, "wrong-secret")
	assert.Error(t, err)
}

func TestValidateJWT_InvalidToken(t *testing.T) {
	_, err := ValidateJWT("not.a.valid.token", testSecret)
	assert.Error(t, err)
}

func TestValidateJWT_EmptyToken(t *testing.T) {
	_, err := ValidateJWT("", testSecret)
	assert.Error(t, err)
}

func TestGenerateAndValidate_MultipleUsers(t *testing.T) {
	testCases := []struct {
		userID uint
	}{
		{1}, {100}, {9999},
	}

	for _, tc := range testCases {
		expiry := time.Now().Add(1 * time.Hour)
		token, err := GenerateJWT(tc.userID, expiry, testSecret)
		require.NoError(t, err)

		claims, err := ValidateJWT(token, testSecret)
		require.NoError(t, err)
		assert.Equal(t, tc.userID, claims.UserID)
	}
}
