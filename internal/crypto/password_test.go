package crypto

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashPassword_Success(t *testing.T) {
	hash, err := HashPassword("mysecretpassword")
	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.True(t, strings.HasPrefix(hash, "$argon2id$"))
}

func TestHashPassword_DifferentHashesForSamePassword(t *testing.T) {
	hash1, err := HashPassword("password123")
	require.NoError(t, err)

	hash2, err := HashPassword("password123")
	require.NoError(t, err)

	assert.NotEqual(t, hash1, hash2)
}

func TestComparePasswordAndHash_Correct(t *testing.T) {
	password := "correctpassword"
	hash, err := HashPassword(password)
	require.NoError(t, err)

	match, err := ComparePasswordAndHash(password, hash)
	require.NoError(t, err)
	assert.True(t, match)
}

func TestComparePasswordAndHash_Wrong(t *testing.T) {
	hash, err := HashPassword("correctpassword")
	require.NoError(t, err)

	match, err := ComparePasswordAndHash("wrongpassword", hash)
	require.NoError(t, err)
	assert.False(t, match)
}

func TestComparePasswordAndHash_InvalidHash(t *testing.T) {
	_, err := ComparePasswordAndHash("password", "notahash")
	assert.Error(t, err)
}

func TestHashPasswordWithParams_CustomParams(t *testing.T) {
	params := &Params{
		Memory:      16 * 1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}

	hash, err := HashPasswordWithParams("testpassword", params)
	require.NoError(t, err)
	assert.NotEmpty(t, hash)

	match, err := ComparePasswordAndHash("testpassword", hash)
	require.NoError(t, err)
	assert.True(t, match)
}

func TestComparePasswordAndHash_EmptyPassword(t *testing.T) {
	hash, err := HashPassword("")
	require.NoError(t, err)

	match, err := ComparePasswordAndHash("", hash)
	require.NoError(t, err)
	assert.True(t, match)

	match, err = ComparePasswordAndHash("notempty", hash)
	require.NoError(t, err)
	assert.False(t, match)
}
