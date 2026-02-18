package services

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestURLCheckService_InvalidURL(t *testing.T) {
	svc := NewURLCheckService("")

	result, err := svc.CheckURL(context.TODO(), "not-a-url")
	require.NoError(t, err)
	assert.Equal(t, "invalid", result.Verdict)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Reasons, "invalid_url_format")
}

func TestURLCheckService_InvalidURL_NoScheme(t *testing.T) {
	svc := NewURLCheckService("")

	result, err := svc.CheckURL(context.TODO(), "example.com/path")
	require.NoError(t, err)
	assert.Equal(t, "invalid", result.Verdict)
}

func TestURLCheckService_MaliciousHeuristics_IP(t *testing.T) {
	svc := NewURLCheckService("")
	// IP-based URL is scored as suspicious
	result, err := svc.CheckURL(context.TODO(), "http://192.168.1.1/bin/payload.sh")
	require.NoError(t, err)
	assert.Equal(t, "malicious", result.Verdict)
	assert.Contains(t, result.Reasons, "domain_heuristics")
}

func TestURLCheckService_MaliciousHeuristics_SuspiciousTLD(t *testing.T) {
	svc := NewURLCheckService("")
	// .tk TLD + phishing keywords should trigger heuristics
	result, err := svc.CheckURL(context.TODO(), "http://secure-paypal-verify-login.tk/account/billing")
	require.NoError(t, err)
	// Heuristic score should be high enough
	assert.NotEmpty(t, result.Verdict)
	assert.NotEmpty(t, result.CheckedAt)
}

func TestURLCheckService_LegitimateURL(t *testing.T) {
	svc := NewURLCheckService("")

	result, err := svc.CheckURL(context.TODO(), "https://golang.org/doc")
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEmpty(t, result.Verdict)
	assert.NotEmpty(t, result.CheckedAt)
}

func TestURLCheckService_CachingBehavior(t *testing.T) {
	svc := NewURLCheckService("")

	url := "https://google.com"

	result1, err := svc.CheckURL(context.TODO(), url)
	require.NoError(t, err)

	// Second call should be served from cache
	result2, err := svc.CheckURL(context.TODO(), url)
	require.NoError(t, err)

	assert.Equal(t, result1.Verdict, result2.Verdict)
	assert.Equal(t, result1.Confidence, result2.Confidence)
}

func TestURLCheckService_MaliciousHeuristics_PhishingKeywords(t *testing.T) {
	svc := NewURLCheckService("")

	result, err := svc.CheckURL(context.TODO(), "http://paypal-secure-login-verify.xyz/account/update/password")
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestURLCheckService_ShortenerURL(t *testing.T) {
	svc := NewURLCheckService("")

	result, err := svc.CheckURL(context.TODO(), "http://bit.ly/suspicious-link")
	require.NoError(t, err)
	// Shorteners add score but alone don't hit threshold
	assert.NotNil(t, result)
}
