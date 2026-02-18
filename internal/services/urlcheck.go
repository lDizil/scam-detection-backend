package services

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type URLCheckResult struct {
	Verdict    string    `json:"verdict"`
	Confidence float64   `json:"confidence"`
	Reasons    []string  `json:"reasons"`
	CheckedAt  time.Time `json:"checked_at"`
}

type URLCheckService struct {
	httpClient     *http.Client
	cache          sync.Map
	cacheTTL       time.Duration
	urlhausAuthKey string
}

func NewURLCheckService(urlhausAuthKey string) *URLCheckService {
	return &URLCheckService{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		cacheTTL:       1 * time.Hour,
		urlhausAuthKey: urlhausAuthKey,
	}
}

func (s *URLCheckService) CheckURL(ctx context.Context, rawURL string) (*URLCheckResult, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return &URLCheckResult{
			Verdict:    "invalid",
			Confidence: 1.0,
			Reasons:    []string{"invalid_url_format"},
			CheckedAt:  time.Now(),
		}, nil
	}

	if cached, ok := s.cache.Load(rawURL); ok {
		if result, ok := cached.(URLCheckResult); ok {
			if time.Since(result.CheckedAt) < s.cacheTTL {
				return &result, nil
			}
		}
		s.cache.Delete(rawURL)
	}

	type checkFunc func(context.Context, string) (bool, string, error)
	checks := []checkFunc{
		s.checkDomainHeuristics,
		s.checkURLHaus,
	}

	results := make(chan struct {
		isMalicious bool
		source      string
		err         error
	}, len(checks))

	for _, checkFn := range checks {
		go func(fn checkFunc) {
			isMalicious, source, err := fn(ctx, rawURL)
			results <- struct {
				isMalicious bool
				source      string
				err         error
			}{isMalicious, source, err}
		}(checkFn)
	}

	var reasons []string
	maliciousCount := 0
	checksCompleted := 0

	for i := 0; i < len(checks); i++ {
		result := <-results
		checksCompleted++

		if result.err != nil {
			continue
		}

		if result.isMalicious {
			maliciousCount++
			reasons = append(reasons, result.source)
		}
	}

	var verdict string
	var confidence float64

	if maliciousCount > 0 {
		verdict = "malicious"
		confidence = float64(maliciousCount) / float64(checksCompleted)
	} else if checksCompleted == 0 {
		verdict = "unknown"
		confidence = 0.0
		reasons = []string{"all_checks_failed"}
	} else {
		verdict = "legitimate"
		confidence = 0.85 - (float64(len(checks)-checksCompleted) * 0.15)
		if confidence < 0.3 {
			confidence = 0.3
		}
		reasons = []string{"not_found_in_blacklists"}
	}

	urlResult := &URLCheckResult{
		Verdict:    verdict,
		Confidence: confidence,
		Reasons:    reasons,
		CheckedAt:  time.Now(),
	}

	s.cache.Store(rawURL, *urlResult)

	return urlResult, nil
}

func (s *URLCheckService) checkDomainHeuristics(ctx context.Context, urlToCheck string) (bool, string, error) {
	parsedURL, err := url.Parse(urlToCheck)
	if err != nil {
		return false, "", err
	}

	suspiciousScore := 0
	domain := parsedURL.Host
	fullURL := strings.ToLower(urlToCheck)

	suspiciousTLDs := []string{".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click", ".pw", ".cc", ".ru", ".su"}
	for _, tld := range suspiciousTLDs {
		if strings.HasSuffix(domain, tld) {
			suspiciousScore += 15
			break
		}
	}

	parts := strings.Split(domain, ".")
	if len(parts) > 3 {
		suspiciousScore += 25
	}

	for _, part := range parts {
		if len(part) > 20 {
			suspiciousScore += 20
			break
		}
	}

	phishingKeywords := []string{
		"verify", "secure", "account", "update", "confirm", "login",
		"bank", "paypal", "signin", "password", "billing", "suspended",
		"locked", "unusual", "activity", "validate", "restore", "urgent",
		"phishing", "phish", "scam", "fraud", "invoice", "payment",
		"gov", "shop", "official", "service", "verification", "support",
	}

	brandKeywords := []string{"paypal", "bank", "gov", "payment", "invoice", "shop", "microsoft", "apple", "google", "amazon"}
	actionKeywords := []string{"login", "verify", "secure", "confirm", "update", "account", "billing", "suspended"}

	keywordMatches := 0
	brandMatches := 0
	actionMatches := 0

	for _, keyword := range phishingKeywords {
		if strings.Contains(fullURL, keyword) {
			keywordMatches++
			suspiciousScore += 8
		}
	}

	for _, brand := range brandKeywords {
		if strings.Contains(domain, brand) {
			brandMatches++
		}
	}

	for _, action := range actionKeywords {
		if strings.Contains(fullURL, action) {
			actionMatches++
		}
	}

	if brandMatches > 0 && actionMatches > 0 {
		suspiciousScore += 35
	}

	hyphenCount := strings.Count(domain, "-")
	if hyphenCount > 0 {
		suspiciousScore += hyphenCount * 8
	}

	isIP := true
	ipParts := strings.Split(strings.Split(domain, ":")[0], ".")
	if len(ipParts) == 4 {
		for _, part := range ipParts {
			if part == "" {
				isIP = false
				break
			}
			for _, ch := range part {
				if ch < '0' || ch > '9' {
					isIP = false
					break
				}
			}
		}
		if isIP {
			suspiciousScore += 60
		}
	}

	if isIP && (strings.Contains(fullURL, "/bin") || strings.Contains(fullURL, "/hidden") ||
		strings.Contains(fullURL, ".sh") || strings.Contains(fullURL, ".elf") ||
		strings.Contains(fullURL, "/i") || strings.Contains(fullURL, "/mozi")) {
		suspiciousScore += 40
	}

	if strings.Contains(parsedURL.Host, "@") {
		suspiciousScore += 50
	}

	shorteners := []string{"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "cutt.ly", "shorturl.at"}
	for _, shortener := range shorteners {
		if strings.Contains(domain, shortener) {
			suspiciousScore += 25
			break
		}
	}

	suspiciousPatterns := []string{
		"payments", "verification", "account-", "secure-",
		"-login", "-verify", "-update", "-confirm",
		"clearfake", "clickfix", "alderstone", "brightden",
	}
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(domain, pattern) {
			suspiciousScore += 15
		}
	}

	malwarePathPatterns := []string{
		"/bin.sh", "/bin/", ".sh", ".elf", ".exe", ".scr",
		"/hiddenbin/", "/hidden/", "/mozi", "/mirai",
		"/boatnet", "/x86", ".arm", ".mips",
	}
	for _, pattern := range malwarePathPatterns {
		if strings.Contains(fullURL, pattern) {
			suspiciousScore += 25
		}
	}

	if suspiciousScore >= 50 {
		return true, "domain_heuristics", nil
	}

	return false, "", nil
}

func (s *URLCheckService) checkURLHaus(ctx context.Context, urlToCheck string) (bool, string, error) {
	apiURL := "https://urlhaus-api.abuse.ch/v1/url/"

	data := url.Values{}
	data.Set("url", urlToCheck)

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(data.Encode()))
	if err != nil {
		return false, "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "FraudGuard/1.0")
	req.Header.Set("Accept", "application/json")

	if s.urlhausAuthKey != "" {
		req.Header.Set("Auth-Key", s.urlhausAuthKey)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return false, "", nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == 401 {
		return false, "", nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", nil
	}

	var result struct {
		QueryStatus string   `json:"query_status"`
		URL         string   `json:"url"`
		URLStatus   string   `json:"url_status"`
		Threat      string   `json:"threat"`
		Tags        []string `json:"tags"`
		Reporter    string   `json:"reporter"`
		Error       string   `json:"error"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return false, "", nil
	}

	if result.QueryStatus == "ok" {
		return true, "urlhaus_database", nil
	}

	return false, "", nil
}
