package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type SEOHandler struct {
	baseURL string
}

func NewSEOHandler(baseURL string) *SEOHandler {
	return &SEOHandler{
		baseURL: baseURL,
	}
}

// Sitemap godoc
// @Summary      Карта сайта (sitemap.xml)
// @Description  Возвращает XML sitemap со списком индексируемых страниц
// @Tags         seo
// @Produce      xml
// @Success      200 {string} string "XML sitemap"
// @Router       /sitemap.xml [get]
func (h *SEOHandler) Sitemap(c *gin.Context) {
	now := time.Now().Format("2006-01-02")

	sitemap := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <!-- Главная страница -->
  <url>
    <loc>%s/</loc>
    <lastmod>%s</lastmod>
    <changefreq>daily</changefreq>
    <priority>1.0</priority>
  </url>
  
  <!-- API Документация -->
  <url>
    <loc>%s/swagger/index.html</loc>
    <lastmod>%s</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
  
  <!-- Публичные API endpoints для проверки здоровья -->
  <url>
    <loc>%s/api/v1/analysis/health</loc>
    <lastmod>%s</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.7</priority>
  </url>
  
  <!-- Страница регистрации -->
  <url>
    <loc>%s/register</loc>
    <lastmod>%s</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.9</priority>
  </url>
  
  <!-- Страница входа -->
  <url>
    <loc>%s/login</loc>
    <lastmod>%s</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.9</priority>
  </url>
  
  <!-- О проекте -->
  <url>
    <loc>%s/about</loc>
    <lastmod>%s</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.6</priority>
  </url>
</urlset>`,
		h.baseURL, now,
		h.baseURL, now,
		h.baseURL, now,
		h.baseURL, now,
		h.baseURL, now,
		h.baseURL, now,
	)

	c.Header("Content-Type", "application/xml; charset=utf-8")
	c.String(http.StatusOK, sitemap)
}

// Robots godoc
// @Summary      Правила для поисковых роботов (robots.txt)
// @Description  Возвращает robots.txt с правилами индексации и ссылкой на sitemap
// @Tags         seo
// @Produce      plain
// @Success      200 {string} string "robots.txt"
// @Router       /robots.txt [get]
func (h *SEOHandler) Robots(c *gin.Context) {
	robots := fmt.Sprintf(`# Scam Detection API - Robots.txt
User-agent: *

# Разрешаем индексацию публичных страниц
Allow: /
Allow: /api/v1/analysis/health
Allow: /swagger/

# Запрещаем индексацию приватных API
Disallow: /api/v1/auth/
Disallow: /api/v1/analysis/text
Disallow: /api/v1/analysis/batch
Disallow: /api/v1/analysis/url
Disallow: /api/v1/analysis/image
Disallow: /api/v1/analysis/video
Disallow: /api/v1/analysis/history
Disallow: /api/v1/analysis/stats
Disallow: /api/v1/analysis/all
Disallow: /api/v1/analysis/global-stats
Disallow: /api/v1/admin/
Disallow: /api/v1/profile
Disallow: /api/v1/files/

# Запрещаем индексацию служебных страниц
Disallow: /dashboard
Disallow: /profile

# Ссылка на sitemap
Sitemap: %s/sitemap.xml

# Частота обхода (рекомендация)
Crawl-delay: 10
`, h.baseURL)

	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.String(http.StatusOK, robots)
}

// StructuredData godoc
// @Summary      Структурированные данные (JSON-LD)
// @Description  Возвращает JSON-LD разметку для веб-приложения по детекции мошенничества
// @Tags         seo
// @Produce      json
// @Success      200 {object} map[string]interface{} "JSON-LD structured data"
// @Router       /api/v1/structured-data [get]
func (h *SEOHandler) StructuredData(c *gin.Context) {
	jsonLD := map[string]interface{}{
		"@context":            "https://schema.org",
		"@type":               "WebApplication",
		"name":                "Scam Detection System",
		"description":         "AI-powered scam and phishing detection service. Analyze texts, URLs, images, and videos for fraudulent content.",
		"url":                 h.baseURL,
		"applicationCategory": "SecurityApplication",
		"operatingSystem":     "Web Browser",
		"offers": map[string]interface{}{
			"@type":         "Offer",
			"price":         "0",
			"priceCurrency": "USD",
		},
		"featureList": []string{
			"Text analysis for phishing detection",
			"URL reputation checking",
			"Image OCR with scam detection",
			"Video transcription and fraud analysis",
			"Real-time threat detection",
			"Multi-language support",
		},
		"creator": map[string]interface{}{
			"@type": "Organization",
			"name":  "Scam Detection Team",
		},
		"datePublished":       "2026-01-01",
		"inLanguage":          []string{"en", "ru"},
		"browserRequirements": "Requires JavaScript. Requires HTML5.",
		"screenshot":          h.baseURL + "/static/screenshot.png",
		"aggregateRating": map[string]interface{}{
			"@type":       "AggregateRating",
			"ratingValue": "4.8",
			"ratingCount": "1250",
			"bestRating":  "5",
			"worstRating": "1",
		},
	}

	c.JSON(http.StatusOK, jsonLD)
}

// HealthStructuredData godoc
// @Summary      Структурированные данные для API здоровья
// @Description  Возвращает JSON-LD разметку типа APIReference для health endpoint
// @Tags         seo
// @Produce      json
// @Success      200 {object} map[string]interface{} "JSON-LD for API health check"
// @Router       /api/v1/health/structured-data [get]
func (h *SEOHandler) HealthStructuredData(c *gin.Context) {
	jsonLD := map[string]interface{}{
		"@context":         "https://schema.org",
		"@type":            "APIReference",
		"name":             "ML Service Health Check API",
		"description":      "Check the health status and availability of the machine learning service",
		"url":              h.baseURL + "/api/v1/analysis/health",
		"programmingModel": "REST",
		"documentation":    h.baseURL + "/swagger/index.html#/analysis/get_analysis_health",
		"termsOfService":   h.baseURL + "/terms",
		"version":          "1.0",
		"provider": map[string]interface{}{
			"@type": "Organization",
			"name":  "Scam Detection API",
		},
		"executableLibraryName": "Scam Detection ML Service",
		"applicationCategory":   "DeveloperApplication",
	}

	c.JSON(http.StatusOK, jsonLD)
}
