package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestSEOHandler_Sitemap(t *testing.T) {
	router := gin.New()
	seoHandler := NewSEOHandler("https://example.com")
	router.GET("/sitemap.xml", seoHandler.Sitemap)

	req := httptest.NewRequest("GET", "/sitemap.xml", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "urlset")
	assert.Contains(t, w.Body.String(), "https://example.com")
}

func TestSEOHandler_Robots(t *testing.T) {
	router := gin.New()
	seoHandler := NewSEOHandler("https://example.com")
	router.GET("/robots.txt", seoHandler.Robots)

	req := httptest.NewRequest("GET", "/robots.txt", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "User-agent")
}

func TestSEOHandler_StructuredData(t *testing.T) {
	router := gin.New()
	seoHandler := NewSEOHandler("https://example.com")
	router.GET("/structured-data.json", seoHandler.StructuredData)

	req := httptest.NewRequest("GET", "/structured-data.json", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSEOHandler_HealthStructuredData(t *testing.T) {
	router := gin.New()
	seoHandler := NewSEOHandler("https://example.com")
	router.GET("/health-structured-data.json", seoHandler.HealthStructuredData)

	req := httptest.NewRequest("GET", "/health-structured-data.json", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
