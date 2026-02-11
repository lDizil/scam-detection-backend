package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"scam-detection-backend/internal/api/middleware"
	"scam-detection-backend/internal/config"
	"scam-detection-backend/internal/mlclient"
	"scam-detection-backend/internal/models"
	"scam-detection-backend/internal/repository"
	"scam-detection-backend/internal/services"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type AnalysisHandler struct {
	mlClient        *mlclient.MLClient
	checkRepo       repository.CheckRepository
	urlCheckService *services.URLCheckService
}

func NewAnalysisHandler(checkRepo repository.CheckRepository, cfg *config.Config) *AnalysisHandler {
	return &AnalysisHandler{
		mlClient:        mlclient.NewMLClient(),
		checkRepo:       checkRepo,
		urlCheckService: services.NewURLCheckService(cfg.URLhaus.AuthKey),
	}
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type AnalyzeTextRequest struct {
	Text string `json:"text" binding:"required,min=1,max=5000" example:"Срочно! Ваш аккаунт заблокирован"`
}

type AnalyzeBatchRequest struct {
	Texts []string `json:"texts" binding:"required,min=1,max=100,dive,min=1,max=5000" example:"[\"Вы выиграли приз\", \"Привет, как дела?\"]"`
}

// AnalyzeText godoc
// @Summary      Анализ текста на мошенничество
// @Description  Отправляет текст в ML сервис для определения, является ли он фишинговым/мошенническим
// @Tags         analysis
// @Accept       json
// @Produce      json
// @Param        request body AnalyzeTextRequest true "Текст для анализа"
// @Success      200 {object} mlclient.TextAnalysisResponse "Успешный анализ"
// @Failure      400 {object} ErrorResponse "Невалидный запрос"
// @Failure      500 {object} ErrorResponse "Ошибка ML сервиса"
// @Security     BearerAuth
// @Router       /analysis/text [post]
func (h *AnalysisHandler) AnalyzeText(c *gin.Context) {
	var req AnalyzeTextRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "user not authenticated"})
		return
	}

	title := req.Text
	if len([]rune(req.Text)) > 50 {
		title = string([]rune(req.Text)[:50])
	}

	check := &models.Check{
		Title:       title,
		ContentType: "text",
		Content:     req.Text,
		Status:      "processing",
		UserID:      userID,
	}

	if err := h.checkRepo.CreateCheck(check); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to save check: " + err.Error()})
		return
	}

	startTime := time.Now()
	result, err := h.mlClient.AnalyzeText(req.Text)
	processingTime := int(time.Since(startTime).Milliseconds())

	if err != nil {
		h.checkRepo.UpdateCheckStatus(check.ID, "failed", 0, "", processingTime)
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to analyze text: " + err.Error()})
		return
	}

	var dangerScore float64
	if result.Prediction.IsScam {
		dangerScore = result.Prediction.Confidence
	} else {
		dangerScore = 1.0 - result.Prediction.Confidence
	}

	dangerLevel := calculateDangerLevel(dangerScore)
	if err := h.checkRepo.UpdateCheckStatus(
		check.ID,
		"completed",
		dangerScore,
		dangerLevel,
		processingTime,
	); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to update check: " + err.Error()})
		return
	}

	detailValue, _ := json.Marshal(map[string]interface{}{
		"label":   result.Prediction.Label,
		"is_scam": result.Prediction.IsScam,
	})

	detail := &models.CheckDetail{
		CheckID:         check.ID,
		FeatureName:     "ml_prediction",
		FeatureValue:    string(detailValue),
		ConfidenceScore: result.Prediction.Confidence,
	}

	if err := h.checkRepo.AddCheckDetail(detail); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to save check detail: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"check_id":        check.ID,
		"success":         result.Success,
		"prediction":      result.Prediction,
		"processing_time": result.ProcessingTime,
	})
}

func calculateDangerLevel(confidence float64) string {
	if confidence < 0.3 {
		return "low"
	} else if confidence < 0.6 {
		return "medium"
	} else if confidence < 0.85 {
		return "high"
	}
	return "critical"
}

// AnalyzeBatch godoc
// @Summary      Пакетный анализ текстов
// @Description  Отправляет несколько текстов в ML сервис для анализа
// @Tags         analysis
// @Accept       json
// @Produce      json
// @Param        request body AnalyzeBatchRequest true "Список текстов для анализа"
// @Success      200 {object} mlclient.BatchTextAnalysisResponse "Успешный анализ"
// @Failure      400 {object} ErrorResponse "Невалидный запрос"
// @Failure      500 {object} ErrorResponse "Ошибка ML сервиса"
// @Security     BearerAuth
// @Router       /analysis/batch [post]
func (h *AnalysisHandler) AnalyzeBatch(c *gin.Context) {
	var req AnalyzeBatchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "user not authenticated"})
		return
	}

	startTime := time.Now()
	result, err := h.mlClient.AnalyzeBatch(req.Texts)
	processingTime := int(time.Since(startTime).Milliseconds())

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to analyze texts: " + err.Error()})
		return
	}

	checkIDs := make([]uint, 0, len(req.Texts))
	for i, text := range req.Texts {
		if i >= len(result.Predictions) {
			break
		}

		pred := result.Predictions[i]

		title := text
		if len([]rune(text)) > 50 {
			title = string([]rune(text)[:50])
		}

		var dangerScore float64
		if pred.IsScam {
			dangerScore = pred.Confidence
		} else {
			dangerScore = 1.0 - pred.Confidence
		}

		check := &models.Check{
			Title:          title,
			ContentType:    "text",
			Content:        text,
			Status:         "completed",
			UserID:         userID,
			DangerScore:    dangerScore,
			DangerLevel:    calculateDangerLevel(dangerScore),
			ProcessingTime: processingTime / len(req.Texts),
		}

		if err := h.checkRepo.CreateCheck(check); err != nil {
			continue
		}

		checkIDs = append(checkIDs, check.ID)

		detailValue, _ := json.Marshal(map[string]interface{}{
			"label":   pred.Label,
			"is_scam": pred.IsScam,
		})

		detail := &models.CheckDetail{
			CheckID:         check.ID,
			FeatureName:     "ml_prediction",
			FeatureValue:    string(detailValue),
			ConfidenceScore: pred.Confidence,
		}

		h.checkRepo.AddCheckDetail(detail)
	}

	c.JSON(http.StatusOK, gin.H{
		"check_ids":       checkIDs,
		"success":         result.Success,
		"predictions":     result.Predictions,
		"processing_time": result.ProcessingTime,
	})
}

// MLHealthCheck godoc
// @Summary      Проверка здоровья ML сервиса
// @Description  Возвращает статус ML сервиса и информацию о модели
// @Tags         analysis
// @Produce      json
// @Success      200 {object} mlclient.HealthResponse "ML сервис здоров"
// @Failure      500 {object} ErrorResponse "ML сервис недоступен"
// @Router       /analysis/health [get]
func (h *AnalysisHandler) MLHealthCheck(c *gin.Context) {
	health, err := h.mlClient.HealthCheck()
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "ML service is unavailable: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, health)
}

type CheckHistoryResponse struct {
	Checks []models.Check `json:"checks"`
	Total  int64          `json:"total"`
	Page   int            `json:"page"`
	Limit  int            `json:"limit"`
}

// GetCheckHistory godoc
// @Summary      История проверок пользователя
// @Description  Возвращает список всех проверок текущего пользователя с пагинацией
// @Tags         analysis
// @Produce      json
// @Param        page query int false "Номер страницы" default(1)
// @Param        limit query int false "Количество записей на странице" default(20)
// @Success      200 {object} CheckHistoryResponse "Список проверок"
// @Failure      401 {object} ErrorResponse "Не авторизован"
// @Failure      500 {object} ErrorResponse "Ошибка БД"
// @Security     BearerAuth
// @Router       /analysis/history [get]
func (h *AnalysisHandler) GetCheckHistory(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "user not authenticated"})
		return
	}

	page := 1
	if p, exists := c.GetQuery("page"); exists {
		if val, err := stringToInt(p); err == nil && val > 0 {
			page = val
		}
	}

	limit := 20
	if l, exists := c.GetQuery("limit"); exists {
		if val, err := stringToInt(l); err == nil && val > 0 && val <= 100 {
			limit = val
		}
	}

	offset := (page - 1) * limit

	checks, total, err := h.checkRepo.GetChecksByUserID(userID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to get check history: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, CheckHistoryResponse{
		Checks: checks,
		Total:  total,
		Page:   page,
		Limit:  limit,
	})
}

func stringToInt(s string) (int, error) {
	var result int
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, http.ErrAbortHandler
		}
		result = result*10 + int(ch-'0')
	}
	return result, nil
}

// DeleteCheck godoc
// @Summary      Удалить проверку
// @Description  Удаляет проверку из истории пользователя
// @Tags         analysis
// @Param        id path int true "ID проверки"
// @Success      200 {object} map[string]string "Успешно удалено"
// @Failure      401 {object} ErrorResponse "Не авторизован"
// @Failure      403 {object} ErrorResponse "Нет доступа"
// @Failure      500 {object} ErrorResponse "Ошибка БД"
// @Security     BearerAuth
// @Router       /analysis/history/{id} [delete]
func (h *AnalysisHandler) DeleteCheck(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "user not authenticated"})
		return
	}

	idStr := c.Param("id")
	id, err := stringToInt(idStr)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid check id"})
		return
	}

	if err := h.checkRepo.DeleteCheck(uint(id), userID); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to delete check: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Check deleted successfully"})
}

// GetStats godoc
// @Summary      Статистика пользователя
// @Description  Возвращает агрегированную статистику по проверкам пользователя
// @Tags         analysis
// @Produce      json
// @Success      200 {object} map[string]interface{} "Статистика"
// @Failure      401 {object} ErrorResponse "Не авторизован"
// @Failure      500 {object} ErrorResponse "Ошибка БД"
// @Security     BearerAuth
// @Router       /analysis/stats [get]
func (h *AnalysisHandler) GetStats(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "user not authenticated"})
		return
	}

	stats, err := h.checkRepo.GetUserStats(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to get stats: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, stats)
}

type AnalyzeURLRequest struct {
	URL string `json:"url" binding:"required,url" example:"https://example-phishing.com"`
}

type AnalyzeURLResponse struct {
	CheckID    uint      `json:"check_id"`
	URL        string    `json:"url"`
	Verdict    string    `json:"verdict"`
	Confidence float64   `json:"confidence"`
	Reasons    []string  `json:"reasons"`
	CheckedAt  time.Time `json:"checked_at"`
}

// AnalyzeURL godoc
// @Summary      Проверка URL на мошенничество
// @Description  Проверяет ссылку через внешние API (Google Safe Browsing, PhishTank) на фишинг и мошенничество
// @Tags         analysis
// @Accept       json
// @Produce      json
// @Param        request body AnalyzeURLRequest true "URL для проверки"
// @Success      200 {object} AnalyzeURLResponse "Результат проверки"
// @Failure      400 {object} ErrorResponse "Невалидный URL"
// @Failure      401 {object} ErrorResponse "Не авторизован"
// @Failure      500 {object} ErrorResponse "Ошибка проверки"
// @Security     BearerAuth
// @Router       /analysis/url [post]
func (h *AnalysisHandler) AnalyzeURL(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "user not authenticated"})
		return
	}

	var req AnalyzeURLRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid request: " + err.Error()})
		return
	}

	req.URL = strings.TrimSpace(req.URL)

	if req.URL == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "URL cannot be empty"})
		return
	}

	startTime := time.Now()

	result, err := h.urlCheckService.CheckURL(c.Request.Context(), req.URL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to check URL: " + err.Error()})
		return
	}

	processingTime := int(time.Since(startTime).Milliseconds())

	var dangerScore float64
	if result.Verdict == "legitimate" {
		dangerScore = 1.0 - result.Confidence
	} else {
		dangerScore = result.Confidence
	}

	check := &models.Check{
		Title:          "URL Check: " + req.URL,
		ContentType:    "url",
		Content:        req.URL,
		DangerScore:    dangerScore,
		DangerLevel:    mapVerdictToDangerLevel(result.Verdict),
		Status:         "completed",
		UserID:         userID,
		ProcessingTime: processingTime,
	}

	if err := h.checkRepo.CreateCheck(check); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to save check: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, AnalyzeURLResponse{
		CheckID:    check.ID,
		URL:        req.URL,
		Verdict:    result.Verdict,
		Confidence: result.Confidence,
		Reasons:    result.Reasons,
		CheckedAt:  result.CheckedAt,
	})
}

// AnalyzeImage godoc
// @Summary      Анализ изображения на мошенничество
// @Description  Извлекает текст из изображения (OCR) и анализирует его на предмет фишинга и мошенничества
// @Tags         analysis
// @Accept       multipart/form-data
// @Produce      json
// @Param        image formData file true "Изображение (JPG, PNG, BMP, TIFF)"
// @Success      200 {object} map[string]interface{} "Результат анализа изображения"
// @Failure      400 {object} ErrorResponse "Невалидный файл"
// @Failure      401 {object} ErrorResponse "Не авторизован"
// @Failure      500 {object} ErrorResponse "Ошибка обработки"
// @Security     BearerAuth
// @Router       /analysis/image [post]
func (h *AnalysisHandler) AnalyzeImage(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "user not authenticated"})
		return
	}

	file, err := c.FormFile("image")
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "No image file provided"})
		return
	}

	allowedExts := map[string]bool{
		".jpg": true, ".jpeg": true, ".png": true, ".bmp": true, ".tiff": true,
	}
	ext := strings.ToLower(filepath.Ext(file.Filename))
	if !allowedExts[ext] {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Unsupported file format. Allowed: JPG, PNG, BMP, TIFF"})
		return
	}

	if file.Size > 10*1024*1024 {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "File size exceeds 10MB limit"})
		return
	}

	uploadDir := "./uploads"
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to create upload directory"})
		return
	}

	filename := fmt.Sprintf("%d_%s", time.Now().Unix(), file.Filename)
	savePath := filepath.Join(uploadDir, filename)

	if err := c.SaveUploadedFile(file, savePath); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to save file"})
		return
	}

	imageFile, err := os.Open(savePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to read uploaded file"})
		return
	}
	defer imageFile.Close()

	imageData, err := io.ReadAll(imageFile)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to read image data"})
		return
	}

	startTime := time.Now()
	result, err := h.mlClient.AnalyzeImage(imageData, file.Filename)
	processingTime := int(time.Since(startTime).Milliseconds())

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to analyze image: " + err.Error()})
		return
	}

	title := "Image Analysis: " + file.Filename
	if result.ExtractedText != "" && len([]rune(result.ExtractedText)) > 30 {
		title = "Image: " + string([]rune(result.ExtractedText)[:30])
	}

	var dangerScore float64
	if result.Prediction.IsScam {
		dangerScore = result.Prediction.Confidence
	} else {
		dangerScore = 1.0 - result.Prediction.Confidence
	}

	check := &models.Check{
		Title:          title,
		ContentType:    "image",
		Content:        result.ExtractedText,
		CheckType:      "image",
		FilePath:       savePath,
		ExtractedText:  result.ExtractedText,
		Status:         "completed",
		UserID:         userID,
		DangerScore:    dangerScore,
		DangerLevel:    calculateDangerLevel(dangerScore),
		ProcessingTime: processingTime,
	}

	if err := h.checkRepo.CreateCheck(check); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to save check: " + err.Error()})
		return
	}

	detailValue, _ := json.Marshal(map[string]interface{}{
		"label":          result.Prediction.Label,
		"is_scam":        result.Prediction.IsScam,
		"extracted_text": result.ExtractedText,
		"filename":       file.Filename,
	})

	detail := &models.CheckDetail{
		CheckID:         check.ID,
		FeatureName:     "image_analysis",
		FeatureValue:    string(detailValue),
		ConfidenceScore: result.Prediction.Confidence,
	}

	if err := h.checkRepo.AddCheckDetail(detail); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to save check detail: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"check_id":        check.ID,
		"success":         result.Success,
		"extracted_text":  result.ExtractedText,
		"prediction":      result.Prediction,
		"processing_time": result.ProcessingTime,
		"message":         result.Message,
	})
}

// AnalyzeVideo godoc
// @Summary      Анализ видео на мошенничество
// @Description  Извлекает аудио из видео, транскрибирует через Whisper и анализирует на предмет мошенничества
// @Tags         analysis
// @Accept       multipart/form-data
// @Produce      json
// @Param        video formData file true "Видео (MP4, AVI, MOV, MKV, WEBM). Макс: 50MB, 5 минут"
// @Success      200 {object} map[string]interface{} "Результат анализа видео"
// @Failure      400 {object} ErrorResponse "Невалидный файл или превышен лимит"
// @Failure      401 {object} ErrorResponse "Не авторизован"
// @Failure      500 {object} ErrorResponse "Ошибка обработки"
// @Security     BearerAuth
// @Router       /analysis/video [post]
func (h *AnalysisHandler) AnalyzeVideo(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "user not authenticated"})
		return
	}

	file, err := c.FormFile("video")
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "No video file provided"})
		return
	}

	allowedExts := map[string]bool{
		".mp4": true, ".avi": true, ".mov": true, ".mkv": true, ".webm": true,
	}
	ext := strings.ToLower(filepath.Ext(file.Filename))
	if !allowedExts[ext] {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Unsupported file format. Allowed: MP4, AVI, MOV, MKV, WEBM"})
		return
	}

	// Лимит 50MB
	if file.Size > 50*1024*1024 {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "File size exceeds 50MB limit"})
		return
	}

	uploadDir := "./uploads"
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to create upload directory"})
		return
	}

	filename := fmt.Sprintf("%d_%s", time.Now().Unix(), file.Filename)
	savePath := filepath.Join(uploadDir, filename)

	if err := c.SaveUploadedFile(file, savePath); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to save file"})
		return
	}

	videoFile, err := os.Open(savePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to read uploaded file"})
		return
	}
	defer videoFile.Close()

	videoData, err := io.ReadAll(videoFile)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to read video data"})
		return
	}

	startTime := time.Now()
	result, err := h.mlClient.AnalyzeVideo(videoData, file.Filename)
	processingTime := int(time.Since(startTime).Milliseconds())

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to analyze video: " + err.Error()})
		return
	}

	title := "Video Analysis: " + file.Filename
	if result.Transcription != "" && len([]rune(result.Transcription)) > 30 {
		title = "Video: " + string([]rune(result.Transcription)[:30])
	}

	var dangerScore float64
	if result.Prediction.IsScam {
		dangerScore = result.Prediction.Confidence
	} else {
		dangerScore = 1.0 - result.Prediction.Confidence
	}

	check := &models.Check{
		Title:          title,
		ContentType:    "video",
		Content:        result.Transcription,
		CheckType:      "video",
		FilePath:       savePath,
		ExtractedText:  result.Transcription,
		Status:         "completed",
		UserID:         userID,
		DangerScore:    dangerScore,
		DangerLevel:    calculateDangerLevel(dangerScore),
		ProcessingTime: processingTime,
	}

	if err := h.checkRepo.CreateCheck(check); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to save check: " + err.Error()})
		return
	}

	detailValue, _ := json.Marshal(map[string]interface{}{
		"label":    result.Prediction.Label,
		"is_scam":  result.Prediction.IsScam,
		"duration": result.Duration,
		"language": result.Language,
		"filename": file.Filename,
	})

	detail := &models.CheckDetail{
		CheckID:         check.ID,
		FeatureName:     "video_analysis",
		FeatureValue:    string(detailValue),
		ConfidenceScore: result.Prediction.Confidence,
	}

	if err := h.checkRepo.AddCheckDetail(detail); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to save check detail: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"check_id":        check.ID,
		"success":         result.Success,
		"transcription":   result.Transcription,
		"duration":        result.Duration,
		"language":        result.Language,
		"prediction":      result.Prediction,
		"processing_time": result.ProcessingTime,
		"message":         result.Message,
	})
}

func mapVerdictToDangerLevel(verdict string) string {
	switch verdict {
	case "malicious":
		return "high"
	case "suspicious":
		return "medium"
	case "legitimate":
		return "safe"
	case "invalid":
		return "unknown"
	default:
		return "unknown"
	}
}

// GetAllChecks godoc
// @Summary      Получить все проверки (только moderator/admin)
// @Description  Возвращает список всех проверок всех пользователей. Доступно модераторам и администраторам.
// @Tags         analysis
// @Accept       json
// @Produce      json
// @Param        page query int false "Номер страницы" default(1)
// @Param        limit query int false "Количество на странице" default(20)
// @Success      200 {object} map[string]interface{}
// @Failure      403 {object} ErrorResponse
// @Failure      500 {object} ErrorResponse
// @Security     CookieAuth
// @Router       /analysis/all [get]
func (h *AnalysisHandler) GetAllChecks(c *gin.Context) {
	page := 1
	limit := 20

	if p, exists := c.GetQuery("page"); exists {
		fmt.Sscanf(p, "%d", &page)
	}
	if l, exists := c.GetQuery("limit"); exists {
		fmt.Sscanf(l, "%d", &limit)
	}

	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}

	offset := (page - 1) * limit

	checks, total, err := h.checkRepo.GetAllChecks(limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to fetch checks"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"checks": checks,
		"total":  total,
		"page":   page,
		"limit":  limit,
	})
}

// GetGlobalStats godoc
// @Summary      Глобальная статистика (только moderator/admin)
// @Description  Возвращает статистику по всем проверкам всех пользователей. Доступно модераторам и администраторам.
// @Tags         analysis
// @Accept       json
// @Produce      json
// @Success      200 {object} map[string]interface{}
// @Failure      403 {object} ErrorResponse
// @Failure      500 {object} ErrorResponse
// @Security     CookieAuth
// @Router       /analysis/global-stats [get]
func (h *AnalysisHandler) GetGlobalStats(c *gin.Context) {
	stats, err := h.checkRepo.GetGlobalStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to fetch global statistics"})
		return
	}

	c.JSON(http.StatusOK, stats)
}
