package handlers

import (
	"encoding/json"
	"net/http"
	"scam-detection-backend/internal/api/middleware"
	"scam-detection-backend/internal/mlclient"
	"scam-detection-backend/internal/models"
	"scam-detection-backend/internal/repository"
	"time"

	"github.com/gin-gonic/gin"
)

type AnalysisHandler struct {
	mlClient  *mlclient.MLClient
	checkRepo repository.CheckRepository
}

func NewAnalysisHandler(checkRepo repository.CheckRepository) *AnalysisHandler {
	return &AnalysisHandler{
		mlClient:  mlclient.NewMLClient(),
		checkRepo: checkRepo,
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

	dangerScore := result.Prediction.Confidence
	if !result.Prediction.IsScam {
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

		dangerScore := pred.Confidence
		if !pred.IsScam {
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
