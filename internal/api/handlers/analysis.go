package handlers

import (
	"net/http"
	"scam-detection-backend/internal/mlclient"

	"github.com/gin-gonic/gin"
)

// AnalysisHandler обработчик для анализа текстов
type AnalysisHandler struct {
	mlClient *mlclient.MLClient
}

// NewAnalysisHandler создает новый обработчик анализа
func NewAnalysisHandler() *AnalysisHandler {
	return &AnalysisHandler{
		mlClient: mlclient.NewMLClient(),
	}
}

// ErrorResponse структура для ошибок
type ErrorResponse struct {
	Error string `json:"error"`
}

// AnalyzeTextRequest запрос на анализ текста
type AnalyzeTextRequest struct {
	Text string `json:"text" binding:"required,min=1,max=5000" example:"Срочно! Ваш аккаунт заблокирован"`
}

// AnalyzeBatchRequest запрос на пакетный анализ
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

	// Отправляем в ML сервис
	result, err := h.mlClient.AnalyzeText(req.Text)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to analyze text: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
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

	// Отправляем в ML сервис
	result, err := h.mlClient.AnalyzeBatch(req.Texts)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to analyze texts: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
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
