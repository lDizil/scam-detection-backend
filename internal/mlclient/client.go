package mlclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type MLClient struct {
	baseURL    string
	httpClient *http.Client
}

type TextAnalysisRequest struct {
	Text string `json:"text"`
}

type BatchTextAnalysisRequest struct {
	Texts []string `json:"texts"`
}

type PredictionResult struct {
	Label      string  `json:"label"`
	Confidence float64 `json:"confidence"`
	IsScam     bool    `json:"is_scam"`
}

type TextAnalysisResponse struct {
	Success        bool             `json:"success"`
	Prediction     PredictionResult `json:"prediction"`
	ProcessingTime float64          `json:"processing_time"`
}

type BatchTextAnalysisResponse struct {
	Success        bool               `json:"success"`
	Predictions    []PredictionResult `json:"predictions"`
	ProcessingTime float64            `json:"processing_time"`
}

type HealthResponse struct {
	Status      string `json:"status"`
	ModelLoaded bool   `json:"model_loaded"`
	ModelName   string `json:"model_name"`
	Version     string `json:"version"`
}

func NewMLClient() *MLClient {
	baseURL := os.Getenv("ML_SERVICE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8000"
	}

	return &MLClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *MLClient) HealthCheck() (*HealthResponse, error) {
	resp, err := c.httpClient.Get(c.baseURL + "/health")
	if err != nil {
		return nil, fmt.Errorf("failed to check ML service health: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ML service health check failed: status %d, body: %s", resp.StatusCode, string(body))
	}

	var health HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return nil, fmt.Errorf("failed to decode health response: %w", err)
	}

	return &health, nil
}

func (c *MLClient) AnalyzeText(text string) (*TextAnalysisResponse, error) {
	reqBody := TextAnalysisRequest{Text: text}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.baseURL+"/api/v1/analyze/text",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to ML service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ML service returned error: status %d, body: %s", resp.StatusCode, string(body))
	}

	var result TextAnalysisResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

func (c *MLClient) AnalyzeBatch(texts []string) (*BatchTextAnalysisResponse, error) {
	reqBody := BatchTextAnalysisRequest{Texts: texts}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.baseURL+"/api/v1/analyze/batch",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to ML service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ML service returned error: status %d, body: %s", resp.StatusCode, string(body))
	}

	var result BatchTextAnalysisResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}
