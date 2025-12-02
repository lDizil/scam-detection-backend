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

type ImageAnalysisResponse struct {
	Success        bool             `json:"success"`
	ExtractedText  string           `json:"extracted_text"`
	Prediction     PredictionResult `json:"prediction"`
	ProcessingTime float64          `json:"processing_time"`
	Message        string           `json:"message,omitempty"`
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

func (c *MLClient) AnalyzeImage(imageData []byte, filename string) (*ImageAnalysisResponse, error) {
	body := &bytes.Buffer{}
	writer := io.Writer(body)

	contentType := "image/jpeg"
	ext := filename[len(filename)-4:]
	switch ext {
	case ".png":
		contentType = "image/png"
	case ".bmp":
		contentType = "image/bmp"
	case "tiff", ".tif":
		contentType = "image/tiff"
	}

	boundary := "----WebKitFormBoundary7MA4YWxkTrZu0gW"
	writer.Write([]byte(fmt.Sprintf("--%s\r\n", boundary)))
	writer.Write([]byte(fmt.Sprintf("Content-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n", filename)))
	writer.Write([]byte(fmt.Sprintf("Content-Type: %s\r\n\r\n", contentType)))
	writer.Write(imageData)
	writer.Write([]byte(fmt.Sprintf("\r\n--%s--\r\n", boundary)))

	req, err := http.NewRequest("POST", c.baseURL+"/api/v1/analyze/image", body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", fmt.Sprintf("multipart/form-data; boundary=%s", boundary))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to ML service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ML service returned error: status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var result ImageAnalysisResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}
