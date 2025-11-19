package repository

import (
	"scam-detection-backend/internal/models"

	"gorm.io/gorm"
)

type checkRepository struct {
	db *gorm.DB
}

func NewCheckRepository(db *gorm.DB) CheckRepository {
	return &checkRepository{db: db}
}

func (r *checkRepository) CreateCheck(check *models.Check) error {
	return r.db.Create(check).Error
}

func (r *checkRepository) GetCheckByID(id uint) (*models.Check, error) {
	var check models.Check
	if err := r.db.Preload("User").First(&check, id).Error; err != nil {
		return nil, err
	}
	return &check, nil
}

func (r *checkRepository) GetChecksByUserID(userID uint, limit, offset int) ([]models.Check, int64, error) {
	var checks []models.Check
	var total int64

	if err := r.db.Model(&models.Check{}).Where("user_id = ?", userID).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	if err := r.db.Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&checks).Error; err != nil {
		return nil, 0, err
	}

	return checks, total, nil
}

func (r *checkRepository) UpdateCheckStatus(id uint, status string, dangerScore float64, dangerLevel string, processingTime int) error {
	return r.db.Model(&models.Check{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"status":          status,
			"danger_score":    dangerScore,
			"danger_level":    dangerLevel,
			"processing_time": processingTime,
		}).Error
}

func (r *checkRepository) AddCheckDetail(detail *models.CheckDetail) error {
	return r.db.Create(detail).Error
}

func (r *checkRepository) GetCheckDetails(checkID uint) ([]models.CheckDetail, error) {
	var details []models.CheckDetail
	if err := r.db.Where("check_id = ?", checkID).Find(&details).Error; err != nil {
		return nil, err
	}
	return details, nil
}

func (r *checkRepository) DeleteCheck(id uint, userID uint) error {
	return r.db.Where("id = ? AND user_id = ?", id, userID).Delete(&models.Check{}).Error
}

func (r *checkRepository) GetUserStats(userID uint) (map[string]interface{}, error) {
	var total int64
	var checks []models.Check

	if err := r.db.Model(&models.Check{}).Where("user_id = ?", userID).Count(&total).Error; err != nil {
		return nil, err
	}

	if err := r.db.Where("user_id = ?", userID).Find(&checks).Error; err != nil {
		return nil, err
	}

	stats := map[string]interface{}{
		"total_analyses":          total,
		"safe_count":              0,
		"suspicious_count":        0,
		"dangerous_count":         0,
		"average_risk_score":      0.0,
		"average_processing_time": 0,
	}

	if total == 0 {
		return stats, nil
	}

	var safeCount, suspiciousCount, dangerousCount int
	var totalRisk float64
	var totalTime int

	for _, check := range checks {
		totalRisk += check.DangerScore
		totalTime += check.ProcessingTime

		switch check.DangerLevel {
		case "low":
			safeCount++
		case "medium":
			suspiciousCount++
		case "high", "critical":
			dangerousCount++
		}
	}

	stats["safe_count"] = safeCount
	stats["suspicious_count"] = suspiciousCount
	stats["dangerous_count"] = dangerousCount
	stats["average_risk_score"] = totalRisk / float64(total)
	stats["average_processing_time"] = totalTime / int(total)

	return stats, nil
}
