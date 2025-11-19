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
