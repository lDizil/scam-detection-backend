package models

import "time"

type CheckDetail struct {
	ID              uint      `gorm:"primaryKey" json:"id"`
	CheckID         uint      `gorm:"not null;index" json:"check_id"`
	FeatureName     string    `gorm:"not null" json:"feature_name"`
	FeatureValue    string    `gorm:"type:text" json:"feature_value"`
	ConfidenceScore float64   `json:"confidence_score"`
	CreatedAt       time.Time `json:"created_at"`

	Check Check `gorm:"foreignKey:CheckID" json:"-"`
}
