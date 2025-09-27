package models

import (
	"time"
)

type Check struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	Title          string    `gorm:"not null" json:"title"`
	ContentType    string    `gorm:"not null" json:"content_type"`
	Content        string    `gorm:"type:text" json:"content"`
	DangerScore    float64   `json:"danger_score"`
	DangerLevel    string    `json:"danger_level"`
	Status         string    `gorm:"default:processing" json:"status"`
	UserID         uint      `gorm:"not null" json:"user_id"`
	ProcessingTime int       `json:"processing_time_ms"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`

	User User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}
