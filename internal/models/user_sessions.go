package models

import (
	"time"
)

type UserSessions struct {
	ID        uuid.UUID `gorm:"primaryKey"`
	UserId    uint      `gorm:"not null; index"`
	TokenHash string    `gorm:"size:64;index;not null"`
	ExpiresAt time.Time `gorm:"not null;index"`
	UsedAt    *time.Time
	CreatedAt time.Time
}
