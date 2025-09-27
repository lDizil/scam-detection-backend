package models

import (
	"time"
)

type User struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Username     string    `gorm:"uniqueIndex;not null" json:"username"`
	Email        *string   `gorm:"uniqueIndex" json:"email"`
	PasswordHash string    `gorm:"not null" json:"-"`
	IsActive     bool      `gorm:"default:true" json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`

	Checks []Check `gorm:"foreignKey:UserID" json:"checks,omitempty"`
}

type CreateUserRequest struct {
	UserName string  `json:"username" binding:"required, min=3"`
	Email    *string `json:"email" binding:"omitempty, email"`
	Password string  `json:"password" binding:"required, min=6"`
}

type UpdateUserRequest struct {
	UserName *string `json:"username,omitempty" binding:"omitempty, min=3"`
	Email    *string `json:"email,omitempty" binding:"omitempty, email"`
}

type UpdatePasswordRequest struct {
	CurrentPassword string `json:"cur_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required, min=6"`
}
