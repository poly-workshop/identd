package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type UserModel struct {
	ID             string         `gorm:"type:varchar(36);primaryKey" json:"id"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	DeletedAt      gorm.DeletedAt `gorm:"index" json:"-"`
	Email          string         `gorm:"type:varchar(255);uniqueIndex;not null" json:"email"`
	HashedPassword *string        `gorm:"column:hashed_password"                 json:"-"`
	GithubID       *string        `gorm:"column:github_id;unique"                json:"github_id"`
	LastLoginAt    *time.Time     `                                              json:"last_login_at"`
}

func (UserModel) TableName() string {
	return "users"
}

// BeforeCreate generates a UUID for the user before creating
func (u *UserModel) BeforeCreate(tx *gorm.DB) error {
	if u.ID == "" {
		u.ID = uuid.New().String()
	}
	return nil
}
