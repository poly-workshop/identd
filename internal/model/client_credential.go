package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ClientCredentialModel represents an OAuth2 client credential for external services
type ClientCredentialModel struct {
	ID                 string         `gorm:"type:varchar(36);primaryKey"           json:"id"`
	CreatedAt          time.Time      `                                             json:"created_at"`
	UpdatedAt          time.Time      `                                             json:"updated_at"`
	DeletedAt          gorm.DeletedAt `gorm:"index"                                 json:"-"`
	ClientID           string         `gorm:"type:varchar(64);uniqueIndex;not null" json:"client_id"`
	HashedClientSecret string         `gorm:"type:varchar(255);not null"            json:"-"`
	Name               string         `gorm:"type:varchar(255);not null"            json:"name"`
	Description        string         `gorm:"type:text"                             json:"description"`
	Scopes             string         `gorm:"type:text"                             json:"scopes"`
	IsActive           bool           `gorm:"default:true"                          json:"is_active"`
	LastUsedAt         *time.Time     `                                             json:"last_used_at"`
	ExpiresAt          *time.Time     `                                             json:"expires_at"`
}

func (ClientCredentialModel) TableName() string {
	return "client_credentials"
}

// BeforeCreate generates a UUID for the client credential before creating
func (c *ClientCredentialModel) BeforeCreate(tx *gorm.DB) error {
	if c.ID == "" {
		c.ID = uuid.New().String()
	}
	return nil
}

// IsExpired checks if the client credential has expired
func (c *ClientCredentialModel) IsExpired() bool {
	if c.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*c.ExpiresAt)
}

// IsValid checks if the client credential is valid (active and not expired)
func (c *ClientCredentialModel) IsValid() bool {
	return c.IsActive && !c.IsExpired()
}
