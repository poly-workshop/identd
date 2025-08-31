package repository

import (
	"context"
	"log/slog"

	"github.com/poly-workshop/identra/internal/model"
	"gorm.io/gorm"
)

// ClientCredentialRepository defines the interface for client credential operations
type ClientCredentialRepository interface {
	Create(ctx context.Context, credential *model.ClientCredentialModel) error
	GetByID(ctx context.Context, id string) (*model.ClientCredentialModel, error)
	GetByClientID(ctx context.Context, clientID string) (*model.ClientCredentialModel, error)
	Update(ctx context.Context, credential *model.ClientCredentialModel) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, offset, limit int) ([]*model.ClientCredentialModel, error)
	Count(ctx context.Context) (int64, error)
	UpdateLastUsed(ctx context.Context, id string) error
}

type clientCredentialRepository struct {
	db *gorm.DB
}

// NewClientCredentialRepository creates a new client credential repository
func NewClientCredentialRepository(db *gorm.DB) ClientCredentialRepository {
	return &clientCredentialRepository{db: db}
}

func (r *clientCredentialRepository) Create(ctx context.Context, credential *model.ClientCredentialModel) error {
	err := r.db.WithContext(ctx).Create(credential).Error
	if err != nil {
		slog.ErrorContext(ctx, "failed to create client credential",
			"error", err,
			"name", credential.Name,
			"client_id", credential.ClientID,
		)
		return err
	}
	slog.InfoContext(ctx, "client credential created successfully",
		"id", credential.ID,
		"name", credential.Name,
		"client_id", credential.ClientID,
	)
	return nil
}

func (r *clientCredentialRepository) GetByID(ctx context.Context, id string) (*model.ClientCredentialModel, error) {
	var credential model.ClientCredentialModel
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&credential).Error
	if err != nil {
		slog.ErrorContext(ctx, "failed to get client credential by ID",
			"error", err,
			"id", id,
		)
		return nil, err
	}
	return &credential, nil
}

func (r *clientCredentialRepository) GetByClientID(ctx context.Context, clientID string) (*model.ClientCredentialModel, error) {
	var credential model.ClientCredentialModel
	err := r.db.WithContext(ctx).Where("client_id = ?", clientID).First(&credential).Error
	if err != nil {
		return nil, err
	}
	return &credential, nil
}

func (r *clientCredentialRepository) Update(ctx context.Context, credential *model.ClientCredentialModel) error {
	err := r.db.WithContext(ctx).Save(credential).Error
	if err != nil {
		slog.ErrorContext(ctx, "failed to update client credential",
			"error", err,
			"id", credential.ID,
		)
		return err
	}
	slog.DebugContext(ctx, "client credential updated successfully",
		"id", credential.ID,
		"name", credential.Name,
	)
	return nil
}

func (r *clientCredentialRepository) Delete(ctx context.Context, id string) error {
	err := r.db.WithContext(ctx).Where("id = ?", id).Delete(&model.ClientCredentialModel{}).Error
	if err != nil {
		slog.ErrorContext(ctx, "failed to delete client credential",
			"error", err,
			"id", id,
		)
		return err
	}
	slog.InfoContext(ctx, "client credential deleted successfully", "id", id)
	return nil
}

func (r *clientCredentialRepository) List(ctx context.Context, offset, limit int) ([]*model.ClientCredentialModel, error) {
	var credentials []*model.ClientCredentialModel
	err := r.db.WithContext(ctx).Offset(offset).Limit(limit).Find(&credentials).Error
	if err != nil {
		slog.ErrorContext(ctx, "failed to list client credentials",
			"error", err,
			"offset", offset,
			"limit", limit,
		)
		return nil, err
	}
	return credentials, nil
}

func (r *clientCredentialRepository) Count(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&model.ClientCredentialModel{}).Count(&count).Error
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (r *clientCredentialRepository) UpdateLastUsed(ctx context.Context, id string) error {
	err := r.db.WithContext(ctx).Model(&model.ClientCredentialModel{}).
		Where("id = ?", id).
		Update("last_used_at", gorm.Expr("NOW()")).Error
	if err != nil {
		slog.ErrorContext(ctx, "failed to update last used timestamp",
			"error", err,
			"id", id,
		)
		return err
	}
	return nil
}
