package provider

import (
	"context"
	"fmt"
)

type UserInfo struct {
	ID    string
	Email string
}

type UserProvider interface {
	GetUserInfo(ctx context.Context, token string) (UserInfo, error)
}

func GetUserProvider(name string) (UserProvider, error) {
	switch name {
	case "github":
		return &GitHubProvider{}, nil
	default:
		return nil, fmt.Errorf("provider %s not supported", name)
	}
}
