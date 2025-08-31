package configs

import (
	"time"

	"github.com/poly-workshop/go-webmods/app"
	gorm_client "github.com/poly-workshop/go-webmods/gorm-client"
	redis_client "github.com/poly-workshop/go-webmods/redis-client"
)

// Configuration keys constants
const (
	// Server configuration keys
	ServerPortKey     = "server.port"
	ServerHTTPPortKey = "server.http_port"

	// Auth configuration keys
	AuthInternalTokenKey          = "auth.internal_token"
	AuthRSAPrivateKeyKey          = "auth.rsa_private_key"
	AuthGithubClientIDKey         = "auth.github_client_id"
	AuthGithubClientSecretKey     = "auth.github_client_secret"
	AuthGithubRedirectURLKey      = "auth.github_redirect_url"
	AuthOAuthStateExpirationKey   = "auth.oauth_state_expiration"
	AuthAccessTokenExpirationKey  = "auth.access_token_expiration"
	AuthRefreshTokenExpirationKey = "auth.refresh_token_expiration"
	AuthTokenIssuerKey            = "auth.token_issuer"

	// Database configuration keys
	DatabaseDriverKey   = "gorm_client.database.driver"
	DatabaseHostKey     = "gorm_client.database.host"
	DatabasePortKey     = "gorm_client.database.port"
	DatabaseUsernameKey = "gorm_client.database.username"
	DatabasePasswordKey = "gorm_client.database.password"
	DatabaseNameKey     = "gorm_client.database.name"
	DatabaseSSLModeKey  = "gorm_client.database.sslmode"

	// Redis configuration keys
	RedisUrlsKey     = "redis.urls"
	RedisPasswordKey = "redis.password"
)

// Default values constants
const (
	DefaultOAuthStateExpiration   = 10 * time.Minute
	DefaultAccessTokenExpiration  = 15 * time.Minute   // Short-lived access token
	DefaultRefreshTokenExpiration = 7 * 24 * time.Hour // 7 days refresh token
	DefaultTokenIssuer            = "identra"
)

type Config struct {
	Server   ServerConfig
	Auth     AuthConfig
	Database gorm_client.Config
	Redis    redis_client.Config
}

type ServerConfig struct {
	Port     uint
	HTTPPort uint
}

type AuthConfig struct {
	InternalToken                  string
	RSAPrivateKey                  string
	GithubClientID                 string
	GithubClientSecret             string
	GithubRedirectURL              string
	OAuthStateExpirationDuration   time.Duration
	AccessTokenExpirationDuration  time.Duration
	RefreshTokenExpirationDuration time.Duration
	TokenIssuer                    string
}

func Load() Config {
	cfg := Config{
		Server: ServerConfig{
			Port:     app.Config().GetUint(ServerPortKey),
			HTTPPort: app.Config().GetUint(ServerHTTPPortKey),
		},
		Auth: AuthConfig{
			InternalToken:                  app.Config().GetString(AuthInternalTokenKey),
			RSAPrivateKey:                  app.Config().GetString(AuthRSAPrivateKeyKey),
			GithubClientID:                 app.Config().GetString(AuthGithubClientIDKey),
			GithubClientSecret:             app.Config().GetString(AuthGithubClientSecretKey),
			GithubRedirectURL:              app.Config().GetString(AuthGithubRedirectURLKey),
			OAuthStateExpirationDuration:   app.Config().GetDuration(AuthOAuthStateExpirationKey),
			AccessTokenExpirationDuration:  app.Config().GetDuration(AuthAccessTokenExpirationKey),
			RefreshTokenExpirationDuration: app.Config().GetDuration(AuthRefreshTokenExpirationKey),
			TokenIssuer:                    app.Config().GetString(AuthTokenIssuerKey),
		},
		Database: gorm_client.Config{
			Driver:   app.Config().GetString(DatabaseDriverKey),
			Host:     app.Config().GetString(DatabaseHostKey),
			Port:     app.Config().GetInt(DatabasePortKey),
			Username: app.Config().GetString(DatabaseUsernameKey),
			Password: app.Config().GetString(DatabasePasswordKey),
			Name:     app.Config().GetString(DatabaseNameKey),
			SSLMode:  app.Config().GetString(DatabaseSSLModeKey),
		},
		Redis: redis_client.Config{
			Urls:     app.Config().GetStringSlice(RedisUrlsKey),
			Password: app.Config().GetString(RedisPasswordKey),
		},
	}

	// Set default OAuth state expiration if not provided
	if cfg.Auth.OAuthStateExpirationDuration == 0 {
		cfg.Auth.OAuthStateExpirationDuration = DefaultOAuthStateExpiration
	}
	// Set default access token expiration if not provided
	if cfg.Auth.AccessTokenExpirationDuration == 0 {
		cfg.Auth.AccessTokenExpirationDuration = DefaultAccessTokenExpiration
	}
	// Set default refresh token expiration if not provided
	if cfg.Auth.RefreshTokenExpirationDuration == 0 {
		cfg.Auth.RefreshTokenExpirationDuration = DefaultRefreshTokenExpiration
	}
	// Set default token issuer if not provided
	if cfg.Auth.TokenIssuer == "" {
		cfg.Auth.TokenIssuer = DefaultTokenIssuer
	}

	return cfg
}
