package utils

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// Helper function to create test token config with generated keys
func createTestTokenConfig(t *testing.T) TokenConfig {
	km := &KeyManager{}
	if err := km.GenerateKeyPair(); err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	return TokenConfig{
		PrivateKey:             km.GetPrivateKey(),
		PublicKey:              km.GetPublicKey(),
		KeyID:                  km.GetKeyID(),
		Issuer:                 "test-issuer",
		AccessTokenExpiration:  15 * time.Minute,
		RefreshTokenExpiration: 7 * 24 * time.Hour,
	}
}

func TestNewTokenPair(t *testing.T) {
	userID := uuid.New().String()
	config := createTestTokenConfig(t)

	tokenPair, err := NewTokenPair(userID, config)
	if err != nil {
		t.Fatalf("Failed to create token pair: %v", err)
	}

	// Check access token
	if tokenPair.AccessToken == "" {
		t.Error("Expected access_token to be non-empty")
	}
	if tokenPair.AccessTokenExpiresAt == nil {
		t.Error("Expected access_token_expires_at to be set")
	}

	// Check refresh token
	if tokenPair.RefreshToken == "" {
		t.Error("Expected refresh_token to be non-empty")
	}
	if tokenPair.RefreshTokenExpiresAt == nil {
		t.Error("Expected refresh_token_expires_at to be set")
	}

	// Check token type
	if tokenPair.TokenType != "Bearer" {
		t.Errorf("Expected token type 'Bearer', got %s", tokenPair.TokenType)
	}

	// Verify access token expiration
	expectedAccessExp := time.Now().Add(config.AccessTokenExpiration)
	accessExp := tokenPair.AccessTokenExpiresAt.AsTime()
	if accessExp.Before(expectedAccessExp.Add(-5*time.Second)) ||
		accessExp.After(expectedAccessExp.Add(5*time.Second)) {
		t.Errorf("Expected access token expiration around %v, got %v", expectedAccessExp, accessExp)
	}

	// Verify refresh token expiration
	expectedRefreshExp := time.Now().Add(config.RefreshTokenExpiration)
	refreshExp := tokenPair.RefreshTokenExpiresAt.AsTime()
	if refreshExp.Before(expectedRefreshExp.Add(-5*time.Second)) ||
		refreshExp.After(expectedRefreshExp.Add(5*time.Second)) {
		t.Errorf("Expected refresh token expiration around %v, got %v", expectedRefreshExp, refreshExp)
	}
}

func TestValidateAccessToken(t *testing.T) {
	userID := uuid.New().String()
	config := createTestTokenConfig(t)

	tokenPair, err := NewTokenPair(userID, config)
	if err != nil {
		t.Fatalf("Failed to create token pair: %v", err)
	}

	// Validate access token
	claims, err := ValidateAccessToken(tokenPair.AccessToken, config.PublicKey)
	if err != nil {
		t.Fatalf("Failed to validate access token: %v", err)
	}

	if claims.UserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, claims.UserID)
	}
	if claims.TokenType != AccessTokenType {
		t.Errorf("Expected token type %s, got %s", AccessTokenType, claims.TokenType)
	}
	if claims.TokenID == "" {
		t.Error("Expected token ID to be set")
	}

	// Access token should NOT be valid as refresh token
	_, err = ValidateRefreshToken(tokenPair.AccessToken, config.PublicKey)
	if err == nil {
		t.Error("Expected access token to fail validation as refresh token")
	}
}

func TestValidateRefreshToken(t *testing.T) {
	userID := uuid.New().String()
	config := createTestTokenConfig(t)

	tokenPair, err := NewTokenPair(userID, config)
	if err != nil {
		t.Fatalf("Failed to create token pair: %v", err)
	}

	// Validate refresh token
	claims, err := ValidateRefreshToken(tokenPair.RefreshToken, config.PublicKey)
	if err != nil {
		t.Fatalf("Failed to validate refresh token: %v", err)
	}

	if claims.UserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, claims.UserID)
	}
	if claims.TokenType != RefreshTokenType {
		t.Errorf("Expected token type %s, got %s", RefreshTokenType, claims.TokenType)
	}

	// Refresh token should NOT be valid as access token
	_, err = ValidateAccessToken(tokenPair.RefreshToken, config.PublicKey)
	if err == nil {
		t.Error("Expected refresh token to fail validation as access token")
	}
}

func TestRefreshTokenPair(t *testing.T) {
	userID := uuid.New().String()
	config := createTestTokenConfig(t)

	// Create initial token pair
	originalPair, err := NewTokenPair(userID, config)
	if err != nil {
		t.Fatalf("Failed to create initial token pair: %v", err)
	}

	// Refresh the token pair
	newPair, err := RefreshTokenPair(originalPair.RefreshToken, config)
	if err != nil {
		t.Fatalf("Failed to refresh token pair: %v", err)
	}

	// New tokens should be different from original
	if newPair.AccessToken == originalPair.AccessToken {
		t.Error("Expected new access token to be different from original")
	}
	if newPair.RefreshToken == originalPair.RefreshToken {
		t.Error("Expected new refresh token to be different from original")
	}

	// Validate new access token
	claims, err := ValidateAccessToken(newPair.AccessToken, config.PublicKey)
	if err != nil {
		t.Fatalf("Failed to validate new access token: %v", err)
	}
	if claims.UserID != userID {
		t.Errorf("Expected user ID %s in refreshed token, got %s", userID, claims.UserID)
	}
}

func TestStandardClaims(t *testing.T) {
	userID := uuid.New().String()
	issuer := "test-issuer"
	expiresAt := time.Now().Add(1 * time.Hour)

	claims, err := NewStandardClaims(userID, AccessTokenType, issuer, expiresAt)
	if err != nil {
		t.Fatalf("Failed to create standard claims: %v", err)
	}

	// Check required fields
	if claims.UserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, claims.UserID)
	}
	if claims.TokenType != AccessTokenType {
		t.Errorf("Expected token type %s, got %s", AccessTokenType, claims.TokenType)
	}
	if claims.TokenID == "" {
		t.Error("Expected token ID (jti) to be set")
	}

	// Check registered claims
	if claims.Issuer != issuer {
		t.Errorf("Expected issuer %s, got %s", issuer, claims.Issuer)
	}
	if claims.Subject != userID {
		t.Errorf("Expected subject %s, got %s", userID, claims.Subject)
	}
	if claims.ID != claims.TokenID {
		t.Errorf("Expected ID and TokenID to match")
	}
}

// Legacy compatibility tests

func TestLegacyUserTokenClaimsWithExpiration(t *testing.T) {
	userID := uuid.New().String()
	customExpiration := time.Now().Add(3 * time.Hour)

	claims := NewUserTokenClaimsWithExpiration(userID, customExpiration)

	// Check user ID
	claimsUserID, ok := claims.MapClaims["user_id"].(string)
	if !ok {
		t.Error("Expected user_id in claims")
	}
	if claimsUserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, claimsUserID)
	}

	// Check expiration (as Unix timestamp)
	expUnix, ok := claims.MapClaims["exp"].(int64)
	if !ok {
		t.Error("Expected exp in claims")
	}

	claimsExpiration := time.Unix(expUnix, 0)
	if claimsExpiration.Before(customExpiration.Add(-5*time.Second)) ||
		claimsExpiration.After(customExpiration.Add(5*time.Second)) {
		t.Errorf("Expected expiration around %v, got %v", customExpiration, claimsExpiration)
	}
}

func TestInvalidTokenValidation(t *testing.T) {
	config := createTestTokenConfig(t)

	// Test with invalid token
	_, err := ValidateAccessToken("invalid-token", config.PublicKey)
	if err == nil {
		t.Error("Expected error for invalid token")
	}

	// Test with wrong key
	userID := uuid.New().String()
	tokenPair, err := NewTokenPair(userID, config)
	if err != nil {
		t.Fatalf("Failed to create token pair: %v", err)
	}

	// Create a different key pair
	wrongKm := &KeyManager{}
	if err := wrongKm.GenerateKeyPair(); err != nil {
		t.Fatalf("Failed to generate wrong key pair: %v", err)
	}

	_, err = ValidateAccessToken(tokenPair.AccessToken, wrongKm.GetPublicKey())
	if err == nil {
		t.Error("Expected error for wrong public key")
	}
}

func TestKeyManager(t *testing.T) {
	km := &KeyManager{}

	// Test uninitialized state
	if km.IsInitialized() {
		t.Error("Expected key manager to be uninitialized")
	}

	// Generate key pair
	if err := km.GenerateKeyPair(); err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test initialized state
	if !km.IsInitialized() {
		t.Error("Expected key manager to be initialized")
	}

	// Test key ID
	if km.GetKeyID() == "" {
		t.Error("Expected key ID to be set")
	}

	// Test public key retrieval
	if km.GetPublicKey() == nil {
		t.Error("Expected public key to be available")
	}

	// Test private key retrieval
	if km.GetPrivateKey() == nil {
		t.Error("Expected private key to be available")
	}

	// Test JWKS generation
	jwks := km.GetJWKS()
	if len(jwks.Keys) != 1 {
		t.Errorf("Expected 1 key in JWKS, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].Kty != "RSA" {
		t.Errorf("Expected key type RSA, got %s", jwks.Keys[0].Kty)
	}
	if jwks.Keys[0].Alg != "RS256" {
		t.Errorf("Expected algorithm RS256, got %s", jwks.Keys[0].Alg)
	}
	if jwks.Keys[0].Use != "sig" {
		t.Errorf("Expected use sig, got %s", jwks.Keys[0].Use)
	}

	// Test PEM export
	privatePEM, err := km.ExportPrivateKeyPEM()
	if err != nil {
		t.Fatalf("Failed to export private key PEM: %v", err)
	}
	if privatePEM == "" {
		t.Error("Expected private key PEM to be non-empty")
	}

	publicPEM, err := km.ExportPublicKeyPEM()
	if err != nil {
		t.Fatalf("Failed to export public key PEM: %v", err)
	}
	if publicPEM == "" {
		t.Error("Expected public key PEM to be non-empty")
	}

	// Test initializing from PEM
	newKm := &KeyManager{}
	if err := newKm.InitializeFromPEM(privatePEM); err != nil {
		t.Fatalf("Failed to initialize from PEM: %v", err)
	}
	if !newKm.IsInitialized() {
		t.Error("Expected new key manager to be initialized from PEM")
	}
}
