package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// GenerateClientID generates a unique client ID
func GenerateClientID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate client ID: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// GenerateClientSecret generates a secure client secret
func GenerateClientSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate client secret: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// HashClientSecret hashes a client secret using the same Argon2ID algorithm as passwords
func HashClientSecret(secret string) (string, error) {
	return HashPassword(secret)
}

// VerifyClientSecret verifies a client secret against its hash
func VerifyClientSecret(secret, hash string) (bool, error) {
	return VerifyPassword(secret, hash)
}
