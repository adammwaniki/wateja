// services/auth/authn/jwt/jwt.go
package jwt

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gofrs/uuid/v5"
)

// JWTService handles JWT token operations
type JWTService struct {
	secretKey       []byte
	issuer          string
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

// Claims represents the JWT claims structure
type Claims struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	TokenType string `json:"token_type"` // "access" or "refresh"
	jwt.RegisteredClaims
}

// TokenPair represents an access token and refresh token pair
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"` // seconds until access token expires
}

// NewJWTService creates a new JWT service with the given secret key and issuer
func NewJWTService(secretKey string, issuer string) *JWTService {
	return &JWTService{
		secretKey:       []byte(secretKey),
		issuer:          issuer,
		accessTokenTTL:  15 * time.Minute,   // Short-lived access tokens
		refreshTokenTTL: 24 * 7 * time.Hour, // 1 week refresh tokens
	}
}

// SetTokenTTL allows customizing token lifetimes
func (s *JWTService) SetTokenTTL(accessTTL, refreshTTL time.Duration) {
	s.accessTokenTTL = accessTTL
	s.refreshTokenTTL = refreshTTL
}

// GenerateTokenPair creates both access and refresh tokens for a user
func (s *JWTService) GenerateTokenPair(userID, email, firstName, lastName string) (*TokenPair, error) {
	if userID == "" || email == "" {
		return nil, errors.New("user ID and email are required")
	}

	// Generate JTI (JWT ID) for both tokens
	accessJTI, err := s.generateJTI()
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token JTI: %w", err)
	}

	refreshJTI, err := s.generateJTI()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token JTI: %w", err)
	}

	now := time.Now()
	
	// Create access token claims
	accessClaims := &Claims{
		UserID:    userID,
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
		TokenType: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        accessJTI,
			Issuer:    s.issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{"bebabeba-app"},
			ExpiresAt: jwt.NewNumericDate(now.Add(s.accessTokenTTL)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	// Create refresh token claims (minimal data for security)
	refreshClaims := &Claims{
		UserID:    userID,
		Email:     email,
		TokenType: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        refreshJTI,
			Issuer:    s.issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{"bebabeba-app"},
			ExpiresAt: jwt.NewNumericDate(now.Add(s.refreshTokenTTL)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	// Generate access token
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(s.secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	// Generate refresh token
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(s.secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.accessTokenTTL.Seconds()),
	}, nil
}

// ValidateToken parses and validates a JWT token, returning the claims
func (s *JWTService) ValidateToken(tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, errors.New("token cannot be empty")
	}

	// Parse the token with claims
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.secretKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Extract and validate claims
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	// Additional validation
	if claims.Issuer != s.issuer {
		return nil, fmt.Errorf("invalid issuer: expected %s, got %s", s.issuer, claims.Issuer)
	}

	// Validate audience
	if claims.Issuer != s.issuer {
		return nil, fmt.Errorf("invalid issuer: expected %s, got %s", s.issuer, claims.Issuer)
	}

	// Validate audience manually
	audValid := false
	for _, aud := range claims.Audience {
		if aud == "bebabeba-app" {
			audValid = true
			break
		}
	}
	if !audValid {
		return nil, errors.New("invalid audience")
	}

	return claims, nil
}

// RefreshTokens validates a refresh token and generates a new token pair
func (s *JWTService) RefreshTokens(refreshTokenString string) (*TokenPair, error) {
	// Validate the refresh token
	claims, err := s.ValidateToken(refreshTokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Ensure it's actually a refresh token
	if claims.TokenType != "refresh" {
		return nil, errors.New("token is not a refresh token")
	}

	// Generate new token pair
	return s.GenerateTokenPair(claims.UserID, claims.Email, claims.FirstName, claims.LastName)
}

// ExtractUserIDFromToken is a convenience method to get user ID from a valid token
func (s *JWTService) ExtractUserIDFromToken(tokenString string) (string, error) {
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return "", err
	}
	return claims.UserID, nil
}

// IsTokenExpired checks if a token is expired (useful for custom error handling)
func (s *JWTService) IsTokenExpired(tokenString string) bool {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return s.secretKey, nil
	})
	
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return true
		}
		return true // treat other errors as expired/invalid
	}

	if claims, ok := token.Claims.(*Claims); ok {
		return time.Now().After(claims.ExpiresAt.Time)
	}
	
	return true
}

// generateJTI creates a cryptographically secure random JWT ID
func (s *JWTService) generateJTI() (string, error) {
	// Generate a UUID v4 as JTI
	id, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

// GenerateSecureSecret creates a cryptographically secure secret key
// This is a utility function for generating secrets during setup
func GenerateSecureSecret(length int) (string, error) {
	if length < 32 {
		return "", errors.New("secret length must be at least 32 bytes")
	}
	
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate secure secret: %w", err)
	}
	
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// TokenBlacklist creates a simple in-memory blacklist for logged out tokens
// In production, I shall use Redis or a database for persistence - most likely redis for speed
type TokenBlacklist struct {
	tokens map[string]time.Time // map[jti]expiry_time
}

func NewTokenBlacklist() *TokenBlacklist {
	return &TokenBlacklist{
		tokens: make(map[string]time.Time),
	}
}

// BlacklistToken adds a token JTI to the blacklist until its natural expiry
func (bl *TokenBlacklist) BlacklistToken(jti string, expiryTime time.Time) {
	bl.tokens[jti] = expiryTime
}

// IsBlacklisted checks if a token JTI is blacklisted
func (bl *TokenBlacklist) IsBlacklisted(jti string) bool {
	if expiry, exists := bl.tokens[jti]; exists {
		if time.Now().After(expiry) {
			// Token naturally expired, remove from blacklist
			delete(bl.tokens, jti)
			return false
		}
		return true
	}
	return false
}

// CleanupExpired removes naturally expired tokens from blacklist
// This should be called periodically (e.g., via a cron job)
func (bl *TokenBlacklist) CleanupExpired() {
	now := time.Now()
	for jti, expiry := range bl.tokens {
		if now.After(expiry) {
			delete(bl.tokens, jti)
		}
	}
}