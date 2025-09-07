// services/gateway/internal/middleware/auth.go
package middleware

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/adammwaniki/wateja/services/auth/authn/jwt"
	"github.com/adammwaniki/wateja/services/auth/session"
	"github.com/adammwaniki/wateja/services/common/utils"
)

// AuthMiddleware handles JWT authentication with session management
type AuthMiddleware struct {
	jwtService     *jwt.JWTService
	sessionManager *session.SessionManager
	skipPaths      map[string]bool // Paths that don't require authentication
}

// AuthContext key type for context values
type authContextKey string

const (
	UserClaimsKey authContextKey = "user_claims"
	UserIDKey     authContextKey = "user_id"
	SessionIDKey  authContextKey = "session_id"
)

// NewAuthMiddleware creates a new authentication middleware with session management
func NewAuthMiddleware(jwtService *jwt.JWTService, sessionManager *session.SessionManager) *AuthMiddleware {
	// These paths must match EXACTLY what the middleware sees
	// The middleware runs BEFORE http.StripPrefix, so paths include /api/v1
	skipPaths := map[string]bool{
		"/api/v1/users/register":        true,  
		"/api/v1/auth/google/login":     true,  
		"/api/v1/auth/google/callback":  true,  
		"/api/v1/auth/login":            true,  
		"/api/v1/auth/refresh":          true,  
		"/api/v1/auth/logout":           true, //(logout needs token but handles it specially)
		"/api/v1/healthz":               true,  
		"/api/v1/readyz":                true,  
		"/healthz":                      true, 
		"/readyz":                       true, 
	}

	return &AuthMiddleware{
		jwtService:     jwtService,
		sessionManager: sessionManager,
		skipPaths:      skipPaths,
	}
}

// HTTPAuthMiddleware is the main authentication middleware with session validation
func (m *AuthMiddleware) HTTPAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// DEBUG: Log the path being checked
		log.Printf("Auth middleware checking path: %s", r.URL.Path)
		
		// Skip authentication for public paths
		if m.skipPaths[r.URL.Path] {
			log.Printf("Path %s is public, skipping auth", r.URL.Path)
			next.ServeHTTP(w, r)
			return
		}

		log.Printf("Path %s requires authentication", r.URL.Path)

		// Extract token from Authorization header
		token, err := m.extractTokenFromHeader(r)
		if err != nil {
			log.Printf("Token extraction failed: %v", err)
			utils.WriteError(w, http.StatusUnauthorized, err)
			return
		}

		// Validate the token
		claims, err := m.jwtService.ValidateToken(token)
		if err != nil {
			log.Printf("Token validation failed: %v", err)
			utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("invalid token: %w", err))
			return
		}

		// Ensure it's an access token, not a refresh token
		if claims.TokenType != "access" {
			log.Printf("Invalid token type: %s", claims.TokenType)
			utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("invalid token type"))
			return
		}

		// Check if token is blacklisted (session-based validation)
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		
		isBlacklisted, err := m.sessionManager.IsTokenBlacklisted(ctx, claims.ID)
		if err != nil {
			log.Printf("Session validation failed: %v", err)
			utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to validate session: %w", err))
			return
		}

		if isBlacklisted {
			log.Printf("Token is blacklisted: %s", claims.ID)
			utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("session has been terminated"))
			return
		}

		// Get session info for additional context
		sessionID := ""
		if sessionInfo, err := m.sessionManager.GetSessionByTokenID(ctx, claims.ID); err == nil {
			sessionID = sessionInfo.ID
		}

		// Add claims and session info to request context
		ctx = context.WithValue(r.Context(), UserClaimsKey, claims)
		ctx = context.WithValue(ctx, UserIDKey, claims.UserID)
		if sessionID != "" {
			ctx = context.WithValue(ctx, SessionIDKey, sessionID)
		}
		
		log.Printf("Authentication successful for user: %s", claims.UserID)
		
		// Continue with the authenticated request
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// extractTokenFromHeader extracts the JWT token from the Authorization header
func (m *AuthMiddleware) extractTokenFromHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("authorization header is required")
	}

	// Expected format: "Bearer <token>"
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", fmt.Errorf("invalid authorization header format")
	}

	token := parts[1]
	if token == "" {
		return "", fmt.Errorf("token cannot be empty")
	}

	return token, nil
}

// Context helper functions

// GetClaimsFromContext extracts user claims from the request context
func GetClaimsFromContext(ctx context.Context) (*jwt.Claims, bool) {
	claims, ok := ctx.Value(UserClaimsKey).(*jwt.Claims)
	return claims, ok
}

// GetUserIDFromContext extracts user ID from the request context
func GetUserIDFromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(UserIDKey).(string)
	return userID, ok
}

// GetSessionIDFromContext extracts session ID from the request context
func GetSessionIDFromContext(ctx context.Context) (string, bool) {
	sessionID, ok := ctx.Value(SessionIDKey).(string)
	return sessionID, ok
}

// RequireAuth is a convenience function for protecting individual handlers
func (m *AuthMiddleware) RequireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		token, err := m.extractTokenFromHeader(r)
		if err != nil {
			log.Printf("Token extraction failed for %s: %v", r.URL.Path, err)
			utils.WriteError(w, http.StatusUnauthorized, err)
			return
		}

		// Validate the token
		claims, err := m.jwtService.ValidateToken(token)
		if err != nil {
			log.Printf("Token validation failed for %s: %v", r.URL.Path, err)
			utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("invalid token: %w", err))
			return
		}

		// Ensure it's an access token, not a refresh token
		if claims.TokenType != "access" {
			log.Printf("Invalid token type for %s: %s", r.URL.Path, claims.TokenType)
			utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("invalid token type"))
			return
		}

		// Check if token is blacklisted (session-based validation)
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		
		isBlacklisted, err := m.sessionManager.IsTokenBlacklisted(ctx, claims.ID)
		if err != nil {
			log.Printf("Session validation failed for %s: %v", r.URL.Path, err)
			utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to validate session: %w", err))
			return
		}

		if isBlacklisted {
			log.Printf("Token is blacklisted for %s: %s", r.URL.Path, claims.ID)
			utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("session has been terminated"))
			return
		}

		// Get session info for additional context
		sessionID := ""
		if sessionInfo, err := m.sessionManager.GetSessionByTokenID(ctx, claims.ID); err == nil {
			sessionID = sessionInfo.ID
		}

		// Add claims and session info to request context
		ctx = context.WithValue(r.Context(), UserClaimsKey, claims)
		ctx = context.WithValue(ctx, UserIDKey, claims.UserID)
		if sessionID != "" {
			ctx = context.WithValue(ctx, SessionIDKey, sessionID)
		}
		
		log.Printf("Authentication successful for user %s on %s", claims.UserID, r.URL.Path)
		
		// Call the protected handler
		handler.ServeHTTP(w, r.WithContext(ctx))
	}
}