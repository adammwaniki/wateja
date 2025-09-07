// services/auth/session/session.go
package session

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/adammwaniki/wateja/services/auth/authn/jwt"
	"github.com/gofrs/uuid/v5"
)

// SessionManager handles user sessions with persistent storage
type SessionManager struct {
	db         *sql.DB
	jwtService *jwt.JWTService
}

// Session represents a user session
type Session struct {
	ID             string    `json:"session_id"`
	UserID         string    `json:"user_id"`
	AccessTokenID  string    `json:"access_token_id"`  // JTI of access token
	RefreshTokenID string    `json:"refresh_token_id"` // JTI of refresh token
	UserAgent      string    `json:"user_agent"`
	IPAddress      string    `json:"ip_address"`
	CreatedAt      time.Time `json:"created_at"`
	LastAccessedAt time.Time `json:"last_accessed_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	IsActive       bool      `json:"is_active"`
}

// SessionResponse includes session info with tokens
type SessionResponse struct {
	Session   *Session       `json:"session"`
	TokenData *jwt.TokenPair `json:"token_data"`
	Message   string         `json:"message"`
}

// NewSessionManager creates a new session manager
func NewSessionManager(db *sql.DB, jwtService *jwt.JWTService) *SessionManager {
	return &SessionManager{
		db:         db,
		jwtService: jwtService,
	}
}

// CreateSession creates a new user session and returns JWT tokens
func (sm *SessionManager) CreateSession(ctx context.Context, userID, email, firstName, lastName string, r *http.Request) (*SessionResponse, error) {
	// Generate session ID
	sessionID, err := sm.generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	// Generate JWT token pair
	tokenPair, err := sm.jwtService.GenerateTokenPair(userID, email, firstName, lastName)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Extract token IDs (JTI) from tokens
	accessClaims, err := sm.jwtService.ValidateToken(tokenPair.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to validate access token: %w", err)
	}
	
	refreshClaims, err := sm.jwtService.ValidateToken(tokenPair.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to validate refresh token: %w", err)
	}

	// Extract client information
	userAgent := r.Header.Get("User-Agent")
	ipAddress := sm.getClientIP(r)

	// Create session
	now := time.Now()
	session := &Session{
		ID:             sessionID,
		UserID:         userID,
		AccessTokenID:  accessClaims.ID,
		RefreshTokenID: refreshClaims.ID,
		UserAgent:      userAgent,
		IPAddress:      ipAddress,
		CreatedAt:      now,
		LastAccessedAt: now,
		ExpiresAt:      refreshClaims.ExpiresAt.Time,
		IsActive:       true,
	}

	// Store session in database
	if err := sm.storeSession(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to store session: %w", err)
	}

	return &SessionResponse{
		Session:   session,
		TokenData: tokenPair,
		Message:   "Session created successfully",
	}, nil
}

// RefreshSession creates new tokens for an existing session
func (sm *SessionManager) RefreshSession(ctx context.Context, refreshToken string, r *http.Request) (*SessionResponse, error) {
	// Validate refresh token
	claims, err := sm.jwtService.ValidateToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	if claims.TokenType != "refresh" {
		return nil, errors.New("token is not a refresh token")
	}

	// Check if session exists and is active
	session, err := sm.getSessionByRefreshTokenID(ctx, claims.ID)
	if err != nil {
		return nil, fmt.Errorf("session not found: %w", err)
	}

	if !session.IsActive {
		return nil, errors.New("session is inactive")
	}

	// Generate new token pair
	newTokenPair, err := sm.jwtService.GenerateTokenPair(claims.UserID, claims.Email, claims.FirstName, claims.LastName)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new tokens: %w", err)
	}

	// Extract new token IDs
	newAccessClaims, err := sm.jwtService.ValidateToken(newTokenPair.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to validate new access token: %w", err)
	}
	
	newRefreshClaims, err := sm.jwtService.ValidateToken(newTokenPair.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to validate new refresh token: %w", err)
	}

	// Update session with new token IDs
	now := time.Now()
	session.AccessTokenID = newAccessClaims.ID
	session.RefreshTokenID = newRefreshClaims.ID
	session.LastAccessedAt = now
	session.ExpiresAt = newRefreshClaims.ExpiresAt.Time

	if err := sm.updateSession(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to update session: %w", err)
	}

	return &SessionResponse{
		Session:   session,
		TokenData: newTokenPair,
		Message:   "Session refreshed successfully",
	}, nil
}

// EndSession terminates a user session
func (sm *SessionManager) EndSession(ctx context.Context, tokenID string) error {
	// Find session by access token ID
	session, err := sm.getSessionByAccessTokenID(ctx, tokenID)
	if err != nil {
		return fmt.Errorf("session not found: %w", err)
	}

	// Deactivate session
	session.IsActive = false
	if err := sm.updateSession(ctx, session); err != nil {
		return fmt.Errorf("failed to deactivate session: %w", err)
	}

	return nil
}

// EndAllUserSessions terminates all active sessions for a user
func (sm *SessionManager) EndAllUserSessions(ctx context.Context, userID string) error {
	query := `UPDATE user_sessions SET is_active = false, updated_at = ? WHERE user_id = ? AND is_active = true`
	
	_, err := sm.db.ExecContext(ctx, query, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to end all user sessions: %w", err)
	}

	return nil
}

// GetUserSessions returns all active sessions for a user
func (sm *SessionManager) GetUserSessions(ctx context.Context, userID string) ([]*Session, error) {
	query := `
	SELECT session_id, user_id, access_token_id, refresh_token_id, user_agent, 
	       ip_address, created_at, last_accessed_at, expires_at, is_active 
	FROM user_sessions 
	WHERE user_id = ? AND is_active = true 
	ORDER BY last_accessed_at DESC`

	rows, err := sm.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query user sessions: %w", err)
	}
	defer rows.Close()

	var sessions []*Session
	for rows.Next() {
		session := &Session{}
		err := rows.Scan(
			&session.ID,
			&session.UserID,
			&session.AccessTokenID,
			&session.RefreshTokenID,
			&session.UserAgent,
			&session.IPAddress,
			&session.CreatedAt,
			&session.LastAccessedAt,
			&session.ExpiresAt,
			&session.IsActive,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}

// IsTokenBlacklisted checks if a token is in an inactive session (replaces simple blacklist)
func (sm *SessionManager) IsTokenBlacklisted(ctx context.Context, tokenID string) (bool, error) {
	query := `SELECT is_active FROM user_sessions WHERE (access_token_id = ? OR refresh_token_id = ?) LIMIT 1`
	
	var isActive bool
	err := sm.db.QueryRowContext(ctx, query, tokenID, tokenID).Scan(&isActive)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return true, nil // Token not found in any session, consider it blacklisted
		}
		return false, fmt.Errorf("failed to check token status: %w", err)
	}

	return !isActive, nil
}

// CleanupExpiredSessions removes expired sessions from database
func (sm *SessionManager) CleanupExpiredSessions(ctx context.Context) error {
	query := `DELETE FROM user_sessions WHERE expires_at < ? OR (is_active = false AND updated_at < ?)`
	
	now := time.Now()
	oneWeekAgo := now.Add(-7 * 24 * time.Hour) // Keep inactive sessions for 1 week for audit purposes

	_, err := sm.db.ExecContext(ctx, query, now, oneWeekAgo)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}

	return nil
}

// Private helper methods

func (sm *SessionManager) generateSessionID() (string, error) {
	sessionUUID, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	return sessionUUID.String(), nil
}

func (sm *SessionManager) getClientIP(r *http.Request) string {
	// Check various headers for the real IP
	headers := []string{
		"CF-Connecting-IP",     // Cloudflare
		"True-Client-IP",       // Cloudflare Enterprise
		"X-Real-IP",           // Nginx
		"X-Forwarded-For",     // Standard
		"X-Client-IP",         // Apache
		"X-Cluster-Client-IP", // Cluster
	}

	for _, header := range headers {
		if ip := r.Header.Get(header); ip != "" {
			return ip
		}
	}

	// Fallback to remote address
	return r.RemoteAddr
}

func (sm *SessionManager) storeSession(ctx context.Context, session *Session) error {
	query := `
	INSERT INTO user_sessions 
	(session_id, user_id, access_token_id, refresh_token_id, user_agent, ip_address, 
	 created_at, last_accessed_at, expires_at, is_active) 
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := sm.db.ExecContext(ctx, query,
		session.ID,
		session.UserID,
		session.AccessTokenID,
		session.RefreshTokenID,
		session.UserAgent,
		session.IPAddress,
		session.CreatedAt,
		session.LastAccessedAt,
		session.ExpiresAt,
		session.IsActive,
	)

	return err
}

func (sm *SessionManager) updateSession(ctx context.Context, session *Session) error {
	query := `
	UPDATE user_sessions 
	SET access_token_id = ?, refresh_token_id = ?, last_accessed_at = ?, 
	    expires_at = ?, is_active = ?, updated_at = ?
	WHERE session_id = ?`

	_, err := sm.db.ExecContext(ctx, query,
		session.AccessTokenID,
		session.RefreshTokenID,
		session.LastAccessedAt,
		session.ExpiresAt,
		session.IsActive,
		time.Now(),
		session.ID,
	)

	return err
}

func (sm *SessionManager) getSessionByAccessTokenID(ctx context.Context, tokenID string) (*Session, error) {
	query := `
	SELECT session_id, user_id, access_token_id, refresh_token_id, user_agent, 
	       ip_address, created_at, last_accessed_at, expires_at, is_active 
	FROM user_sessions 
	WHERE access_token_id = ? LIMIT 1`

	session := &Session{}
	err := sm.db.QueryRowContext(ctx, query, tokenID).Scan(
		&session.ID,
		&session.UserID,
		&session.AccessTokenID,
		&session.RefreshTokenID,
		&session.UserAgent,
		&session.IPAddress,
		&session.CreatedAt,
		&session.LastAccessedAt,
		&session.ExpiresAt,
		&session.IsActive,
	)

	if err != nil {
		return nil, err
	}

	return session, nil
}

func (sm *SessionManager) getSessionByRefreshTokenID(ctx context.Context, tokenID string) (*Session, error) {
	query := `
	SELECT session_id, user_id, access_token_id, refresh_token_id, user_agent, 
	       ip_address, created_at, last_accessed_at, expires_at, is_active 
	FROM user_sessions 
	WHERE refresh_token_id = ? LIMIT 1`

	session := &Session{}
	err := sm.db.QueryRowContext(ctx, query, tokenID).Scan(
		&session.ID,
		&session.UserID,
		&session.AccessTokenID,
		&session.RefreshTokenID,
		&session.UserAgent,
		&session.IPAddress,
		&session.CreatedAt,
		&session.LastAccessedAt,
		&session.ExpiresAt,
		&session.IsActive,
	)

	if err != nil {
		return nil, err
	}

	return session, nil
}

// GetSessionByTokenID retrieves session by access token ID
func (sm *SessionManager) GetSessionByTokenID(ctx context.Context, tokenID string) (*Session, error) {
	query := `
	SELECT session_id, user_id, access_token_id, refresh_token_id, user_agent, 
	       ip_address, created_at, last_accessed_at, expires_at, is_active 
	FROM user_sessions 
	WHERE access_token_id = ? AND is_active = true 
	LIMIT 1`

	session := &Session{}
	err := sm.db.QueryRowContext(ctx, query, tokenID).Scan(
		&session.ID,
		&session.UserID,
		&session.AccessTokenID,
		&session.RefreshTokenID,
		&session.UserAgent,
		&session.IPAddress,
		&session.CreatedAt,
		&session.LastAccessedAt,
		&session.ExpiresAt,
		&session.IsActive,
	)

	if err != nil {
		return nil, err
	}

	return session, nil
}