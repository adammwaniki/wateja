// services/gateway/internal/handler/auth.go
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/adammwaniki/wateja/services/auth/authn/jwt"
	"github.com/adammwaniki/wateja/services/auth/authn/passwords"
	"github.com/adammwaniki/wateja/services/auth/session"
	"github.com/adammwaniki/wateja/services/common/utils"
	"github.com/adammwaniki/wateja/services/gateway/internal/middleware"
	userproto "github.com/adammwaniki/wateja/services/user/proto/genproto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

// AuthHandler handles authentication-related HTTP requests with session management
type AuthHandler struct {
	userClient     userproto.UserServiceClient
	sessionManager *session.SessionManager
	jwtService     *jwt.JWTService
}

// LoginRequest represents the request payload for password-based login
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// RefreshRequest represents the request payload for token refresh
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// LogoutRequest represents the request payload for logout
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token,omitempty"` // Optional
	LogoutAll    bool   `json:"logout_all,omitempty"`    // Logout from all devices
}

// NewAuthHandler creates a new authentication handler with session management
func NewAuthHandler(
	userClient userproto.UserServiceClient,
	sessionManager *session.SessionManager,
	jwtService *jwt.JWTService,
) *AuthHandler {
	return &AuthHandler{
		userClient:     userClient,
		sessionManager: sessionManager,
		jwtService:     jwtService,
	}
}

// HandleLogin handles POST requests for password-based authentication
func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("failed to read request body: %w", err))
		return
	}
	defer r.Body.Close()

	// Parse login request
	var loginReq LoginRequest
	if err := json.Unmarshal(body, &loginReq); err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid request format: %w", err))
		return
	}

	// Validate required fields
	if loginReq.Email == "" || loginReq.Password == "" {
		utils.WriteError(w, http.StatusBadRequest, errors.New("email and password are required"))
		return
	}

	// Set context with timeout for gRPC calls
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Get user authentication data
	authReq := &userproto.GetUserForAuthRequest{Email: loginReq.Email}
	authResp, err := h.userClient.GetUserForAuth(ctx, authReq)
	if err != nil {
		st, ok := status.FromError(err)
		if ok && st.Code() == codes.NotFound {
			utils.WriteError(w, http.StatusUnauthorized, errors.New("invalid email or password"))
			return
		}
		log.Printf("GetUserForAuth failed: %v", err)
		utils.WriteError(w, http.StatusInternalServerError, errors.New("authentication service unavailable"))
		return
	}

	// Check if user is active
	if authResp.Status != userproto.UserStatusEnum_ACTIVE {
		utils.WriteError(w, http.StatusForbidden, errors.New("user account is not active"))
		return
	}

	// Check if user has password hash (not SSO user)
	if authResp.PasswordHash == "" {
		utils.WriteError(w, http.StatusBadRequest, errors.New("this account uses SSO authentication. Please use Google login"))
		return
	}

	// Verify password
	passwordMatch, err := passwords.VerifyPassword(loginReq.Password, authResp.PasswordHash)
	if err != nil {
		log.Printf("Password verification error: %v", err)
		utils.WriteError(w, http.StatusInternalServerError, errors.New("authentication error"))
		return
	}

	if !passwordMatch {
		utils.WriteError(w, http.StatusUnauthorized, errors.New("invalid email or password"))
		return
	}

	// Get full user details
	userReq := &userproto.GetUserRequest{UserId: authResp.Id}
	userResp, err := h.userClient.GetUserByID(ctx, userReq)
	if err != nil {
		log.Printf("GetUserByID failed after successful auth: %v", err)
		utils.WriteError(w, http.StatusInternalServerError, errors.New("failed to retrieve user details"))
		return
	}

	// Create session with JWT tokens
	sessionResp, err := h.sessionManager.CreateSession(
		ctx,
		userResp.Id,
		userResp.Email,
		userResp.FirstName,
		userResp.LastName,
		r,
	)
	if err != nil {
		log.Printf("Failed to create session: %v", err)
		utils.WriteError(w, http.StatusInternalServerError, errors.New("failed to create session"))
		return
	}

	// Return successful login response with session info
	response := struct {
		User         *userproto.GetUserResponse `json:"user"`
		TokenData    *jwt.TokenPair             `json:"token_data"`
		SessionID    string                     `json:"session_id"`
		Message      string                     `json:"message"`
	}{
		User:      userResp,
		TokenData: sessionResp.TokenData,
		SessionID: sessionResp.Session.ID,
		Message:   "Login successful",
	}

	log.Printf("User %s (%s) logged in successfully with session %s", userResp.Email, userResp.Id, sessionResp.Session.ID)
	utils.WriteJSON(w, http.StatusOK, response)
}

// HandleRefresh handles POST requests for token refresh
func (h *AuthHandler) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("failed to read request body: %w", err))
		return
	}
	defer r.Body.Close()

	// Parse refresh request
	var refreshReq RefreshRequest
	if err := json.Unmarshal(body, &refreshReq); err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid request format: %w", err))
		return
	}

	if refreshReq.RefreshToken == "" {
		utils.WriteError(w, http.StatusBadRequest, errors.New("refresh_token is required"))
		return
	}

	// Set context with timeout
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Refresh session
	sessionResp, err := h.sessionManager.RefreshSession(ctx, refreshReq.RefreshToken, r)
	if err != nil {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("failed to refresh session: %w", err))
		return
	}

	log.Printf("Session %s refreshed for user %s", sessionResp.Session.ID, sessionResp.Session.UserID)
	utils.WriteJSON(w, http.StatusOK, sessionResp.TokenData)
}

// HandleLogout handles POST requests for user logout
func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	// Extract token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		utils.WriteError(w, http.StatusBadRequest, errors.New("authorization header is required"))
		return
	}

	// Parse bearer token
	token := ""
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		token = authHeader[7:]
	} else {
		utils.WriteError(w, http.StatusBadRequest, errors.New("invalid authorization header format"))
		return
	}

	// Validate token to get claims
	claims, err := h.jwtService.ValidateToken(token)
	if err != nil {
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("invalid token: %w", err))
		return
	}

	// Set context with timeout
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Parse logout request (optional body)
	var logoutReq LogoutRequest
	if r.Body != nil {
		body, err := io.ReadAll(r.Body)
		if err == nil {
			json.Unmarshal(body, &logoutReq)
		}
		defer r.Body.Close()
	}

	// Handle logout from all devices
	if logoutReq.LogoutAll {
		if err := h.sessionManager.EndAllUserSessions(ctx, claims.UserID); err != nil {
			log.Printf("Failed to end all sessions for user %s: %v", claims.UserID, err)
			utils.WriteError(w, http.StatusInternalServerError, errors.New("failed to logout from all devices"))
			return
		}
		log.Printf("All sessions ended for user %s", claims.UserID)
		utils.WriteJSON(w, http.StatusOK, map[string]string{"message": "Logged out from all devices successfully"})
		return
	}

	// Regular logout - end current session
	if err := h.sessionManager.EndSession(ctx, claims.ID); err != nil {
		log.Printf("Failed to end session for token %s: %v", claims.ID, err)
		utils.WriteError(w, http.StatusInternalServerError, errors.New("failed to end session"))
		return
	}

	log.Printf("Session ended for user %s", claims.UserID)
	utils.WriteJSON(w, http.StatusOK, map[string]string{"message": "Logged out successfully"})
}

// HandleProfile handles GET requests to return current user's profile
func (h *AuthHandler) HandleProfile(w http.ResponseWriter, r *http.Request) {
	// Extract user claims from context (set by auth middleware)
	claims, ok := middleware.GetClaimsFromContext(r.Context())
	if !ok {
		utils.WriteError(w, http.StatusUnauthorized, errors.New("user not authenticated"))
		return
	}

	// Set context with timeout for gRPC call
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Get full user details
	userReq := &userproto.GetUserRequest{UserId: claims.UserID}
	userResp, err := h.userClient.GetUserByID(ctx, userReq)
	if err != nil {
		utils.HandleGRPCError(w, err)
		return
	}

	utils.WriteProtoJSON(w, http.StatusOK, userResp)
}

// HandleGetSessions handles GET requests to return user's active sessions
func (h *AuthHandler) HandleGetSessions(w http.ResponseWriter, r *http.Request) {
	// Extract user claims from context
	claims, ok := middleware.GetClaimsFromContext(r.Context())
	if !ok {
		utils.WriteError(w, http.StatusUnauthorized, errors.New("user not authenticated"))
		return
	}

	// Set context with timeout
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Get user sessions
	sessions, err := h.sessionManager.GetUserSessions(ctx, claims.UserID)
	if err != nil {
		log.Printf("Failed to get sessions for user %s: %v", claims.UserID, err)
		utils.WriteError(w, http.StatusInternalServerError, errors.New("failed to retrieve sessions"))
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"sessions": sessions,
		"count":    len(sessions),
	})
}

// HandleCreateUserWithJWT extends user registration to include automatic login
func (h *AuthHandler) HandleCreateUserWithJWT(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("failed to read request body: %w", err))
		return
	}
	defer r.Body.Close()

	// Unmarshal the request body into the RegistrationRequest protobuf message
	var regRequest userproto.RegistrationRequest
	unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}
	if err := unmarshaler.Unmarshal(body, &regRequest); err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid request format: %w", err))
		return
	}

	// Create the gRPC request message for CreateUser
	grpcReq := &userproto.CreateUserRequest{User: &regRequest}

	// Set a context with timeout for the gRPC call
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Call the gRPC service's CreateUser method
	resp, err := h.userClient.CreateUser(ctx, grpcReq)
	if err != nil {
		utils.HandleGRPCError(w, err)
		return
	}

	// Create session with JWT tokens for auto-login after registration
	sessionResp, err := h.sessionManager.CreateSession(
		ctx,
		resp.Id,
		resp.Email,
		resp.FirstName,
		resp.LastName,
		r,
	)
	if err != nil {
		log.Printf("Failed to create session for new user: %v", err)
		// Still return success for user creation, but without auto-login
		utils.WriteProtoJSON(w, http.StatusCreated, resp)
		return
	}

	// Convert CreateUserResponse to GetUserResponse format
	userResp := &userproto.GetUserResponse{
		Id:              resp.Id,
		FirstName:       resp.FirstName,
		LastName:        resp.LastName,
		Status:          resp.Status,
		Email:           resp.Email,
		TermsAcceptedAt: resp.TermsAcceptedAt,
		CreatedAt:       resp.CreatedAt,
	}

	// Return user data with session tokens
	response := struct {
		User         *userproto.GetUserResponse `json:"user"`
		TokenData    *jwt.TokenPair             `json:"token_data"`
		SessionID    string                     `json:"session_id"`
		Message      string                     `json:"message"`
	}{
		User:      userResp,
		TokenData: sessionResp.TokenData,
		SessionID: sessionResp.Session.ID,
		Message:   "Registration successful",
	}

	log.Printf("User %s registered and logged in with session %s", resp.Email, sessionResp.Session.ID)
	utils.WriteJSON(w, http.StatusCreated, response)
}