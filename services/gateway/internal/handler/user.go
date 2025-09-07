// services/gateway/internal/handler/user.go
package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/adammwaniki/wateja/services/auth/authn/jwt"
	"github.com/adammwaniki/wateja/services/auth/session"
	"github.com/adammwaniki/wateja/services/common/utils"
	userproto "github.com/adammwaniki/wateja/services/user/proto/genproto"
	"github.com/gofrs/uuid/v5"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// UserHandler handles HTTP requests for the user.UserService, including OAuth.
type UserHandler struct {
	userClient        userproto.UserServiceClient
	googleOAuthConfig *oauth2.Config // Google OAuth2 configuration
	// For simplicity, using an in-memory map for state.
	// In production, we shall use a secure session store (e.g., Redis, database)
	// to prevent CSRF and ensure state persistence across redirects.
	oauthStates map[string]string // map[state]redirect_url
}

// LoginResponse for consistency across handlers
type LoginResponse struct {
	User         *userproto.GetUserResponse `json:"user"`
	TokenData    *jwt.TokenPair             `json:"token_data"`
	Message      string                     `json:"message"`
}

// NewUserHandler creates a new UserHandler.
func NewUserHandler(
    userClient userproto.UserServiceClient,
    googleOAuthConfig *oauth2.Config,
) *UserHandler {
    return &UserHandler{
        userClient:        userClient,
        googleOAuthConfig: googleOAuthConfig,
        oauthStates:       make(map[string]string),
    }
}

// HandleCreateUser handles POST requests to create a new user.
func (h *UserHandler) HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("failed to read request body: %w", err))
		return
	}
	defer r.Body.Close()

	// Unmarshal the request body into the RegistrationRequest protobuf message.
	var regRequest userproto.RegistrationRequest
	unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}
	if err := unmarshaler.Unmarshal(body, &regRequest); err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid request format: %w", err))
		return
	}

	// Create the gRPC request message for CreateUser.
	grpcReq := &userproto.CreateUserRequest{
		User: &regRequest,
	}

	// Set a context with timeout for the gRPC call.
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second) // Adjust timeout as needed
	defer cancel()

	// Call the gRPC service's CreateUser method.
	resp, err := h.userClient.CreateUser(ctx, grpcReq)
	if err != nil {
		utils.HandleGRPCError(w, err)
		return
	}

	// Return the successful response.
	utils.WriteProtoJSON(w, http.StatusCreated, resp)
}

// HandleGetUserByID handles GET requests to retrieve a user by their external ID.
func (h *UserHandler) HandleGetUserByID(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.PathValue("id")
	if userIDStr == "" {
		utils.WriteError(w, http.StatusBadRequest, errors.New("user ID is required"))
		return
	}

	// Parse the UUID string from the URL path.
	parsedUUID, err := uuid.FromString(userIDStr)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid UUID format: %w", err))
		return
	}

	// Create the gRPC request message, sending the 16-byte representation of the UUID.
	grpcReq := &userproto.GetUserRequest{
		UserId: parsedUUID.String(),
	}

	// Set a context with timeout for the gRPC call.
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second) // Adjust timeout as needed
	defer cancel()

	// Call the gRPC service's GetUserByID method.
	resp, err := h.userClient.GetUserByID(ctx, grpcReq)
	if err != nil {
		utils.HandleGRPCError(w, err)
		return
	}

	// Return the successful response.
	utils.WriteProtoJSON(w, http.StatusOK, resp)
}

// HandleListUsers handles GET requests to list users with pagination.
func (h *UserHandler) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	pageSize := int32(50) // Default page size
	if ps := r.URL.Query().Get("page_size"); ps != "" {
		if n, err := strconv.Atoi(ps); err == nil && n > 0 {
			pageSize = int32(n)
		}
	}

	// Create the gRPC request message for ListUsers.
	grpcReq := &userproto.ListUsersRequest{
		PageSize:  pageSize,
		PageToken: r.URL.Query().Get("page_token"),
	}

	// Set a context with timeout for the gRPC call.
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second) // Adjust timeout for potential large lists
	defer cancel()

	// Call the gRPC service's ListUsers method.
	resp, err := h.userClient.ListUsers(ctx, grpcReq)
	if err != nil {
		utils.HandleGRPCError(w, err)
		return
	}

	// Return the successful response.
	utils.WriteProtoJSON(w, http.StatusOK, resp)
}

// HandleGoogleLogin initiates the Google OAuth2 login flow.
func (h *UserHandler) HandleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	log.Println("DEBUG: HandleGoogleLogin initiated.")
	// Generate a cryptographically secure random state to prevent CSRF attacks.
	stateBytes := make([]byte, 32)
	_, err := rand.Read(stateBytes)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to generate state: %w", err))
		return
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	// Store the state. In a real application, this should be stored securely
	// in a session or a cookie, not in an in-memory map.
	h.oauthStates[state] = "/" // Default redirect to root or a specified target
	log.Printf("DEBUG: Generated OAuth state: %s", state)

	// Redirect the user to Google's consent screen.
	url := h.googleOAuthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.ApprovalForce) // Request refresh token
	log.Printf("DEBUG: Redirecting to Google Auth URL: %s", url)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// HandleGoogleCallbackWithJWT handles the redirect from Google after user authorization with JWT and session management
func (h *UserHandler) HandleGoogleCallbackWithJWT(sessionManager *session.SessionManager, w http.ResponseWriter, r *http.Request) {
	log.Println("DEBUG: HandleGoogleCallback initiated.")
	
	// Verify the 'state' parameter to prevent CSRF
	state := r.URL.Query().Get("state")
	log.Printf("DEBUG: Received state parameter: %s", state)
	if _, ok := h.oauthStates[state]; !ok {
		utils.WriteError(w, http.StatusBadRequest, errors.New("invalid or missing OAuth state parameter"))
		return
	}
	delete(h.oauthStates, state)
	log.Println("DEBUG: OAuth state verified and removed.")

	// Check for errors from Google
	if authErr := r.URL.Query().Get("error"); authErr != "" {
		errorDescription := r.URL.Query().Get("error_description")
		log.Printf("ERROR: OAuth authorization failed from Google: %s - %s", authErr, errorDescription)
		utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("OAuth authorization failed: %s - %s", authErr, errorDescription))
		return
	}

	// Get the authorization code
	code := r.URL.Query().Get("code")
	log.Printf("DEBUG: Received authorization code (first 10 chars): %s...", code[:min(10, len(code))])
	if code == "" {
		utils.WriteError(w, http.StatusBadRequest, errors.New("missing authorization code"))
		return
	}

	// Exchange the authorization code for an OAuth2 token
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	log.Println("DEBUG: Attempting to exchange authorization code for token...")
	token, err := h.googleOAuthConfig.Exchange(ctx, code)
	if err != nil {
		log.Printf("ERROR: Failed to exchange authorization code for token: %v", err)
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to exchange authorization code for token: %w", err))
		return
	}
	log.Println("DEBUG: Successfully exchanged code for token.")

	// Get user information from Google
	userInfoClient := h.googleOAuthConfig.Client(ctx, token)
	log.Println("DEBUG: Attempting to fetch user info from Google UserInfo endpoint...")
	userInfoResp, err := userInfoClient.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		log.Printf("ERROR: Failed to get user info from Google: %v", err)
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to get user info from Google: %w", err))
		return
	}
	defer userInfoResp.Body.Close()

	if userInfoResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(userInfoResp.Body)
		log.Printf("ERROR: Google user info API returned non-200 status: %d, body: %s", userInfoResp.StatusCode, string(bodyBytes))
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("google user info API returned non-200 status: %d", userInfoResp.StatusCode))
		return
	}

	var googleUserInfo struct {
		ID        string `json:"sub"`
		Email     string `json:"email"`
		FirstName string `json:"given_name"`
		LastName  string `json:"family_name"`
	}
	
	if err := json.NewDecoder(userInfoResp.Body).Decode(&googleUserInfo); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to parse Google user info: %w", err))
		return
	}
	log.Printf("DEBUG: Successfully decoded Google user info. Email: %s, SSO ID: %s", googleUserInfo.Email, googleUserInfo.ID)

	// Try to get existing user by SSO ID
	getUserReq := &userproto.GetUserBySSOIDRequest{SsoId: googleUserInfo.ID}
	userResp, err := h.userClient.GetUserBySSOID(ctx, getUserReq)

	if err != nil {
		st, ok := status.FromError(err)
		if ok && st.Code() == codes.NotFound {
			// User not found, create new user
			log.Printf("DEBUG: User with SSO ID '%s' not found. Creating new user.", googleUserInfo.ID)
			createReq := &userproto.CreateUserRequest{
				User: &userproto.RegistrationRequest{
					FirstName: googleUserInfo.FirstName,
					LastName:  googleUserInfo.LastName,
					Email:     googleUserInfo.Email,
					AuthMethod: &userproto.RegistrationRequest_SsoId{SsoId: googleUserInfo.ID},
				},
			}
			
			createResp, createErr := h.userClient.CreateUser(ctx, createReq)
			if createErr != nil {
				log.Printf("ERROR: Failed to create new SSO user: %v", createErr)
				utils.HandleGRPCError(w, createErr)
				return
			}
			
			// Convert to GetUserResponse format
			userResp = &userproto.GetUserResponse{
				Id: createResp.Id,
				FirstName: createResp.FirstName,
				LastName: createResp.LastName,
				Status: createResp.Status,
				Email: createResp.Email,
				TermsAcceptedAt: createResp.TermsAcceptedAt,
				CreatedAt: createResp.CreatedAt,
			}
		} else {
			log.Printf("ERROR: GetUserBySSOID returned unexpected error: %v", err)
			utils.HandleGRPCError(w, err)
			return
		}
	}

	// Check user status
	if userResp.GetStatus() != userproto.UserStatusEnum_ACTIVE {
		utils.WriteError(w, http.StatusForbidden, errors.New("user account is not active"))
		return
	}

	// Create session with JWT tokens
	sessionResp, err := sessionManager.CreateSession(
		ctx,
		userResp.Id,
		userResp.Email,
		userResp.FirstName,
		userResp.LastName,
		r,
	)
	if err != nil {
		log.Printf("Failed to create session for SSO user: %v", err)
		// Still return success but without session
		utils.WriteProtoJSON(w, http.StatusOK, userResp)
		return
	}

	// Return successful response with session and tokens
	response := struct {
		User         *userproto.GetUserResponse `json:"user"`
		TokenData    *jwt.TokenPair             `json:"token_data"`
		SessionID    string                     `json:"session_id"`
		Message      string                     `json:"message"`
	}{
		User:      userResp,
		TokenData: sessionResp.TokenData,
		SessionID: sessionResp.Session.ID,
		Message:   "SSO authentication successful",
	}

	log.Printf("User %s successfully authenticated via Google SSO with session %s", userResp.GetEmail(), sessionResp.Session.ID)
	utils.WriteJSON(w, http.StatusOK, response)
}


// HandleUpdateUserByID handles PUT requests to fully update a user.
func (h *UserHandler) HandleUpdateUserByID(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.PathValue("id")
	if userIDStr == "" {
		utils.WriteError(w, http.StatusBadRequest, errors.New("user ID is required"))
		return
	}

	// Parse the UUID string from the URL path
	parsedUUID, err := uuid.FromString(userIDStr)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid UUID format: %w", err))
		return
	}

	// Read and validate request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("failed to read request body: %w", err))
		return
	}
	defer r.Body.Close()

	// Parse the request payload
	var updateRequest struct {
		User       *userproto.UserInput `json:"user"`
		UpdateMask []string             `json:"update_mask,omitempty"`
	}

	if err := json.Unmarshal(body, &updateRequest); err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid request format: %w", err))
		return
	}

	if updateRequest.User == nil {
		utils.WriteError(w, http.StatusBadRequest, errors.New("user data is required"))
		return
	}

	// Create field mask if provided
	var fieldMask *fieldmaskpb.FieldMask
	if len(updateRequest.UpdateMask) > 0 {
		fieldMask = &fieldmaskpb.FieldMask{
			Paths: updateRequest.UpdateMask,
		}
	}

	// Create the gRPC request with the user ID from the URL path
	grpcReq := &userproto.UpdateUserRequest{
		UserId:     parsedUUID.String(),
		User:       updateRequest.User,
		UpdateMask: fieldMask,
	}

	// Set a context with timeout for the gRPC call
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Call the gRPC service's UpdateUser method
	resp, err := h.userClient.UpdateUser(ctx, grpcReq)
	if err != nil {
		utils.HandleGRPCError(w, err)
		return
	}

	// Return the successful response
	utils.WriteProtoJSON(w, http.StatusOK, resp)
}

// HandleDeleteUserByID handles DELETE requests to soft-delete a user.
func (h *UserHandler) HandleDeleteUserByID(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.PathValue("id")
	if userIDStr == "" {
		utils.WriteError(w, http.StatusBadRequest, errors.New("user ID is required"))
		return
	}

	// Parse the UUID string from the URL path
	parsedUUID, err := uuid.FromString(userIDStr)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, fmt.Errorf("invalid UUID format: %w", err))
		return
	}

	// Create the gRPC request message
	grpcReq := &userproto.DeleteUserRequest{
		UserId: parsedUUID.String(),
	}

	// Set a context with timeout for the gRPC call
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Call the gRPC service's DeleteUser method
	_, err = h.userClient.DeleteUser(ctx, grpcReq)
	if err != nil {
		utils.HandleGRPCError(w, err)
		return
	}

	// Return success with no content
	w.WriteHeader(http.StatusNoContent)
}