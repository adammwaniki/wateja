// services/gateway/internal/handler/routes.go
package handler

import (
	"net/http"

	"github.com/adammwaniki/wateja/services/auth/session"
	"github.com/adammwaniki/wateja/services/gateway/internal/middleware"
)

// SetupAPIRoutes configures the HTTP routes with JWT authentication and session management
func SetupAPIRoutes(
	mux *http.ServeMux, 
	userHandler *UserHandler, 
	authHandler *AuthHandler,
	healthHandler *HealthHandler,
	authMiddleware *middleware.AuthMiddleware,
	sessionManager *session.SessionManager,
) {
	// API v1 subrouter - this handles requests AFTER /api/v1 is stripped
	apiV1Router := http.NewServeMux()

	// Wrapper for Google OAuth callback with session management
	googleCallbackWithSessions := func(w http.ResponseWriter, r *http.Request) {
		userHandler.HandleGoogleCallbackWithJWT(sessionManager, w, r)
	}

	// ================= PUBLIC ENDPOINTS =================
	// No authentication required - these paths are seen WITHOUT /api/v1
	apiV1Router.HandleFunc("POST /users/register", authHandler.HandleCreateUserWithJWT)
	apiV1Router.HandleFunc("POST /auth/login", authHandler.HandleLogin)
	apiV1Router.HandleFunc("POST /auth/refresh", authHandler.HandleRefresh)
	apiV1Router.HandleFunc("GET /auth/google/login", userHandler.HandleGoogleLogin)
	apiV1Router.HandleFunc("GET /auth/google/callback", googleCallbackWithSessions)
	
	// Health endpoints (public)
	apiV1Router.HandleFunc("GET /healthz", healthHandler.LivenessCheck)
	apiV1Router.HandleFunc("GET /readyz", healthHandler.ReadinessCheck)

	// ================= PROTECTED ENDPOINTS =================
	// Require authentication - wrapped with auth middleware individually
	
	// Auth & User Management
	apiV1Router.HandleFunc("GET /auth/profile", authMiddleware.RequireAuth(authHandler.HandleProfile))
	apiV1Router.HandleFunc("GET /auth/sessions", authMiddleware.RequireAuth(authHandler.HandleGetSessions))
	apiV1Router.HandleFunc("POST /auth/logout", authMiddleware.RequireAuth(authHandler.HandleLogout))
	apiV1Router.HandleFunc("GET /users/{id}", authMiddleware.RequireAuth(userHandler.HandleGetUserByID))
	apiV1Router.HandleFunc("GET /users", authMiddleware.RequireAuth(userHandler.HandleListUsers))
	apiV1Router.HandleFunc("PUT /users/{id}", authMiddleware.RequireAuth(userHandler.HandleUpdateUserByID))
	apiV1Router.HandleFunc("DELETE /users/{id}", authMiddleware.RequireAuth(userHandler.HandleDeleteUserByID))

	
	// Mount the API router at /api/v1/ with prefix stripping
	// The StripPrefix happens BEFORE routes are matched, so the apiV1Router sees clean paths
	mux.Handle("/api/v1/", http.StripPrefix("/api/v1", apiV1Router))
	
	// Redirect requests at /api/v1 to /api/v1/
	mux.HandleFunc("/api/v1", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/api/v1/", http.StatusPermanentRedirect)
	})

	// Gateway-level health for load balancers (public) - these see the full path
	mux.HandleFunc("/healthz", healthHandler.LivenessCheck)
	mux.HandleFunc("/readyz", healthHandler.ReadinessCheck)
}