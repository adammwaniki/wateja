// services/gateway/cmd/main.go
package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/adammwaniki/wateja/services/auth/authn/jwt"
	"github.com/adammwaniki/wateja/services/auth/session"
	"github.com/adammwaniki/wateja/services/gateway/internal/handler"
	"github.com/adammwaniki/wateja/services/gateway/internal/middleware"
	userproto "github.com/adammwaniki/wateja/services/user/proto/genproto"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/joho/godotenv/autoload"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
)

var (
	userGRPCAddr    = os.Getenv("USER_GRPC_ADDR")
	vehicleGRPCAddr = os.Getenv("VEHICLE_GRPC_ADDR")
	staffGRPCAddr   = os.Getenv("STAFF_GRPC_ADDR")
	gatewayAddr     = os.Getenv("GATEWAY_HTTP_ADDR")

	// Google OAuth2 credentials
	googleClientID     = os.Getenv("GOOGLE_CLIENT_ID")
	googleClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
	googleRedirectURL  = os.Getenv("GOOGLE_REDIRECT_URL")

	// JWT configuration
	jwtSecret = os.Getenv("JWT_SECRET")
	jwtIssuer = os.Getenv("JWT_ISSUER")

    /*
    // In production for AWS, Azure, GCP, etc.
    jwtSecret, err := secretsManager.GetSecret("jwt-signing-key")
    if err != nil {
        log.Fatalf("Failed to retrieve JWT secret: %v", err)
    }
    */

	// Database configuration for sessions
	dbDSN = os.Getenv("SESSIONS_DB_DSN")
)

func main() {
	// Validate required environment variables
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is required")
	}
	if jwtIssuer == "" {
		jwtIssuer = "wateja-gateway" // Default issuer
	}
	if dbDSN == "" {
		dbDSN = os.Getenv("DB_DSN") // Fallback to user service DB
		if dbDSN == "" {
			log.Fatal("SESSIONS_DB_DSN or DB_DSN environment variable is required")
		}
	}

	// Initialize database connection for session management
	//db, err := sql.Open("mysql", dbDSN+"?parseTime=true&loc=Local") // Removed for docker testing
	db, err := sql.Open("mysql", dbDSN)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Test database connection
	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	// Initialize JWT service
	jwtService := jwt.NewJWTService(jwtSecret, jwtIssuer)
	jwtService.SetTokenTTL(15*time.Minute, 7*24*time.Hour) // 15 min access, 7 day refresh

	// Initialize session manager
	sessionManager := session.NewSessionManager(db, jwtService)

	// Start cleanup goroutine for expired sessions
	go func() {
		ticker := time.NewTicker(1 * time.Hour) // Clean up every hour
		defer ticker.Stop()
		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := sessionManager.CleanupExpiredSessions(ctx); err != nil {
				log.Printf("Failed to cleanup expired sessions: %v", err)
			}
			cancel()
		}
	}()

	// Create gRPC connection to User Service
	userConn, err := grpc.NewClient(
		userGRPCAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatal("Failed to dial user service: ", err)
	}
	defer userConn.Close()

	// Create gRPC connection to Vehicle Service
	vehicleConn, err := grpc.NewClient(
		vehicleGRPCAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatal("Failed to dial vehicle service: ", err)
	}
	defer vehicleConn.Close()

	// Create gRPC connection to Staff Service 
	staffConn, err := grpc.NewClient(
		staffGRPCAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatal("Failed to dial staff service: ", err)
	}
	defer staffConn.Close()

	// Create clients
	userClient := userproto.NewUserServiceClient(userConn)
	userHealth := grpc_health_v1.NewHealthClient(userConn)

	// Configure Google OAuth2
	googleOAuthConfig := &oauth2.Config{
		ClientID:     googleClientID,
		ClientSecret: googleClientSecret,
		RedirectURL:  googleRedirectURL,
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint:     google.Endpoint,
	}

	// Initialize handlers with session management
	healthHandler := handler.NewHealthHandler(userHealth)
	userHandler := handler.NewUserHandler(userClient, googleOAuthConfig)
	authHandler := handler.NewAuthHandler(userClient, sessionManager, jwtService)
	
	// Initialize authentication middleware with session support
	authMiddleware := middleware.NewAuthMiddleware(jwtService, sessionManager)

	// Configure server
	mux := http.NewServeMux()
	handler.SetupAPIRoutes(mux, userHandler, authHandler, healthHandler, authMiddleware, sessionManager)

	server := &http.Server{
		Addr:    gatewayAddr,
		Handler: mux,
	}

	// Graceful shutdown setup
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Start server
	go func() {
		log.Printf("Gateway server starting on %s", gatewayAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-done
	log.Println("Server shutting down...")

	healthHandler.MarkNotReady()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}
	log.Println("Server stopped")
}
