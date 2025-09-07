// services/user/api/handler.go
package api

import (
	"context"
	"errors"
	"log"

	"github.com/adammwaniki/wateja/services/user/internal/types"
	"github.com/adammwaniki/wateja/services/user/internal/validator"
	"github.com/adammwaniki/wateja/services/user/proto/genproto"
	"github.com/gofrs/uuid/v5"

	_ "github.com/joho/godotenv/autoload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// grpcHandler implements the genproto.UserServiceServer interface.
type grpcHandler struct{
    genproto.UnimplementedUserServiceServer // Embed for forward compatibility with new methods
    service types.UserService
    healthServer *health.Server
}

// NewGRPCHandler registers the gRPC User Service and Health Service with the given gRPC server.
func NewGRPCHandler(grpcServer *grpc.Server, service types.UserService) {
    handler := &grpcHandler{
        service:      service,
        healthServer: health.NewServer(), // Initialize gRPC health server
    }
    
    // Register the user service implementation with the gRPC server.
    genproto.RegisterUserServiceServer(grpcServer, handler)

    // Register gRPC health service and set initial serving status.
    grpc_health_v1.RegisterHealthServer(grpcServer, handler.healthServer)
    handler.healthServer.SetServingStatus(
        "user.UserService", // This service name should match the one queried by the gateway
        grpc_health_v1.HealthCheckResponse_SERVING,
    )
    log.Println("gRPC User and Health services registered.")
}

// CreateUser handles the gRPC request to create a new user.
func (h *grpcHandler) CreateUser(ctx context.Context, req *genproto.CreateUserRequest) (*genproto.CreateUserResponse, error) {
    log.Println("Handling CreateUser gRPC request.")
    // Validate request input using the validator package.
    if err := validator.ValidateAndNormalizeRegistrationInput(req.User); err != nil {
        log.Printf("CreateUser validation failed: %v", err)
        return nil, status.Error(codes.InvalidArgument, err.Error())
    }

    // Call the business logic layer to create the user.
    createdUser, err := h.service.CreateUser(ctx, req.User)
    if err != nil {
        // Log the exact error from the service layer, then return it directly.
        // The service layer is responsible for translating domain errors (e.g., ErrDuplicateEntry)
        // into appropriate gRPC status errors.
        log.Printf("CreateUser failed from service layer: %v", err)
        return nil, err // Return the gRPC status error directly as received from service
    }

    log.Println("CreateUser successful.")
    return createdUser, nil
}

// GetUserForAuth handles the gRPC request to get user authentication data
func (h *grpcHandler) GetUserForAuth(ctx context.Context, req *genproto.GetUserForAuthRequest) (*genproto.AuthUserResponse, error) {
    log.Printf("Handling GetUserForAuth gRPC request for email: %s", req.GetEmail())
    
    // Call the service layer to get the user for authentication
    user, err := h.service.GetUserForAuth(ctx, req)
    if err != nil {
        // If the error from the service layer is already a gRPC status error, return it directly
        if st, ok := status.FromError(err); ok {
            log.Printf("GetUserForAuth failed from service layer with gRPC status: %v", st.Code())
            return nil, st.Err()
        }
        // For any other unexpected errors from the service layer, log and return Internal
        log.Printf("GetUserForAuth failed from service layer with unexpected error: %v", err)
        return nil, status.Error(codes.Internal, "failed to get user for authentication")
    }
    
    log.Printf("GetUserForAuth successful for email: %s", req.GetEmail())
    return user, nil
}

// GetUserByID handles the gRPC request to retrieve a user by their external UUID.
func (h *grpcHandler) GetUserByID(ctx context.Context, req *genproto.GetUserRequest) (*genproto.GetUserResponse, error) {
    log.Printf("Handling GetUserByID gRPC request for ID : %s", uuid.FromStringOrNil(req.UserId))
    // Call the service layer to get the user by ID.
    user, err := h.service.GetUserByID(ctx, req)
    if err != nil {
        // Map common service errors (e.g., ErrNotFound) to gRPC status codes.
        if errors.Is(err, types.ErrUserNotFound) {
            log.Printf("GetUserByID: user not found for ID: %x", req.UserId)
            return nil, status.Error(codes.NotFound, "user not found")
        }
        // If the error from the service layer is already a gRPC status error, return it directly.
        if st, ok := status.FromError(err); ok {
            log.Printf("GetUserByID failed from service layer with gRPC status: %v", st.Code())
            return nil, st.Err() // Propagate the gRPC status error directly
        }
        // For any other unexpected errors from the service layer, log and return Internal.
        log.Printf("GetUserByID failed from service layer with unexpected error: %v", err)
        return nil, status.Error(codes.Internal, "failed to retrieve user")
    }
    log.Printf("GetUserByID successful for ID: %s", uuid.FromStringOrNil(req.UserId))
    return user, nil
}


// GetUserBySSOID handles the gRPC request to retrieve a user by their SSO ID.
func (h *grpcHandler) GetUserBySSOID(ctx context.Context, req *genproto.GetUserBySSOIDRequest) (*genproto.GetUserResponse, error) {
    log.Printf("Handling GetUserBySSOID gRPC request for SSO ID: %s", req.GetSsoId())
    // Validate SSO ID is not empty.
    if req.GetSsoId() == "" {
        log.Println("GetUserBySSOID: empty SSO ID provided.")
        return nil, status.Error(codes.InvalidArgument, "SSO ID cannot be empty")
    }

    // Call the service layer to get the user by SSO ID.
    user, err := h.service.GetUserBySSOID(ctx, req)
    if err != nil {
        // Map common service errors (e.g., ErrNotFound) to gRPC status codes.
        if errors.Is(err, types.ErrUserNotFound) {
            log.Printf("GetUserBySSOID: user not found for SSO ID: %s", req.GetSsoId())
            return nil, status.Error(codes.NotFound, "user not found")
        }
        // FIX: If the error from the service layer is already a gRPC status error, return it directly.
        if st, ok := status.FromError(err); ok {
            log.Printf("GetUserBySSOID failed from service layer with gRPC status: %v", st.Code())
            return nil, st.Err() // Propagate the gRPC status error directly
        }
        // For any other unexpected errors from the service layer, log and return Internal.
        log.Printf("GetUserBySSOID failed from service layer with unexpected error: %v", err)
        return nil, status.Error(codes.Internal, "failed to retrieve user by SSO ID")
    }
    log.Printf("GetUserBySSOID successful for SSO ID: %s", req.GetSsoId())
    return user, nil
}

func (h *grpcHandler) ListUsers(ctx context.Context, req *genproto.ListUsersRequest) (*genproto.ListUsersResponse, error) {
	log.Println("Handling ListUsers gRPC request.")

	// Validate page size limits
	if req.GetPageSize() > 100 {
		log.Printf("ListUsers: page size %d exceeds maximum of 100", req.GetPageSize())
		return nil, status.Error(codes.InvalidArgument, "page size cannot exceed 100")
	}

	// Call the service layer to list users
	resp, err := h.service.ListUsers(ctx, req)
	if err != nil {
		// If the error from the service layer is already a gRPC status error, return it directly
		if st, ok := status.FromError(err); ok {
			log.Printf("ListUsers failed from service layer with gRPC status: %v", st.Code())
			return nil, st.Err()
		}
		// For any other unexpected errors from the service layer, log and return Internal
		log.Printf("ListUsers failed from service layer with unexpected error: %v", err)
		return nil, status.Error(codes.Internal, "failed to list users")
	}

	log.Printf("ListUsers successful, returned %d users", len(resp.Users))
	return resp, nil
}

// UpdateUser implements the gRPC UpdateUser method
func (s *grpcHandler) UpdateUser(ctx context.Context, req *genproto.UpdateUserRequest) (*genproto.UpdateUserResponse, error) {
	return s.service.UpdateUser(ctx, req)
}

// DeleteUser implements the gRPC DeleteUser method
func (s *grpcHandler) DeleteUser(ctx context.Context, req *genproto.DeleteUserRequest) (*emptypb.Empty, error) {
	err := s.service.DeleteUser(ctx, req)
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}