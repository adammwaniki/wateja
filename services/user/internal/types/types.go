// services/user/internal/types/types.go
package types

import (
	"context"
	"errors"
	"time"

	"github.com/adammwaniki/wateja/services/user/proto/genproto"
	"github.com/gofrs/uuid/v5"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// Business logic interface
type UserService interface {
    CreateUser(ctx context.Context, user *genproto.RegistrationRequest) (*genproto.CreateUserResponse, error)
    GetUserByID(ctx context.Context, req *genproto.GetUserRequest) (*genproto.GetUserResponse, error)
    GetUserBySSOID(ctx context.Context, req *genproto.GetUserBySSOIDRequest) (*genproto.GetUserResponse, error)
	GetUserForAuth(ctx context.Context, req *genproto.GetUserForAuthRequest) (*genproto.AuthUserResponse, error)
	ListUsers(ctx context.Context, req *genproto.ListUsersRequest) (*genproto.ListUsersResponse, error)
	UpdateUser(ctx context.Context, req *genproto.UpdateUserRequest) (*genproto.UpdateUserResponse, error)
	DeleteUser(ctx context.Context, req *genproto.DeleteUserRequest) error
}

type UserStore interface {
    Create(
		ctx context.Context,
		internalID uint64,
		externalID uuid.UUID,
		firstName, lastName, email string,
		hashedPassword *string, // Pointer to string to allow nil (for SSO users)
		ssoID *string,          // Pointer to string to allow nil (for password users)
	) error
    GetByID(ctx context.Context, id uuid.UUID) (*genproto.GetUserResponse, error)
    GetUserBySSOID(ctx context.Context, ssoID string) (*genproto.GetUserResponse, error)
	GetUserForAuth(ctx context.Context, email string) (*genproto.AuthUserResponse, error)
	ListUsers(ctx context.Context, pageSize int32, pageToken string, statusFilter *genproto.UserStatusEnum, nameFilter string) ([]*genproto.GetUserResponse, string, error)
	Update(ctx context.Context, externalID uuid.UUID, updates UserUpdateFields, updateMask *fieldmaskpb.FieldMask) (*genproto.UpdateUserResponse, error)
	Delete(ctx context.Context, externalID uuid.UUID) error
}

// UserUpdateFields represents the fields that can be updated for a user
type UserUpdateFields struct {
	FirstName      *string
	LastName       *string
	Email          *string
	HashedPassword *string // For password updates
	SsoID          *string // For SSO ID updates
}
// gRPC handler interface
type UserServiceServer interface {
    genproto.UserServiceServer
}

// Error types
var (
	ErrUserNotFound     = errors.New("user not found")
	ErrDuplicateEntry   = errors.New("duplicate entry") // New custom error for duplicate entries
)

// Authentication user
type AuthUser struct {
    ID           string
    PasswordHash *string
    Status       genproto.UserStatusEnum
}
// User represents the internal data model for a user, typically used for database interactions.
// This struct would be used by the store implementation to map database rows to Go objects.
// For now we'll just stick to using the DTOs for ease and speed of implementation
type User struct {
	InternalID      int64
	ExternalID      uuid.UUID
	FirstName       string
	LastName        string
	Email           string
	Password        *string    // Pointer to string to allow NULL in DB
	SsoID           *string    // Pointer to string to allow NULL in DB
	Status          genproto.UserStatusEnum
	TermsAcceptedAt time.Time
	CreatedAt       time.Time
	UpdatedAt       *time.Time // Pointer to time.Time to allow NULL in DB
}