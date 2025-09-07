// services/user/internal/store/store.go
package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/adammwaniki/wateja/services/user/internal/types"
	"github.com/adammwaniki/wateja/services/user/proto/genproto"
	"github.com/go-sql-driver/mysql"
	"github.com/gofrs/uuid/v5"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Contains storage logic pertaining to the coreUser

type store struct {
    db *sql.DB
}

// Returns a raw *sql.DB for use in migrations
func NewRawDB(cfg mysql.Config) (*sql.DB, error) {
	return sql.Open("mysql", cfg.FormatDSN())
}

func NewStore(dsn string) (*store, error) {
  	// Ensure conversion of DATETIME columns to Go's time.Time and local time zone
	//dsn += "?parseTime=true&loc=Local" // removed for docker testing
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}
  // TODO: Add db.SetMaxOpenConns, db.SetMaxIdleConns, db.SetConnMaxLifetime for production
	return &store{db: db}, nil
}

const (
	createUserQuery = `
    INSERT INTO users (
        internal_id, external_id, first_name, last_name, email, 
        password_hash, sso_id, status, terms_accepted_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
)

// Create inserts a new user into the database.
// It now accepts hashed password and SSO ID as *string, allowing for nil values.
func (s *store) Create(
    ctx context.Context, 
    internalID uint64, 
    externalID uuid.UUID, 
    firstName, lastName, email string,
    hashedPassword *string, // Can be nil for SSO users
    ssoID *string,          // Can be nil for password users
    ) error {
        tx, err := s.db.BeginTx(ctx, nil)
        if err != nil {
          return fmt.Errorf("beginning transaction: %w", err)
        }
        // Defer a rollback in case of error. If commit is successful, rollback is a no-op.
        defer func() {
          if rerr := tx.Rollback(); rerr != nil && !errors.Is(rerr, sql.ErrTxDone) {
            // Log the rollback error if it's not already done
            fmt.Printf("rollback failed: %v\n", rerr)
          }
        }()

        // Use sql.NullString to properly insert NULL values into the database
        // for optional fields like password and sso_id.
        var dbPassword sql.NullString
        if hashedPassword != nil {
          dbPassword = sql.NullString{String: *hashedPassword, Valid: true}
        }

        var dbSsoID sql.NullString
        if ssoID != nil {
          dbSsoID = sql.NullString{String: *ssoID, Valid: true}
        }

        now := time.Now()
        // User status should be ACTIVE as per service layer logic for new registrations.
        status := genproto.UserStatusEnum_ACTIVE.String()

        _, err = tx.ExecContext(ctx, createUserQuery,
          internalID,
          externalID.Bytes(), // Store UUID as BINARY(16)
          firstName,
          lastName,
          email,
          dbPassword, // Will be NULL if hashedPassword was nil
          dbSsoID,    // Will be NULL if ssoID was nil
          status,
          now, // terms_accepted_at
          now, // created_at
          now, // updated_at (can be NULL in DB for initial creation)
        )
        if err != nil {
          var mysqlErr *mysql.MySQLError
          if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 { // 1062 is duplicate entry error
            return types.ErrDuplicateEntry
          }
          return fmt.Errorf("inserting user data: %w", err)
        }

        // Commit the transaction if all operations were successful.
        if err = tx.Commit(); err != nil {
          return fmt.Errorf("committing transaction: %w", err)
        }

        return nil
}

const getUserByIDQuery = `
SELECT
  LOWER(
        CONCAT(
            HEX(SUBSTR(external_id, 1, 4)), '-',
            HEX(SUBSTR(external_id, 5, 2)), '-',
            HEX(SUBSTR(external_id, 7, 2)), '-',
            HEX(SUBSTR(external_id, 9, 2)), '-',
            HEX(SUBSTR(external_id, 11, 6))
        )
    ) AS external_id,
  users.first_name,
  users.last_name,
  users.email,
  users.status,
  users.terms_accepted_at,
  users.created_at,
  users.updated_at
FROM users
WHERE users.external_id = ?
LIMIT 1`

// GetByID retrieves a user by their external ID from the database
func (s *store) GetByID(ctx context.Context, externalID uuid.UUID) (*genproto.GetUserResponse, error) {
  var user genproto.GetUserResponse
  var (
    dbExternalID    string // For formatted UUID string
    dbFirstName     string
    dbLastName      string
    dbEmail         string // For the primary email
    statusStr       string
    termsAcceptedAt time.Time
    createdAt       time.Time
    updatedAt       sql.NullTime // Use sql.NullString for potentially nullable text fields
  )

  // Query the database rows
  err := s.db.QueryRowContext(ctx, getUserByIDQuery, externalID.Bytes()).Scan(
    &dbExternalID,
    &dbFirstName,
    &dbLastName,
    &dbEmail,
    &statusStr,
    &termsAcceptedAt,
    &createdAt,
    &updatedAt,
  )
  if err != nil {
      if errors.Is(err, sql.ErrNoRows) {
          return nil, sql.ErrNoRows // Propagate this specific error for service layer to handle
      }
      return nil, fmt.Errorf("querying user by external_id %s: %w", externalID.String(), err)
  }

  // Populate the GetUserResponse fields
  user.Id = dbExternalID
  user.FirstName = dbFirstName
	user.LastName = dbLastName
	user.Email = dbEmail

  // Convert status string to enum
  statusVal, ok := genproto.UserStatusEnum_value[statusStr]
  if !ok {
      return nil, fmt.Errorf("invalid status value found in DB: %s", statusStr)
  }
  user.Status = genproto.UserStatusEnum(statusVal)

  // Convert Go time.Time to Protobuf Timestamp
  user.TermsAcceptedAt = timestamppb.New(termsAcceptedAt)
  user.CreatedAt = timestamppb.New(createdAt)
	
	// Convert nullable updatedAt to protobuf timestamp
	if updatedAt.Valid {
		user.UpdatedAt = timestamppb.New(updatedAt.Time)
	}
	

  return &user, err
}


const getUserBySSOIDQuery = `
SELECT
  LOWER(
        CONCAT(
            HEX(SUBSTR(external_id, 1, 4)), '-',
            HEX(SUBSTR(external_id, 5, 2)), '-',
            HEX(SUBSTR(external_id, 7, 2)), '-',
            HEX(SUBSTR(external_id, 9, 2)), '-',
            HEX(SUBSTR(external_id, 11, 6))
        )
    ) AS external_id,
  first_name,
  last_name,
  email,
  status,
  terms_accepted_at,
  created_at,
  updated_at
FROM users
WHERE sso_id = ?
LIMIT 1`

// GetUserBySSOID retrieves a user by their SSO ID from the database.
func (s *store) GetUserBySSOID(ctx context.Context, ssoID string) (*genproto.GetUserResponse, error) {
	var user genproto.GetUserResponse
	var (
		dbExternalID    string
		dbFirstName     string
		dbLastName      string
		dbEmail         string
		statusStr       string
		termsAcceptedAt time.Time
		createdAt       time.Time
		updatedAt       sql.NullTime // Can be NULL in DB
	)

	// Query the database row using the sso_id.
	err := s.db.QueryRowContext(ctx, getUserBySSOIDQuery, ssoID).Scan(
		&dbExternalID,
		&dbFirstName,
		&dbLastName,
		&dbEmail,
		&statusStr,
		&termsAcceptedAt,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows // Propagate this specific error for service layer to handle
		}
		return nil, fmt.Errorf("querying user by sso_id %s: %w", ssoID, err)
	}

	// Populate the GetUserResponse fields.
	user.Id = dbExternalID
	user.FirstName = dbFirstName
	user.LastName = dbLastName
	user.Email = dbEmail

	// Convert status string from DB to enum.
	statusVal, ok := genproto.UserStatusEnum_value[statusStr]
	if !ok {
		return nil, fmt.Errorf("invalid status value found in DB: %s", statusStr)
	}
	user.Status = genproto.UserStatusEnum(statusVal)

	// Convert Go time.Time to Protobuf Timestamp.
	user.TermsAcceptedAt = timestamppb.New(termsAcceptedAt)
	user.CreatedAt = timestamppb.New(createdAt)

	// Convert nullable updatedAt to Protobuf Timestamp.
	if updatedAt.Valid {
		user.UpdatedAt = timestamppb.New(updatedAt.Time)
	}

	return &user, nil
}

const getUserForAuthQuery = `
SELECT
  LOWER(
        CONCAT(
            HEX(SUBSTR(external_id, 1, 4)), '-',
            HEX(SUBSTR(external_id, 5, 2)), '-',
            HEX(SUBSTR(external_id, 7, 2)), '-',
            HEX(SUBSTR(external_id, 9, 2)), '-',
            HEX(SUBSTR(external_id, 11, 6))
        )
    ) AS id,
  password_hash,
  status
FROM users
WHERE email = ?
LIMIT 1`

func (s *store) GetUserForAuth(ctx context.Context, email string) (*genproto.AuthUserResponse, error) {
    var resp genproto.AuthUserResponse
    var dbPasswordHash sql.NullString
    var statusStr string
    
    err := s.db.QueryRowContext(ctx, getUserForAuthQuery, email).Scan(
        &resp.Id,
        &dbPasswordHash,
        &statusStr,
    )
    
    if dbPasswordHash.Valid {
        resp.PasswordHash = dbPasswordHash.String
    }
    
    if err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            return nil, sql.ErrNoRows
        }
        return nil, fmt.Errorf("querying user by email %s: %w", email, err)
    }
    
    // Convert status string to enum
    statusVal, ok := genproto.UserStatusEnum_value[statusStr]
    if !ok {
        return nil, fmt.Errorf("invalid status value found in DB: %s", statusStr)
    }
    resp.Status = genproto.UserStatusEnum(statusVal)
    
    return &resp, nil
}

const listUsersQuery = `
SELECT
  LOWER(
        CONCAT(
            HEX(SUBSTR(external_id, 1, 4)), '-',
            HEX(SUBSTR(external_id, 5, 2)), '-',
            HEX(SUBSTR(external_id, 7, 2)), '-',
            HEX(SUBSTR(external_id, 9, 2)), '-',
            HEX(SUBSTR(external_id, 11, 6))
        )
    ) AS external_id,
  first_name,
  last_name,
  email,
  status,
  terms_accepted_at,
  created_at,
  updated_at
FROM users
WHERE (?='' OR status = ?)
  AND (?='' OR CONCAT(first_name, ' ', last_name) LIKE ?)
  AND (?='' OR created_at > ?)
ORDER BY created_at DESC
LIMIT ?`

// ListUsers retrieves a paginated list of users with optional filtering
func (s *store) ListUsers(ctx context.Context, pageSize int32, pageToken string, statusFilter *genproto.UserStatusEnum, nameFilter string) ([]*genproto.GetUserResponse, string, error) {
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 50 // Default page size with maximum limit
	}

	// Parse page token to get cursor timestamp
	var cursorTime time.Time
	if pageToken != "" {
		// Decode base64 page token to get timestamp
		decoded, err := base64.URLEncoding.DecodeString(pageToken)
		if err != nil {
			return nil, "", fmt.Errorf("invalid page token: %w", err)
		}
		if err := cursorTime.UnmarshalText(decoded); err != nil {
			return nil, "", fmt.Errorf("invalid page token format: %w", err)
		}
	}

	// Prepare filter parameters
	statusStr := ""
	if statusFilter != nil {
		statusStr = statusFilter.String()
	}

	namePattern := ""
	if nameFilter != "" {
		namePattern = "%" + nameFilter + "%"
	}

	cursorStr := ""
	if !cursorTime.IsZero() {
		cursorStr = cursorTime.Format(time.RFC3339Nano)
	}

	// Execute query with filters
	rows, err := s.db.QueryContext(ctx, listUsersQuery,
		statusStr, statusStr,           // Status filter (twice for WHERE condition)
		namePattern, namePattern,       // Name filter (twice for WHERE condition)
		cursorStr, cursorStr,           // Cursor time filter (twice for WHERE condition)
		pageSize+1,                     // Fetch one extra to determine if there are more pages
	)
	if err != nil {
		return nil, "", fmt.Errorf("querying users: %w", err)
	}
	defer rows.Close()

	var users []*genproto.GetUserResponse
	var lastCreatedAt time.Time

	for rows.Next() {
		var user genproto.GetUserResponse
		var (
			dbExternalID    string
			dbFirstName     string
			dbLastName      string
			dbEmail         string
			statusStr       string
			termsAcceptedAt time.Time
			createdAt       time.Time
			updatedAt       sql.NullTime
		)

		err := rows.Scan(
			&dbExternalID,
			&dbFirstName,
			&dbLastName,
			&dbEmail,
			&statusStr,
			&termsAcceptedAt,
			&createdAt,
			&updatedAt,
		)
		if err != nil {
			return nil, "", fmt.Errorf("scanning user row: %w", err)
		}

		// Convert status string to enum
		statusVal, ok := genproto.UserStatusEnum_value[statusStr]
		if !ok {
			return nil, "", fmt.Errorf("invalid status value found in DB: %s", statusStr)
		}

		// Populate user response
		user.Id = dbExternalID
		user.FirstName = dbFirstName
		user.LastName = dbLastName
		user.Email = dbEmail
		user.Status = genproto.UserStatusEnum(statusVal)
		user.TermsAcceptedAt = timestamppb.New(termsAcceptedAt)
		user.CreatedAt = timestamppb.New(createdAt)

		if updatedAt.Valid {
			user.UpdatedAt = timestamppb.New(updatedAt.Time)
		}

		users = append(users, &user)
		lastCreatedAt = createdAt
	}

	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("iterating user rows: %w", err)
	}

	// Determine next page token
	var nextPageToken string
	if int32(len(users)) > pageSize {
		// Remove the extra user we fetched
		users = users[:pageSize]
		// Create next page token from the last user's created_at timestamp
		tokenBytes, err := lastCreatedAt.MarshalText()
		if err != nil {
			return nil, "", fmt.Errorf("creating next page token: %w", err)
		}
		nextPageToken = base64.URLEncoding.EncodeToString(tokenBytes)
	}

	return users, nextPageToken, nil
}

const updateUserQuery = `
UPDATE users 
SET first_name = CASE WHEN ? THEN ? ELSE first_name END,
    last_name = CASE WHEN ? THEN ? ELSE last_name END,
    email = CASE WHEN ? THEN ? ELSE email END,
    password_hash = CASE WHEN ? THEN ? ELSE password_hash END,
    sso_id = CASE WHEN ? THEN ? ELSE sso_id END,
    updated_at = ?
WHERE external_id = ?`

const getUserForUpdateQuery = `
SELECT
  LOWER(
        CONCAT(
            HEX(SUBSTR(external_id, 1, 4)), '-',
            HEX(SUBSTR(external_id, 5, 2)), '-',
            HEX(SUBSTR(external_id, 7, 2)), '-',
            HEX(SUBSTR(external_id, 9, 2)), '-',
            HEX(SUBSTR(external_id, 11, 6))
        )
    ) AS external_id,
  first_name,
  last_name,
  email,
  status,
  terms_accepted_at,
  created_at,
  updated_at
FROM users
WHERE external_id = ?
LIMIT 1`

// Update modifies an existing user's information based on the provided field mask
func (s *store) Update(ctx context.Context, externalID uuid.UUID, updates types.UserUpdateFields, updateMask *fieldmaskpb.FieldMask) (*genproto.UpdateUserResponse, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() {
		if rerr := tx.Rollback(); rerr != nil && !errors.Is(rerr, sql.ErrTxDone) {
			fmt.Printf("rollback failed: %v\n", rerr)
		}
	}()

	now := time.Now()

	// Determine which fields to update based on the field mask or provided fields
	updateFirstName := false
	updateLastName := false
	updateEmail := false
	updatePassword := false
	updateSsoID := false

	if updateMask != nil {
		for _, path := range updateMask.Paths {
			switch path {
			case "first_name":
				updateFirstName = true
			case "last_name":
				updateLastName = true
			case "email":
				updateEmail = true
			case "password":
				updatePassword = true
			case "sso_id":
				updateSsoID = true
			}
		}
	} else {
		// If no field mask is provided, update all non-nil fields
		updateFirstName = updates.FirstName != nil
		updateLastName = updates.LastName != nil
		updateEmail = updates.Email != nil
		updatePassword = updates.HashedPassword != nil
		updateSsoID = updates.SsoID != nil
	}

	// Prepare values for conditional update
	var firstNameValue, lastNameValue, emailValue string
	var passwordValue, ssoIDValue sql.NullString

	if updateFirstName && updates.FirstName != nil {
		firstNameValue = *updates.FirstName
	}
	if updateLastName && updates.LastName != nil {
		lastNameValue = *updates.LastName
	}
	if updateEmail && updates.Email != nil {
		emailValue = *updates.Email
	}
	
	// Handle authentication method updates (simplified - no switching allowed)
	if updatePassword && updates.HashedPassword != nil {
		passwordValue = sql.NullString{String: *updates.HashedPassword, Valid: true}
	}
	
	if updateSsoID && updates.SsoID != nil {
		ssoIDValue = sql.NullString{String: *updates.SsoID, Valid: true}
	}

	// Execute the update query
	result, err := tx.ExecContext(ctx, updateUserQuery,
		updateFirstName, firstNameValue,
		updateLastName, lastNameValue,
		updateEmail, emailValue,
		updatePassword, passwordValue,
		updateSsoID, ssoIDValue,
		now, // updated_at
		externalID.Bytes(),
	)
	if err != nil {
		var mysqlErr *mysql.MySQLError
		if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 { // 1062 is duplicate entry error
			return nil, types.ErrDuplicateEntry
		}
		return nil, fmt.Errorf("updating user data: %w", err)
	}

	// Check if any rows were affected
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("checking affected rows: %w", err)
	}
	if rowsAffected == 0 {
		return nil, sql.ErrNoRows // User not found
	}

	// Fetch the updated user data
	var user genproto.UpdateUserResponse
	var (
		dbExternalID    string
		dbFirstName     string
		dbLastName      string
		dbEmail         string
		statusStr       string
		termsAcceptedAt time.Time
		createdAt       time.Time
		updatedAt       sql.NullTime
	)

	err = tx.QueryRowContext(ctx, getUserForUpdateQuery, externalID.Bytes()).Scan(
		&dbExternalID,
		&dbFirstName,
		&dbLastName,
		&dbEmail,
		&statusStr,
		&termsAcceptedAt,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("fetching updated user data: %w", err)
	}

	// Populate the UpdateUserResponse fields
	user.Id = dbExternalID
	user.FirstName = dbFirstName
	user.LastName = dbLastName
	user.Email = dbEmail

	// Convert status string to enum
	statusVal, ok := genproto.UserStatusEnum_value[statusStr]
	if !ok {
		return nil, fmt.Errorf("invalid status value found in DB: %s", statusStr)
	}
	user.Status = genproto.UserStatusEnum(statusVal)

	// Convert Go time.Time to Protobuf Timestamp
	user.TermsAcceptedAt = timestamppb.New(termsAcceptedAt)
	user.CreatedAt = timestamppb.New(createdAt)

	// Convert nullable updatedAt to protobuf timestamp
	if updatedAt.Valid {
		user.UpdatedAt = timestamppb.New(updatedAt.Time)
	}

	// Commit the transaction
	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing transaction: %w", err)
	}

	return &user, nil
}


const softDeleteUserQuery = `
UPDATE users 
SET status = 'CLOSED',
    updated_at = ?
WHERE external_id = ? AND status != 'CLOSED'`

// Delete performs a soft delete by setting the user status to CLOSED
func (s *store) Delete(ctx context.Context, externalID uuid.UUID) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() {
		if rerr := tx.Rollback(); rerr != nil && !errors.Is(rerr, sql.ErrTxDone) {
			fmt.Printf("rollback failed: %v\n", rerr)
		}
	}()

	now := time.Now()

	// Execute soft delete by updating status to CLOSED
	result, err := tx.ExecContext(ctx, softDeleteUserQuery, now, externalID.Bytes())
	if err != nil {
		return fmt.Errorf("soft deleting user: %w", err)
	}

	// Check if any rows were affected
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking affected rows: %w", err)
	}
	if rowsAffected == 0 {
		return sql.ErrNoRows // User not found or already deleted
	}

	// Commit the transaction
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}

	return nil
}