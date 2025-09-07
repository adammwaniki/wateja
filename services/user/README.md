# User Service

Core user management microservice providing gRPC APIs for user registration, authentication, profile management, and CRUD operations.

## Architecture

The User Service follows clean architecture principles:

```text
┌─────────────────┐
│   gRPC Handler  │  ← API Layer (Protocol Buffers)
└─────────────────┘
         │
┌─────────────────┐
│  Service Layer  │  ← Business Logic & Validation  
└─────────────────┘
         │
┌─────────────────┐
│  Store Layer    │  ← Data Access & Persistence
└─────────────────┘
         │
┌─────────────────┐
│     MySQL       │  ← Database Storage
└─────────────────┘
```

## Features

### User Management

- **Dual Authentication**: Password-based and SSO (Google OAuth) authentication methods
- **Validation**: Comprehensive input validation with RFC 5322 email compliance
- **Security**: Argon2id password hashing with secure parameters
- **Data Integrity**: UUID external IDs for opacity with Snowflake internal IDs for scalability

### Business Logic

- **Status Management**: Active, suspended, pending, and closed user states
- **Authentication Switching Prevention**: Users cannot switch between password and SSO authentication
- **Name Normalization**: Automatic capitalization and formatting of user names
- **Soft Deletion**: Users are marked as closed rather than permanently deleted

### Data Model

- **External IDs**: UUID v4 for public-facing identifiers
- **Internal IDs**: Snowflake IDs for efficient database operations and ordering
- **Flexible Auth**: Support for both password and SSO authentication methods
- **Audit Trail**: Creation timestamps, update tracking, and terms acceptance

## API Reference

### User Registration

#### CreateUser

```protobuf
rpc CreateUser(CreateUserRequest) returns (CreateUserResponse);
```

Creates a new user with either password or SSO authentication.

**Request:**

```json
{
  "user": {
    "first_name": "John",
    "last_name": "Doe", 
    "email": "john@example.com",
    "password": "securepassword123"  // OR "sso_id": "google_user_id"
  }
}
```

**Response:**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "first_name": "John",
  "last_name": "Doe",
  "email": "john@example.com", 
  "status": "ACTIVE",
  "terms_accepted_at": "2023-01-01T12:00:00Z",
  "created_at": "2023-01-01T12:00:00Z"
}
```

### User Retrieval

#### GetUserByID

```protobuf
rpc GetUserByID(GetUserRequest) returns (GetUserResponse);
```

#### GetUserBySSOID

```protobuf
rpc GetUserBySSOID(GetUserBySSOIDRequest) returns (GetUserResponse);
```

#### GetUserForAuth (Internal)

```protobuf
rpc GetUserForAuth(GetUserForAuthRequest) returns (AuthUserResponse);
```

Returns minimal user data needed for authentication, including password hash.

### User Listing

#### ListUsers

```protobuf
rpc ListUsers(ListUsersRequest) returns (ListUsersResponse);
```

Supports pagination, status filtering, and name-based search.

**Request:**

```json
{
  "page_size": 50,
  "page_token": "base64_encoded_cursor",
  "status_filter": "ACTIVE",
  "name_filter": "john"
}
```

### User Updates

#### UpdateUser**

```protobuf
rpc UpdateUser(UpdateUserRequest) returns (UpdateUserResponse);
```

Supports partial updates with field masks. Includes business logic to prevent authentication method switching.

**Request:**

```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "user": {
    "first_name": "Jane",
    "last_name": "Smith"
  },
  "update_mask": ["first_name", "last_name"]
}
```

### User Deletion

#### DeleteUser

```protobuf
rpc DeleteUser(DeleteUserRequest) returns (google.protobuf.Empty);
```

Performs soft deletion by setting user status to `CLOSED`.

## Database Schema

### Users Table

```sql
CREATE TABLE users (
    internal_id BIGINT UNSIGNED PRIMARY KEY,           -- Snowflake ID
    external_id BINARY(16) UNIQUE NOT NULL,            -- UUID v4 bytes
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    email VARCHAR(320) NOT NULL UNIQUE,                -- RFC 5321 max length
    password_hash VARCHAR(255) BINARY NULL,            -- Argon2id hash
    sso_id VARCHAR(255) NULL,                          -- OAuth provider ID
    status ENUM('STATUS_UNSPECIFIED', 'ACTIVE', 'SUSPENDED', 'PENDING', 'CLOSED') 
           NOT NULL DEFAULT 'ACTIVE',
    terms_accepted_at DATETIME NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(6)
);
```

### Key Constraints

- **Email Uniqueness**: Prevents duplicate registrations
- **Authentication Method**: Either `password_hash` OR `sso_id` must be set (enforced in business logic)
- **UUID Storage**: External IDs stored as `BINARY(16)` for efficiency
- **Status Management**: Enum ensures valid user states

## Validation Rules

### Email Validation

- RFC 5322 compliance using Go's `net/mail` package
- No display names allowed
- Case-insensitive uniqueness
- Maximum 320 characters (RFC 5321)

### Name Validation

- 1-30 characters per field
- Letters, marks, spaces, hyphens, apostrophes, periods, commas allowed
- Automatic capitalization (John, Mary-Jane, O'Connor)
- Unicode support for international names

### Password Requirements

- Minimum 8 characters
- Maximum 128 characters
- No character composition requirements (relies on length and hashing)
- Hashed with Argon2id (64MB memory, 3 iterations, 4 threads)

### SSO ID Validation

- Maximum 256 characters
- Non-empty after trimming
- Provider-specific format validation can be added

## Development

### Prerequisites

- Go 1.24.2+
- MySQL 8.0+
- Protocol Buffers compiler
- Air for hot reloading

### Setup

1. **Install dependencies**

```bash
go mod tidy
```

2. **Generate protobuf files**

```bash
make gen
```

3. **Set up environment**

```bash
cp cmd/.env.example cmd/.env
# Edit cmd/.env with your database credentials
```

4. **Create database**

```bash
make createdb
```

5. **Run migrations**

```bash
make migrate-up
```

### Running

**Development mode:**

```bash
make run
```

**Production mode:**

```bash
cd cmd
go build -o user-service
./user-service
```

### Available Commands

```bash
# Generate protobuf files
make gen

# Clean generated files
make clean

# Database operations
make createdb         # Create database
make dropdb           # Drop database (with confirmation)
make migration name   # Create new migration
make migrate-up       # Apply migrations
make migrate-down     # Rollback migrations

# Development
make run             # Run with hot reload
```

## Testing

### Postman Collection

Import the comprehensive Postman collection included in this README:

1. Copy the JSON collection from the main README
2. Import into Postman
3. Set environment variables:
   - `base_url`: `http://localhost:8080/api/v1`
   - Other variables are set automatically by tests

### Test Scenarios

The collection includes:

- **Health Checks**: Gateway and service health verification
- **User Registration**: Both password and SSO user creation
- **Authentication**: Login, token refresh, profile access
- **CRUD Operations**: Full user lifecycle management
- **Session Management**: Multi-device session tracking
- **Error Handling**: Various validation and business logic scenarios

### Manual Testing

**Register a user:**

```bash
curl -X POST http://localhost:8080/api/v1/users/register \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "John",
    "last_name": "Doe",
    "email": "john@example.com", 
    "password": "securepassword123"
  }'
```

**Get user profile:**

```bash
# After registration, use the returned access token
curl -X GET http://localhost:8080/api/v1/auth/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Configuration

### Environment Variables

```bash
# Service Configuration
USER_GRPC_ADDR=localhost:2000          # gRPC server address
NODE_ID=24                             # Snowflake node ID (0-1023)

# Database Configuration  
DB_DSN=user:password@tcp(localhost:3306)/wateja_users
DB_USER=user                          # For migrations
DB_PASSWORD=password                  # For migrations  
DB_HOST=localhost                     # For migrations
DB_PORT=3306                          # For migrations
DB_NAME=wateja_users                  # For migrations
```

### Database Connection

The service supports MySQL with the following DSN format:

```text
username:password@tcp(host:port)/database?parseTime=true&loc=Local
```

Connection pooling and timeout settings should be configured based on your deployment environment.

## Error Handling

### gRPC Status Codes

The service returns appropriate gRPC status codes:

- `INVALID_ARGUMENT`: Validation failures, malformed requests
- `ALREADY_EXISTS`: Duplicate email or other unique constraint violations
- `NOT_FOUND`: User does not exist
- `PERMISSION_DENIED`: Authentication method switching attempts
- `INTERNAL`: Database errors, unexpected failures

### Error Messages

Error messages are designed to be:

- **User-friendly**: Clear indication of what went wrong
- **Secure**: No sensitive information leakage
- **Actionable**: Guidance on how to fix the issue

Example validation error:

```json
{
  "error": "validation failed: first_name: must have at least one non-space character"
}
```

## Monitoring & Health

### Health Checks

The service provides gRPC health check support:

```bash
# Check if service is serving
grpc_health_probe -addr=localhost:2000 -service=user.UserService
```

### Metrics & Observability

Ready for integration with:

- **Prometheus**: Metrics collection
- **Jaeger/Zipkin**: Distributed tracing  
- **Structured Logging**: JSON log format with correlation IDs
- **Database Monitoring**: Connection pool metrics, query performance

### Performance Considerations

- **Database Indexing**: Optimized indexes on email, external_id, and status
- **Connection Pooling**: Configurable database connection limits
- **UUID Storage**: Binary storage for 50% space savings vs string storage
- **Pagination**: Cursor-based pagination for consistent results

## Security

### Authentication Data Protection

- **Password Hashing**: Argon2id with memory-hard parameters
- **SSO Integration**: Secure token exchange with identity providers
- **No Plaintext Storage**: Passwords never stored in plaintext

### Access Control

- **Service-to-Service**: gRPC mutual TLS recommended for production
- **Authentication Method Immutability**: Prevents privilege escalation
- **Soft Deletion**: Maintains audit trail while protecting user privacy

### Data Privacy

- **GDPR Compliance**: Structure ready for data export and deletion requests
- **Data Minimization**: Only collects necessary user information
- **Audit Logging**: Tracks data access and modifications

## Deployment

### Production Considerations

1. **Database**: Use managed MySQL service with automated backups
2. **Secrets**: Store JWT secrets and database credentials in secret management system
3. **Monitoring**: Set up health checks, metrics, and alerting
4. **Scaling**: Service is stateless and horizontally scalable
5. **Security**: Enable TLS for all communication, use network policies

### Docker Support

```dockerfile
docker build -t user-service:latest .

docker run --rm -p 2000:2000 --env-file cmd/.env user-service:latest
```

---

For questions specific to the User Service, refer to the [main project documentation](../../README.md) or open an issue.

## How To Test API Using Postman Collection

Copy and import the following json script into your Postman collections and then run.

The variables you'll need in your postman environment can be found at the end of this json script.

```json
{
  "info": {
    "_postman_id": "Wateja User Service API",
    "name": "Wateja User Service API Testing",
    "description": "Enhanced testing collection for user registration, authentication, profile management, and sessions",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {
      "name": "Health & Setup",
      "item": [
        {
          "name": "Gateway Health Check",
          "request": {
            "method": "GET",
            "header": [],
            "url": {
              "raw": "{{base_url}}/healthz",
              "host": ["{{base_url}}"],
              "path": ["healthz"]
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "pm.test('Gateway health check successful', function() {",
                  "    pm.response.to.have.status(204);",
                  "});"
                ],
                "type": "text/javascript"
              }
            }
          ]
        }
      ]
    },
    {
      "name": "User Registration & Authentication",
      "item": [
        {
          "name": "Register New User",
          "request": {
            "method": "POST",
            "header": [
              { "key": "Content-Type", "value": "application/json" }
            ],
            "body": {
              "mode": "raw",
              "raw": "{\n  \"first_name\": \"John\",\n  \"last_name\": \"Doe\",\n  \"email\": \"john.doe@example.com\",\n  \"password\": \"securepassword123\"\n}"
            },
            "url": {
              "raw": "{{base_url}}/users/register",
              "host": ["{{base_url}}"],
              "path": ["users", "register"]
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "pm.test('Registration successful', function() {",
                  "    pm.response.to.have.status(201);",
                  "    const response = pm.response.json();",
                  "    pm.expect(response).to.have.property('user');",
                  "    pm.expect(response).to.have.property('token_data');",
                  "    pm.expect(response).to.have.property('session_id');",
                  "    ",
                  "    pm.environment.set('access_token', response.token_data.access_token);",
                  "    pm.environment.set('refresh_token', response.token_data.refresh_token);",
                  "    pm.environment.set('session_id', response.session_id);",
                  "    pm.environment.set('user_id', response.user.id);",
                  "    pm.environment.set('user_email', response.user.email);",
                  "});"
                ],
                "type": "text/javascript"
              }
            }
          ]
        },
        {
          "name": "Login with Password",
          "request": {
            "method": "POST",
            "header": [
              { "key": "Content-Type", "value": "application/json" }
            ],
            "body": {
              "mode": "raw",
              "raw": "{\n  \"email\": \"{{user_email}}\",\n  \"password\": \"securepassword123\"\n}"
            },
            "url": {
              "raw": "{{base_url}}/auth/login",
              "host": ["{{base_url}}"],
              "path": ["auth", "login"]
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "pm.test('Login successful', function() {",
                  "    pm.response.to.have.status(200);",
                  "    const response = pm.response.json();",
                  "    pm.expect(response).to.have.property('user');",
                  "    pm.expect(response).to.have.property('token_data');",
                  "    pm.expect(response).to.have.property('session_id');",
                  "    ",
                  "    pm.environment.set('access_token', response.token_data.access_token);",
                  "    pm.environment.set('refresh_token', response.token_data.refresh_token);",
                  "    pm.environment.set('session_id', response.session_id);",
                  "});"
                ],
                "type": "text/javascript"
              }
            }
          ]
        },
        {
          "name": "Refresh Token",
          "request": {
            "method": "POST",
            "header": [
              { "key": "Content-Type", "value": "application/json" }
            ],
            "body": {
              "mode": "raw",
              "raw": "{\n  \"refresh_token\": \"{{refresh_token}}\"\n}"
            },
            "url": {
              "raw": "{{base_url}}/auth/refresh",
              "host": ["{{base_url}}"],
              "path": ["auth", "refresh"]
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "pm.test('Token refreshed successfully', function() {",
                  "    pm.response.to.have.status(200);",
                  "    const response = pm.response.json();",
                  "    pm.expect(response).to.have.property('access_token');",
                  "    pm.expect(response).to.have.property('refresh_token');",
                  "    pm.environment.set('access_token', response.access_token);",
                  "    pm.environment.set('refresh_token', response.refresh_token);",
                  "});"
                ],
                "type": "text/javascript"
              }
            }
          ]
        }
      ]
    },
    {
      "name": "Protected User Operations",
      "item": [
        {
          "name": "Get User Profile",
          "request": {
            "method": "GET",
            "header": [
              { "key": "Authorization", "value": "Bearer {{access_token}}" }
            ],
            "url": {
              "raw": "{{base_url}}/auth/profile",
              "host": ["{{base_url}}"],
              "path": ["auth", "profile"]
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "pm.test('Profile retrieved successfully', function() {",
                  "    pm.response.to.have.status(200);",
                  "    const response = pm.response.json();",
                  "    pm.expect(response).to.have.property('id');",
                  "    pm.expect(response.id).to.equal(pm.environment.get('user_id'));",
                  "});"
                ],
                "type": "text/javascript"
              }
            }
          ]
        },
        {
          "name": "Get User by ID",
          "request": {
            "method": "GET",
            "header": [
              { "key": "Authorization", "value": "Bearer {{access_token}}" }
            ],
            "url": {
              "raw": "{{base_url}}/users/{{user_id}}",
              "host": ["{{base_url}}"],
              "path": ["users", "{{user_id}}"]
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "pm.test('User retrieved successfully', function() {",
                  "    pm.response.to.have.status(200);",
                  "    const response = pm.response.json();",
                  "    pm.expect(response).to.have.property('id');",
                  "    pm.expect(response.id).to.equal(pm.environment.get('user_id'));",
                  "});"
                ],
                "type": "text/javascript"
              }
            }
          ]
        },
        {
          "name": "Update User Profile",
          "request": {
            "method": "PUT",
            "header": [
              { "key": "Authorization", "value": "Bearer {{access_token}}" },
              { "key": "Content-Type", "value": "application/json" }
            ],
            "body": {
              "mode": "raw",
              "raw": "{\n  \"user\": {\n    \"first_name\": \"Jane\",\n    \"last_name\": \"Smith\"\n  },\n  \"update_mask\": [\"first_name\", \"last_name\"]\n}"
            },
            "url": {
              "raw": "{{base_url}}/users/{{user_id}}",
              "host": ["{{base_url}}"],
              "path": ["users", "{{user_id}}"]
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "pm.test('User updated successfully', function() {",
                  "    pm.response.to.have.status(200);",
                  "    const response = pm.response.json();",
                  "    pm.expect(response.first_name).to.equal('Jane');",
                  "    pm.expect(response.last_name).to.equal('Smith');",
                  "});"
                ],
                "type": "text/javascript"
              }
            }
          ]
        },
        {
          "name": "List Users",
          "request": {
            "method": "GET",
            "header": [
              { "key": "Authorization", "value": "Bearer {{access_token}}" }
            ],
            "url": {
              "raw": "{{base_url}}/users?page_size=10",
              "host": ["{{base_url}}"],
              "path": ["users"],
              "query": [
                { "key": "page_size", "value": "10" }
              ]
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "pm.test('Users listed successfully', function() {",
                  "    pm.response.to.have.status(200);",
                  "    const response = pm.response.json();",
                  "    pm.expect(response).to.have.property('users');",
                  "    pm.expect(response.users).to.be.an('array');",
                  "});"
                ],
                "type": "text/javascript"
              }
            }
          ]
        },
        {
          "name": "Delete User",
          "request": {
            "method": "DELETE",
            "header": [
              { "key": "Authorization", "value": "Bearer {{access_token}}" }
            ],
            "url": {
              "raw": "{{base_url}}/users/{{user_id}}",
              "host": ["{{base_url}}"],
              "path": ["users", "{{user_id}}"]
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "pm.test('User deletion returns expected response', function() {",
                  "    pm.expect([204, 401]).to.include(pm.response.code);",
                  "});"
                ],
                "type": "text/javascript"
              }
            }
          ]
        }
      ]
    },
    {
      "name": "Session Management",
      "item": [
        {
          "name": "Get Active Sessions",
          "request": {
            "method": "GET",
            "header": [
              { "key": "Authorization", "value": "Bearer {{access_token}}" }
            ],
            "url": {
              "raw": "{{base_url}}/auth/sessions",
              "host": ["{{base_url}}"],
              "path": ["auth", "sessions"]
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "pm.test('Sessions retrieved successfully', function() {",
                  "    pm.response.to.have.status(200);",
                  "    const response = pm.response.json();",
                  "    pm.expect(response).to.have.property('sessions');",
                  "    pm.expect(response).to.have.property('count');",
                  "});"
                ],
                "type": "text/javascript"
              }
            }
          ]
        },
        {
          "name": "Logout Current Session",
          "request": {
            "method": "POST",
            "header": [
              { "key": "Authorization", "value": "Bearer {{access_token}}" },
              { "key": "Content-Type", "value": "application/json" }
            ],
            "body": {
              "mode": "raw",
              "raw": "{\n  \"refresh_token\": \"{{refresh_token}}\"\n}"
            },
            "url": {
              "raw": "{{base_url}}/auth/logout",
              "host": ["{{base_url}}"],
              "path": ["auth", "logout"]
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "pm.test('Logout successful', function() {",
                  "    pm.response.to.have.status(200);",
                  "});"
                ],
                "type": "text/javascript"
              }
            }
          ]
        },
        {
          "name": "Verify Access After Logout",
          "request": {
            "method": "GET",
            "header": [
              { "key": "Authorization", "value": "Bearer {{access_token}}" }
            ],
            "url": {
              "raw": "{{base_url}}/auth/profile",
              "host": ["{{base_url}}"],
              "path": ["auth", "profile"]
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "pm.test('Access denied after logout', function() {",
                  "    pm.response.to.have.status(401);",
                  "});"
                ],
                "type": "text/javascript"
              }
            }
          ]
        }
      ]
    }
  ],
  "variable": [
    { "key": "base_url", "value": "http://localhost:8080/api/v1" },
    { "key": "access_token", "value": "" },
    { "key": "refresh_token", "value": "" },
    { "key": "session_id", "value": "" },
    { "key": "user_id", "value": "" },
    { "key": "user_email", "value": "" }
  ]
}
```
