# Gateway Service

HTTP/REST API gateway that provides a unified interface to microservices with authentication, session management, and OAuth integration.

## Overview

The Gateway Service acts as the single entry point for all client applications, handling:

- **HTTP to gRPC Translation**: Converts REST requests to internal gRPC calls
- **Authentication & Authorization**: JWT-based authentication with session management
- **OAuth Integration**: Google OAuth2 flow with automatic user registration
- **Request Routing**: Intelligent routing to appropriate microservices
- **Error Handling**: Consistent error responses across all endpoints
- **Health Monitoring**: Service health aggregation and reporting

## Architecture

```text
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client Apps   │────│   Gateway       │────│  User Service   │
│ (Web/Mobile/API)│    │  (HTTP/REST)    │    │    (gRPC)       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                       ┌─────────────────┐
                       │ Auth & Session  │
                       │   Management    │
                       └─────────────────┘
                                │
                       ┌─────────────────┐
                       │    Database     │
                       │   (Sessions)    │
                       └─────────────────┘
```

## Features

### Authentication & Session Management

#### JWT Token System

- **Access Tokens**: Short-lived (15 minutes) for API access
- **Refresh Tokens**: Long-lived (7 days) for token renewal
- **Session Tracking**: Persistent sessions with device and location info
- **Multi-device Support**: Users can have multiple active sessions

#### OAuth2 Integration

- **Google OAuth**: Complete OAuth2 flow with user registration
- **CSRF Protection**: State parameter validation
- **Automatic Registration**: Creates users from OAuth provider data
- **Profile Mapping**: Maps OAuth profile to user attributes

#### Security Features

- **Token Blacklisting**: Immediate session invalidation
- **Session Management**: Track and revoke device sessions
- **IP Tracking**: Monitor access patterns
- **Secure Headers**: Proper authentication header handling

### API Gateway Capabilities

#### Request Processing

- **Content Negotiation**: JSON request/response handling
- **Validation**: Input validation before forwarding to services
- **Error Translation**: gRPC to HTTP status code mapping
- **Timeout Handling**: Configurable request timeouts

#### Routing & Load Balancing

- **Path-based Routing**: Intelligent request routing by path
- **Service Discovery**: Ready for service mesh integration
- **Health-aware Routing**: Route only to healthy service instances
- **Graceful Degradation**: Fallback mechanisms for service failures

### Middleware System

#### Authentication Middleware

- **Selective Protection**: Public and protected endpoint support
- **Token Validation**: JWT signature and claims verification
- **Session Verification**: Cross-reference with session database
- **Context Injection**: Add user context to downstream requests

#### Error Handling Features

- **Consistent Responses**: Standardized error response format
- **Status Code Mapping**: gRPC to HTTP status translation
- **Error Logging**: Structured error logging for debugging
- **Security**: No sensitive information leakage

## API Endpoints

### Public Endpoints (No Authentication Required)

#### User Registration & Authentication Endpoints

```http
POST /api/v1/users/register     # Register new user with auto-login
POST /api/v1/auth/login         # Password-based authentication
POST /api/v1/auth/refresh       # Refresh access tokens
```

#### OAuth2 Flow Endpoints

```http
GET  /api/v1/auth/google/login    # Initiate Google OAuth
GET  /api/v1/auth/google/callback # Google OAuth callback
```

#### Health & Monitoring Endpoints

```http
GET  /api/v1/healthz            # Service health check
GET  /api/v1/readyz             # Service readiness check
GET  /healthz                   # Gateway-level health
GET  /readyz                    # Gateway-level readiness
```

### Protected Endpoints (Authentication Required)

#### User Profile & Session Management Endpoints

```http
GET    /api/v1/auth/profile     # Get current user profile
GET    /api/v1/auth/sessions    # List active sessions
POST   /api/v1/auth/logout      # Logout current session
```

#### User Management Endpoints

```http
GET    /api/v1/users            # List users (paginated)
GET    /api/v1/users/{id}       # Get user by ID
PUT    /api/v1/users/{id}       # Update user
DELETE /api/v1/users/{id}       # Soft delete user
```

## Authentication Flow

### Password-based Authentication

```mermaid
sequenceDiagram
    participant C as Client
    participant G as Gateway
    participant U as User Service
    participant D as Database

    C->>G: POST /auth/login {email, password}
    G->>U: GetUserForAuth(email)
    U->>D: Query user by email
    D-->>U: User data + password hash
    U-->>G: AuthUserResponse
    G->>G: Verify password (Argon2id)
    G->>G: Generate JWT tokens
    G->>D: Create session record
    G-->>C: {user, tokens, session_id}
```

### OAuth2 Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant G as Gateway
    participant GOO as Google OAuth
    participant U as User Service

    C->>G: GET /auth/google/login
    G-->>C: Redirect to Google OAuth
    C->>GOO: OAuth authorization
    GOO-->>C: Redirect with auth code
    C->>G: GET /auth/google/callback?code=...
    G->>GOO: Exchange code for token
    GOO-->>G: Access token + user info
    G->>U: GetUserBySSOID or CreateUser
    U-->>G: User data
    G->>G: Generate JWT tokens + session
    G-->>C: {user, tokens, session_id}
```

## Session Management

### Session Lifecycle

#### Session Creation

- Generated UUID session ID
- Device fingerprinting (User-Agent, IP)
- Token binding (Access + Refresh token JTIs)
- Expiration tracking

#### Session Maintenance

- Token refresh updates session
- Last access timestamp tracking
- Device information updates
- Security monitoring

#### Session Termination

- Explicit logout invalidates session
- Token expiration cleanup
- Multi-session management
- Security-triggered revocation

### Session Database Schema

```sql
CREATE TABLE user_sessions (
    session_id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    access_token_id VARCHAR(36) NOT NULL UNIQUE,
    refresh_token_id VARCHAR(36) NOT NULL UNIQUE,
    user_agent TEXT,
    ip_address VARCHAR(45),
    created_at DATETIME(6) NOT NULL,
    last_accessed_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at DATETIME(6) NULL ON UPDATE CURRENT_TIMESTAMP(6)
);
```

## Configuration

### Environment Variables

#### Gateway Configuration (localhost, docker-ready is in the .env.example)

```bash
GATEWAY_HTTP_ADDR=localhost:8080      # HTTP server address
```

#### Service Discovery

```bash
USER_GRPC_ADDR=localhost:2000         # User service gRPC endpoint
# Your future services
FLEET_GRPC_ADDR=localhost:2002        # Fleet service gRPC endpoint 
STAFF_GRPC_ADDR=localhost:2003        # Staff service gRPC endpoint
```

#### JWT Configuration

```bash
JWT_SECRET=your-super-secure-secret-key-minimum-32-characters
JWT_ISSUER=wateja-gateway
```

#### OAuth2 Configuration

```bash
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URL=http://localhost:8080/api/v1/auth/google/callback
```

#### Database Configuration

```bash
SESSIONS_DB_DSN=user:password@tcp(localhost:3306)/wateja_sessions
```

### JWT Token Configuration

#### Default Settings

- Access Token TTL: 15 minutes
- Refresh Token TTL: 7 days
- Token Algorithm: HS256
- Audience: "wateja-app"

#### Customizable Parameters

```go
// Modify token lifetimes
jwtService.SetTokenTTL(15*time.Minute, 7*24*time.Hour)
```

### Security Configuration

#### Argon2id Parameters

```go
Memory: 64 * 1024,    // 64MB memory cost
Iterations: 3,        // Time cost
Parallelism: 4,       // Thread count
SaltLength: 16,       // Salt length in bytes
KeyLength: 32,        // Hash length in bytes
```

## Development

### Prerequisites

- Go 1.24.2+
- MySQL 8.0+ (for session storage)
- Access to User Service gRPC endpoint

### Setup

1. **Install dependencies**

```bash
go mod tidy
```

2. **Configure environment**

```bash
   cp cmd/.env.example cmd/.env
   # Edit cmd/.env with your configuration
```

3. **Set up session database**

```bash
   # Create sessions table (if using separate database from user) - replace 'user' with your mysql username
   mysql -u user -p -e "CREATE DATABASE IF NOT EXISTS wateja_sessions;"
   
   # Run migrations to create user_sessions table
   cd ../user && make migrate-up
```

### Running

**Development mode:**

```bash
make run
```

**Production mode:**

```bash
cd cmd
go build -o gateway-service
./gateway-service
```

### Available Commands

```bash
make run             # Run with hot reload
```

## Request/Response Examples

### User Registration with Auto-Login

**Request:**

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

**Response:**

```json
{
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "first_name": "John",
    "last_name": "Doe",
    "email": "john@example.com",
    "status": "ACTIVE",
    "terms_accepted_at": "2023-12-01T10:00:00Z",
    "created_at": "2023-12-01T10:00:00Z"
  },
  "token_data": {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
    "token_type": "Bearer",
    "expires_in": 900
  },
  "session_id": "123e4567-e89b-12d3-a456-426614174000",
  "message": "Registration successful"
}
```

### Password-based Login

**Request:**

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "securepassword123"
  }'
```

**Response:**

```json
{
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "first_name": "John",
    "last_name": "Doe",
    "email": "john@example.com",
    "status": "ACTIVE"
  },
  "token_data": {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
    "token_type": "Bearer",
    "expires_in": 900
  },
  "session_id": "456e7890-e89b-12d3-a456-426614174000",
  "message": "Login successful"
}
```

### Protected Endpoint Access

**Request:**

```bash
curl -X GET http://localhost:8080/api/v1/auth/profile \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

**Response:**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "first_name": "John",
  "last_name": "Doe",
  "email": "john@example.com",
  "status": "ACTIVE",
  "terms_accepted_at": "2023-12-01T10:00:00Z",
  "created_at": "2023-12-01T10:00:00Z",
  "updated_at": "2023-12-01T10:30:00Z"
}
```

### Session Management Example

**List Active Sessions:**

```bash
curl -X GET http://localhost:8080/api/v1/auth/sessions \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

**Response:**

```json
{
  "sessions": [
    {
      "session_id": "123e4567-e89b-12d3-a456-426614174000",
      "user_id": "550e8400-e29b-41d4-a716-446655440000",
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...",
      "ip_address": "192.168.1.100",
      "created_at": "2023-12-01T10:00:00Z",
      "last_accessed_at": "2023-12-01T10:30:00Z",
      "is_active": true
    }
  ],
  "count": 1
}
```

### Token Refresh

**Request:**

```bash
curl -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
  }'
```

**Response:**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

## Error Handling

### Standard Error Response Format

```json
{
  "error": "error message describing what went wrong"
}
```

### HTTP Status Code Mapping

The gateway translates gRPC status codes to appropriate HTTP status codes:

| gRPC Status | HTTP Status | Description |
|-------------|-------------|-------------|
| `OK` | `200` | Success |
| `INVALID_ARGUMENT` | `400` | Bad Request (validation errors) |
| `UNAUTHENTICATED` | `401` | Unauthorized (invalid/missing token) |
| `PERMISSION_DENIED` | `403` | Forbidden (insufficient permissions) |
| `NOT_FOUND` | `404` | Not Found (resource doesn't exist) |
| `ALREADY_EXISTS` | `409` | Conflict (duplicate resource) |
| `INTERNAL` | `500` | Internal Server Error |
| `UNAVAILABLE` | `503` | Service Unavailable |

### Example Error Responses

**Validation Error (400):**

```json
{
  "error": "validation failed: email: rfc 5322 invalid email address"
}
```

**Authentication Error (401):**

```json
{
  "error": "invalid token: token has expired"
}
```

**Authorization Error (403):**

```json
{
  "error": "SSO users cannot set passwords. Please manage your password through your identity provider."
}
```

**Not Found Error (404):**

```json
{
  "error": "user not found"
}
```

**Conflict Error (409):**

```json
{
  "error": "email is already in use"
}
```

## Middleware Architecture

### Authn Middleware

#### Public Path Handling

```go
skipPaths := map[string]bool{
    "/api/v1/users/register":        true,
    "/api/v1/auth/login":            true,
    "/api/v1/auth/refresh":          true,
    "/api/v1/auth/google/login":     true,
    "/api/v1/auth/google/callback":  true,
    "/api/v1/healthz":               true,
    "/api/v1/readyz":                true,
}
```

#### Token Validation Flow

1. Extract Bearer token from Authorization header
2. Validate JWT signature and claims
3. Verify token type (access vs refresh)
4. Check session database for token blacklisting
5. Add user context to request for downstream handlers

#### Session Validation

- Cross-reference token JTI with session database
- Verify session is active and not expired
- Update last access timestamp
- Provide session context to handlers

### Error Handling Middleware

#### gRPC to HTTP Translation

- Consistent error response format
- Appropriate HTTP status codes
- Security-conscious error messages
- Structured logging for debugging

#### Request/Response Logging

- Request correlation IDs
- Performance metrics
- Error tracking
- Security audit logging

## Health Checks

### Liveness Check (`/healthz`)

- Gateway service basic health
- Process responsiveness
- Memory/resource status

**Response:**

```http
HTTP/1.1 204 No Content
```

### Readiness Check (`/readyz`)

- Gateway service readiness
- Downstream service health
- Database connectivity
- External service availability

**Healthy Response:**

```http
HTTP/1.1 204 No Content
```

**Unhealthy Response:**

```http
HTTP/1.1 503 Service Unavailable
Content-Type: application/json

{
  "status": "USER_SERVICE_UNHEALTHY"
}
```

## Monitoring & Observability

### Structured Logging

#### Request Logging

```json
{
  "timestamp": "2023-12-01T10:00:00Z",
  "level": "INFO",
  "message": "HTTP request",
  "method": "POST",
  "path": "/api/v1/auth/login",
  "status": 200,
  "duration": "45ms",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "ip_address": "192.168.1.100"
}
```

#### Error Logging

```json
{
  "timestamp": "2023-12-01T10:05:00Z",
  "level": "ERROR",
  "message": "Authentication failed",
  "error": "invalid token: signature is invalid",
  "path": "/api/v1/auth/profile",
  "ip_address": "192.168.1.100"
}
```

### Metrics Integration

Ready for integration with monitoring systems:

#### HTTP Metrics

- Request duration histograms
- Request count by endpoint and status
- Error rate tracking
- Session creation/termination rates

#### gRPC Metrics

- Service call latencies
- Success/failure rates
- Circuit breaker status
- Connection pool metrics

#### Custom Metrics

- Active session count
- Token refresh rates
- OAuth conversion rates
- User registration patterns

## Security Considerations

### Authentication Security

#### Token Security

- Short access token lifetimes (15 minutes)
- Secure refresh token rotation
- Session-based token blacklisting
- Strong JWT signing keys (minimum 32 bytes)

#### Session Security

- Session binding to devices and IPs
- Configurable session timeouts
- Multi-device session management
- Suspicious activity detection

OAuth Security

- CSRF protection via state parameter
- Secure redirect URL validation
- Token exchange over HTTPS only
- Profile data validation

### API Security

#### Input Validation

- Comprehensive request validation
- SQL injection prevention
- XSS protection via JSON responses
- Request size limits

#### Rate Limiting (Ready for implementation)

- Per-user rate limiting
- Per-IP rate limiting
- Endpoint-specific limits
- Adaptive rate limiting

#### HTTPS/TLS

- TLS termination at load balancer
- HSTS headers for browsers
- Secure cookie settings
- Certificate management

## Performance Optimization

### Connection Management

#### HTTP Server

- Configurable timeouts
- Keep-alive connections
- Graceful shutdown
- Resource cleanup

#### gRPC Connections

- Connection pooling
- Load balancing
- Circuit breakers
- Retry policies

### Caching Strategy

#### Session Caching (Ready for Redis)

- Session data caching
- Token blacklist caching
- User profile caching
- TTL-based invalidation

#### Response Caching

- Static content caching
- API response caching
- ETags and conditional requests
- Cache invalidation strategies

## Deployment

### Production Configuration

#### Environment-specific Settings

```bash
# Production
GATEWAY_HTTP_ADDR=:8080
JWT_SECRET=<secure-randomly-generated-key>
SESSIONS_DB_DSN=<production-database-connection>

# TLS Configuration (if not terminated at load balancer)
TLS_CERT_PATH=/etc/ssl/certs/gateway.crt
TLS_KEY_PATH=/etc/ssl/private/gateway.key
```

#### Security Headers

```go
// Add security headers middleware
w.Header().Set("X-Content-Type-Options", "nosniff")
w.Header().Set("X-Frame-Options", "DENY")
w.Header().Set("X-XSS-Protection", "1; mode=block")
w.Header().Set("Strict-Transport-Security", "max-age=31536000")
```

### Docker Deployment

**Dockerfile:**

```dockerfile
docker build -t gateway-service:latest .

docker run --rm -p 8080:8080 --env-file cmd/.env gateway-service:latest
```

### Kubernetes Deployment

Start Kubernetes Cluster

```yaml
ilianza na kaselfie dabo tap
```

## Troubleshooting

### Common Issues

#### Authentication Failures

- Verify JWT secret configuration
- Check token expiration times
- Validate session database connectivity
- Review clock synchronization

#### Service Communication

- Verify gRPC service endpoints
- Check network connectivity
- Review service health status
- Validate service discovery configuration

#### Database Issues

- Check session database connectivity
- Verify schema migrations
- Review connection pool settings
- Monitor query performance

### Debug Mode

Enable debug logging for troubleshooting:

```bash
export LOG_LEVEL=debug
./gateway-service
```

### Health Check URLs

```bash
# Basic health check
curl http://localhost:8080/healthz

# Readiness with dependency checks
curl http://localhost:8080/readyz

# Service-specific health
curl http://localhost:8080/api/v1/healthz
```

---

For integration with the Gateway Service, refer to the API documentation and example requests above.
