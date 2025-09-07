# Wateja

A production-ready microservices architecture for user management with authentication, session handling, and OAuth integration.

## Why Wateja?

Modern applications need robust user management that scales. Wateja provides:

- **Microservices Foundation**: Clean separation of concerns with machine-efficient gRPC communication
- **Enterprise Authentication**: JWT tokens with session management and OAuth2 (Google) integration
- **Security First**: Argon2id password hashing, secure session tracking, and token blacklisting
- **Developer Experience**: Comprehensive validation, structured error handling, and API documentation
- **Production Ready**: Database migrations, health checks, graceful shutdown, and observability hooks

## Architecture

Entity relationship diagram

```text
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Gateway       │────│   User Service  │────│     Database    │
│   (HTTP/REST)   │    │     (gRPC)      │    │     (MySQL)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │
         │              ┌─────────────────┐
         └──────────────│  Auth Service   │
                        │  (JWT/Session)  │
                        └─────────────────┘
```

### Core Services

- **Gateway Service**: HTTP/REST API gateway with routing, authentication middleware, and OAuth handling
- **User Service**: Core user management with gRPC interface, validation, and CRUD operations
- **Auth Service**: JWT token generation, session management, and password hashing
- **Common Service**: Shared utilities, error handling, and helper functions

## Features

### Authentication & Authorization

- **Multi-auth Support**: Password-based and Google OAuth2 authentication
- **JWT Tokens**: Short-lived access tokens (15min) with long-lived refresh tokens (7 days)
- **Session Management**: Persistent session tracking with device information and IP logging
- **Security**: Argon2id password hashing, token blacklisting, and session invalidation

### User Management

- **Full CRUD**: Create, read, update, delete users with validation
- **Dual Auth Methods**: Users can authenticate via password or SSO (not both)
- **Status Management**: Active, suspended, pending, and closed user states
- **Data Validation**: RFC 5322 email validation, name normalization(with multilingual support), and secure input handling

### API & Integration

- **RESTful Gateway**: Clean HTTP/REST interface with proper status codes
- **gRPC Backend**: High-performance internal service communication
- **Health Checks**: Liveness and readiness endpoints for orchestration
- **Error Handling**: Consistent error responses with proper HTTP status mapping

### Development & Operations

- **Database Migrations**: Version-controlled schema changes with rollback support
- **Environment Configuration**: Flexible configuration via environment variables
- **Testing Support**: Postman collection for comprehensive API testing
- **Graceful Shutdown**: Proper cleanup and connection handling

## Quick Start

### Prerequisites

- Go 1.24.2+
- MySQL 8.0+
- Protocol Buffers compiler (`protoc`)
- Air (for hot reload development)

### Setup

1. **Clone the repository**

```bash
    git clone <repository-url>
    cd wateja
```

2. **Install dependencies**

```bash
    # At the services root
    go work init

    # Per service directory
    go mod tidy
```

3. **Configure environment**

```bash
    # Copy and modify environment files
    cp services/user/cmd/.env.example services/user/cmd/.env
    cp services/gateway/cmd/.env.example services/gateway/cmd/.env
   
   # Update database credentials and other settings
```

4. **Setup database**

```bash
   # Create database
   cd services/user
   make createdb
   
   # Run migrations
   make migrate-up
```

5. **Generate protobuf files**

```bash
   cd services/user
   make gen
```

### Running the Services

#### Development Mode (with hot reload)

```bash
# Terminal 1: Start User Service
cd services/user
air init
make run

# Terminal 2: Start Gateway Service  
cd services/gateway
air init
make run
```

#### Production Mode

```bash
# Build and run User Service
cd services/user/cmd
go build -o user-service
./user

# Build and run Gateway Service
cd services/gateway/cmd
go build -o gateway-service
./gateway
```

### Verify Installation

```bash
# Check health
curl http://localhost:8080/healthz

# Test user registration
curl -X POST http://localhost:8080/api/v1/users/register \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "John",
    "last_name": "Doe", 
    "email": "john@example.com",
    "password": "securepassword123"
  }'
```

## API Documentation

### Authentication Endpoints

- `POST /api/v1/users/register` - Register new user with auto-login
- `POST /api/v1/auth/login` - Password-based authentication
- `POST /api/v1/auth/refresh` - Refresh access tokens
- `POST /api/v1/auth/logout` - Logout current session
- `GET /api/v1/auth/profile` - Get current user profile
- `GET /api/v1/auth/sessions` - List active sessions

### OAuth Endpoints

- `GET /api/v1/auth/google/login` - Initiate Google OAuth flow
- `GET /api/v1/auth/google/callback` - Google OAuth callback

### User Management Endpoints

- `GET /api/v1/users` - List users (paginated)
- `GET /api/v1/users/{id}` - Get user by ID
- `PUT /api/v1/users/{id}` - Update user
- `DELETE /api/v1/users/{id}` - Soft delete user

### Health & Monitoring Endpoints

- `GET /healthz` - Liveness check
- `GET /readyz` - Readiness check (includes dependency health)

## Testing

**Docker Compose:**

```yaml
docker compose up --build
```

then test endpoints with CURL

Or

Import the provided Postman collection for comprehensive API testing:

```bash
# Copy the collection from services/user/README.md
# Import into Postman and set environment variables:
# - base_url: http://localhost:8080/api/v1
```

## Configuration

### Environment Variables

#### User Service

```bash
USER_GRPC_ADDR=localhost:2000
DB_DSN=user:password@tcp(localhost:3306)/wateja_users
NODE_ID=24  # Unique ID for distributed systems (0-1023)
```

#### Gateway Service

```bash
GATEWAY_HTTP_ADDR=localhost:8080
USER_GRPC_ADDR=localhost:2000

# JWT Configuration
JWT_SECRET=your-super-secure-secret-key-minimum-32-characters
JWT_ISSUER=wateja-gateway

# Google OAuth2
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URL=http://localhost:8080/api/v1/auth/google/callback

# Session Database
SESSIONS_DB_DSN=user:password@tcp(localhost:3306)/wateja_sessions
```

## Database Schema

### Users Table

- **Identity**: Internal snowflake ID + external UUID
- **Profile**: First name, last name, email
- **Authentication**: Password hash (Argon2id) OR SSO ID
- **Status**: Enum for user state management
- **Timestamps**: Creation, updates, terms acceptance

### Sessions Table

- **Session Tracking**: Unique session IDs with token relationships
- **Device Info**: User agent and IP address logging
- **Security**: Token blacklisting and expiration handling
- **Audit**: Access patterns and session lifecycle

## Security Considerations

### Password Security

- **Argon2id Hashing**: Memory-hard function resistant to GPU attacks
- **Secure Parameters**: 64MB memory, 3 iterations, 4 threads
- **PHC Format**: Standard password hash string format

### Token Security

- **Short Access Tokens**: 15-minute expiration reduces exposure window
- **Secure Refresh**: 7-day refresh tokens with rotation
- **Session Binding**: Tokens tied to specific sessions for revocation
- **Blacklist Support**: Immediate token invalidation on logout

### API Security

- **Input Validation**: Comprehensive validation with sanitization
- **Error Handling**: No information leakage in error responses
- **Rate Limiting**: Ready for rate limiting middleware integration
- **HTTPS Ready**: TLS termination at load balancer level

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For questions and support:

- Open an issue on GitHub
- Review the API documentation
- Check the Postman collection for examples

---

**Wateja** - Building blocks for scalable user management
