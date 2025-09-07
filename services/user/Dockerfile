# services/user/Dockerfile
# Builder stage
FROM golang:1.24-alpine AS builder
WORKDIR /app

# Copy module files first to cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy rest of the code
COPY . .

# Build binary
RUN go build -o user-service cmd/main.go

# Final stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

# Copy binary from builder
COPY --from=builder /app/user-service .

# Expose gRPC ports
EXPOSE 2000

# Use ENTRYPOINT so Docker Compose env variables are used
ENTRYPOINT ["./user-service"]
