# services/gateway/Dockerfile
# Builder stage
FROM golang:1.24-alpine AS builder
WORKDIR /app

# Copy module files first
COPY go.mod go.sum ./
RUN go mod download

# Copy rest of the code
COPY . .

# Build binary
RUN go build -o gateway-service cmd/main.go

# Final stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

# Copy binary from builder
COPY --from=builder /app/gateway-service .

# Expose HTTP port
EXPOSE 8080

# Use ENTRYPOINT so Docker Compose env variables are used
ENTRYPOINT ["./gateway-service"]
