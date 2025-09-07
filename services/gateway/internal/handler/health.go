//services/gateway/internal/handler/health.go
package handler

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/health/grpc_health_v1"
)

type HealthHandler struct {
	ready atomic.Bool
	userHealth grpc_health_v1.HealthClient
}

func NewHealthHandler(userHealth grpc_health_v1.HealthClient) *HealthHandler {
	h := &HealthHandler{
		userHealth: userHealth,
	}
	h.MarkReady() // Assuming service starts healthy
	return h
}

// LivenessCheck indicates whether the service itself is alive
func (h *HealthHandler) LivenessCheck(w http.ResponseWriter, r *http.Request) {
    if h.ready.Load() {
        w.WriteHeader(http.StatusNoContent) 
    } else {
        w.WriteHeader(http.StatusServiceUnavailable)
    }
}

// ReadinessCheck indicates whether the service is ready to receive traffic
// including checking its dependencies.
func (h *HealthHandler) ReadinessCheck(w http.ResponseWriter, r *http.Request) {
    // Check dependency health
    ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
    defer cancel()
    
    resp, err := h.userHealth.Check(ctx, &grpc_health_v1.HealthCheckRequest{
        Service: "user.UserService",
    })
    
    if err != nil || resp.Status != grpc_health_v1.HealthCheckResponse_SERVING {
        w.WriteHeader(http.StatusServiceUnavailable)
        w.Write([]byte(`{"status":"USER_SERVICE_UNHEALTHY"}`))
        return
    }

    if h.ready.Load() {
        w.WriteHeader(http.StatusNoContent)
    } else {
        w.WriteHeader(http.StatusServiceUnavailable)
        w.Write([]byte(`{"status":"NOT_READY"}`))
    }
}

// MarkReady sets the service as ready to serve traffic.
func (h *HealthHandler) MarkReady() {
    h.ready.Store(true)
}

// MarkNotReady sets the service as not ready (e.g. shutting down, DB down, etc.).
func (h *HealthHandler) MarkNotReady() {
    h.ready.Store(false)
}
