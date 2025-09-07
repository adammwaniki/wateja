//services/common/utils/utils.go
package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"

	_ "github.com/joho/godotenv/autoload"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func WriteJSON(w http.ResponseWriter, status int , data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)

}

func ReadJSON(r *http.Request, data any) error {
	if r.Body == nil {
		return fmt.Errorf("missing request body")
	} 
	return json.NewDecoder(r.Body).Decode(data)
}

// Provide standard output for http error messages
func WriteError(w http.ResponseWriter, status int, errorMessage error) {
	WriteJSON(w, status, map[string]string{"error": errorMessage.Error()})
}

// WriteProtoJSON handles protobuf message serialization with error handling
func WriteProtoJSON(w http.ResponseWriter, status int, msg proto.Message) {
	// Configure protobuf JSON marshaler
	marshaler := protojson.MarshalOptions{
		UseProtoNames:     false,
		EmitUnpopulated:   true,
	}

	// Marshal to bytes first to catch errors before writing headers
	data, err := marshaler.Marshal(msg)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, 
			fmt.Errorf("failed to marshal protobuf response: %w", err))
		return
	}

	// Write successful response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(data)
}

// HandleGRPCError translates a gRPC error to an appropriate HTTP response.
func HandleGRPCError(w http.ResponseWriter, err error) {
	// Use status.FromError to correctly extract the gRPC status from the error chain.
	st, ok := status.FromError(err)
	if !ok {
		// If it's not a gRPC status error, treat as a generic internal server error.
		// Log the original error for debugging.
		fmt.Printf("Non-gRPC error received by gateway: %v\n", err)
		WriteError(w, http.StatusInternalServerError, errors.New("internal server error"))
		return
	}

	// Now 'st' contains the gRPC status, and we can switch on its code.
	switch st.Code() {
	case codes.InvalidArgument: // gRPC for bad input (e.g., validation failed)
		WriteError(w, http.StatusBadRequest, errors.New(st.Message()))
	case codes.NotFound: // gRPC for resource not found
		WriteError(w, http.StatusNotFound, errors.New(st.Message()))
	case codes.AlreadyExists: // gRPC for resource already existing (e.g., duplicate email/ID)
		WriteError(w, http.StatusConflict, errors.New(st.Message())) // Use 409 Conflict
	case codes.PermissionDenied: // gRPC for authorization issues
		WriteError(w, http.StatusForbidden, errors.New(st.Message()))
	case codes.Unauthenticated: // gRPC for authentication issues (e.g., missing/invalid token)
		WriteError(w, http.StatusUnauthorized, errors.New(st.Message()))
	case codes.Unavailable: // gRPC for temporary service unavailability
		WriteError(w, http.StatusServiceUnavailable, errors.New("service unavailable, please try again later"))
	default: // All other gRPC errors (e.g., Internal, Unknown, DataLoss)
		// Log the full gRPC error details on the server for debugging
		fmt.Printf("Unhandled gRPC error: code=%s, message=%s, details=%v\n", st.Code(), st.Message(), st.Details())
		WriteError(w, http.StatusInternalServerError, errors.New("internal server error"))
	}
}

// Making snowflake ID generation a utility
// Fetch and validate unique nodeID (must be 0–1023 for 10-bit Snowflake machineID compatibility)
// In the generators, the epoch starts from 2017-04-09T00:00:00Z
func GetSnowflakeNodeID() (uint64, error) {
	// Extract value and convert to uint64
	nodeID, err := strconv.Atoi(os.Getenv("NODE_ID"))
	unodeID := uint64(nodeID)
	if err != nil {
		return 0, err
	} else if unodeID > 1023 {
		return 0, fmt.Errorf("NODE_ID %d is out of valid range (0 - 1023)", unodeID)
	}
	return unodeID, nil
}