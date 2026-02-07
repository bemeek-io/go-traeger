package traeger

import (
	"errors"
	"fmt"
)

var (
	// ErrNotConnected is returned when an operation requires an active connection.
	ErrNotConnected = errors.New("traeger: client not connected")

	// ErrGrillNotFound is returned when a grill lookup fails.
	ErrGrillNotFound = errors.New("traeger: grill not found")

	// ErrAuthFailed is returned when Cognito authentication fails.
	ErrAuthFailed = errors.New("traeger: authentication failed")

	// ErrTimeout is returned when an operation exceeds its deadline.
	ErrTimeout = errors.New("traeger: operation timed out")
)

// APIError wraps a non-2xx HTTP response from the Traeger API.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("traeger: API error %d: %s", e.StatusCode, e.Body)
}
