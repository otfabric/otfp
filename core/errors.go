package core

import "fmt"

// DetectError wraps an error that occurred during protocol detection.
// Callers can inspect Protocol and Op for structured logging and metrics.
type DetectError struct {
	Protocol Protocol
	Op       string // short operation name, e.g. "dial", "send", "receive"
	Err      error
}

func (e *DetectError) Error() string {
	return fmt.Sprintf("%s %s: %v", e.Protocol, e.Op, e.Err)
}

func (e *DetectError) Unwrap() error { return e.Err }

// TimeoutError indicates a detection attempt exceeded its deadline.
type TimeoutError struct {
	Protocol Protocol
	Addr     string
	Err      error
}

func (e *TimeoutError) Error() string {
	return fmt.Sprintf("%s timeout connecting to %s: %v", e.Protocol, e.Addr, e.Err)
}

func (e *TimeoutError) Unwrap() error { return e.Err }

// ConnectionError indicates a transport-level failure (refused, unreachable, etc.).
type ConnectionError struct {
	Protocol Protocol
	Addr     string
	Err      error
}

func (e *ConnectionError) Error() string {
	return fmt.Sprintf("%s connection to %s failed: %v", e.Protocol, e.Addr, e.Err)
}

func (e *ConnectionError) Unwrap() error { return e.Err }

// InvalidResponseError indicates the target responded, but the response
// was malformed or did not conform to the expected protocol framing.
// Useful for distinguishing "wrong protocol" from "broken implementation".
type InvalidResponseError struct {
	Protocol Protocol
	Reason   string
}

func (e *InvalidResponseError) Error() string {
	return fmt.Sprintf("%s invalid response: %s", e.Protocol, e.Reason)
}
