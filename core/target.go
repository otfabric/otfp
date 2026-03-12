package core

import (
	"fmt"
	"net"
	"time"
)

// Target represents a network endpoint to fingerprint.
type Target struct {
	// IP is the target IP address.
	IP string
	// Port is the target TCP port.
	Port int
	// Timeout is the maximum duration for the fingerprint operation.
	// If zero, a default timeout of 5 seconds is used.
	Timeout time.Duration
}

// DefaultTimeout is used when Target.Timeout is zero.
const DefaultTimeout = 5 * time.Second

// EffectiveTimeout returns the configured timeout or DefaultTimeout if zero.
func (t Target) EffectiveTimeout() time.Duration {
	if t.Timeout == 0 {
		return DefaultTimeout
	}
	return t.Timeout
}

// Addr returns the target address in "host:port" format.
func (t Target) Addr() string {
	return t.IP + ":" + itoa(t.Port)
}

// Validate checks that the target fields are well-formed.
// It returns an error describing the first invalid field found:
//   - IP must be a parseable IPv4 or IPv6 address
//   - Port must be in range [1, 65535]
//   - Timeout must not be negative
func (t Target) Validate() error {
	if net.ParseIP(t.IP) == nil {
		return fmt.Errorf("invalid IP address: %q", t.IP)
	}
	if t.Port < 1 || t.Port > 65535 {
		return fmt.Errorf("port out of range [1, 65535]: %d", t.Port)
	}
	if t.Timeout < 0 {
		return fmt.Errorf("negative timeout: %v", t.Timeout)
	}
	return nil
}

// itoa converts a non-negative integer to a string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
