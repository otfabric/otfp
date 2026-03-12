package core

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// Confidence represents a detection certainty score between 0.0 and 1.0.
// Using a named type prevents accidental misuse and makes domain logic
// explicit.
type Confidence float64

// Valid reports whether c is within the allowed range [0.0, 1.0].
func (c Confidence) Valid() bool {
	return c >= 0.0 && c <= 1.0
}

// IsHigh reports whether c meets or exceeds the given threshold.
func (c Confidence) IsHigh(threshold float64) bool {
	return float64(c) >= threshold
}

// Fingerprint holds structured identification data from a detection.
// It provides machine-readable fields suitable for SIEM integration,
// asset fingerprint databases, and security product embedding.
type Fingerprint struct {
	// ID is a dot-separated identifier, e.g. "modbus.fc43".
	ID string `json:"id"`

	// Signature is a compact machine-parseable string of key observations.
	Signature string `json:"signature"`

	// Metadata holds protocol-specific key-value pairs.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// String returns a compact representation of the fingerprint.
func (f *Fingerprint) String() string {
	if f == nil {
		return ""
	}
	return f.ID + ":" + f.Signature
}

// Exchange records the raw bytes of a single probe/response round-trip.
// Populated when debug tracing is desired; nil otherwise.
type Exchange struct {
	// Label describes this exchange phase (e.g. "phase1", "probe").
	Label string `json:"label"`
	// Probe is the raw bytes sent to the target.
	Probe []byte `json:"probe"`
	// Response is the raw bytes received from the target.
	Response []byte `json:"response"`
}

// Result holds the outcome of a fingerprint detection attempt.
//
// Detection semantics:
//
//	Scenario            Matched   Error             Confidence
//	Positive match      true      nil               > 0
//	No match            false     nil               0
//	Timeout             false     *TimeoutError      0
//	Connection refused  false     *ConnectionError   0
//	Invalid response    false     *InvalidRespError  0
type Result struct {
	// Protocol identifies the protocol this result relates to.
	Protocol Protocol

	// Matched is true if the protocol was positively identified.
	Matched bool

	// Confidence is a score between 0.0 and 1.0 indicating detection certainty.
	Confidence Confidence

	// Details provides additional human-readable information about the detection.
	Details string

	// Error records the underlying error when detection fails.
	// A non-nil Error with Matched==false allows callers to distinguish
	// "no match" from "could not reach host".
	Error error

	// Fingerprint holds structured identification data.
	// Nil when no fingerprint is available.
	Fingerprint *Fingerprint

	// DetectionID is a unique identifier for this detection attempt,
	// useful for correlating log entries and audit trails.
	DetectionID string

	// Timestamp records when this result was created.
	Timestamp time.Time

	// Exchanges records raw probe/response byte pairs for debug tracing.
	// Nil when tracing is not enabled.
	Exchanges []Exchange `json:"exchanges,omitempty"`
}

// String returns a human-readable summary of the result.
func (r Result) String() string {
	if !r.Matched {
		if r.Error != nil {
			return fmt.Sprintf("Protocol: %s, Matched: false, Error: %v", r.Protocol, r.Error)
		}
		return fmt.Sprintf("Protocol: %s, Matched: false", r.Protocol)
	}
	return fmt.Sprintf("Protocol: %s, Matched: true, Confidence: %.2f, Details: %s",
		r.Protocol, r.Confidence, r.Details)
}

// WithFingerprint returns a copy of r with the given fingerprint set.
func (r Result) WithFingerprint(fp *Fingerprint) Result {
	r.Fingerprint = fp
	return r
}

// WithExchange appends a probe/response exchange to the result for debug tracing.
func (r Result) WithExchange(label string, probe, response []byte) Result {
	r.Exchanges = append(r.Exchanges, Exchange{
		Label:    label,
		Probe:    probe,
		Response: response,
	})
	return r
}

func generateDetectionID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// NoMatch returns a Result indicating no protocol was detected.
func NoMatch(protocol Protocol) Result {
	return Result{
		Protocol:    protocol,
		Matched:     false,
		Confidence:  0.0,
		DetectionID: generateDetectionID(),
		Timestamp:   time.Now(),
	}
}

// Match returns a Result indicating a successful protocol detection.
func Match(protocol Protocol, confidence Confidence, details string) Result {
	return Result{
		Protocol:    protocol,
		Matched:     true,
		Confidence:  confidence,
		Details:     details,
		DetectionID: generateDetectionID(),
		Timestamp:   time.Now(),
	}
}

// ErrorResult returns a Result recording a detection error.
// Matched is false and the error is preserved for inspection.
func ErrorResult(protocol Protocol, err error) Result {
	return Result{
		Protocol:    protocol,
		Matched:     false,
		Confidence:  0.0,
		Error:       err,
		DetectionID: generateDetectionID(),
		Timestamp:   time.Now(),
	}
}
