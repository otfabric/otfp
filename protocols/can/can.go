// Package can implements CAN-over-TCP gateway fingerprinting.
//
// Native CAN bus (Controller Area Network) is not a TCP protocol.
// This detector targets SLCAN/ASCII CAN gateways that expose CAN frames
// over a TCP socket (e.g. Lawicel SLCAN, SocketCAN bridges, CAN-Ethernet
// gateways). Detection sends minimal SLCAN commands and validates strict
// SLCAN-compatible ASCII responses while rejecting common false positives
// such as HTTP/HTML/JSON/SSH/TLS-style banners.
package can

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/otfabric/otfp/core"
	"github.com/otfabric/otfp/transport"
)

const (
	protocolName = core.ProtocolCAN

	maxResponseSize = 512

	// A CAN-over-TCP / SLCAN identification should require a strong positive
	// signature. Generic ASCII-ness is not enough.
	matchThreshold core.Confidence = 0.85
)

// SLCAN commands.
var (
	// "V\r" — request firmware version.
	probeVersion = []byte{'V', '\r'}
	// "N\r" — request serial number.
	probeSerial = []byte{'N', '\r'}
)

// Fingerprinter detects CAN-over-TCP gateways.
type Fingerprinter struct{}

// New creates a new CAN gateway fingerprinter.
func New() *Fingerprinter {
	return &Fingerprinter{}
}

// Name returns the protocol identifier.
func (f *Fingerprinter) Name() core.Protocol {
	return protocolName
}

// Priority returns the detection order (lower = tested first).
func (f *Fingerprinter) Priority() int { return 90 }

// Detect attempts to identify a CAN-over-TCP gateway on the target.
// It sends minimal SLCAN probes and only accepts strict SLCAN-compatible
// responses. Weak reactions such as bare ACKs are intentionally not treated
// as protocol identification because they create too many false positives
// on generic line-based TCP services.
func (f *Fingerprinter) Detect(ctx context.Context, target core.Target) (core.Result, error) {
	conn, err := transport.Dial(ctx, target.Addr(), target.EffectiveTimeout())
	if err != nil {
		return core.NoMatch(protocolName), fmt.Errorf("can: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	var versionEvidence *evidence
	var serialEvidence *evidence

	// Probe 1: version.
	respV, err := conn.SendReceive(probeVersion, maxResponseSize)
	if err == nil {
		if ev := classifyResponse(respV, probeKindVersion); ev.strongMatch {
			versionEvidence = &ev
		}
	}

	// Probe 2: serial.
	respN, err := conn.SendReceive(probeSerial, maxResponseSize)
	if err == nil {
		if ev := classifyResponse(respN, probeKindSerial); ev.strongMatch {
			serialEvidence = &ev
		}
	}

	// Strongest case: both probes returned mutually compatible SLCAN responses.
	if versionEvidence != nil && serialEvidence != nil {
		confidence := core.Confidence(0.98)
		details := "strict SLCAN version+serial responses"

		result := core.Match(protocolName, confidence, details)
		result.Fingerprint = &core.Fingerprint{
			ID:        "can.slcan",
			Signature: fmt.Sprintf("version=%q; serial=%q", versionEvidence.normalized, serialEvidence.normalized),
		}
		return result.
			WithExchange("version", probeVersion, respV).
			WithExchange("serial", probeSerial, respN), nil
	}

	// Next best: one strong explicit SLCAN response.
	if versionEvidence != nil {
		result := core.Match(protocolName, versionEvidence.confidence, versionEvidence.details)
		result.Fingerprint = &core.Fingerprint{
			ID:        "can.slcan",
			Signature: versionEvidence.normalized,
		}
		return result.WithExchange("version", probeVersion, respV), nil
	}

	if serialEvidence != nil {
		result := core.Match(protocolName, serialEvidence.confidence, serialEvidence.details)
		result.Fingerprint = &core.Fingerprint{
			ID:        "can.slcan",
			Signature: serialEvidence.normalized,
		}
		return result.WithExchange("serial", probeSerial, respN), nil
	}

	return core.NoMatch(protocolName), nil
}

type probeKind int

const (
	probeKindVersion probeKind = iota
	probeKindSerial
)

type evidence struct {
	strongMatch bool
	confidence  core.Confidence
	details     string
	normalized  string
}

// classifyResponse validates a response for a specific probe.
// It is intentionally strict:
//
//   - rejects obvious web / JSON / SSH / TLS / telnet-like banners
//   - requires printable ASCII line semantics
//   - requires exact SLCAN-shaped payload for the probe that was sent
//
// Bare ACK/error bytes are treated as weak reactions and do not identify CAN.
func classifyResponse(resp []byte, expected probeKind) evidence {
	if len(resp) == 0 {
		return evidence{}
	}

	// Reject obviously unrelated application protocols early.
	if looksLikeNonSLCAN(resp) {
		return evidence{}
	}

	// SLCAN is ASCII-oriented. Reject obviously binary data.
	if !isMostlyPrintableASCII(resp) {
		return evidence{}
	}

	trimmed := trimLine(resp)
	if trimmed == "" {
		return evidence{}
	}

	switch expected {
	case probeKindVersion:
		if isStrictVersionResponse(trimmed) {
			return evidence{
				strongMatch: true,
				confidence:  0.90,
				details:     "strict SLCAN version response",
				normalized:  trimmed,
			}
		}
	case probeKindSerial:
		if isStrictSerialResponse(trimmed) {
			return evidence{
				strongMatch: true,
				confidence:  0.88,
				details:     "strict SLCAN serial response",
				normalized:  trimmed,
			}
		}
	}

	return evidence{}
}

// looksLikeNonSLCAN filters out common false positives from internet scanning.
func looksLikeNonSLCAN(resp []byte) bool {
	if len(resp) == 0 {
		return false
	}

	upper := strings.ToUpper(string(resp))

	// Common web/text protocols.
	if strings.HasPrefix(upper, "HTTP/") ||
		strings.HasPrefix(upper, "GET ") ||
		strings.HasPrefix(upper, "POST ") ||
		strings.HasPrefix(upper, "HEAD ") ||
		strings.Contains(upper, "<HTML") ||
		strings.Contains(upper, "<!DOCTYPE") ||
		strings.Contains(upper, "CONTENT-TYPE:") ||
		strings.Contains(upper, "LOCATION:") ||
		strings.Contains(upper, "SERVER:") {
		return true
	}

	trimmed := strings.TrimSpace(string(resp))
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return true
	}

	// SSH banner.
	if strings.HasPrefix(upper, "SSH-") {
		return true
	}

	// Telnet IAC.
	for _, b := range resp {
		if b == 0xFF {
			return true
		}
	}

	// Likely TLS / binary record prefix.
	if len(resp) >= 3 {
		// TLS record types 0x14..0x17 plus version 0x03 xx.
		if (resp[0] == 0x14 || resp[0] == 0x15 || resp[0] == 0x16 || resp[0] == 0x17) && resp[1] == 0x03 {
			return true
		}
	}

	return false
}

// isMostlyPrintableASCII returns true when the response is plausibly
// a short line-oriented ASCII control protocol.
func isMostlyPrintableASCII(resp []byte) bool {
	if len(resp) == 0 {
		return false
	}

	printable := 0
	for _, b := range resp {
		if (b >= 0x20 && b <= 0x7E) || b == '\r' || b == '\n' || b == '\t' {
			printable++
		}
	}

	ratio := float64(printable) / float64(len(resp))
	return ratio >= 0.95
}

// trimLine trims common line endings and surrounding whitespace.
func trimLine(resp []byte) string {
	return strings.TrimSpace(string(bytes.Trim(resp, "\x00")))
}

// isStrictVersionResponse validates a strict SLCAN version response.
// Accepted examples:
//   - V1013
//   - V2.0
//   - V1.25
//
// Rejected examples:
//   - V
//   - Version: 1.0
//   - Vabc
func isStrictVersionResponse(s string) bool {
	if len(s) < 2 || s[0] != 'V' {
		return false
	}

	body := s[1:]
	if len(body) == 0 || len(body) > 8 {
		return false
	}

	digitCount := 0
	dotCount := 0
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case c >= '0' && c <= '9':
			digitCount++
		case c == '.':
			dotCount++
			// No leading, trailing, or repeated dots.
			if i == 0 || i == len(body)-1 {
				return false
			}
			if i > 0 && body[i-1] == '.' {
				return false
			}
		default:
			return false
		}
	}

	if digitCount == 0 {
		return false
	}
	if dotCount > 2 {
		return false
	}

	return true
}

// isStrictSerialResponse validates a strict SLCAN serial response.
// Accepted examples:
//   - N1
//   - NA123
//   - N00AF12
//
// Rejected examples:
//   - N
//   - N-123
//   - N serial
func isStrictSerialResponse(s string) bool {
	if len(s) < 2 || s[0] != 'N' {
		return false
	}

	body := s[1:]
	if len(body) == 0 || len(body) > 16 {
		return false
	}

	for i := 0; i < len(body); i++ {
		c := body[i]
		if !isHex(c) {
			return false
		}
	}

	return true
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') ||
		(c >= 'A' && c <= 'F') ||
		(c >= 'a' && c <= 'f')
}

// validateResponse is kept as a compatibility wrapper in case other code paths
// still call it directly. It now applies strict matching only and does not
// consider weak ACK-style responses or generic ASCII traits sufficient.
//
// By default it evaluates the response as "unknown probe" and only accepts it
// if it is a strict version OR strict serial response.
func validateResponse(resp []byte) core.Result {
	if len(resp) == 0 {
		return core.NoMatch(protocolName)
	}

	if looksLikeNonSLCAN(resp) || !isMostlyPrintableASCII(resp) {
		return core.NoMatch(protocolName)
	}

	trimmed := trimLine(resp)
	if trimmed == "" {
		return core.NoMatch(protocolName)
	}

	if isStrictVersionResponse(trimmed) {
		confidence := core.Confidence(0.90)
		if confidence < matchThreshold {
			return core.NoMatch(protocolName)
		}

		result := core.Match(protocolName, confidence, "strict SLCAN version response")
		result.Fingerprint = &core.Fingerprint{
			ID:        "can.slcan",
			Signature: trimmed,
		}
		return result
	}

	if isStrictSerialResponse(trimmed) {
		confidence := core.Confidence(0.88)
		if confidence < matchThreshold {
			return core.NoMatch(protocolName)
		}

		result := core.Match(protocolName, confidence, "strict SLCAN serial response")
		result.Fingerprint = &core.Fingerprint{
			ID:        "can.slcan",
			Signature: trimmed,
		}
		return result
	}

	return core.NoMatch(protocolName)
}

// matchesSLCAN is kept for compatibility with older tests/callers.
// It now means: strict positive SLCAN response only.
func matchesSLCAN(resp []byte) bool {
	if len(resp) == 0 {
		return false
	}
	if looksLikeNonSLCAN(resp) || !isMostlyPrintableASCII(resp) {
		return false
	}

	trimmed := trimLine(resp)
	return isStrictVersionResponse(trimmed) || isStrictSerialResponse(trimmed)
}
