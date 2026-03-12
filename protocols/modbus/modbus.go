// Package modbus implements Modbus TCP protocol fingerprinting.
//
// Detection is based on MBAP (Modbus Application Protocol) header validation
// at the transport framing level. No application-layer Modbus function calls
// are performed beyond minimal frame exchange for protocol detection.
package modbus

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/otfabric/otfp/core"
	"github.com/otfabric/otfp/transport"
)

const (
	protocolName = core.ProtocolModbus

	// MBAP header constants.
	mbapHeaderSize = 7 // Transaction ID (2) + Protocol ID (2) + Length (2) + Unit ID (1)
	protocolID     = 0 // Modbus protocol identifier is always 0x0000.

	// We use Function Code 43 (0x2B) / MEI Type 14 (0x0E) - Read Device Identification.
	// This is a safe, read-only diagnostic function code.
	// Category: Basic Device Identification (Object ID 0x00).
	fcReadDeviceID = 0x2B
	meiType        = 0x0E
	readDevIDCode  = 0x01 // Basic device identification
	objectID       = 0x00 // VendorName
	exceptionMask  = 0x80 // Bit 7 set indicates exception response.

	// Transaction ID used in our probe. We check if the response echoes it.
	probeTransactionID = 0x1337

	maxResponseSize = 260 // Max Modbus TCP ADU size.
)

// Fingerprinter detects Modbus TCP protocol presence.
type Fingerprinter struct{}

// New creates a new Modbus TCP fingerprinter.
func New() *Fingerprinter {
	return &Fingerprinter{}
}

// Name returns the protocol identifier.
func (f *Fingerprinter) Name() core.Protocol {
	return protocolName
}

// Priority returns the detection order (lower = tested first).
func (f *Fingerprinter) Priority() int { return 60 }

// Detect attempts to identify Modbus TCP on the target.
func (f *Fingerprinter) Detect(ctx context.Context, target core.Target) (core.Result, error) {
	conn, err := transport.Dial(ctx, target.Addr(), target.EffectiveTimeout())
	if err != nil {
		return core.NoMatch(protocolName), fmt.Errorf("modbus: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	// Build minimal Modbus TCP probe.
	probe := buildProbe()

	// Send probe and receive response.
	resp, err := conn.SendReceive(probe, maxResponseSize)
	if err != nil {
		return core.NoMatch(protocolName), fmt.Errorf("modbus: %w", err)
	}

	// Validate response.
	return validateResponse(resp).WithExchange("probe", probe, resp), nil
}

// buildProbe constructs a minimal Modbus TCP request frame.
// Uses FC43/MEI - Read Device Identification as a safe probe.
func buildProbe() []byte {
	// PDU: FC(1) + MEI Type(1) + Read Dev ID Code(1) + Object ID(1) = 4 bytes
	// MBAP Length field = Unit ID (1) + PDU (4) = 5
	pdu := []byte{fcReadDeviceID, meiType, readDevIDCode, objectID}

	frame := make([]byte, mbapHeaderSize+len(pdu))

	// Transaction ID.
	binary.BigEndian.PutUint16(frame[0:2], probeTransactionID)
	// Protocol ID (always 0 for Modbus).
	binary.BigEndian.PutUint16(frame[2:4], protocolID)
	// Length (Unit ID + PDU).
	binary.BigEndian.PutUint16(frame[4:6], uint16(1+len(pdu)))
	// Unit ID.
	frame[6] = 0x01

	copy(frame[7:], pdu)
	return frame
}

// validateResponse checks the response against Modbus TCP protocol expectations.
func validateResponse(resp []byte) core.Result {
	if len(resp) < mbapHeaderSize+1 {
		return core.NoMatch(protocolName)
	}

	var confidence core.Confidence
	details := ""

	// Check 1: Protocol ID must be 0x0000.
	respProtocolID := binary.BigEndian.Uint16(resp[2:4])
	if respProtocolID != protocolID {
		return core.NoMatch(protocolName)
	}
	confidence += 0.25
	details = "Protocol ID=0"

	// Check 2: Transaction ID echo.
	respTransactionID := binary.BigEndian.Uint16(resp[0:2])
	if respTransactionID == probeTransactionID {
		confidence += 0.25
		details += ", Transaction ID echoed"
	}

	// Check 3: Length field consistency.
	respLength := binary.BigEndian.Uint16(resp[4:6])
	expectedDataLen := int(respLength) + 6 // MBAP header without length field = 6 bytes
	if expectedDataLen <= len(resp) && respLength >= 2 {
		confidence += 0.20
		details += ", Length consistent"
	}

	// Check 4: Function code validation.
	fc := resp[7]
	if fc == fcReadDeviceID || fc == (fcReadDeviceID|exceptionMask) {
		confidence += 0.20
		if fc&exceptionMask != 0 {
			details += ", Exception response (valid Modbus)"
		} else {
			details += ", Normal response"
		}
	} else if fc&exceptionMask != 0 {
		// Any exception response to our FC is still Modbus.
		confidence += 0.15
		details += fmt.Sprintf(", Exception FC=0x%02X", fc)
	}

	// Check 5: Unit ID present (non-zero is common but 0 is also valid).
	unitID := resp[6]
	if unitID == 0x01 {
		confidence += 0.10
		details += ", Unit ID echoed"
	}

	if confidence < 0.25 {
		return core.NoMatch(protocolName)
	}

	// Cap confidence at 1.0.
	if confidence > 1.0 {
		confidence = 1.0
	}

	result := core.Match(protocolName, confidence, details)
	result.Fingerprint = &core.Fingerprint{
		ID:        "modbus.fc43",
		Signature: details,
	}
	return result
}
