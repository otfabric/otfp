// Package bacnet implements BACnet/IP protocol fingerprinting over TCP.
//
// BACnet/IP primarily operates over UDP (port 47808). This detector targets
// the less common TCP encapsulation by sending a minimal BVLL frame and
// validating the response header. UDP BACnet detection is not supported.
package bacnet

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/otfabric/otfp/core"
	"github.com/otfabric/otfp/transport"
)

const (
	protocolName = core.ProtocolBACnet

	// BVLC (BACnet Virtual Link Control) constants.
	bvlcType        byte = 0x81 // BACnet/IP (Annex J)
	bvlcFuncUnicast byte = 0x0A // Original-Unicast-NPDU
	bvlcHeaderSize  int  = 4    // Type(1) + Function(1) + Length(2)

	// Minimal NPDU for WHO-IS (unconfirmed request).
	npduVersion     byte = 0x01
	npduControl     byte = 0x20 // No DNET/DADDR, expecting reply
	apduUnconfirmed byte = 0x10 // Unconfirmed request PDU type
	serviceWhoIs    byte = 0x08 // Who-Is service choice

	maxResponseSize = 1500
)

// Fingerprinter detects BACnet/IP protocol presence over TCP.
type Fingerprinter struct{}

// New creates a new BACnet/IP fingerprinter.
func New() *Fingerprinter {
	return &Fingerprinter{}
}

// Name returns the protocol identifier.
func (f *Fingerprinter) Name() core.Protocol {
	return protocolName
}

// Priority returns the detection order (lower = tested first).
func (f *Fingerprinter) Priority() int { return 80 }

// Detect attempts to identify BACnet/IP on the target by sending a minimal
// BVLL frame and validating the response.
func (f *Fingerprinter) Detect(ctx context.Context, target core.Target) (core.Result, error) {
	conn, err := transport.Dial(ctx, target.Addr(), target.EffectiveTimeout())
	if err != nil {
		return core.NoMatch(protocolName), fmt.Errorf("bacnet: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	probe := buildProbe()

	resp, err := conn.SendReceive(probe, maxResponseSize)
	if err != nil {
		return core.NoMatch(protocolName), fmt.Errorf("bacnet: %w", err)
	}

	return validateResponse(resp).WithExchange("probe", probe, resp), nil
}

// buildProbe constructs a minimal BVLL/NPDU/APDU frame.
func buildProbe() []byte {
	// NPDU + APDU payload.
	payload := []byte{
		npduVersion, npduControl, // NPDU
		apduUnconfirmed, serviceWhoIs, // APDU: Who-Is
	}

	totalLen := bvlcHeaderSize + len(payload)
	frame := make([]byte, totalLen)
	frame[0] = bvlcType
	frame[1] = bvlcFuncUnicast
	binary.BigEndian.PutUint16(frame[2:4], uint16(totalLen))
	copy(frame[4:], payload)

	return frame
}

// validateResponse checks the response against BACnet/IP protocol expectations.
func validateResponse(resp []byte) core.Result {
	if len(resp) < bvlcHeaderSize {
		return core.NoMatch(protocolName)
	}

	var confidence core.Confidence
	details := ""

	// Check 1: BVLC type byte.
	if resp[0] != bvlcType {
		return core.NoMatch(protocolName)
	}
	confidence += 0.40
	details = "BVLC type 0x81"

	// Check 2: Valid BVLC function code.
	funcCode := resp[1]
	validFuncs := map[byte]string{
		0x00: "Result",
		0x01: "Write-BDT",
		0x02: "Read-BDT",
		0x03: "Read-BDT-Ack",
		0x04: "Forwarded-NPDU",
		0x05: "Register-FD",
		0x06: "Read-FD-Table",
		0x07: "Read-FD-Table-Ack",
		0x08: "Delete-FD-Entry",
		0x09: "Distribute-Broadcast",
		0x0A: "Original-Unicast",
		0x0B: "Original-Broadcast",
	}
	if name, ok := validFuncs[funcCode]; ok {
		confidence += 0.30
		details += fmt.Sprintf(", Function: %s (0x%02X)", name, funcCode)
	}

	// Check 3: Length field consistency.
	bvlcLen := binary.BigEndian.Uint16(resp[2:4])
	if int(bvlcLen) >= bvlcHeaderSize && int(bvlcLen) <= len(resp)+4 {
		confidence += 0.20
		details += ", Length consistent"
	}

	// Check 4: NPDU version byte if payload present.
	if len(resp) > bvlcHeaderSize && resp[4] == npduVersion {
		confidence += 0.10
		details += ", NPDU v1"
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	if confidence < 0.3 {
		return core.NoMatch(protocolName)
	}

	result := core.Match(protocolName, confidence, details)
	result.Fingerprint = &core.Fingerprint{
		ID:        "bacnet.bvll",
		Signature: details,
	}
	return result
}
