// Package iec104 implements IEC 60870-5-104 protocol fingerprinting over TCP.
//
// IEC 104 is the dominant SCADA protocol in European power substations.
// It uses APCI (Application Protocol Control Information) frames over TCP.
// This detector sends a minimal STARTDT_ACT U-format frame and validates
// the STARTDT_CON response. No ASDU (I-format) frames are sent or parsed.
package iec104

import (
	"bytes"
	"context"
	"fmt"

	"github.com/otfabric/otfp/core"
	"github.com/otfabric/otfp/transport"
)

const (
	protocolName = core.ProtocolIEC104

	// APCI constants.
	startByte byte = 0x68 // IEC 104 start byte

	// APCI frame length (fixed for U-format).
	apciLength byte = 0x04 // 4 bytes of control field

	// U-format control field values.
	startdtAct byte = 0x07 // STARTDT Activation
	startdtCon byte = 0x0B // STARTDT Confirmation
	stopdtAct  byte = 0x13 // STOPDT Activation
	stopdtCon  byte = 0x23 // STOPDT Confirmation
	testfrAct  byte = 0x43 // TESTFR Activation
	testfrCon  byte = 0x83 // TESTFR Confirmation

	// Frame sizes.
	apciHeaderSize = 6 // start(1) + length(1) + control(4)

	maxResponseSize = 255 // Max APCI frame
)

// Fingerprinter detects IEC 60870-5-104 protocol presence over TCP.
type Fingerprinter struct{}

// New creates a new IEC 104 fingerprinter.
func New() *Fingerprinter {
	return &Fingerprinter{}
}

// Name returns the protocol identifier.
func (f *Fingerprinter) Name() core.Protocol {
	return protocolName
}

// Priority returns the detection order (lower = tested first).
func (f *Fingerprinter) Priority() int { return 40 }

// Detect attempts to identify IEC 104 on the target by sending a STARTDT_ACT
// frame and validating the response.
func (f *Fingerprinter) Detect(ctx context.Context, target core.Target) (core.Result, error) {
	conn, err := transport.Dial(ctx, target.Addr(), target.EffectiveTimeout())
	if err != nil {
		return core.NoMatch(protocolName), fmt.Errorf("iec104: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	probe := buildProbe()

	resp, err := conn.SendReceive(probe, maxResponseSize)
	if err != nil {
		return core.NoMatch(protocolName), fmt.Errorf("iec104: %w", err)
	}

	// If the response is an exact echo of our probe, the remote endpoint
	// is not an IEC 104 device (common with Modbus and other services).
	if bytes.Equal(resp, probe) {
		return core.NoMatch(protocolName).WithExchange("probe", probe, resp), nil
	}

	return validateResponse(resp).WithExchange("probe", probe, resp), nil
}

// buildProbe constructs a STARTDT_ACT U-format APCI frame.
func buildProbe() []byte {
	// APCI: start(1) + length(1) + control(4) = 6 bytes.
	frame := make([]byte, apciHeaderSize)
	frame[0] = startByte
	frame[1] = apciLength
	frame[2] = startdtAct // Control byte 1: STARTDT_ACT
	frame[3] = 0x00       // Control byte 2
	frame[4] = 0x00       // Control byte 3
	frame[5] = 0x00       // Control byte 4
	return frame
}

// validateResponse checks the response against IEC 104 APCI expectations.
func validateResponse(resp []byte) core.Result {
	if len(resp) < apciHeaderSize {
		return core.NoMatch(protocolName)
	}

	var confidence core.Confidence
	details := ""

	// Check 1: Start byte.
	if resp[0] != startByte {
		return core.NoMatch(protocolName)
	}
	confidence += 0.30
	details = "Start byte 0x68"

	// Check 2: Length field validation.
	length := resp[1]
	if length >= apciLength && int(length)+2 <= len(resp)+2 {
		confidence += 0.20
		details += fmt.Sprintf(", Length=%d", length)
	}

	// Check 3: Control field - check for valid U-format or S-format.
	controlByte1 := resp[2]
	// U-format frames have bits 0 and 1 of first control byte = 11.
	isUFormat := (controlByte1 & 0x03) == 0x03
	// S-format frames have bits 0 and 1 = 01.
	isSFormat := (controlByte1 & 0x03) == 0x01

	if isUFormat || isSFormat {
		confidence += 0.30
		if isUFormat {
			details += ", U-format"
		} else {
			details += ", S-format"
		}
	}

	// Check 4: For U-format frames, control bytes 3-5 MUST be 0x00 per spec.
	if isUFormat {
		if resp[3] != 0x00 || resp[4] != 0x00 || resp[5] != 0x00 {
			// Invalid U-format frame — not IEC 104.
			return core.NoMatch(protocolName)
		}
	}

	// Check 5: Specific U-format command (STARTDT_CON is the expected response).
	if isUFormat {
		switch controlByte1 {
		case startdtCon:
			confidence += 0.20
			details += " STARTDT_CON"
		case stopdtCon:
			confidence += 0.15
			details += " STOPDT_CON"
		case testfrAct:
			confidence += 0.15
			details += " TESTFR_ACT"
		case testfrCon:
			confidence += 0.15
			details += " TESTFR_CON"
		case startdtAct:
			// STARTDT_ACT is what we sent — receiving it back indicates
			// an echo (e.g. from a Modbus device), not a real IEC 104
			// response. Do not award confidence.
			return core.NoMatch(protocolName)
		case stopdtAct:
			confidence += 0.10
			details += " STOPDT_ACT"
		}
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	if confidence < 0.3 {
		return core.NoMatch(protocolName)
	}

	result := core.Match(protocolName, confidence, details)
	result.Fingerprint = &core.Fingerprint{
		ID:        "iec104.startdt",
		Signature: details,
	}
	return result
}
