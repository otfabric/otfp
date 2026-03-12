// Package enip implements EtherNet/IP (CIP over TCP) protocol fingerprinting.
//
// EtherNet/IP is the dominant industrial protocol in Rockwell/Allen-Bradley
// environments. This detector sends a minimal RegisterSession encapsulation
// command and validates the response header. No CIP messages, Forward Open
// requests, or attribute reads are performed.
package enip

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/otfabric/otfp/core"
	"github.com/otfabric/otfp/transport"
)

const (
	protocolName = core.ProtocolENIP

	// Encapsulation header constants.
	cmdRegisterSession   uint16 = 0x0065
	cmdUnregisterSession uint16 = 0x0066
	cmdListIdentity      uint16 = 0x0063

	// Encapsulation header size.
	encapHeaderSize = 24 // Command(2) + Length(2) + Session(4) + Status(4) + Context(8) + Options(4)

	// Status codes.
	statusSuccess uint32 = 0x00000000

	maxResponseSize = 4096
)

// Fingerprinter detects EtherNet/IP protocol presence over TCP.
type Fingerprinter struct{}

// New creates a new EtherNet/IP fingerprinter.
func New() *Fingerprinter {
	return &Fingerprinter{}
}

// Name returns the protocol identifier.
func (f *Fingerprinter) Name() core.Protocol {
	return protocolName
}

// Priority returns the detection order (lower = tested first).
func (f *Fingerprinter) Priority() int { return 30 }

// Detect attempts to identify EtherNet/IP on the target by sending a
// RegisterSession command and validating the response.
func (f *Fingerprinter) Detect(ctx context.Context, target core.Target) (core.Result, error) {
	conn, err := transport.Dial(ctx, target.Addr(), target.EffectiveTimeout())
	if err != nil {
		return core.NoMatch(protocolName), fmt.Errorf("enip: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	probe := buildProbe()

	resp, err := conn.SendReceive(probe, maxResponseSize)
	if err != nil {
		return core.NoMatch(protocolName), fmt.Errorf("enip: %w", err)
	}

	if isModbusErrorEcho(probe, resp) {
		return core.NoMatch(protocolName).WithExchange("probe", probe, resp), nil
	}

	return validateResponse(resp).WithExchange("probe", probe, resp), nil
}

// buildProbe constructs an EtherNet/IP RegisterSession command.
func buildProbe() []byte {
	// Encapsulation header (24 bytes) + RegisterSession data (4 bytes).
	msg := make([]byte, encapHeaderSize+4)

	// Command: RegisterSession (0x0065).
	binary.LittleEndian.PutUint16(msg[0:2], cmdRegisterSession)
	// Length: 4 bytes (protocol version + option flags).
	binary.LittleEndian.PutUint16(msg[2:4], 4)
	// Session Handle: 0 (we're registering).
	binary.LittleEndian.PutUint32(msg[4:8], 0)
	// Status: 0.
	binary.LittleEndian.PutUint32(msg[8:12], 0)
	// Sender Context: 8 bytes of zero.
	// Options: 0.

	// RegisterSession data.
	// Protocol version: 1.
	binary.LittleEndian.PutUint16(msg[24:26], 1)
	// Option flags: 0.
	binary.LittleEndian.PutUint16(msg[26:28], 0)

	return msg
}

// isModbusErrorEcho returns true if the response matches the Modbus error echo
// pattern: same length, byte 7 has the error bit (0x80) set relative to the probe,
// byte 8 is a valid Modbus exception code (1-11), and all other bytes are identical.
func isModbusErrorEcho(probe, resp []byte) bool {
	if len(probe) != len(resp) || len(probe) < 9 {
		return false
	}
	for i := range probe {
		if probe[i] != resp[i] {
			if i == 7 && resp[7] == probe[7]|0x80 {
				continue
			}
			if i == 8 && resp[8] >= 0x01 && resp[8] <= 0x0B {
				continue
			}
			return false
		}
	}
	return resp[7] == probe[7]|0x80
}

// validateResponse checks the response against EtherNet/IP encapsulation expectations.
func validateResponse(resp []byte) core.Result {
	if len(resp) < encapHeaderSize {
		return core.NoMatch(protocolName)
	}

	var confidence core.Confidence
	details := ""

	// Check 1: Command field.
	command := binary.LittleEndian.Uint16(resp[0:2])
	switch command {
	case cmdRegisterSession:
		confidence += 0.30
		details = "RegisterSession response"
	case cmdListIdentity:
		confidence += 0.25
		details = "ListIdentity response"
	default:
		// Check if it's any valid encapsulation command (0x0001-0x0070 range).
		if command >= 0x0001 && command <= 0x0070 {
			confidence += 0.15
			details = fmt.Sprintf("Encapsulation command 0x%04X", command)
		} else {
			return core.NoMatch(protocolName)
		}
	}

	// Check 2: Status field.
	status := binary.LittleEndian.Uint32(resp[8:12])
	if status == statusSuccess {
		confidence += 0.20
		details += ", Status=Success"
	} else if status <= 0x00000069 {
		// Known EtherNet/IP status code range.
		confidence += 0.10
		details += fmt.Sprintf(", Status=0x%08X", status)
	}

	// Check 3: Session handle.
	sessionID := binary.LittleEndian.Uint32(resp[4:8])
	if command == cmdRegisterSession && sessionID != 0 && status == statusSuccess {
		confidence += 0.30
		details += fmt.Sprintf(", SessionID=0x%08X", sessionID)
	} else if command == cmdRegisterSession && sessionID == 0 && status != statusSuccess {
		// Session 0 with error status is still valid EtherNet/IP.
		confidence += 0.10
		details += ", Session=0 (error response)"
	}

	// Check 4: Length field consistency.
	dataLen := binary.LittleEndian.Uint16(resp[2:4])
	if int(dataLen)+encapHeaderSize <= len(resp)+8 {
		confidence += 0.20
		details += fmt.Sprintf(", DataLen=%d", dataLen)
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	if confidence < 0.3 {
		return core.NoMatch(protocolName)
	}

	result := core.Match(protocolName, confidence, details)
	result.Fingerprint = &core.Fingerprint{
		ID:        "enip.register_session",
		Signature: details,
	}
	return result
}
