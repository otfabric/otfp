// Package dnp3 implements DNP3 (Distributed Network Protocol 3) fingerprinting
// over TCP.
//
// DNP3 is the dominant SCADA protocol in North American power utilities.
// Even over TCP, DNP3 retains its link-layer framing with start bytes 0x05 0x64.
// This detector sends a minimal Link Status Request frame and validates the
// link-layer response. No application-layer objects are parsed.
package dnp3

import (
	"context"
	"fmt"

	"github.com/otfabric/otfp/core"
	"github.com/otfabric/otfp/transport"
)

const (
	protocolName = core.ProtocolDNP3

	// DNP3 link-layer constants.
	startByte1 byte = 0x05
	startByte2 byte = 0x64

	// Function codes (link layer).
	fcLinkStatusReq  byte = 0x09 // Request Link Status
	fcLinkStatusResp byte = 0x0B // Respond Link Status

	// Direction/Primary bits in control byte.
	dirPrimary byte = 0x40 // DIR=1: from primary
	dirResp    byte = 0x00 // DIR=0: from secondary

	// Frame sizes.
	minFrameSize = 10 // start(2) + length(1) + control(1) + dest(2) + source(2) + crc(2)

	maxResponseSize = 292 // Max DNP3 frame = 292 bytes
)

// Fingerprinter detects DNP3 protocol presence over TCP.
type Fingerprinter struct{}

// New creates a new DNP3 fingerprinter.
func New() *Fingerprinter {
	return &Fingerprinter{}
}

// Name returns the protocol identifier.
func (f *Fingerprinter) Name() core.Protocol {
	return protocolName
}

// Priority returns the detection order (lower = tested first).
func (f *Fingerprinter) Priority() int { return 50 }

// Detect attempts to identify DNP3 on the target by sending a Link Status
// Request and validating the response.
func (f *Fingerprinter) Detect(ctx context.Context, target core.Target) (core.Result, error) {
	conn, err := transport.Dial(ctx, target.Addr(), target.EffectiveTimeout())
	if err != nil {
		return core.NoMatch(protocolName), fmt.Errorf("dnp3: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	probe := buildProbe()

	resp, err := conn.SendReceive(probe, maxResponseSize)
	if err != nil {
		return core.NoMatch(protocolName), fmt.Errorf("dnp3: %w", err)
	}

	if isModbusErrorEcho(probe, resp) {
		return core.NoMatch(protocolName).WithExchange("probe", probe, resp), nil
	}

	return validateResponse(resp).WithExchange("probe", probe, resp), nil
}

// buildProbe constructs a minimal DNP3 Link Status Request frame.
func buildProbe() []byte {
	// Frame: start(2) + length(1) + control(1) + dest(2) + source(2) + crc(2)
	frame := make([]byte, 10)
	frame[0] = startByte1
	frame[1] = startByte2
	frame[2] = 0x05                         // Length: 5 bytes of data (control + dest + source)
	frame[3] = dirPrimary | fcLinkStatusReq // Control: DIR=1, PRM=0, FC=9
	frame[4] = 0x01                         // Destination address low
	frame[5] = 0x00                         // Destination address high
	frame[6] = 0x00                         // Source address low
	frame[7] = 0x00                         // Source address high

	// Compute CRC-16 over bytes 0..7.
	crc := crc16DNP(frame[0:8])
	frame[8] = byte(crc & 0xFF)
	frame[9] = byte((crc >> 8) & 0xFF)

	return frame
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

// validateResponse checks the response against DNP3 link-layer expectations.
func validateResponse(resp []byte) core.Result {
	if len(resp) < minFrameSize {
		return core.NoMatch(protocolName)
	}

	var confidence core.Confidence
	details := ""

	// Check 1: Start bytes.
	if resp[0] != startByte1 || resp[1] != startByte2 {
		return core.NoMatch(protocolName)
	}

	// Check 2: CRC validation (mandatory for valid DNP3 frames).
	headerCRC := uint16(resp[8]) | uint16(resp[9])<<8
	computedCRC := crc16DNP(resp[0:8])
	if headerCRC != computedCRC {
		return core.NoMatch(protocolName)
	}

	confidence += 0.60
	details = "DNP3 start bytes 0x0564, Valid CRC"

	// Check 3: Valid length field.
	length := resp[2]
	if length >= 5 && int(length) <= len(resp) {
		confidence += 0.20
		details += fmt.Sprintf(", Length=%d", length)
	}

	// Check 4: Control field - response characteristics.
	control := resp[3]
	fc := control & 0x0F
	// DIR bit = 0 means from secondary (response direction).
	// Valid response FCs: 0x00 (ACK), 0x01 (NACK), 0x0B (Link Status).
	switch {
	case control&0x40 == dirResp && fc == fcLinkStatusResp:
		confidence += 0.20
		details += ", Link Status response"
	case control&0x40 == dirResp && (fc == 0x00 || fc == 0x01):
		confidence += 0.20
		details += fmt.Sprintf(", Response FC=0x%02X", fc)
	case control&0x40 == dirPrimary:
		// Primary station responding - still valid DNP3.
		confidence += 0.10
		details += ", Primary frame detected"
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	result := core.Match(protocolName, confidence, details)
	result.Fingerprint = &core.Fingerprint{
		ID:        "dnp3.link_status",
		Signature: details,
	}
	return result
}

// crc16DNP computes the DNP3 CRC-16 over the given data.
// DNP3 uses a CRC-16 with polynomial 0x3D65 (bit-reversed: 0xA6BC).
// The lookup table approach matches the DNP3 specification.
func crc16DNP(data []byte) uint16 {
	crc := uint16(0x0000)
	for _, b := range data {
		idx := (crc ^ uint16(b)) & 0xFF
		crc = (crc >> 8) ^ crcTable[idx]
	}
	return ^crc
}

// crcTable is the precomputed DNP3 CRC-16 lookup table.
// Generated from polynomial 0xA6BC (bit-reversed 0x3D65).
var crcTable = [256]uint16{
	0x0000, 0x365E, 0x6CBC, 0x5AE2, 0xD978, 0xEF26, 0xB5C4, 0x839A,
	0xFF89, 0xC9D7, 0x9335, 0xA56B, 0x26F1, 0x10AF, 0x4A4D, 0x7C13,
	0xB26B, 0x8435, 0xDED7, 0xE889, 0x6B13, 0x5D4D, 0x07AF, 0x31F1,
	0x4DE2, 0x7BBC, 0x215E, 0x1700, 0x949A, 0xA2C4, 0xF826, 0xCE78,
	0x29AF, 0x1FF1, 0x4513, 0x734D, 0xF0D7, 0xC689, 0x9C6B, 0xAA35,
	0xD626, 0xE078, 0xBA9A, 0x8CC4, 0x0F5E, 0x3900, 0x63E2, 0x55BC,
	0x9BC4, 0xAD9A, 0xF778, 0xC126, 0x42BC, 0x74E2, 0x2E00, 0x185E,
	0x644D, 0x5213, 0x08F1, 0x3EAF, 0xBD35, 0x8B6B, 0xD189, 0xE7D7,
	0x535E, 0x6500, 0x3FE2, 0x09BC, 0x8A26, 0xBC78, 0xE69A, 0xD0C4,
	0xACD7, 0x9A89, 0xC06B, 0xF635, 0x75AF, 0x43F1, 0x1913, 0x2F4D,
	0xE135, 0xD76B, 0x8D89, 0xBBD7, 0x384D, 0x0E13, 0x54F1, 0x62AF,
	0x1EBC, 0x28E2, 0x7200, 0x445E, 0xC7C4, 0xF19A, 0xAB78, 0x9D26,
	0x7AF1, 0x4CAF, 0x164D, 0x2013, 0xA389, 0x95D7, 0xCF35, 0xF96B,
	0x8578, 0xB326, 0xE9C4, 0xDF9A, 0x5C00, 0x6A5E, 0x30BC, 0x06E2,
	0xC89A, 0xFEC4, 0xA426, 0x9278, 0x11E2, 0x27BC, 0x7D5E, 0x4B00,
	0x3713, 0x014D, 0x5BAF, 0x6DF1, 0xEE6B, 0xD835, 0x82D7, 0xB489,
	0xA6BC, 0x90E2, 0xCA00, 0xFC5E, 0x7FC4, 0x499A, 0x1378, 0x2526,
	0x5935, 0x6F6B, 0x3589, 0x03D7, 0x804D, 0xB613, 0xECF1, 0xDAAF,
	0x14D7, 0x2289, 0x786B, 0x4E35, 0xCDAF, 0xFBF1, 0xA113, 0x974D,
	0xEB5E, 0xDD00, 0x87E2, 0xB1BC, 0x3226, 0x0478, 0x5E9A, 0x68C4,
	0x8F13, 0xB94D, 0xE3AF, 0xD5F1, 0x566B, 0x6035, 0x3AD7, 0x0C89,
	0x709A, 0x46C4, 0x1C26, 0x2A78, 0xA9E2, 0x9FBC, 0xC55E, 0xF300,
	0x3D78, 0x0B26, 0x51C4, 0x679A, 0xE400, 0xD25E, 0x88BC, 0xBEE2,
	0xC2F1, 0xF4AF, 0xAE4D, 0x9813, 0x1B89, 0x2DD7, 0x7735, 0x416B,
	0xF5E2, 0xC3BC, 0x995E, 0xAF00, 0x2C9A, 0x1AC4, 0x4026, 0x7678,
	0x0A6B, 0x3C35, 0x66D7, 0x5089, 0xD313, 0xE54D, 0xBFAF, 0x89F1,
	0x4789, 0x71D7, 0x2B35, 0x1D6B, 0x9EF1, 0xA8AF, 0xF24D, 0xC413,
	0xB800, 0x8E5E, 0xD4BC, 0xE2E2, 0x6178, 0x5726, 0x0DC4, 0x3B9A,
	0xDC4D, 0xEA13, 0xB0F1, 0x86AF, 0x0535, 0x336B, 0x6989, 0x5FD7,
	0x23C4, 0x159A, 0x4F78, 0x7926, 0xFABC, 0xCCE2, 0x9600, 0xA05E,
	0x6E26, 0x5878, 0x029A, 0x34C4, 0xB75E, 0x8100, 0xDBE2, 0xEDBC,
	0x91AF, 0xA7F1, 0xFD13, 0xCB4D, 0x48D7, 0x7E89, 0x246B, 0x1235,
}
