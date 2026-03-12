// Package profinet implements PROFINET (Industrial Ethernet) fingerprinting
// via DCE/RPC over TCP.
//
// PROFINET IO uses DCE/RPC for configuration and acyclic data exchange.
// This detector sends a minimal DCE/RPC Bind request targeting the PROFINET
// IO CM (Connection Manager) interface UUID and validates the Bind-Ack
// response. PROFIBUS (RS-485 fieldbus) is NOT detectable via TCP.
package profinet

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/otfabric/otfp/core"
	"github.com/otfabric/otfp/transport"
)

const (
	protocolName = core.ProtocolPROFINET

	// DCE/RPC constants.
	rpcVersion      byte = 5
	rpcMinorVersion byte = 0
	rpcTypeBind     byte = 11
	rpcTypeBindAck  byte = 12
	rpcTypeBindNak  byte = 13

	// Byte order: little-endian data representation.
	dataRepLittleEndian byte = 0x10

	// PROFINET IO CM (Connection Manager) interface UUID.
	// DEA00001-6C97-11D1-8271-00A02442DF7D
	// This is the well-known UUID for PNIO services.

	maxResponseSize = 4096
)

// PNIO CM interface UUID in little-endian wire format.
var pnioCMUUID = []byte{
	0x01, 0x00, 0xA0, 0xDE, // DEA00001 (LE)
	0x97, 0x6C, // 6C97 (LE)
	0xD1, 0x11, // 11D1 (LE)
	0x82, 0x71, // 8271
	0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D, // 00A02442DF7D
}

// Transfer syntax UUID (NDR 2.0).
var ndrSyntaxUUID = []byte{
	0x04, 0x5D, 0x88, 0x8A, // 8A885D04 (LE)
	0xEB, 0x1C, // 1CEB (LE)
	0xC9, 0x11, // 11C9 (LE)
	0x9F, 0xE8, // 9FE8
	0x08, 0x00, 0x2B, 0x10, 0x48, 0x60, // 08002B104860
}

// Fingerprinter detects PROFINET endpoints via DCE/RPC.
type Fingerprinter struct{}

// New creates a new PROFINET fingerprinter.
func New() *Fingerprinter {
	return &Fingerprinter{}
}

// Name returns the protocol identifier.
func (f *Fingerprinter) Name() core.Protocol {
	return protocolName
}

// Priority returns the detection order (lower = tested first).
func (f *Fingerprinter) Priority() int { return 100 }

// Detect attempts to identify PROFINET on the target by sending a DCE/RPC
// Bind request and validating the Bind-Ack response.
func (f *Fingerprinter) Detect(ctx context.Context, target core.Target) (core.Result, error) {
	conn, err := transport.Dial(ctx, target.Addr(), target.EffectiveTimeout())
	if err != nil {
		return core.NoMatch(protocolName), fmt.Errorf("profinet: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	probe := buildBindRequest()

	resp, err := conn.SendReceive(probe, maxResponseSize)
	if err != nil {
		return core.NoMatch(protocolName), fmt.Errorf("profinet: %w", err)
	}

	return validateResponse(resp).WithExchange("probe", probe, resp), nil
}

// buildBindRequest constructs a minimal DCE/RPC Bind request with PNIO CM UUID.
func buildBindRequest() []byte {
	// DCE/RPC header: 16 bytes
	// Bind body: max_xmit(2) + max_recv(2) + assoc_group(4) + num_ctx(1) + pad(3) = 12
	// Context item: ctx_id(2) + num_items(1) + pad(1) + abstract(20) + transfer(20) = 44
	// Total body: 56 bytes

	bodyLen := 56
	totalLen := 16 + bodyLen

	msg := make([]byte, totalLen)

	// DCE/RPC header.
	msg[0] = rpcVersion
	msg[1] = rpcMinorVersion
	msg[2] = rpcTypeBind
	msg[3] = 0x00 // Flags (first+last fragment)
	// Data representation: little-endian, ASCII, IEEE float.
	msg[4] = dataRepLittleEndian
	msg[5] = 0x00
	msg[6] = 0x00
	msg[7] = 0x00
	// Fragment length (little-endian).
	binary.LittleEndian.PutUint16(msg[8:10], uint16(totalLen))
	// Auth length.
	binary.LittleEndian.PutUint16(msg[10:12], 0)
	// Call ID.
	binary.LittleEndian.PutUint32(msg[12:16], 1)

	// Bind body.
	off := 16
	binary.LittleEndian.PutUint16(msg[off:off+2], 5840)   // max_xmit_frag
	binary.LittleEndian.PutUint16(msg[off+2:off+4], 5840) // max_recv_frag
	binary.LittleEndian.PutUint32(msg[off+4:off+8], 0)    // assoc_group_id
	msg[off+8] = 1                                        // num context items
	msg[off+9] = 0                                        // padding
	msg[off+10] = 0                                       // padding
	msg[off+11] = 0                                       // padding

	// Context item.
	ctxOff := off + 12
	binary.LittleEndian.PutUint16(msg[ctxOff:ctxOff+2], 0) // context ID
	msg[ctxOff+2] = 1                                      // num transfer syntaxes
	msg[ctxOff+3] = 0                                      // padding

	// Abstract syntax: PNIO CM UUID + version 1.0.
	copy(msg[ctxOff+4:ctxOff+20], pnioCMUUID)
	binary.LittleEndian.PutUint32(msg[ctxOff+20:ctxOff+24], 1) // version

	// Transfer syntax: NDR 2.0.
	copy(msg[ctxOff+24:ctxOff+40], ndrSyntaxUUID)
	binary.LittleEndian.PutUint32(msg[ctxOff+40:ctxOff+44], 2) // version

	return msg
}

// validateResponse checks the response against DCE/RPC + PROFINET expectations.
func validateResponse(resp []byte) core.Result {
	if len(resp) < 16 {
		return core.NoMatch(protocolName)
	}

	var confidence core.Confidence
	details := ""

	// Check 1: DCE/RPC header validation.
	if resp[0] != rpcVersion || resp[1] != rpcMinorVersion {
		return core.NoMatch(protocolName)
	}

	pktType := resp[2]
	switch pktType {
	case rpcTypeBindAck:
		confidence += 0.40
		details = "DCE/RPC Bind-Ack"
	case rpcTypeBindNak:
		confidence += 0.35
		details = "DCE/RPC Bind-Nak (valid RPC)"
	default:
		return core.NoMatch(protocolName)
	}

	// Check 2: Fragment length sanity.
	fragLen := binary.LittleEndian.Uint16(resp[8:10])
	if fragLen >= 16 && int(fragLen) <= len(resp)+16 {
		confidence += 0.10
		details += ", Valid fragment length"
	}

	// Check 3: For Bind-Ack, look for PNIO UUID acceptance.
	if pktType == rpcTypeBindAck && len(resp) >= 26 {
		// After the fixed Bind-Ack header (24 bytes min with secondary addr),
		// look for result list indicating acceptance.
		// A secondary address length is at offset 24 (2 bytes LE).
		if len(resp) >= 28 {
			secAddrLen := binary.LittleEndian.Uint16(resp[24:26])
			// Align to 4 bytes.
			padded := int(secAddrLen)
			if padded%2 != 0 {
				padded++
			}
			resultOff := 26 + padded
			if resultOff+4 <= len(resp) {
				numResults := binary.LittleEndian.Uint32(resp[resultOff : resultOff+4])
				if numResults >= 1 && resultOff+8 <= len(resp) {
					ackResult := binary.LittleEndian.Uint16(resp[resultOff+4 : resultOff+6])
					switch ackResult {
					case 0: // Acceptance
						confidence += 0.50
						details += ", PNIO interface accepted"
					case 2: // Provider rejection
						confidence += 0.25
						details += ", Provider rejection (valid PNIO endpoint)"
					}
				}
			}
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
		ID:        "profinet.dcerpc_bind",
		Signature: details,
	}
	return result
}
