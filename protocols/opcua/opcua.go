// Package opcua implements OPC UA Binary TCP protocol fingerprinting.
//
// Detection sends a minimal UA TCP Hello (HEL) message and validates the
// Acknowledge (ACK) response. No OpenSecureChannel or higher-layer UA
// operations are performed.
package opcua

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/otfabric/otfp/core"
	"github.com/otfabric/otfp/transport"
)

const (
	protocolName = core.ProtocolOPCUA

	// UA TCP message types (3-byte ASCII).
	msgTypeHEL = "HEL"
	msgTypeACK = "ACK"
	msgTypeERR = "ERR"

	// Chunk type: Final.
	chunkFinal byte = 'F'

	// Header sizes.
	uaTCPHeaderSize = 8 // MessageType(3) + ChunkType(1) + MessageSize(4)

	// Protocol version we advertise.
	protocolVersion uint32 = 0

	// Buffer sizes used in our Hello.
	receiveBufferSize uint32 = 65535
	sendBufferSize    uint32 = 65535
	maxMessageSize    uint32 = 0 // 0 = no limit
	maxChunkCount     uint32 = 0 // 0 = no limit

	maxResponseSize = 4096
)

// Fingerprinter detects OPC UA Binary TCP protocol presence.
type Fingerprinter struct{}

// New creates a new OPC UA fingerprinter.
func New() *Fingerprinter {
	return &Fingerprinter{}
}

// Name returns the protocol identifier.
func (f *Fingerprinter) Name() core.Protocol {
	return protocolName
}

// Priority returns the detection order (lower = tested first).
func (f *Fingerprinter) Priority() int { return 70 }

// Detect attempts to identify OPC UA on the target by sending a HEL
// message and validating the ACK response.
func (f *Fingerprinter) Detect(ctx context.Context, target core.Target) (core.Result, error) {
	conn, err := transport.Dial(ctx, target.Addr(), target.EffectiveTimeout())
	if err != nil {
		return core.NoMatch(protocolName), fmt.Errorf("opcua: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	probe := buildHello()

	resp, err := conn.SendReceive(probe, maxResponseSize)
	if err != nil {
		return core.NoMatch(protocolName), fmt.Errorf("opcua: %w", err)
	}

	return validateResponse(resp).WithExchange("probe", probe, resp), nil
}

// buildHello constructs a minimal UA TCP Hello message.
func buildHello() []byte {
	// EndpointURL is empty string: length prefix (4 bytes) = 0xFFFFFFFF (null)
	// Hello body: ProtocolVersion(4) + ReceiveBufferSize(4) + SendBufferSize(4) +
	//             MaxMessageSize(4) + MaxChunkCount(4) + EndpointURL length(4) = 24 bytes
	bodyLen := 24
	totalLen := uaTCPHeaderSize + bodyLen

	msg := make([]byte, totalLen)

	// Header.
	copy(msg[0:3], msgTypeHEL)
	msg[3] = chunkFinal
	binary.LittleEndian.PutUint32(msg[4:8], uint32(totalLen))

	// Body.
	binary.LittleEndian.PutUint32(msg[8:12], protocolVersion)
	binary.LittleEndian.PutUint32(msg[12:16], receiveBufferSize)
	binary.LittleEndian.PutUint32(msg[16:20], sendBufferSize)
	binary.LittleEndian.PutUint32(msg[20:24], maxMessageSize)
	binary.LittleEndian.PutUint32(msg[24:28], maxChunkCount)
	// EndpointURL: null string (length = -1 = 0xFFFFFFFF).
	binary.LittleEndian.PutUint32(msg[28:32], 0xFFFFFFFF)

	return msg
}

// validateResponse checks the response against OPC UA TCP protocol expectations.
func validateResponse(resp []byte) core.Result {
	if len(resp) < uaTCPHeaderSize {
		return core.NoMatch(protocolName)
	}

	var confidence core.Confidence
	details := ""

	// Check 1: Message type is ACK or ERR (both are valid OPC UA responses).
	msgType := string(resp[0:3])
	switch msgType {
	case msgTypeACK:
		confidence += 0.40
		details = "ACK response"
	case msgTypeERR:
		confidence += 0.35
		details = "ERR response (valid OPC UA)"
	default:
		return core.NoMatch(protocolName)
	}

	// Check 2: Message size field.
	msgSize := binary.LittleEndian.Uint32(resp[4:8])
	if msgSize >= uaTCPHeaderSize && msgSize <= uint32(len(resp))+64 {
		confidence += 0.20
		details += ", Valid message size"
	}

	// Check 3: For ACK, validate body fields.
	if msgType == msgTypeACK && len(resp) >= uaTCPHeaderSize+20 {
		// ACK body: ProtocolVersion(4) + ReceiveBufferSize(4) + SendBufferSize(4) +
		//           MaxMessageSize(4) + MaxChunkCount(4) = 20 bytes
		respVersion := binary.LittleEndian.Uint32(resp[8:12])
		respRecvBuf := binary.LittleEndian.Uint32(resp[12:16])
		respSendBuf := binary.LittleEndian.Uint32(resp[16:20])

		if respVersion <= 1 {
			confidence += 0.20
			details += fmt.Sprintf(", Protocol version %d", respVersion)
		}

		if respRecvBuf >= 8192 && respSendBuf >= 8192 {
			confidence += 0.20
			details += ", Valid buffer sizes"
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
		ID:        "opcua.hel_ack",
		Signature: details,
	}
	return result
}
