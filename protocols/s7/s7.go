// Package s7 implements Siemens S7comm protocol fingerprinting over ISO-on-TCP.
//
// Detection is performed in two phases:
//  1. TPKT/COTP Connection Request -> Connection Confirm (shared with MMS)
//  2. S7 Setup Communication request -> S7 ACK response (S7-specific)
//
// This two-phase approach allows distinguishing S7comm from pure MMS/ISO endpoints.
// No deep S7 parsing, block reads, or device info queries are performed.
package s7

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/otfabric/otfp/core"
	"github.com/otfabric/otfp/protocols/iso"
	"github.com/otfabric/otfp/transport"
)

const (
	protocolName    = core.ProtocolS7
	maxResponseSize = 512

	// S7comm constants.
	s7ProtocolID     = 0x32 // S7comm protocol magic byte.
	s7MsgTypeJob     = 0x01 // Job request.
	s7MsgTypeAck     = 0x02 // Ack without data.
	s7MsgTypeAckData = 0x03 // Ack with data.

	// S7 Setup Communication function code.
	s7FuncSetupComm = 0xF0

	// S7 header sizes.
	s7HeaderSize    = 10 // Protocol ID(1) + MsgType(1) + Reserved(2) + PDU Ref(2) + Param Len(2) + Data Len(2)
	s7AckHeaderSize = 12 // Same + Error Class(1) + Error Code(1)
)

// Fingerprinter detects Siemens S7comm protocol.
type Fingerprinter struct{}

// New creates a new S7comm fingerprinter.
func New() *Fingerprinter {
	return &Fingerprinter{}
}

// Name returns the protocol identifier.
func (f *Fingerprinter) Name() core.Protocol {
	return protocolName
}

// Priority returns the detection order (lower = tested first).
func (f *Fingerprinter) Priority() int { return 20 }

// Detect attempts to identify S7comm on the target.
// Phase 1: COTP CR -> CC (ISO-on-TCP)
// Phase 2: S7 Setup Communication -> S7 ACK
func (f *Fingerprinter) Detect(ctx context.Context, target core.Target) (core.Result, error) {
	conn, err := transport.Dial(ctx, target.Addr(), target.EffectiveTimeout())
	if err != nil {
		return core.NoMatch(protocolName), fmt.Errorf("s7: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	// Phase 1: COTP Connection Request.
	// Use S7-specific TSAP parameters:
	// Calling TSAP: 0x01 0x00 (typically rack 0, slot 0 source)
	// Called TSAP:  0x01 0x02 (rack 0, slot 2 - common for S7-300/400)
	tsapParams := []byte{
		0xC1, 0x02, 0x01, 0x00, // Calling TSAP
		0xC2, 0x02, 0x01, 0x02, // Called TSAP (rack 0, slot 2)
		0xC0, 0x01, 0x0A, // TPDU size parameter: 1024 bytes
	}

	cotpCR := iso.BuildCOTPConnectionRequestWithParams(0x0000, 0x0001, 0x00, tsapParams)
	probe1 := iso.BuildTPKT(cotpCR)

	resp1, err := conn.SendReceive(probe1, maxResponseSize)
	if err != nil {
		return core.NoMatch(protocolName), fmt.Errorf("s7: phase1: %w", err)
	}

	// Validate Phase 1 response.
	cotpOK, cotpConfidence, cotpDetails := validateCOTPResponse(resp1)
	if !cotpOK {
		return core.NoMatch(protocolName).WithExchange("phase1-cotp", probe1, resp1), nil
	}

	// Phase 2: S7 Setup Communication.
	probe2 := buildS7SetupProbe()

	resp2, err := conn.SendReceive(probe2, maxResponseSize)
	if err != nil {
		// Got COTP but S7 setup failed - this is ISO-on-TCP but not S7.
		r := core.Result{
			Protocol:   protocolName,
			Matched:    false,
			Confidence: cotpConfidence * 0.5,
			Details:    cotpDetails + ", S7 setup failed",
		}
		return r.WithExchange("phase1-cotp", probe1, resp1), nil
	}

	// Validate Phase 2 response.
	return validateS7Response(resp2, cotpConfidence, cotpDetails).
		WithExchange("phase1-cotp", probe1, resp1).
		WithExchange("phase2-s7", probe2, resp2), nil
}

// validateCOTPResponse validates the COTP Connection Confirm.
func validateCOTPResponse(resp []byte) (bool, core.Confidence, string) {
	if len(resp) < iso.TPKTHeaderLen+2 {
		return false, 0, ""
	}

	tpktLen := iso.ValidateTPKT(resp)
	if tpktLen == 0 {
		return false, 0, ""
	}

	cotpData := resp[iso.TPKTHeaderLen:]
	if !iso.ValidateCOTPCC(cotpData) {
		return false, 0, ""
	}

	return true, 0.35, "COTP CC confirmed"
}

// buildS7SetupProbe constructs an S7 Setup Communication request wrapped in TPKT/COTP DT.
func buildS7SetupProbe() []byte {
	// S7 Setup Communication parameters:
	// Reserved(1) + Max AmQ calling(2) + Max AmQ called(2) + PDU Length(2) = 7 bytes
	s7Params := []byte{
		0x00,       // Reserved
		0x00, 0x01, // Max AmQ calling
		0x00, 0x01, // Max AmQ called
		0x01, 0xE0, // PDU length (480)
	}

	// S7 header (Job request).
	s7Header := make([]byte, s7HeaderSize)
	s7Header[0] = s7ProtocolID                                         // Protocol ID: 0x32
	s7Header[1] = s7MsgTypeJob                                         // Message type: Job
	binary.BigEndian.PutUint16(s7Header[2:4], 0x0000)                  // Reserved
	binary.BigEndian.PutUint16(s7Header[4:6], 0x0001)                  // PDU reference
	binary.BigEndian.PutUint16(s7Header[6:8], uint16(1+len(s7Params))) // Parameter length (function code + params)
	binary.BigEndian.PutUint16(s7Header[8:10], 0x0000)                 // Data length

	// S7 PDU: header + function code + parameters.
	s7PDU := append(s7Header, s7FuncSetupComm)
	s7PDU = append(s7PDU, s7Params...)

	// Wrap in COTP DT (Data Transfer) header.
	cotpDT := []byte{
		0x02,           // COTP header length
		iso.COTPTypeDT, // DT PDU type
		0x80,           // TPDU number + EOT (last fragment)
	}

	// Combine COTP DT + S7 PDU.
	payload := append(cotpDT, s7PDU...)

	// Wrap in TPKT.
	return iso.BuildTPKT(payload)
}

// validateS7Response validates the S7 Setup Communication response.
func validateS7Response(resp []byte, baseConfidence core.Confidence, baseDetails string) core.Result {
	if len(resp) < iso.TPKTHeaderLen+3 {
		return core.NoMatch(protocolName)
	}

	confidence := baseConfidence
	details := baseDetails

	// Validate TPKT.
	tpktLen := iso.ValidateTPKT(resp)
	if tpktLen == 0 {
		return core.NoMatch(protocolName)
	}

	// Skip TPKT header.
	data := resp[iso.TPKTHeaderLen:]

	// Validate COTP DT header.
	if len(data) < 3 {
		return core.NoMatch(protocolName)
	}
	cotpLen := int(data[0])
	if cotpLen < 2 {
		return core.NoMatch(protocolName)
	}
	cotpType := data[1] & 0xF0
	if cotpType != iso.COTPTypeDT {
		return core.NoMatch(protocolName)
	}

	// Skip COTP DT header.
	s7Data := data[cotpLen+1:]

	if len(s7Data) < s7HeaderSize {
		return core.NoMatch(protocolName)
	}

	// Check S7 protocol ID.
	if s7Data[0] != s7ProtocolID {
		return core.NoMatch(protocolName)
	}
	confidence += 0.25
	details += ", S7 protocol ID (0x32)"

	// Check message type (should be Ack-Data for setup communication).
	msgType := s7Data[1]

	switch msgType {
	case s7MsgTypeAckData:
		confidence += 0.20
		details += ", Ack-Data response"

		// For Ack-Data, check error fields.
		if len(s7Data) >= s7AckHeaderSize {
			errorClass := s7Data[10]
			errorCode := s7Data[11]
			if errorClass == 0x00 && errorCode == 0x00 {
				confidence += 0.10
				details += ", No error"
			} else {
				confidence += 0.05
				details += fmt.Sprintf(", Error: class=0x%02X code=0x%02X", errorClass, errorCode)
			}

			// Check for Setup Communication function code in response parameters.
			paramLen := binary.BigEndian.Uint16(s7Data[6:8])
			if paramLen > 0 && len(s7Data) >= s7AckHeaderSize+1 {
				funcCode := s7Data[s7AckHeaderSize]
				if funcCode == s7FuncSetupComm {
					confidence += 0.10
					details += ", Setup Comm confirmed"
				}
			}
		}

	case s7MsgTypeAck:
		confidence += 0.15
		details += ", Ack response"
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	if confidence < 0.3 {
		return core.NoMatch(protocolName)
	}

	result := core.Match(protocolName, confidence, details)
	result.Fingerprint = &core.Fingerprint{
		ID:        "s7.setup_comm",
		Signature: details,
	}
	return result
}
