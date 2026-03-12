// Package mms implements IEC 61850 MMS (Manufacturing Message Specification)
// protocol fingerprinting over ISO-on-TCP (RFC1006).
//
// Detection is based on TPKT/COTP connection-level handshake only.
// No MMS application association or ASN.1 parsing is performed.
package mms

import (
	"context"
	"fmt"

	"github.com/otfabric/otfp/core"
	"github.com/otfabric/otfp/protocols/iso"
	"github.com/otfabric/otfp/transport"
)

const (
	protocolName    = core.ProtocolMMS
	maxResponseSize = 512
)

// Fingerprinter detects IEC 61850 MMS protocol over ISO-on-TCP.
type Fingerprinter struct{}

// New creates a new MMS fingerprinter.
func New() *Fingerprinter {
	return &Fingerprinter{}
}

// Name returns the protocol identifier.
func (f *Fingerprinter) Name() core.Protocol {
	return protocolName
}

// Priority returns the detection order (lower = tested first).
func (f *Fingerprinter) Priority() int { return 10 }

// Detect attempts to identify IEC 61850 MMS on the target.
// It sends a TPKT/COTP Connection Request and validates the response.
func (f *Fingerprinter) Detect(ctx context.Context, target core.Target) (core.Result, error) {
	conn, err := transport.Dial(ctx, target.Addr(), target.EffectiveTimeout())
	if err != nil {
		return core.NoMatch(protocolName), fmt.Errorf("mms: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	// Build ISO-on-TCP COTP Connection Request.
	// Use standard TSAP parameters for MMS (generic ISO transport).
	// TSAP parameters: calling TSAP and called TSAP.
	tsapParams := []byte{
		0xC1, 0x02, 0x00, 0x01, // Calling TSAP: Parameter code 0xC1, length 2, value 0x0001
		0xC2, 0x02, 0x00, 0x01, // Called TSAP: Parameter code 0xC2, length 2, value 0x0001
	}

	cotpCR := iso.BuildCOTPConnectionRequestWithParams(0x0000, 0x0001, 0x00, tsapParams)
	probe := iso.BuildTPKT(cotpCR)

	resp, err := conn.SendReceive(probe, maxResponseSize)
	if err != nil {
		return core.NoMatch(protocolName), fmt.Errorf("mms: %w", err)
	}

	if isModbusErrorEcho(probe, resp) {
		return core.NoMatch(protocolName).WithExchange("probe", probe, resp), nil
	}

	return validateResponse(resp).WithExchange("probe", probe, resp), nil
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

// validateResponse checks the response for MMS over ISO-on-TCP indicators.
func validateResponse(resp []byte) core.Result {
	if len(resp) < iso.TPKTHeaderLen+2 {
		return core.NoMatch(protocolName)
	}

	var confidence core.Confidence
	details := ""

	// Check 1: Valid TPKT header.
	tpktLen := iso.ValidateTPKT(resp)
	if tpktLen == 0 {
		return core.NoMatch(protocolName)
	}
	confidence += 0.30
	details = "Valid TPKT header"

	// Check 2: COTP CC (Connection Confirm).
	cotpData := resp[iso.TPKTHeaderLen:]
	if !iso.ValidateCOTPCC(cotpData) {
		// TPKT header alone is insufficient to identify MMS.
		return core.NoMatch(protocolName)
	}
	confidence += 0.35
	details += ", COTP CC received"

	// Check 3: TPKT length consistency.
	if tpktLen <= len(resp) {
		confidence += 0.15
		details += ", Length consistent"
	}

	// Check 4: COTP header structure.
	if len(cotpData) >= 7 {
		headerLen := int(cotpData[0])
		pduType := cotpData[1] & 0xF0

		if pduType == iso.COTPTypeCC && headerLen >= 6 {
			confidence += 0.15
			details += ", CC structure valid"

			// Check TPDU class in CC response.
			if headerLen >= 6 {
				tpduClass := cotpData[6] & 0xF0
				if tpduClass == 0x00 {
					confidence += 0.05
					details += ", Class 0"
				}
			}
		}
	}

	// Note: This detects ISO-on-TCP / MMS capability.
	// S7comm also uses ISO-on-TCP but will be further distinguished
	// by the S7 fingerprinter which performs an additional S7 setup step.

	if confidence > 1.0 {
		confidence = 1.0
	}

	result := core.Match(protocolName, confidence, details)
	result.Fingerprint = &core.Fingerprint{
		ID:        "mms.cotp_cc",
		Signature: details,
	}
	return result
}
