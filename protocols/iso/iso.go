// Package iso provides shared ISO-on-TCP (RFC1006) TPKT/COTP constants and utilities
// used by both MMS and S7comm fingerprinters.
package iso

// TPKT constants (RFC 1006).
const (
	TPKTVersion  = 0x03
	TPKTReserved = 0x00
	TPKTHeaderLen = 4
)

// COTP PDU types.
const (
	COTPTypeCR = 0xE0 // Connection Request
	COTPTypeCC = 0xD0 // Connection Confirm
	COTPTypeDT = 0xF0 // Data Transfer
)

// BuildTPKT constructs a TPKT header for the given payload length.
// Total length = TPKT header (4) + payload length.
func BuildTPKT(payload []byte) []byte {
	totalLen := TPKTHeaderLen + len(payload)
	header := []byte{
		TPKTVersion,
		TPKTReserved,
		byte(totalLen >> 8),
		byte(totalLen & 0xFF),
	}
	return append(header, payload...)
}

// BuildCOTPConnectionRequest builds a COTP CR (Connection Request) TPDU.
// dstRef: destination reference
// srcRef: source reference
// tpduClass: transport class (typically 0)
func BuildCOTPConnectionRequest(dstRef, srcRef uint16, tpduClass byte) []byte {
	cotp := []byte{
		0x06,                                       // COTP header length (excluding this byte)
		COTPTypeCR,                                  // CR PDU type
		byte(dstRef >> 8), byte(dstRef & 0xFF),      // Destination reference
		byte(srcRef >> 8), byte(srcRef & 0xFF),      // Source reference
		tpduClass,                                   // Class 0, no extended formats
	}
	return cotp
}

// BuildCOTPConnectionRequestWithParams builds a COTP CR with additional parameter bytes.
func BuildCOTPConnectionRequestWithParams(dstRef, srcRef uint16, tpduClass byte, params []byte) []byte {
	headerLen := 6 + len(params) // 6 = type(1) + dstRef(2) + srcRef(2) + class(1)
	cotp := []byte{
		byte(headerLen), // COTP header length (excluding this byte)
		COTPTypeCR,
		byte(dstRef >> 8), byte(dstRef & 0xFF),
		byte(srcRef >> 8), byte(srcRef & 0xFF),
		tpduClass,
	}
	return append(cotp, params...)
}

// ValidateTPKT validates a TPKT header in the response.
// Returns the total packet length indicated by TPKT, or 0 if invalid.
func ValidateTPKT(data []byte) int {
	if len(data) < TPKTHeaderLen {
		return 0
	}
	if data[0] != TPKTVersion {
		return 0
	}
	if data[1] != TPKTReserved {
		return 0
	}
	totalLen := int(data[2])<<8 | int(data[3])
	if totalLen < TPKTHeaderLen {
		return 0
	}
	return totalLen
}

// ValidateCOTPCC validates a COTP Connection Confirm (CC) in the response.
// data should start after the TPKT header (at byte offset 4).
// Returns true if the response contains a valid CC PDU.
func ValidateCOTPCC(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	headerLen := int(data[0])
	if headerLen < 6 {
		return false
	}
	if len(data) < headerLen+1 {
		return false
	}
	pduType := data[1] & 0xF0
	return pduType == COTPTypeCC
}

// ExtractCOTPSrcRef extracts the source reference from a COTP CC response.
// data should start after the TPKT header.
func ExtractCOTPSrcRef(data []byte) uint16 {
	if len(data) < 6 {
		return 0
	}
	return uint16(data[4])<<8 | uint16(data[5])
}
