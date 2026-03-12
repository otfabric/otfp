package core

import "fmt"

// Protocol represents a named OT protocol identifier as an efficient
// integer type. String representations are maintained via a lookup table.
// Protocol values are stable across versions and must not be reordered.
type Protocol uint8

// Known protocol identifiers.
const (
	ProtocolUnknown  Protocol = 0
	ProtocolModbus   Protocol = 1
	ProtocolMMS      Protocol = 2
	ProtocolS7       Protocol = 3
	ProtocolOPCUA    Protocol = 4
	ProtocolBACnet   Protocol = 5
	ProtocolCAN      Protocol = 6
	ProtocolPROFINET Protocol = 7
	ProtocolDNP3     Protocol = 8
	ProtocolIEC104   Protocol = 9
	ProtocolENIP     Protocol = 10
	protocolCount    Protocol = 11 // unexported sentinel
)

// protocolNames maps Protocol values to human-readable names.
var protocolNames = [protocolCount]string{
	ProtocolUnknown:  "Unknown",
	ProtocolModbus:   "Modbus TCP",
	ProtocolMMS:      "IEC 61850 MMS",
	ProtocolS7:       "Siemens S7comm",
	ProtocolOPCUA:    "OPC UA",
	ProtocolBACnet:   "BACnet/IP",
	ProtocolCAN:      "CAN (TCP Gateway)",
	ProtocolPROFINET: "PROFINET (Ethernet)",
	ProtocolDNP3:     "DNP3 (TCP)",
	ProtocolIEC104:   "IEC 60870-5-104",
	ProtocolENIP:     "EtherNet/IP",
}

// protocolsByName provides reverse lookup from name string to Protocol.
var protocolsByName map[string]Protocol

func init() {
	protocolsByName = make(map[string]Protocol, int(protocolCount))
	for i := Protocol(0); i < protocolCount; i++ {
		protocolsByName[protocolNames[i]] = i
	}
}

// String returns the human-readable protocol name.
func (p Protocol) String() string {
	if p < protocolCount {
		return protocolNames[p]
	}
	return "Unknown"
}

// IsValid reports whether p is a known, non-Unknown protocol.
func (p Protocol) IsValid() bool {
	return p > ProtocolUnknown && p < protocolCount
}

// ParseProtocol converts a protocol name string to its typed constant.
// Returns an error if the name does not match any known protocol.
func ParseProtocol(s string) (Protocol, error) {
	if p, ok := protocolsByName[s]; ok && p != ProtocolUnknown {
		return p, nil
	}
	return ProtocolUnknown, fmt.Errorf("unknown protocol: %q", s)
}

// AllProtocols returns every known protocol in recommended detection order.
// The order prioritises ISO-based protocols, then progressively moves to
// lighter-weight probes and niche gateways.
func AllProtocols() []Protocol {
	return []Protocol{
		ProtocolMMS,
		ProtocolS7,
		ProtocolENIP,
		ProtocolIEC104,
		ProtocolDNP3,
		ProtocolModbus,
		ProtocolOPCUA,
		ProtocolBACnet,
		ProtocolCAN,
		ProtocolPROFINET,
	}
}
