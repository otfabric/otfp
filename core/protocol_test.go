package core

import "testing"

func TestProtocolString(t *testing.T) {
	if ProtocolModbus.String() != "Modbus TCP" {
		t.Errorf("ProtocolModbus.String() = %q", ProtocolModbus.String())
	}
	if ProtocolUnknown.String() != "Unknown" {
		t.Errorf("ProtocolUnknown.String() = %q", ProtocolUnknown.String())
	}
	// Out-of-range value.
	if Protocol(255).String() != "Unknown" {
		t.Errorf("Protocol(255).String() = %q", Protocol(255).String())
	}
}

func TestProtocolIsValid(t *testing.T) {
	for _, p := range AllProtocols() {
		if !p.IsValid() {
			t.Errorf("%s should be valid", p)
		}
	}
	if ProtocolUnknown.IsValid() {
		t.Error("ProtocolUnknown should not be valid")
	}
	if Protocol(255).IsValid() {
		t.Error("out-of-range protocol should not be valid")
	}
}

func TestAllProtocols(t *testing.T) {
	all := AllProtocols()
	if len(all) != 10 {
		t.Errorf("AllProtocols() returned %d, want 10", len(all))
	}
	// First should be MMS (ISO-based), last should be PROFINET.
	if all[0] != ProtocolMMS {
		t.Errorf("first protocol = %s, want %s", all[0], ProtocolMMS)
	}
	if all[len(all)-1] != ProtocolPROFINET {
		t.Errorf("last protocol = %s, want %s", all[len(all)-1], ProtocolPROFINET)
	}
}

func TestParseProtocol(t *testing.T) {
	p, err := ParseProtocol("Modbus TCP")
	if err != nil {
		t.Fatalf(`ParseProtocol("Modbus TCP") error: %v`, err)
	}
	if p != ProtocolModbus {
		t.Errorf("parsed = %s, want %s", p, ProtocolModbus)
	}

	_, err = ParseProtocol("bogus")
	if err == nil {
		t.Error(`ParseProtocol("bogus") should return error`)
	}

	_, err = ParseProtocol("Unknown")
	if err == nil {
		t.Error(`ParseProtocol("Unknown") should return error`)
	}
}
