package iso

import "testing"

func TestBuildTPKT(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	pkt := BuildTPKT(payload)

	if len(pkt) != TPKTHeaderLen+3 {
		t.Fatalf("TPKT length = %d, want %d", len(pkt), TPKTHeaderLen+3)
	}
	if pkt[0] != TPKTVersion {
		t.Errorf("Version = 0x%02X, want 0x%02X", pkt[0], TPKTVersion)
	}
	if pkt[1] != TPKTReserved {
		t.Errorf("Reserved = 0x%02X, want 0x%02X", pkt[1], TPKTReserved)
	}
	totalLen := int(pkt[2])<<8 | int(pkt[3])
	if totalLen != 7 {
		t.Errorf("Total length = %d, want 7", totalLen)
	}
}

func TestValidateTPKT(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want int
	}{
		{"valid", []byte{0x03, 0x00, 0x00, 0x0B, 0x01, 0x02}, 11},
		{"too short", []byte{0x03, 0x00}, 0},
		{"wrong version", []byte{0x04, 0x00, 0x00, 0x0B}, 0},
		{"wrong reserved", []byte{0x03, 0x01, 0x00, 0x0B}, 0},
		{"short length", []byte{0x03, 0x00, 0x00, 0x02}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateTPKT(tt.data); got != tt.want {
				t.Errorf("ValidateTPKT() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestBuildCOTPConnectionRequest(t *testing.T) {
	cr := BuildCOTPConnectionRequest(0x0000, 0x0001, 0x00)

	if len(cr) != 7 {
		t.Fatalf("COTP CR length = %d, want 7", len(cr))
	}
	if cr[0] != 0x06 {
		t.Errorf("Header length byte = 0x%02X, want 0x06", cr[0])
	}
	if cr[1] != COTPTypeCR {
		t.Errorf("PDU type = 0x%02X, want 0x%02X", cr[1], COTPTypeCR)
	}
}

func TestBuildCOTPConnectionRequestWithParams(t *testing.T) {
	params := []byte{0xC1, 0x02, 0x00, 0x01}
	cr := BuildCOTPConnectionRequestWithParams(0x0000, 0x0001, 0x00, params)

	expectedLen := 7 + len(params) // base (7) + params
	if len(cr) != expectedLen {
		t.Fatalf("COTP CR with params length = %d, want %d", len(cr), expectedLen)
	}
	if cr[0] != byte(6+len(params)) {
		t.Errorf("Header length byte = 0x%02X, want 0x%02X", cr[0], 6+len(params))
	}
}

func TestValidateCOTPCC(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{
			"valid CC",
			[]byte{0x06, COTPTypeCC, 0x00, 0x01, 0x00, 0x02, 0x00},
			true,
		},
		{
			"CR not CC",
			[]byte{0x06, COTPTypeCR, 0x00, 0x01, 0x00, 0x02, 0x00},
			false,
		},
		{
			"too short",
			[]byte{0x06},
			false,
		},
		{
			"header too small",
			[]byte{0x02, COTPTypeCC, 0x00},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateCOTPCC(tt.data); got != tt.want {
				t.Errorf("ValidateCOTPCC() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractCOTPSrcRef(t *testing.T) {
	data := []byte{0x06, COTPTypeCC, 0x00, 0x01, 0x00, 0x42, 0x00}
	ref := ExtractCOTPSrcRef(data)
	if ref != 0x0042 {
		t.Errorf("ExtractCOTPSrcRef() = 0x%04X, want 0x0042", ref)
	}
}
