package modbus

import "testing"

func FuzzValidateResponse(f *testing.F) {
	// Seed corpus with various response types.
	// Valid Modbus exception response.
	f.Add([]byte{0x13, 0x37, 0x00, 0x00, 0x00, 0x03, 0x01, 0xAB, 0x01})
	// Valid Modbus normal response.
	f.Add([]byte{0x13, 0x37, 0x00, 0x00, 0x00, 0x05, 0x01, 0x2B, 0x0E, 0x01, 0x00})
	// Too short.
	f.Add([]byte{0x13, 0x37})
	// Wrong protocol ID.
	f.Add([]byte{0x13, 0x37, 0x00, 0x01, 0x00, 0x03, 0x01, 0x2B, 0x01})
	// Empty.
	f.Add([]byte{})
	// Random data.
	f.Add([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic.
		result := validateResponse(data)
		// Basic sanity checks.
		if result.Confidence < 0 || result.Confidence > 1.0 {
			t.Errorf("confidence out of range: %f", result.Confidence)
		}
		if result.Matched && result.Confidence == 0 {
			t.Error("matched but confidence is 0")
		}
	})
}
