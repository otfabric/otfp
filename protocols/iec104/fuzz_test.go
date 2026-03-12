package iec104

import "testing"

func FuzzValidateResponse(f *testing.F) {
	// Seed corpus.
	// Valid STARTDT_CON.
	f.Add([]byte{0x68, 0x04, 0x0B, 0x00, 0x00, 0x00})
	// TESTFR_ACT.
	f.Add([]byte{0x68, 0x04, 0x43, 0x00, 0x00, 0x00})
	// S-format.
	f.Add([]byte{0x68, 0x04, 0x01, 0x00, 0x02, 0x00})
	// Too short.
	f.Add([]byte{0x68, 0x04})
	// Wrong start byte.
	f.Add([]byte{0xFF, 0x04, 0x0B, 0x00, 0x00, 0x00})
	// Empty.
	f.Add([]byte{})
	// Random data.
	f.Add([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic.
		result := validateResponse(data)
		if result.Confidence < 0 || result.Confidence > 1.0 {
			t.Errorf("confidence out of range: %f", result.Confidence)
		}
		if result.Matched && result.Confidence == 0 {
			t.Error("matched but confidence is 0")
		}
	})
}
