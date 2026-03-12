package dnp3

import "testing"

func FuzzValidateResponse(f *testing.F) {
	// Seed corpus.
	// Valid DNP3 Link Status response.
	valid := buildDNP3Response(0x0B, 0x0000, 0x0001)
	f.Add(valid)
	// ACK response.
	f.Add(buildDNP3Response(0x00, 0x0000, 0x0001))
	// Too short.
	f.Add([]byte{0x05, 0x64})
	// Wrong start bytes.
	f.Add([]byte{0xFF, 0xFF, 0x05, 0x0B, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00})
	// Empty.
	f.Add([]byte{})
	// Random data.
	f.Add([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02})

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
