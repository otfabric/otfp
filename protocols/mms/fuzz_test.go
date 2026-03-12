package mms

import "testing"

func FuzzValidateResponse(f *testing.F) {
	// Valid TPKT + COTP CC.
	f.Add([]byte{0x03, 0x00, 0x00, 0x0B, 0x06, 0xD0, 0x00, 0x01, 0x00, 0x02, 0x00})
	// Invalid TPKT version.
	f.Add([]byte{0x04, 0x00, 0x00, 0x0B, 0x06, 0xD0, 0x00, 0x01, 0x00, 0x02, 0x00})
	// Too short.
	f.Add([]byte{0x03, 0x00})
	// Empty.
	f.Add([]byte{})
	// HTTP response.
	f.Add([]byte("HTTP/1.1 200 OK\r\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		result := validateResponse(data)
		if result.Confidence < 0 || result.Confidence > 1.0 {
			t.Errorf("confidence out of range: %f", result.Confidence)
		}
	})
}
