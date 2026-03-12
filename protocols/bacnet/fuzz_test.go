package bacnet

import "testing"

func FuzzValidateResponse(f *testing.F) {
	f.Add([]byte{0x81, 0x0A, 0x00, 0x08, 0x01, 0x00, 0x30, 0x08})
	f.Add([]byte{0x81, 0x0B, 0x00, 0x04})
	f.Add([]byte{0x82, 0x0A, 0x00, 0x04})
	f.Add([]byte{0x81})
	f.Add([]byte{})
	f.Add([]byte{0xDE, 0xAD, 0xBE, 0xEF})

	f.Fuzz(func(t *testing.T, data []byte) {
		result := validateResponse(data)
		if result.Confidence < 0 || result.Confidence > 1.0 {
			t.Errorf("confidence out of range: %f", result.Confidence)
		}
		if result.Matched && result.Confidence == 0 {
			t.Error("matched but confidence is 0")
		}
	})
}
