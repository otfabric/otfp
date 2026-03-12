package enip

import (
	"encoding/binary"
	"testing"
)

func FuzzValidateResponse(f *testing.F) {
	// Seed corpus.
	// Valid RegisterSession response.
	valid := make([]byte, 28)
	binary.LittleEndian.PutUint16(valid[0:2], 0x0065)
	binary.LittleEndian.PutUint16(valid[2:4], 4)
	binary.LittleEndian.PutUint32(valid[4:8], 1)
	f.Add(valid)

	// Error response.
	errResp := make([]byte, 28)
	binary.LittleEndian.PutUint16(errResp[0:2], 0x0065)
	binary.LittleEndian.PutUint32(errResp[8:12], 1)
	f.Add(errResp)

	// Too short.
	f.Add([]byte{0x65, 0x00, 0x04, 0x00})
	// Wrong command.
	wrong := make([]byte, 24)
	binary.LittleEndian.PutUint16(wrong[0:2], 0xFFFF)
	f.Add(wrong)
	// Empty.
	f.Add([]byte{})
	// Random data.
	f.Add([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

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
