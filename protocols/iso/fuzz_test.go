package iso

import "testing"

func FuzzValidateTPKT(f *testing.F) {
	f.Add([]byte{0x03, 0x00, 0x00, 0x0B})
	f.Add([]byte{0x03, 0x00})
	f.Add([]byte{})
	f.Add([]byte{0x04, 0x00, 0x00, 0x0B})

	f.Fuzz(func(t *testing.T, data []byte) {
		result := ValidateTPKT(data)
		if result < 0 {
			t.Errorf("ValidateTPKT returned negative: %d", result)
		}
	})
}

func FuzzValidateCOTPCC(f *testing.F) {
	f.Add([]byte{0x06, 0xD0, 0x00, 0x01, 0x00, 0x02, 0x00})
	f.Add([]byte{0x06, 0xE0, 0x00, 0x01, 0x00, 0x02, 0x00})
	f.Add([]byte{0x02})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic.
		_ = ValidateCOTPCC(data)
	})
}
