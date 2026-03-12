package can

import "testing"

func FuzzValidateResponse(f *testing.F) {
	f.Add([]byte("V1013\r"))
	f.Add([]byte("V2.0\r"))
	f.Add([]byte("NA1B2\r"))
	f.Add([]byte("\r"))
	f.Add([]byte("\a"))
	f.Add([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	f.Add([]byte("{\"version\":\"1.0\"}\r\n"))
	f.Add([]byte{0x00, 0x01, 0x80, 0xFF})
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x2A})
	f.Add([]byte{})
	f.Add([]byte("Hello World\r\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		result := validateResponse(data)

		if result.Confidence < 0 || result.Confidence > 1.0 {
			t.Fatalf("confidence out of range: %f", result.Confidence)
		}
		if result.Matched && result.Confidence == 0 {
			t.Fatal("matched but confidence is 0")
		}
		if !result.Matched && result.Fingerprint != nil {
			t.Fatal("no-match result should not carry a fingerprint")
		}
	})
}

func FuzzMatchesSLCAN(f *testing.F) {
	f.Add([]byte("V1013\r"))
	f.Add([]byte("V2.0\r"))
	f.Add([]byte("NA1B2\r"))
	f.Add([]byte("\r"))
	f.Add([]byte("\a"))
	f.Add([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	f.Add([]byte("{\"ok\":true}\r\n"))
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x2A})
	f.Add([]byte{0x00, 0xFF})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = matchesSLCAN(data)
	})
}
