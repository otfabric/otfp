package dnp3

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/otfabric/otfp/core"
)

// startMockServer starts a TCP server that accepts one connection,
// reads data, and responds with the provided response bytes.
func startMockServer(t *testing.T, response []byte) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck

		buf := make([]byte, 1024)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Read(buf)

		if response != nil {
			_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_, _ = conn.Write(response)
		}
	}()

	return ln.Addr().String(), func() { _ = ln.Close() }
}

func parseAddr(addr string) (string, int) {
	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	return host, port
}

// buildDNP3Response builds a minimal DNP3 link-layer response frame with valid CRC.
func buildDNP3Response(control byte, dest, source uint16) []byte {
	frame := make([]byte, 10)
	frame[0] = 0x05
	frame[1] = 0x64
	frame[2] = 0x05 // length
	frame[3] = control
	frame[4] = byte(dest & 0xFF)
	frame[5] = byte(dest >> 8)
	frame[6] = byte(source & 0xFF)
	frame[7] = byte(source >> 8)
	crc := crc16DNP(frame[0:8])
	frame[8] = byte(crc & 0xFF)
	frame[9] = byte((crc >> 8) & 0xFF)
	return frame
}

func TestDNP3DetectValidLinkStatus(t *testing.T) {
	// Build a valid Link Status response: DIR=0, FC=0x0B.
	resp := buildDNP3Response(0x0B, 0x0000, 0x0001)
	addr, cleanup := startMockServer(t, resp)
	defer cleanup()

	host, port := parseAddr(addr)
	fp := New()
	result, err := fp.Detect(context.Background(), core.Target{
		IP:      host,
		Port:    port,
		Timeout: 2 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if !result.Matched {
		t.Error("Expected match for valid DNP3 Link Status response")
	}
	if result.Confidence < 0.9 {
		t.Errorf("Confidence too low: %f", result.Confidence)
	}
	t.Logf("Result: %s", result)
}

func TestDNP3DetectACKResponse(t *testing.T) {
	// ACK response: DIR=0, FC=0x00.
	resp := buildDNP3Response(0x00, 0x0000, 0x0001)
	addr, cleanup := startMockServer(t, resp)
	defer cleanup()

	host, port := parseAddr(addr)
	fp := New()
	result, err := fp.Detect(context.Background(), core.Target{
		IP:      host,
		Port:    port,
		Timeout: 2 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if !result.Matched {
		t.Error("Expected match for valid DNP3 ACK response")
	}
	if result.Confidence < 0.9 {
		t.Errorf("Confidence too low: %f", result.Confidence)
	}
	t.Logf("Result: %s", result)
}

func TestDNP3DetectWrongStartBytes(t *testing.T) {
	resp := buildDNP3Response(0x0B, 0x0000, 0x0001)
	resp[0] = 0xFF // Corrupt start byte.
	addr, cleanup := startMockServer(t, resp)
	defer cleanup()

	host, port := parseAddr(addr)
	fp := New()
	result, err := fp.Detect(context.Background(), core.Target{
		IP:      host,
		Port:    port,
		Timeout: 2 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if result.Matched {
		t.Error("Should not match with wrong start bytes")
	}
}

func TestDNP3DetectCorruptCRC(t *testing.T) {
	resp := buildDNP3Response(0x0B, 0x0000, 0x0001)
	resp[8] = 0xFF // Corrupt CRC.
	resp[9] = 0xFF
	addr, cleanup := startMockServer(t, resp)
	defer cleanup()

	host, port := parseAddr(addr)
	fp := New()
	result, err := fp.Detect(context.Background(), core.Target{
		IP:      host,
		Port:    port,
		Timeout: 2 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	// CRC is mandatory for valid DNP3 - corrupt CRC should not match.
	if result.Matched {
		t.Errorf("Should not match with corrupt CRC (confidence=%f)", result.Confidence)
	}
	t.Logf("Result: %s", result)
}

func TestDNP3DetectTruncatedResponse(t *testing.T) {
	resp := []byte{0x05, 0x64, 0x05}
	addr, cleanup := startMockServer(t, resp)
	defer cleanup()

	host, port := parseAddr(addr)
	fp := New()
	result, err := fp.Detect(context.Background(), core.Target{
		IP:      host,
		Port:    port,
		Timeout: 2 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if result.Matched {
		t.Error("Should not match truncated response")
	}
}

func TestDNP3DetectNoResponse(t *testing.T) {
	addr, cleanup := startMockServer(t, nil)
	defer cleanup()

	host, port := parseAddr(addr)
	fp := New()
	_, err := fp.Detect(context.Background(), core.Target{
		IP:      host,
		Port:    port,
		Timeout: 1 * time.Second,
	})
	_ = err // Should not panic.
}

func TestDNP3DetectConnectionRefused(t *testing.T) {
	fp := New()
	_, err := fp.Detect(context.Background(), core.Target{
		IP:      "127.0.0.1",
		Port:    1,
		Timeout: 1 * time.Second,
	})
	if err == nil {
		t.Error("Expected error for connection refused")
	}
}

func TestDNP3DetectRandomBinary(t *testing.T) {
	resp := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02}
	addr, cleanup := startMockServer(t, resp)
	defer cleanup()

	host, port := parseAddr(addr)
	fp := New()
	result, err := fp.Detect(context.Background(), core.Target{
		IP:      host,
		Port:    port,
		Timeout: 2 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if result.Matched {
		t.Error("Random binary should not match DNP3")
	}
}

func TestDNP3DetectInvalidLength(t *testing.T) {
	resp := buildDNP3Response(0x0B, 0x0000, 0x0001)
	resp[2] = 0x00 // Zero length - invalid.
	// Recompute CRC.
	crc := crc16DNP(resp[0:8])
	resp[8] = byte(crc & 0xFF)
	resp[9] = byte((crc >> 8) & 0xFF)
	addr, cleanup := startMockServer(t, resp)
	defer cleanup()

	host, port := parseAddr(addr)
	fp := New()
	result, err := fp.Detect(context.Background(), core.Target{
		IP:      host,
		Port:    port,
		Timeout: 2 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	// Start bytes match but length is invalid - reduced confidence.
	if result.Matched && result.Confidence >= 0.9 {
		t.Errorf("Should not have high confidence with invalid length: %f", result.Confidence)
	}
	t.Logf("Result: %s", result)
}

func TestDNP3Name(t *testing.T) {
	fp := New()
	if fp.Name() != core.ProtocolDNP3 {
		t.Errorf("Name() = %s, want %s", fp.Name(), core.ProtocolDNP3)
	}
}

func TestBuildProbe(t *testing.T) {
	probe := buildProbe()
	if len(probe) != 10 {
		t.Fatalf("probe length = %d, want 10", len(probe))
	}
	if probe[0] != 0x05 || probe[1] != 0x64 {
		t.Errorf("start bytes = %02X %02X, want 05 64", probe[0], probe[1])
	}
	if probe[2] != 0x05 {
		t.Errorf("length = 0x%02X, want 0x05", probe[2])
	}
	// Verify CRC.
	crc := crc16DNP(probe[0:8])
	gotCRC := uint16(probe[8]) | uint16(probe[9])<<8
	if gotCRC != crc {
		t.Errorf("CRC mismatch: got 0x%04X, computed 0x%04X", gotCRC, crc)
	}
}

func TestCRC16DNP(t *testing.T) {
	// Known test vector: DNP3 spec uses specific CRC values.
	// Test with a simple known input.
	data := []byte{0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x00, 0x00}
	crc := crc16DNP(data)
	// CRC should be non-zero for valid data.
	if crc == 0 {
		t.Error("CRC should not be zero for valid data")
	}
	// Verify deterministic.
	crc2 := crc16DNP(data)
	if crc != crc2 {
		t.Errorf("CRC not deterministic: %04X != %04X", crc, crc2)
	}
}

func TestDNP3DetectModbusEcho(t *testing.T) {
	// Simulate a Modbus device echoing the DNP3 probe with error flag at byte 7.
	probe := buildProbe()
	resp := make([]byte, len(probe))
	copy(resp, probe)
	resp[7] = probe[7] | 0x80 // Modbus error flag
	resp[8] = 0x04            // Exception code

	addr, cleanup := startMockServer(t, resp)
	defer cleanup()

	host, port := parseAddr(addr)
	fp := New()
	result, err := fp.Detect(context.Background(), core.Target{
		IP:      host,
		Port:    port,
		Timeout: 2 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if result.Matched {
		t.Errorf("Modbus echo should not match as DNP3 (confidence=%f)", result.Confidence)
	}
}
