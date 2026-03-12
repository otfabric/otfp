package modbus

import (
	"context"
	"encoding/binary"
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

// buildModbusResponse creates a valid Modbus TCP response frame.
func buildModbusResponse(transactionID uint16, unitID byte, fc byte, data []byte) []byte {
	frame := make([]byte, 7+1+len(data))
	binary.BigEndian.PutUint16(frame[0:2], transactionID)
	binary.BigEndian.PutUint16(frame[2:4], 0) // Protocol ID
	binary.BigEndian.PutUint16(frame[4:6], uint16(2+len(data)))
	frame[6] = unitID
	frame[7] = fc
	copy(frame[8:], data)
	return frame
}

func parseAddr(addr string) (string, int) {
	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	return host, port
}

func TestModbusDetectValidResponse(t *testing.T) {
	// Build a valid Modbus exception response (FC 0x2B with exception bit set).
	resp := buildModbusResponse(probeTransactionID, 0x01, fcReadDeviceID|exceptionMask, []byte{0x01})
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
		t.Error("Expected match for valid Modbus response")
	}
	if result.Confidence < 0.5 {
		t.Errorf("Confidence too low: %f", result.Confidence)
	}
	t.Logf("Result: %s", result)
}

func TestModbusDetectNormalResponse(t *testing.T) {
	// Build a valid normal Modbus FC43 response.
	meiData := []byte{meiType, readDevIDCode, 0x01, 0x00, 0x00, 0x01, 0x00, 0x06, 'V', 'e', 'n', 'd', 'o', 'r'}
	resp := buildModbusResponse(probeTransactionID, 0x01, fcReadDeviceID, meiData)
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
		t.Error("Expected match for valid Modbus response")
	}
	if result.Confidence < 0.8 {
		t.Errorf("Confidence too low for normal response: %f", result.Confidence)
	}
	t.Logf("Result: %s", result)
}

func TestModbusDetectInvalidProtocolID(t *testing.T) {
	// Response with wrong Protocol ID (not 0).
	resp := buildModbusResponse(probeTransactionID, 0x01, fcReadDeviceID, nil)
	binary.BigEndian.PutUint16(resp[2:4], 0x0001) // Wrong protocol ID
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
		t.Error("Should not match with wrong Protocol ID")
	}
}

func TestModbusDetectTruncatedResponse(t *testing.T) {
	// Response too short.
	resp := []byte{0x13, 0x37, 0x00}
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

func TestModbusDetectNoResponse(t *testing.T) {
	// Server that closes immediately.
	addr, cleanup := startMockServer(t, nil)
	defer cleanup()

	host, port := parseAddr(addr)
	fp := New()
	_, err := fp.Detect(context.Background(), core.Target{
		IP:      host,
		Port:    port,
		Timeout: 1 * time.Second,
	})

	// Should return error or no match, not panic.
	_ = err
}

func TestModbusDetectConnectionRefused(t *testing.T) {
	fp := New()
	_, err := fp.Detect(context.Background(), core.Target{
		IP:      "127.0.0.1",
		Port:    1, // Very unlikely to have a listener.
		Timeout: 1 * time.Second,
	})

	if err == nil {
		t.Error("Expected error for connection refused")
	}
}

func TestModbusDetectRandomBinary(t *testing.T) {
	// Random binary data (not Modbus).
	resp := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03}
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
	// Random data should not match (Protocol ID won't be 0).
	if result.Matched && result.Confidence > 0.5 {
		t.Errorf("Random binary should not match with high confidence: %f", result.Confidence)
	}
}

func TestModbusName(t *testing.T) {
	fp := New()
	if fp.Name() != core.ProtocolModbus {
		t.Errorf("Name() = %s, want %s", fp.Name(), core.ProtocolModbus)
	}
}

func TestBuildProbe(t *testing.T) {
	probe := buildProbe()

	// Verify MBAP header.
	if len(probe) != mbapHeaderSize+4 {
		t.Fatalf("probe length = %d, want %d", len(probe), mbapHeaderSize+4)
	}

	tid := binary.BigEndian.Uint16(probe[0:2])
	if tid != probeTransactionID {
		t.Errorf("Transaction ID = 0x%04X, want 0x%04X", tid, probeTransactionID)
	}

	pid := binary.BigEndian.Uint16(probe[2:4])
	if pid != 0 {
		t.Errorf("Protocol ID = %d, want 0", pid)
	}

	length := binary.BigEndian.Uint16(probe[4:6])
	if length != 5 {
		t.Errorf("Length = %d, want 5", length)
	}

	if probe[6] != 0x01 {
		t.Errorf("Unit ID = 0x%02X, want 0x01", probe[6])
	}

	if probe[7] != fcReadDeviceID {
		t.Errorf("FC = 0x%02X, want 0x%02X", probe[7], fcReadDeviceID)
	}
}
