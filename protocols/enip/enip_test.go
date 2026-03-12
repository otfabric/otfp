package enip

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

func parseAddr(addr string) (string, int) {
	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	return host, port
}

// buildRegisterSessionResponse builds a valid RegisterSession response.
func buildRegisterSessionResponse(sessionID uint32, status uint32) []byte {
	resp := make([]byte, encapHeaderSize+4)
	binary.LittleEndian.PutUint16(resp[0:2], cmdRegisterSession)
	binary.LittleEndian.PutUint16(resp[2:4], 4) // data length
	binary.LittleEndian.PutUint32(resp[4:8], sessionID)
	binary.LittleEndian.PutUint32(resp[8:12], status)
	// Context and Options remain zero.
	// RegisterSession data.
	binary.LittleEndian.PutUint16(resp[24:26], 1) // protocol version
	binary.LittleEndian.PutUint16(resp[26:28], 0) // options
	return resp
}

func TestENIPDetectValidSession(t *testing.T) {
	resp := buildRegisterSessionResponse(0x00000001, 0x00000000)
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
		t.Error("Expected match for valid RegisterSession response")
	}
	if result.Confidence < 0.9 {
		t.Errorf("Confidence too low: %f", result.Confidence)
	}
	t.Logf("Result: %s", result)
}

func TestENIPDetectErrorResponse(t *testing.T) {
	// Error response: session=0, status=1 (unsupported command).
	resp := buildRegisterSessionResponse(0x00000000, 0x00000001)
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
	// Should still match with reduced confidence.
	if !result.Matched {
		t.Error("Expected match for error response (still valid EtherNet/IP)")
	}
	t.Logf("Result: %s", result)
}

func TestENIPDetectWrongCommand(t *testing.T) {
	resp := make([]byte, encapHeaderSize)
	binary.LittleEndian.PutUint16(resp[0:2], 0xFFFF) // Invalid command.
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
		t.Error("Should not match with invalid command")
	}
}

func TestENIPDetectTruncatedResponse(t *testing.T) {
	resp := []byte{0x65, 0x00, 0x04, 0x00}
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

func TestENIPDetectNoResponse(t *testing.T) {
	addr, cleanup := startMockServer(t, nil)
	defer cleanup()

	host, port := parseAddr(addr)
	fp := New()
	_, err := fp.Detect(context.Background(), core.Target{
		IP:      host,
		Port:    port,
		Timeout: 1 * time.Second,
	})
	_ = err
}

func TestENIPDetectConnectionRefused(t *testing.T) {
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

func TestENIPDetectRandomBinary(t *testing.T) {
	resp := []byte{
		0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
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
		t.Error("Random binary should not match EtherNet/IP")
	}
}

func TestENIPDetectPartialResponse(t *testing.T) {
	// Valid header but only 20 bytes (less than 24).
	resp := make([]byte, 20)
	binary.LittleEndian.PutUint16(resp[0:2], cmdRegisterSession)
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
		t.Error("Should not match partial response")
	}
}

func TestENIPName(t *testing.T) {
	fp := New()
	if fp.Name() != core.ProtocolENIP {
		t.Errorf("Name() = %s, want %s", fp.Name(), core.ProtocolENIP)
	}
}

func TestBuildProbe(t *testing.T) {
	probe := buildProbe()
	if len(probe) != 28 {
		t.Fatalf("probe length = %d, want 28", len(probe))
	}
	command := binary.LittleEndian.Uint16(probe[0:2])
	if command != cmdRegisterSession {
		t.Errorf("command = 0x%04X, want 0x%04X", command, cmdRegisterSession)
	}
	dataLen := binary.LittleEndian.Uint16(probe[2:4])
	if dataLen != 4 {
		t.Errorf("data length = %d, want 4", dataLen)
	}
	sessionID := binary.LittleEndian.Uint32(probe[4:8])
	if sessionID != 0 {
		t.Errorf("session ID = %d, want 0", sessionID)
	}
	protoVer := binary.LittleEndian.Uint16(probe[24:26])
	if protoVer != 1 {
		t.Errorf("protocol version = %d, want 1", protoVer)
	}
}

func TestENIPDetectModbusEcho(t *testing.T) {
	// Simulate a Modbus device echoing the ENIP probe with error flag at byte 7.
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
		t.Errorf("Modbus echo should not match as EtherNet/IP (confidence=%f)", result.Confidence)
	}
}
