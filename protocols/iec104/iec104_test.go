package iec104

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

func TestIEC104DetectStartdtCon(t *testing.T) {
	// Valid STARTDT_CON response.
	resp := []byte{0x68, 0x04, 0x0B, 0x00, 0x00, 0x00}
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
		t.Error("Expected match for STARTDT_CON")
	}
	if result.Confidence < 0.9 {
		t.Errorf("Confidence too low: %f", result.Confidence)
	}
	t.Logf("Result: %s", result)
}

func TestIEC104DetectTestfrAct(t *testing.T) {
	// TESTFR_ACT from remote.
	resp := []byte{0x68, 0x04, 0x43, 0x00, 0x00, 0x00}
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
		t.Error("Expected match for TESTFR_ACT")
	}
	t.Logf("Result: %s", result)
}

func TestIEC104DetectWrongStartByte(t *testing.T) {
	resp := []byte{0xFF, 0x04, 0x0B, 0x00, 0x00, 0x00}
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
		t.Error("Should not match with wrong start byte")
	}
}

func TestIEC104DetectInvalidLength(t *testing.T) {
	// Length = 0 (invalid).
	resp := []byte{0x68, 0x00, 0x0B, 0x00, 0x00, 0x00}
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
	// Start byte matches but length is wrong.
	if result.Matched && result.Confidence >= 0.9 {
		t.Errorf("Should not have high confidence with invalid length: %f", result.Confidence)
	}
	t.Logf("Result: %s", result)
}

func TestIEC104DetectTruncatedResponse(t *testing.T) {
	resp := []byte{0x68, 0x04}
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

func TestIEC104DetectNoResponse(t *testing.T) {
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

func TestIEC104DetectConnectionRefused(t *testing.T) {
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

func TestIEC104DetectRandomBinary(t *testing.T) {
	resp := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00}
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
		t.Error("Random binary should not match IEC 104")
	}
}

func TestIEC104DetectSFormat(t *testing.T) {
	// S-format response: bits 0,1 = 01.
	resp := []byte{0x68, 0x04, 0x01, 0x00, 0x02, 0x00}
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
		t.Error("Expected match for S-format response")
	}
	t.Logf("Result: %s", result)
}

func TestIEC104Name(t *testing.T) {
	fp := New()
	if fp.Name() != core.ProtocolIEC104 {
		t.Errorf("Name() = %s, want %s", fp.Name(), core.ProtocolIEC104)
	}
}

func TestBuildProbe(t *testing.T) {
	probe := buildProbe()
	if len(probe) != 6 {
		t.Fatalf("probe length = %d, want 6", len(probe))
	}
	if probe[0] != 0x68 {
		t.Errorf("start byte = 0x%02X, want 0x68", probe[0])
	}
	if probe[1] != 0x04 {
		t.Errorf("length = 0x%02X, want 0x04", probe[1])
	}
	if probe[2] != 0x07 {
		t.Errorf("control = 0x%02X, want 0x07 (STARTDT_ACT)", probe[2])
	}
}
