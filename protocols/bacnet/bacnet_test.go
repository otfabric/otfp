package bacnet

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/otfabric/otfp/core"
)

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

func buildBACnetResponse(funcCode byte, payload []byte) []byte {
	totalLen := bvlcHeaderSize + len(payload)
	frame := make([]byte, totalLen)
	frame[0] = bvlcType
	frame[1] = funcCode
	binary.BigEndian.PutUint16(frame[2:4], uint16(totalLen))
	copy(frame[4:], payload)
	return frame
}

func TestBACnetDetectValidResponse(t *testing.T) {
	payload := []byte{npduVersion, 0x00, 0x30, 0x08} // NPDU + I-Am
	resp := buildBACnetResponse(0x0A, payload)
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
		t.Error("Expected match for valid BACnet response")
	}
	if result.Confidence < 0.7 {
		t.Errorf("Confidence too low: %f", result.Confidence)
	}
	t.Logf("Result: %s", result)
}

func TestBACnetDetectWrongType(t *testing.T) {
	resp := []byte{0x82, 0x0A, 0x00, 0x04}
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
		t.Error("Should not match wrong BVLC type")
	}
}

func TestBACnetDetectTruncated(t *testing.T) {
	resp := []byte{0x81}
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

func TestBACnetDetectNoResponse(t *testing.T) {
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

func TestBACnetDetectConnectionRefused(t *testing.T) {
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

func TestBACnetName(t *testing.T) {
	fp := New()
	if fp.Name() != core.ProtocolBACnet {
		t.Errorf("Name() = %s, want %s", fp.Name(), core.ProtocolBACnet)
	}
}

func TestBuildProbe(t *testing.T) {
	probe := buildProbe()
	if len(probe) < bvlcHeaderSize {
		t.Fatalf("probe too short: %d", len(probe))
	}
	if probe[0] != bvlcType {
		t.Errorf("BVLC type = 0x%02X, want 0x%02X", probe[0], bvlcType)
	}
	pktLen := binary.BigEndian.Uint16(probe[2:4])
	if int(pktLen) != len(probe) {
		t.Errorf("length field = %d, actual = %d", pktLen, len(probe))
	}
}
