package opcua

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

func buildACKResponse(version, recvBuf, sendBuf, maxMsg, maxChunk uint32) []byte {
	msg := make([]byte, 28)
	copy(msg[0:3], "ACK")
	msg[3] = 'F'
	binary.LittleEndian.PutUint32(msg[4:8], 28)
	binary.LittleEndian.PutUint32(msg[8:12], version)
	binary.LittleEndian.PutUint32(msg[12:16], recvBuf)
	binary.LittleEndian.PutUint32(msg[16:20], sendBuf)
	binary.LittleEndian.PutUint32(msg[20:24], maxMsg)
	binary.LittleEndian.PutUint32(msg[24:28], maxChunk)
	return msg
}

func buildERRResponse(errorCode uint32) []byte {
	msg := make([]byte, 16)
	copy(msg[0:3], "ERR")
	msg[3] = 'F'
	binary.LittleEndian.PutUint32(msg[4:8], 16)
	binary.LittleEndian.PutUint32(msg[8:12], errorCode)
	// Reason string length = 0.
	binary.LittleEndian.PutUint32(msg[12:16], 0)
	return msg
}

func TestOPCUADetectValidACK(t *testing.T) {
	resp := buildACKResponse(0, 65535, 65535, 0, 0)
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
		t.Error("Expected match for valid ACK response")
	}
	if result.Confidence < 0.8 {
		t.Errorf("Confidence too low: %f", result.Confidence)
	}
	t.Logf("Result: %s", result)
}

func TestOPCUADetectERR(t *testing.T) {
	resp := buildERRResponse(0x80010000)
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
		t.Error("Expected match for ERR response (valid OPC UA)")
	}
	t.Logf("Result: %s", result)
}

func TestOPCUADetectTruncated(t *testing.T) {
	resp := []byte{'A', 'C'}
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

func TestOPCUADetectWrongType(t *testing.T) {
	resp := make([]byte, 28)
	copy(resp[0:3], "MSG")
	resp[3] = 'F'
	binary.LittleEndian.PutUint32(resp[4:8], 28)
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
		t.Error("Should not match non-ACK/ERR response")
	}
}

func TestOPCUADetectNoResponse(t *testing.T) {
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

func TestOPCUADetectConnectionRefused(t *testing.T) {
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

func TestOPCUAName(t *testing.T) {
	fp := New()
	if fp.Name() != core.ProtocolOPCUA {
		t.Errorf("Name() = %s, want %s", fp.Name(), core.ProtocolOPCUA)
	}
}

func TestBuildHello(t *testing.T) {
	hello := buildHello()

	if len(hello) != 32 {
		t.Fatalf("hello length = %d, want 32", len(hello))
	}
	if string(hello[0:3]) != "HEL" {
		t.Errorf("message type = %q, want HEL", string(hello[0:3]))
	}
	if hello[3] != 'F' {
		t.Errorf("chunk type = %c, want F", hello[3])
	}
	msgSize := binary.LittleEndian.Uint32(hello[4:8])
	if msgSize != 32 {
		t.Errorf("message size = %d, want 32", msgSize)
	}
}
