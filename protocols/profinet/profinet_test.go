package profinet

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

// buildBindAckResponse constructs a minimal DCE/RPC Bind-Ack response.
func buildBindAckResponse(accepted bool) []byte {
	// Minimal Bind-Ack: header(16) + max_xmit(2) + max_recv(2) + assoc(4) +
	// sec_addr_len(2) + sec_addr("") + pad + num_results(4) + result(4+20)
	secAddr := []byte{0x00}  // empty secondary addr
	secAddrLen := uint16(len(secAddr))
	padLen := 0
	if int(secAddrLen)%2 != 0 {
		padLen = 1
	}

	// Result entry: result(2) + reason(2) + transfer_syntax(20)
	resultEntry := make([]byte, 24)
	if accepted {
		binary.LittleEndian.PutUint16(resultEntry[0:2], 0) // acceptance
	} else {
		binary.LittleEndian.PutUint16(resultEntry[0:2], 2) // provider rejection
	}

	bodyLen := 2 + 2 + 4 + 2 + int(secAddrLen) + padLen + 4 + len(resultEntry)
	totalLen := 16 + bodyLen

	msg := make([]byte, totalLen)

	// Header.
	msg[0] = rpcVersion
	msg[1] = rpcMinorVersion
	msg[2] = rpcTypeBindAck
	msg[3] = 0x03 // first+last frag
	msg[4] = dataRepLittleEndian
	binary.LittleEndian.PutUint16(msg[8:10], uint16(totalLen))
	binary.LittleEndian.PutUint32(msg[12:16], 1) // Call ID

	// Body.
	off := 16
	binary.LittleEndian.PutUint16(msg[off:off+2], 5840) // max_xmit
	binary.LittleEndian.PutUint16(msg[off+2:off+4], 5840) // max_recv
	binary.LittleEndian.PutUint32(msg[off+4:off+8], 0) // assoc_group
	binary.LittleEndian.PutUint16(msg[off+8:off+10], secAddrLen)
	copy(msg[off+10:off+10+int(secAddrLen)], secAddr)
	resultStart := off + 10 + int(secAddrLen) + padLen
	binary.LittleEndian.PutUint32(msg[resultStart:resultStart+4], 1) // num results
	copy(msg[resultStart+4:], resultEntry)

	return msg
}

func buildBindNakResponse() []byte {
	msg := make([]byte, 20)
	msg[0] = rpcVersion
	msg[1] = rpcMinorVersion
	msg[2] = rpcTypeBindNak
	msg[3] = 0x03
	msg[4] = dataRepLittleEndian
	binary.LittleEndian.PutUint16(msg[8:10], 20)
	binary.LittleEndian.PutUint32(msg[12:16], 1)
	binary.LittleEndian.PutUint16(msg[16:18], 2) // reject reason
	return msg
}

func TestPROFINETDetectBindAck(t *testing.T) {
	resp := buildBindAckResponse(true)
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
		t.Error("Expected match for Bind-Ack response")
	}
	if result.Confidence < 0.8 {
		t.Errorf("Confidence too low: %f", result.Confidence)
	}
	t.Logf("Result: %s", result)
}

func TestPROFINETDetectBindAckRejection(t *testing.T) {
	resp := buildBindAckResponse(false)
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
		t.Error("Expected match for Bind-Ack with rejection (still valid PNIO)")
	}
	t.Logf("Result: %s", result)
}

func TestPROFINETDetectBindNak(t *testing.T) {
	resp := buildBindNakResponse()
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
		t.Error("Expected match for Bind-Nak (valid RPC endpoint)")
	}
	t.Logf("Result: %s", result)
}

func TestPROFINETDetectNonRPC(t *testing.T) {
	resp := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}
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
		t.Error("Should not match non-RPC data")
	}
}

func TestPROFINETDetectTruncated(t *testing.T) {
	resp := []byte{0x05, 0x00}
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

func TestPROFINETDetectNoResponse(t *testing.T) {
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

func TestPROFINETDetectConnectionRefused(t *testing.T) {
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

func TestPROFINETName(t *testing.T) {
	fp := New()
	if fp.Name() != core.ProtocolPROFINET {
		t.Errorf("Name() = %s, want %s", fp.Name(), core.ProtocolPROFINET)
	}
}

func TestBuildBindRequest(t *testing.T) {
	req := buildBindRequest()

	if len(req) < 16 {
		t.Fatalf("bind request too short: %d", len(req))
	}
	if req[0] != rpcVersion {
		t.Errorf("RPC version = %d, want %d", req[0], rpcVersion)
	}
	if req[2] != rpcTypeBind {
		t.Errorf("packet type = %d, want %d (Bind)", req[2], rpcTypeBind)
	}
	fragLen := binary.LittleEndian.Uint16(req[8:10])
	if int(fragLen) != len(req) {
		t.Errorf("fragment length = %d, actual = %d", fragLen, len(req))
	}
}
