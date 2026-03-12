package s7

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/otfabric/otfp/core"
	"github.com/otfabric/otfp/protocols/iso"
)

// mockS7Server handles a two-phase S7 handshake.
func startMockS7Server(t *testing.T, cotpResp []byte, s7Resp []byte) (string, func()) {
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

		// Phase 1: Read COTP CR, respond with COTP CC.
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Read(buf)

		if cotpResp != nil {
			_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_, _ = conn.Write(cotpResp)
		}

		// Phase 2: Read S7 Setup, respond with S7 Ack.
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Read(buf)

		if s7Resp != nil {
			_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_, _ = conn.Write(s7Resp)
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

func buildCOTPCC() []byte {
	cc := []byte{
		0x06,
		iso.COTPTypeCC,
		0x00, 0x01,
		0x00, 0x02,
		0x00,
	}
	return iso.BuildTPKT(cc)
}

func buildS7AckData(errClass, errCode byte, funcCode byte) []byte {
	// S7 Ack-Data header (12 bytes) + function code + setup params (7 bytes).
	s7Header := make([]byte, s7AckHeaderSize)
	s7Header[0] = s7ProtocolID
	s7Header[1] = s7MsgTypeAckData
	binary.BigEndian.PutUint16(s7Header[2:4], 0x0000)  // Reserved
	binary.BigEndian.PutUint16(s7Header[4:6], 0x0001)  // PDU ref
	binary.BigEndian.PutUint16(s7Header[6:8], 0x0008)  // Param length (1 + 7)
	binary.BigEndian.PutUint16(s7Header[8:10], 0x0000) // Data length
	s7Header[10] = errClass
	s7Header[11] = errCode

	params := []byte{funcCode, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xE0}

	payload := append(s7Header, params...)

	// Wrap in COTP DT.
	cotpDT := []byte{0x02, iso.COTPTypeDT, 0x80}
	cotpPayload := append(cotpDT, payload...)

	return iso.BuildTPKT(cotpPayload)
}

func TestS7DetectValid(t *testing.T) {
	cotpResp := buildCOTPCC()
	s7Resp := buildS7AckData(0x00, 0x00, s7FuncSetupComm)
	addr, cleanup := startMockS7Server(t, cotpResp, s7Resp)
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
		t.Error("Expected match for valid S7 response")
	}
	if result.Confidence < 0.8 {
		t.Errorf("Confidence too low: %f", result.Confidence)
	}
	t.Logf("Result: %s", result)
}

func TestS7DetectNoCOTPCC(t *testing.T) {
	// Respond with non-COTP data.
	badResp := []byte{0x04, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x00}
	addr, cleanup := startMockS7Server(t, badResp, nil)
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
		t.Error("Should not match without valid COTP CC")
	}
}

func TestS7DetectCOTPButNoS7(t *testing.T) {
	// Valid COTP CC but no S7 response (MMS endpoint, not S7).
	cotpResp := buildCOTPCC()
	addr, cleanup := startMockS7Server(t, cotpResp, nil)
	defer cleanup()

	host, port := parseAddr(addr)
	fp := New()
	result, err := fp.Detect(context.Background(), core.Target{
		IP:      host,
		Port:    port,
		Timeout: 2 * time.Second,
	})

	// Should not match as S7 if S7 setup phase fails.
	_ = err
	if result.Matched {
		t.Error("Should not match as S7 without S7 setup response")
	}
}

func TestS7DetectWithError(t *testing.T) {
	cotpResp := buildCOTPCC()
	// S7 Ack-Data with error.
	s7Resp := buildS7AckData(0x81, 0x04, s7FuncSetupComm)
	addr, cleanup := startMockS7Server(t, cotpResp, s7Resp)
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
	// Even with S7 error, it should still be identified as S7.
	if !result.Matched {
		t.Error("Expected match even with S7 error response")
	}
	t.Logf("Result: %s", result)
}

func TestS7DetectConnectionRefused(t *testing.T) {
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

func TestS7Name(t *testing.T) {
	fp := New()
	if fp.Name() != core.ProtocolS7 {
		t.Errorf("Name() = %s, want %s", fp.Name(), core.ProtocolS7)
	}
}

func TestBuildS7SetupProbe(t *testing.T) {
	probe := buildS7SetupProbe()

	// Verify TPKT header.
	if probe[0] != iso.TPKTVersion {
		t.Errorf("TPKT version = 0x%02X, want 0x%02X", probe[0], iso.TPKTVersion)
	}

	// Verify COTP DT.
	cotpStart := iso.TPKTHeaderLen
	if probe[cotpStart+1]&0xF0 != iso.COTPTypeDT {
		t.Errorf("COTP type = 0x%02X, want DT (0x%02X)", probe[cotpStart+1]&0xF0, iso.COTPTypeDT)
	}

	// Verify S7 protocol ID.
	s7Start := cotpStart + 3 // COTP DT header is 3 bytes
	if probe[s7Start] != s7ProtocolID {
		t.Errorf("S7 Protocol ID = 0x%02X, want 0x%02X", probe[s7Start], s7ProtocolID)
	}

	// Verify message type is Job.
	if probe[s7Start+1] != s7MsgTypeJob {
		t.Errorf("S7 msg type = 0x%02X, want 0x%02X", probe[s7Start+1], s7MsgTypeJob)
	}
}
