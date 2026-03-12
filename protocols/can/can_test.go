package can

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/otfabric/otfp/core"
)

func startMockServer(t *testing.T, responder func([]byte) []byte) (string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}

	done := make(chan struct{})

	go func() {
		defer close(done)

		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close() //nolint:errcheck

				buf := make([]byte, 1024)

				for {
					_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
					n, err := c.Read(buf)
					if err != nil {
						if ne, ok := err.(net.Error); ok && ne.Timeout() {
							return
						}
						if err == io.EOF {
							return
						}
						return
					}

					if responder == nil {
						continue
					}

					resp := responder(buf[:n])
					if resp == nil {
						continue
					}

					_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
					_, _ = c.Write(resp)
				}
			}(conn)
		}
	}()

	cleanup := func() {
		_ = ln.Close()
		<-done
	}

	return ln.Addr().String(), cleanup
}

func parseAddr(t *testing.T, addr string) (string, int) {
	t.Helper()

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("failed to split host/port %q: %v", addr, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("failed to parse port %q: %v", portStr, err)
	}

	return host, port
}

func TestCANDetectSLCANVersion(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req []byte) []byte {
		switch string(req) {
		case "V\r":
			return []byte("V1013\r")
		case "N\r":
			return nil
		default:
			return nil
		}
	})
	defer cleanup()

	host, port := parseAddr(t, addr)

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
		t.Fatal("expected match for strict SLCAN version response")
	}
	if result.Confidence < 0.85 {
		t.Fatalf("confidence too low: got %f want >= 0.85", result.Confidence)
	}
	if result.Fingerprint == nil {
		t.Fatal("expected fingerprint")
	}
	if result.Fingerprint.ID != "can.slcan" {
		t.Fatalf("fingerprint ID = %q, want %q", result.Fingerprint.ID, "can.slcan")
	}
}

func TestCANDetectSLCANSerial(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req []byte) []byte {
		switch string(req) {
		case "V\r":
			// Immediate response, but not a valid strict SLCAN version.
			return []byte("ERR\r")
		case "N\r":
			return []byte("NA1B2\r")
		default:
			return nil
		}
	})
	defer cleanup()

	host, port := parseAddr(t, addr)

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
		t.Fatal("expected match for strict SLCAN serial response")
	}
	if result.Confidence < 0.85 {
		t.Fatalf("confidence too low: got %f want >= 0.85", result.Confidence)
	}
	if result.Fingerprint == nil {
		t.Fatal("expected fingerprint")
	}
	if result.Fingerprint.Signature != "NA1B2" {
		t.Fatalf("fingerprint signature = %q, want %q", result.Fingerprint.Signature, "NA1B2")
	}
}

func TestCANDetectSLCANVersionAndSerial(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req []byte) []byte {
		switch string(req) {
		case "V\r":
			return []byte("V2.0\r")
		case "N\r":
			return []byte("NA1B2\r")
		default:
			return nil
		}
	})
	defer cleanup()

	host, port := parseAddr(t, addr)

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
		t.Fatal("expected match when both version and serial are returned")
	}
	if result.Confidence < 0.95 {
		t.Fatalf("confidence too low for dual evidence: got %f want >= 0.95", result.Confidence)
	}
	if result.Fingerprint == nil {
		t.Fatal("expected fingerprint")
	}
}

func TestCANDetectRejectBinaryData(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req []byte) []byte {
		switch string(req) {
		case "V\r":
			return []byte{0x00, 0x01, 0x80, 0xFF, 0xFE}
		case "N\r":
			return []byte{0x16, 0x03, 0x01, 0x00, 0x2A}
		default:
			return nil
		}
	})
	defer cleanup()

	host, port := parseAddr(t, addr)

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
		t.Fatal("should not match binary data")
	}
}

func TestCANDetectRejectHTTPResponse(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req []byte) []byte {
		return []byte("HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\n\r\n<html>nope</html>")
	})
	defer cleanup()

	host, port := parseAddr(t, addr)

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
		t.Fatal("should not match HTTP response")
	}
}

func TestCANDetectRejectJSONResponse(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req []byte) []byte {
		return []byte("{\"version\":\"1.0\"}\r\n")
	})
	defer cleanup()

	host, port := parseAddr(t, addr)

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
		t.Fatal("should not match JSON response")
	}
}

func TestCANDetectRejectACKOnly(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req []byte) []byte {
		switch string(req) {
		case "V\r":
			return []byte("\r")
		case "N\r":
			return []byte("\a")
		default:
			return nil
		}
	})
	defer cleanup()

	host, port := parseAddr(t, addr)

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
		t.Fatal("ACK-only responses must not be treated as CAN matches")
	}
}

func TestCANDetectNoResponse(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req []byte) []byte {
		return nil
	})
	defer cleanup()

	host, port := parseAddr(t, addr)

	fp := New()
	result, err := fp.Detect(context.Background(), core.Target{
		IP:      host,
		Port:    port,
		Timeout: 1 * time.Second,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Matched {
		t.Fatal("expected no match for no response")
	}
}

func TestCANDetectConnectionRefused(t *testing.T) {
	fp := New()
	_, err := fp.Detect(context.Background(), core.Target{
		IP:      "127.0.0.1",
		Port:    1,
		Timeout: 1 * time.Second,
	})
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestCANName(t *testing.T) {
	fp := New()
	if fp.Name() != core.ProtocolCAN {
		t.Fatalf("Name() = %s, want %s", fp.Name(), core.ProtocolCAN)
	}
}

func TestMatchesSLCAN(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{"version", []byte("V1013\r"), true},
		{"version_dot", []byte("V2.0\r"), true},
		{"version_multi_dot", []byte("V1.2.3\r"), true},
		{"serial", []byte("NA1B2\r"), true},
		{"serial_lower_hex", []byte("Naa10\r"), true},

		{"ack_cr", []byte("\r"), false},
		{"ack_bel", []byte("\a"), false},
		{"empty", []byte{}, false},
		{"random", []byte("hello world"), false},
		{"short_v", []byte("V"), false},
		{"short_n", []byte("N"), false},
		{"bad_version_alpha", []byte("Vabc\r"), false},
		{"bad_version_text", []byte("Version: 1.0\r"), false},
		{"bad_serial_dash", []byte("N-123\r"), false},
		{"http", []byte("HTTP/1.1 200 OK\r\n\r\n"), false},
		{"json", []byte("{\"ok\":true}\r\n"), false},
		{"tls_like", []byte{0x16, 0x03, 0x01, 0x00, 0x2A}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesSLCAN(tt.input)
			if got != tt.want {
				t.Fatalf("matchesSLCAN(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateResponse(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantMatch bool
		minConf   core.Confidence
		wantFPID  string
	}{
		{
			name:      "strict_version",
			input:     []byte("V1013\r"),
			wantMatch: true,
			minConf:   0.85,
			wantFPID:  "can.slcan",
		},
		{
			name:      "strict_serial",
			input:     []byte("NA1B2\r"),
			wantMatch: true,
			minConf:   0.85,
			wantFPID:  "can.slcan",
		},
		{
			name:      "ack_only",
			input:     []byte("\r"),
			wantMatch: false,
		},
		{
			name:      "http",
			input:     []byte("HTTP/1.1 200 OK\r\n\r\n"),
			wantMatch: false,
		},
		{
			name:      "json",
			input:     []byte("{\"version\":\"1.0\"}\r\n"),
			wantMatch: false,
		},
		{
			name:      "binary",
			input:     []byte{0x00, 0x01, 0x80, 0xFF},
			wantMatch: false,
		},
		{
			name:      "random_text",
			input:     []byte("hello world\r\n"),
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateResponse(tt.input)

			if result.Matched != tt.wantMatch {
				t.Fatalf("validateResponse(%q) matched = %v, want %v", tt.input, result.Matched, tt.wantMatch)
			}

			if tt.wantMatch {
				if result.Confidence < tt.minConf {
					t.Fatalf("confidence = %f, want >= %f", result.Confidence, tt.minConf)
				}
				if result.Fingerprint == nil {
					t.Fatal("expected fingerprint")
				}
				if result.Fingerprint.ID != tt.wantFPID {
					t.Fatalf("fingerprint ID = %q, want %q", result.Fingerprint.ID, tt.wantFPID)
				}
			} else {
				if result.Confidence != 0 {
					t.Fatalf("expected zero confidence for no-match, got %f", result.Confidence)
				}
			}
		})
	}
}
