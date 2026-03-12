package transport

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDialSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			_ = conn.Close()
		}
	}()

	conn, err := Dial(context.Background(), ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close() //nolint:errcheck
}

func TestDialConnectionRefused(t *testing.T) {
	_, err := Dial(context.Background(), "127.0.0.1:1", 1*time.Second)
	if err == nil {
		t.Error("Expected error for connection refused")
	}
}

func TestDialContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Dial(ctx, "127.0.0.1:1", 5*time.Second)
	if err == nil {
		t.Error("Expected error for cancelled context")
	}
}

func TestSendReceive(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck

	echoData := []byte{0x01, 0x02, 0x03, 0x04}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck

		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		_, _ = conn.Write(buf[:n])
	}()

	conn, err := Dial(context.Background(), ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck

	resp, err := conn.SendReceive(echoData, 1024)
	if err != nil {
		t.Fatalf("SendReceive error: %v", err)
	}

	if len(resp) != len(echoData) {
		t.Fatalf("Response length = %d, want %d", len(resp), len(echoData))
	}

	for i := range echoData {
		if resp[i] != echoData[i] {
			t.Errorf("resp[%d] = 0x%02X, want 0x%02X", i, resp[i], echoData[i])
		}
	}
}

func TestReceiveTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck
		// Never write back - let it timeout.
		time.Sleep(5 * time.Second)
	}()

	conn, err := Dial(context.Background(), ln.Addr().String(), 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck

	_, err = conn.Receive(1024)
	if err == nil {
		t.Error("Expected timeout error")
	}
}
