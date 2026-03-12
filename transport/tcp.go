// Package transport provides low-level TCP connection utilities for OT protocol detection.
package transport

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"
)

// TCPConn wraps a net.Conn with convenience methods for protocol fingerprinting.
type TCPConn struct {
	conn    net.Conn
	timeout time.Duration
}

// Dial establishes a TCP connection to the given address with timeout and context support.
func Dial(ctx context.Context, addr string, timeout time.Duration) (*TCPConn, error) {
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial %s: %w", addr, err)
	}

	return &TCPConn{
		conn:    conn,
		timeout: timeout,
	}, nil
}

// Send writes data to the connection with deadline enforcement.
func (tc *TCPConn) Send(data []byte) error {
	if err := tc.conn.SetWriteDeadline(time.Now().Add(tc.timeout)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}

	n, err := tc.conn.Write(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if n != len(data) {
		return fmt.Errorf("short write: sent %d of %d bytes", n, len(data))
	}

	return nil
}

// Receive reads up to maxBytes from the connection with deadline enforcement.
// Returns the data read, which may be shorter than maxBytes.
// Returns an error only on connection-level failures, not on short reads.
func (tc *TCPConn) Receive(maxBytes int) ([]byte, error) {
	if err := tc.conn.SetReadDeadline(time.Now().Add(tc.timeout)); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}

	buf := make([]byte, maxBytes)
	n, err := tc.conn.Read(buf)
	if err != nil && err != io.EOF {
		return buf[:n], fmt.Errorf("read: %w", err)
	}

	return buf[:n], nil
}

// ReceiveExact reads exactly n bytes from the connection.
// Returns an error if fewer bytes are available before timeout.
func (tc *TCPConn) ReceiveExact(n int) ([]byte, error) {
	if err := tc.conn.SetReadDeadline(time.Now().Add(tc.timeout)); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}

	buf := make([]byte, n)
	_, err := io.ReadFull(tc.conn, buf)
	if err != nil {
		return nil, fmt.Errorf("read exact %d bytes: %w", n, err)
	}

	return buf, nil
}

// SendReceive sends data and reads the response in one operation.
func (tc *TCPConn) SendReceive(data []byte, maxResponseBytes int) ([]byte, error) {
	if err := tc.Send(data); err != nil {
		return nil, err
	}
	return tc.Receive(maxResponseBytes)
}

// Close gracefully closes the TCP connection.
func (tc *TCPConn) Close() error {
	return tc.conn.Close()
}

// LocalAddr returns the local network address.
func (tc *TCPConn) LocalAddr() net.Addr {
	return tc.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (tc *TCPConn) RemoteAddr() net.Addr {
	return tc.conn.RemoteAddr()
}
