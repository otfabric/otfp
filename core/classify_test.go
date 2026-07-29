// SPDX-License-Identifier: MIT

package core

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
)

func TestClassifyDial_Timeout(t *testing.T) {
	err := ClassifyDial(ProtocolModbus, "10.0.0.1:502", context.DeadlineExceeded)
	var te *TimeoutError
	if !errors.As(err, &te) {
		t.Fatalf("want TimeoutError, got %T: %v", err, err)
	}
	if te.Protocol != ProtocolModbus || te.Addr != "10.0.0.1:502" {
		t.Fatalf("unexpected fields: %+v", te)
	}
}

func TestClassifyDial_Connection(t *testing.T) {
	err := ClassifyDial(ProtocolModbus, "10.0.0.1:502", errors.New("connection refused"))
	var ce *ConnectionError
	if !errors.As(err, &ce) {
		t.Fatalf("want ConnectionError, got %T: %v", err, err)
	}
}

func TestClassifyIO_TimeoutNetError(t *testing.T) {
	err := ClassifyIO(ProtocolModbus, "10.0.0.1:502", "receive", &net.DNSError{
		Err:       "i/o timeout",
		IsTimeout: true,
	})
	var te *TimeoutError
	if !errors.As(err, &te) {
		t.Fatalf("want TimeoutError, got %T: %v", err, err)
	}
}

func TestClassifyIO_DetectError(t *testing.T) {
	err := ClassifyIO(ProtocolModbus, "10.0.0.1:502", "send", errors.New("broken pipe"))
	var de *DetectError
	if !errors.As(err, &de) {
		t.Fatalf("want DetectError, got %T: %v", err, err)
	}
	if de.Op != "send" {
		t.Fatalf("op=%q", de.Op)
	}
}

func TestIsTimeout_OSDeadline(t *testing.T) {
	if !isTimeout(os.ErrDeadlineExceeded) {
		t.Fatal("os.ErrDeadlineExceeded should be timeout")
	}
	if isTimeout(errors.New("nope")) {
		t.Fatal("plain error should not be timeout")
	}
}
