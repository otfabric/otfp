// SPDX-License-Identifier: MIT

package core

import (
	"context"
	"errors"
	"net"
	"os"
)

// ClassifyDial maps a dial failure to TimeoutError or ConnectionError.
func ClassifyDial(protocol Protocol, addr string, err error) error {
	if err == nil {
		return nil
	}
	if isTimeout(err) {
		return &TimeoutError{Protocol: protocol, Addr: addr, Err: err}
	}
	return &ConnectionError{Protocol: protocol, Addr: addr, Err: err}
}

// ClassifyIO maps a send/receive failure to TimeoutError or DetectError.
func ClassifyIO(protocol Protocol, addr, op string, err error) error {
	if err == nil {
		return nil
	}
	if isTimeout(err) {
		return &TimeoutError{Protocol: protocol, Addr: addr, Err: err}
	}
	return &DetectError{Protocol: protocol, Op: op, Err: err}
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
