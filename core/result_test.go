package core

import (
	"fmt"
	"strings"
	"testing"
)

func TestNoMatch(t *testing.T) {
	r := NoMatch(ProtocolModbus)
	if r.Matched {
		t.Error("NoMatch should have Matched=false")
	}
	if r.Protocol != ProtocolModbus {
		t.Errorf("Protocol = %s, want %s", r.Protocol, ProtocolModbus)
	}
	if r.Confidence != 0.0 {
		t.Errorf("Confidence = %f, want 0.0", r.Confidence)
	}
	if r.DetectionID == "" {
		t.Error("DetectionID should be set")
	}
	if r.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}
}

func TestMatch(t *testing.T) {
	r := Match(ProtocolModbus, 0.95, "test details")
	if !r.Matched {
		t.Error("Match should have Matched=true")
	}
	if r.Protocol != ProtocolModbus {
		t.Errorf("Protocol = %s, want %s", r.Protocol, ProtocolModbus)
	}
	if r.Confidence != 0.95 {
		t.Errorf("Confidence = %f, want 0.95", r.Confidence)
	}
	if r.Details != "test details" {
		t.Errorf("Details = %q, want %q", r.Details, "test details")
	}
	if r.DetectionID == "" {
		t.Error("DetectionID should be set")
	}
	if r.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}
}

func TestErrorResult(t *testing.T) {
	err := fmt.Errorf("connection refused")
	r := ErrorResult(ProtocolModbus, err)
	if r.Matched {
		t.Error("ErrorResult should have Matched=false")
	}
	if r.Protocol != ProtocolModbus {
		t.Errorf("Protocol = %s, want %s", r.Protocol, ProtocolModbus)
	}
	if r.Error == nil {
		t.Error("ErrorResult should preserve error")
	}
	if r.DetectionID == "" {
		t.Error("DetectionID should be set")
	}
}

func TestResultString(t *testing.T) {
	t.Run("matched", func(t *testing.T) {
		r := Match(ProtocolModbus, 0.90, "good match")
		s := r.String()
		if !strings.Contains(s, "Modbus") {
			t.Errorf("String() missing protocol name: %s", s)
		}
		if !strings.Contains(s, "0.90") {
			t.Errorf("String() missing confidence: %s", s)
		}
	})

	t.Run("not matched", func(t *testing.T) {
		r := NoMatch(ProtocolModbus)
		s := r.String()
		if !strings.Contains(s, "false") {
			t.Errorf("String() missing 'false': %s", s)
		}
	})

	t.Run("error", func(t *testing.T) {
		r := ErrorResult(ProtocolModbus, fmt.Errorf("timeout"))
		s := r.String()
		if !strings.Contains(s, "Error") {
			t.Errorf("String() missing 'Error': %s", s)
		}
	})
}

func TestConfidenceValid(t *testing.T) {
	tests := []struct {
		c    Confidence
		want bool
	}{
		{0.0, true},
		{0.5, true},
		{1.0, true},
		{-0.1, false},
		{1.1, false},
	}
	for _, tt := range tests {
		if got := tt.c.Valid(); got != tt.want {
			t.Errorf("Confidence(%f).Valid() = %v, want %v", tt.c, got, tt.want)
		}
	}
}

func TestConfidenceIsHigh(t *testing.T) {
	c := Confidence(0.95)
	if !c.IsHigh(0.9) {
		t.Error("0.95 should be high at threshold 0.9")
	}
	if c.IsHigh(0.99) {
		t.Error("0.95 should not be high at threshold 0.99")
	}
}

func TestWithFingerprint(t *testing.T) {
	r := Match(ProtocolModbus, 0.9, "ok")
	fp := &Fingerprint{
		ID:        "modbus.fc43",
		Signature: "txid_echo",
		Metadata:  map[string]string{"unit_id": "1"},
	}
	r2 := r.WithFingerprint(fp)
	if r2.Fingerprint == nil {
		t.Fatal("Fingerprint should be set")
	}
	if r2.Fingerprint.ID != "modbus.fc43" {
		t.Errorf("Fingerprint.ID = %q, want %q", r2.Fingerprint.ID, "modbus.fc43")
	}
	// Original should be unchanged.
	if r.Fingerprint != nil {
		t.Error("original result should not be modified")
	}
}

func TestFingerprintString(t *testing.T) {
	fp := &Fingerprint{ID: "test.probe", Signature: "sig"}
	if fp.String() != "test.probe:sig" {
		t.Errorf("Fingerprint.String() = %q", fp.String())
	}
	var nilFP *Fingerprint
	if nilFP.String() != "" {
		t.Errorf("nil Fingerprint.String() = %q", nilFP.String())
	}
}
