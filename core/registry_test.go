package core

import (
	"context"
	"testing"
)

// mockFingerprinter is a test double for Fingerprinter.
type mockFingerprinter struct {
	name     Protocol
	priority int
	result   Result
	err      error
}

func (m *mockFingerprinter) Name() Protocol { return m.name }

func (m *mockFingerprinter) Priority() int { return m.priority }

func (m *mockFingerprinter) Detect(_ context.Context, _ Target) (Result, error) {
	return m.result, m.err
}

func TestRegistryRegister(t *testing.T) {
	reg := NewRegistry()

	fp := &mockFingerprinter{name: ProtocolModbus}
	if err := reg.Register(fp); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Duplicate registration.
	if err := reg.Register(fp); err == nil {
		t.Error("expected error on duplicate registration")
	}
}

func TestRegistryGet(t *testing.T) {
	reg := NewRegistry()
	fp := &mockFingerprinter{name: ProtocolModbus}
	_ = reg.Register(fp)

	if got := reg.Get(ProtocolModbus); got == nil {
		t.Error("Get returned nil for registered fingerprinter")
	}
	if got := reg.Get(ProtocolS7); got != nil {
		t.Error("Get returned non-nil for unregistered fingerprinter")
	}
}

func TestRegistryAll(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&mockFingerprinter{name: ProtocolMMS, priority: 10})
	_ = reg.Register(&mockFingerprinter{name: ProtocolS7, priority: 20})
	_ = reg.Register(&mockFingerprinter{name: ProtocolENIP, priority: 30})

	all := reg.All()
	if len(all) != 3 {
		t.Errorf("All() returned %d items, want 3", len(all))
	}
	// All() now returns sorted by priority (ascending).
	if all[0].Name() != ProtocolMMS || all[1].Name() != ProtocolS7 || all[2].Name() != ProtocolENIP {
		t.Error("All() items not sorted by priority")
	}
}

func TestRegistryNames(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&mockFingerprinter{name: ProtocolModbus})
	_ = reg.Register(&mockFingerprinter{name: ProtocolMMS})

	names := reg.Names()
	if len(names) != 2 || names[0] != ProtocolModbus || names[1] != ProtocolMMS {
		t.Errorf("Names() = %v, want [ProtocolModbus ProtocolMMS]", names)
	}
}
