package core

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestEngineDetectBestMatch(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&mockFingerprinter{
		name:     ProtocolMMS,
		priority: 10,
		result:   Match(ProtocolMMS, 0.3, "low match"),
	})
	_ = reg.Register(&mockFingerprinter{
		name:     ProtocolModbus,
		priority: 20,
		result:   Match(ProtocolModbus, 0.95, "high match"),
	})

	engine := NewEngine(reg, DefaultEngineConfig())
	result := engine.Detect(context.Background(), Target{IP: "127.0.0.1", Port: 1234})

	if result.Protocol != ProtocolModbus {
		t.Errorf("Detect() returned %s, want %s", result.Protocol, ProtocolModbus)
	}
	if result.Confidence != 0.95 {
		t.Errorf("Confidence = %f, want 0.95", result.Confidence)
	}
}

func TestEngineDetectUnknown(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&mockFingerprinter{
		name:   ProtocolMMS,
		result: NoMatch(ProtocolMMS),
	})

	engine := NewEngine(reg, DefaultEngineConfig())
	result := engine.Detect(context.Background(), Target{IP: "127.0.0.1", Port: 1234})

	if result.Protocol != ProtocolUnknown {
		t.Errorf("Detect() returned %s, want %s", result.Protocol, ProtocolUnknown)
	}
	if result.Matched {
		t.Error("Expected Matched=false")
	}
}

func TestEngineDetectProtocol(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&mockFingerprinter{
		name:   ProtocolModbus,
		result: Match(ProtocolModbus, 0.9, "ok"),
	})

	engine := NewEngine(reg, DefaultEngineConfig())

	t.Run("existing protocol", func(t *testing.T) {
		result, err := engine.DetectProtocol(context.Background(), Target{IP: "127.0.0.1", Port: 80}, ProtocolModbus)
		if err != nil {
			t.Fatalf("DetectProtocol error: %v", err)
		}
		if !result.Matched {
			t.Error("Expected match")
		}
	})

	t.Run("missing protocol", func(t *testing.T) {
		_, err := engine.DetectProtocol(context.Background(), Target{IP: "127.0.0.1", Port: 80}, ProtocolS7)
		if err == nil {
			t.Error("Expected error for missing protocol")
		}
	})
}

func TestEngineSequential(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&mockFingerprinter{
		name:     ProtocolMMS,
		priority: 10,
		result:   Match(ProtocolMMS, 0.5, "partial"),
	})
	_ = reg.Register(&mockFingerprinter{
		name:     ProtocolS7,
		priority: 20,
		result:   Match(ProtocolS7, 0.8, "good"),
	})

	config := EngineConfig{
		Parallel:                false,
		EarlyStop:               false,
		HighConfidenceThreshold: 0.9,
	}
	engine := NewEngine(reg, config)
	results := engine.DetectAll(context.Background(), Target{IP: "127.0.0.1", Port: 1234})

	if len(results) != 2 {
		t.Fatalf("DetectAll returned %d results, want 2", len(results))
	}
	// Should be sorted by confidence.
	if results[0].Confidence < results[1].Confidence {
		t.Error("Results not sorted by confidence descending")
	}
}

func TestEngineEarlyStop(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&mockFingerprinter{
		name:     ProtocolMMS,
		priority: 10,
		result:   Match(ProtocolMMS, 0.95, "early"),
	})
	_ = reg.Register(&mockFingerprinter{
		name:     ProtocolModbus,
		priority: 20,
		result:   NoMatch(ProtocolModbus),
	})

	config := EngineConfig{
		Parallel:                false,
		EarlyStop:               true,
		HighConfidenceThreshold: 0.9,
	}
	engine := NewEngine(reg, config)
	results := engine.DetectAll(context.Background(), Target{IP: "127.0.0.1", Port: 1234})

	// With early stop, should only have 1 result since first match is high confidence.
	if len(results) != 1 {
		t.Errorf("Expected 1 result with early stop, got %d", len(results))
	}
}

func TestEngineWithErrors(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&mockFingerprinter{
		name: ProtocolModbus,
		err:  fmt.Errorf("connection failed"),
	})

	engine := NewEngine(reg, DefaultEngineConfig())
	result := engine.Detect(context.Background(), Target{IP: "127.0.0.1", Port: 1234})

	if result.Protocol != ProtocolUnknown {
		t.Errorf("Expected %s, got %s", ProtocolUnknown, result.Protocol)
	}
}

func TestEngineContextCancellation(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&mockFingerprinter{
		name:   ProtocolModbus,
		result: NoMatch(ProtocolModbus),
	})

	config := EngineConfig{Parallel: false}
	engine := NewEngine(reg, config)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	time.Sleep(5 * time.Millisecond) // Ensure context is cancelled.

	results := engine.DetectAll(ctx, Target{IP: "127.0.0.1", Port: 1234})
	// With cancelled context, we may get 0 results.
	_ = results // Just ensure no panic.
}

func TestEngineEmptyRegistry(t *testing.T) {
	reg := NewRegistry()
	engine := NewEngine(reg, DefaultEngineConfig())
	result := engine.Detect(context.Background(), Target{IP: "127.0.0.1", Port: 1234})

	if result.Protocol != ProtocolUnknown {
		t.Errorf("Expected %s, got %s", ProtocolUnknown, result.Protocol)
	}
}

func TestEngineSafeConfig(t *testing.T) {
	cfg := SafeEngineConfig()
	if cfg.Parallel {
		t.Error("SafeEngineConfig should disable parallel")
	}
	if cfg.MaxConcurrency != 1 {
		t.Errorf("SafeEngineConfig MaxConcurrency = %d, want 1", cfg.MaxConcurrency)
	}
}

func TestEngineMaxConcurrency(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&mockFingerprinter{
		name:     ProtocolMMS,
		priority: 10,
		result:   NoMatch(ProtocolMMS),
	})
	_ = reg.Register(&mockFingerprinter{
		name:     ProtocolS7,
		priority: 20,
		result:   Match(ProtocolS7, 0.8, "ok"),
	})

	config := EngineConfig{
		Parallel:                true,
		EarlyStop:               false,
		HighConfidenceThreshold: 0.9,
		MaxConcurrency:          1,
	}
	engine := NewEngine(reg, config)
	results := engine.DetectAll(context.Background(), Target{IP: "127.0.0.1", Port: 5555})

	if len(results) != 2 {
		t.Fatalf("Expected 2 results with bounded concurrency, got %d", len(results))
	}
}

func TestEngineScan(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&mockFingerprinter{
		name:     ProtocolModbus,
		priority: 10,
		result:   Match(ProtocolModbus, 0.95, "good"),
	})

	engine := NewEngine(reg, DefaultEngineConfig())
	report := engine.Scan(context.Background(), Target{IP: "127.0.0.1", Port: 502})

	if report.Target.Port != 502 {
		t.Errorf("report.Target.Port = %d, want 502", report.Target.Port)
	}
	if report.StartedAt.IsZero() {
		t.Error("StartedAt should be set")
	}
	if report.Duration < 0 {
		t.Error("Duration should be non-negative")
	}
	if !report.BestMatch.Matched {
		t.Error("BestMatch should be matched")
	}
	if report.BestMatch.Protocol != ProtocolModbus {
		t.Errorf("BestMatch.Protocol = %s, want %s", report.BestMatch.Protocol, ProtocolModbus)
	}
}

func TestEngineObserver(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&mockFingerprinter{
		name:   ProtocolModbus,
		result: Match(ProtocolModbus, 0.9, "ok"),
	})

	obs := &testObserver{}
	config := DefaultEngineConfig()
	config.Observer = obs
	config.Parallel = false

	engine := NewEngine(reg, config)
	_ = engine.Detect(context.Background(), Target{IP: "127.0.0.1", Port: 502})

	obs.mu.Lock()
	defer obs.mu.Unlock()
	if obs.starts != 1 {
		t.Errorf("Observer.OnStart called %d times, want 1", obs.starts)
	}
	if obs.results != 1 {
		t.Errorf("Observer.OnResult called %d times, want 1", obs.results)
	}
}

func TestEngineMinInterval(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&mockFingerprinter{
		name:     ProtocolMMS,
		priority: 10,
		result:   NoMatch(ProtocolMMS),
	})
	_ = reg.Register(&mockFingerprinter{
		name:     ProtocolModbus,
		priority: 20,
		result:   NoMatch(ProtocolModbus),
	})

	config := EngineConfig{
		Parallel:                false,
		EarlyStop:               false,
		HighConfidenceThreshold: 0.9,
		MinInterval:             10 * time.Millisecond,
	}
	engine := NewEngine(reg, config)

	start := time.Now()
	results := engine.DetectAll(context.Background(), Target{IP: "127.0.0.1", Port: 1234})
	elapsed := time.Since(start)

	if len(results) != 2 {
		t.Fatalf("Expected 2 results, got %d", len(results))
	}
	// With 2 probes and 10ms min interval, should take at least 10ms.
	if elapsed < 10*time.Millisecond {
		t.Errorf("MinInterval not enforced: elapsed %v", elapsed)
	}
}

// testObserver is a thread-safe Observer for testing.
type testObserver struct {
	mu      sync.Mutex
	starts  int
	results int
}

func (o *testObserver) OnStart(_ Protocol, _ Target) {
	o.mu.Lock()
	o.starts++
	o.mu.Unlock()
}

func (o *testObserver) OnResult(_ Result) {
	o.mu.Lock()
	o.results++
	o.mu.Unlock()
}
