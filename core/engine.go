package core

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Observer receives callbacks during protocol detection for instrumentation.
// Implementations must be safe for concurrent use when Parallel is true.
// All methods must be non-blocking.
type Observer interface {
	// OnStart is called before each protocol detection attempt begins.
	OnStart(protocol Protocol, target Target)
	// OnResult is called after each detection attempt completes.
	OnResult(result Result)
}

// EngineConfig configures the detection engine behavior.
type EngineConfig struct {
	// Parallel enables parallel protocol detection.
	// When false, protocols are tested sequentially.
	Parallel bool

	// EarlyStop causes the engine to stop after the first high-confidence match
	// (Confidence >= HighConfidenceThreshold).
	EarlyStop bool

	// HighConfidenceThreshold is the minimum confidence to trigger early stop.
	// Default: 0.9
	HighConfidenceThreshold Confidence

	// MaxConcurrency limits the number of in-flight goroutines when Parallel
	// is true. Zero or negative means unbounded.
	MaxConcurrency int

	// MinInterval enforces a minimum delay between sequential protocol
	// attempts (or between goroutine launches in parallel mode).
	// In ICS environments, burst scanning may trigger IDS alerts.
	// Zero means no delay.
	MinInterval time.Duration

	// Observer receives callbacks during detection for metrics, tracing,
	// or audit logging. Nil disables observation.
	Observer Observer
}

// DefaultEngineConfig returns sensible default engine configuration.
// Parallel is disabled by default because protocol detection always targets
// a single endpoint, and many industrial devices cannot handle concurrent
// TCP connections reliably — leading to non-deterministic results.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		Parallel:                false,
		EarlyStop:               true,
		HighConfidenceThreshold: 0.9,
		MaxConcurrency:          0,
	}
}

// SafeEngineConfig returns a conservative configuration suitable for
// production OT environments where minimising network impact is critical.
func SafeEngineConfig() EngineConfig {
	return EngineConfig{
		Parallel:                false,
		EarlyStop:               true,
		HighConfidenceThreshold: 0.9,
		MaxConcurrency:          1,
	}
}

// Engine orchestrates protocol detection using registered fingerprinters.
type Engine struct {
	registry *Registry
	config   EngineConfig
}

// NewEngine creates a new detection engine with the given registry and config.
func NewEngine(registry *Registry, config EngineConfig) *Engine {
	if config.HighConfidenceThreshold <= 0 {
		config.HighConfidenceThreshold = 0.9
	}
	return &Engine{
		registry: registry,
		config:   config,
	}
}

// ScanReport is a structured summary of a complete detection run.
type ScanReport struct {
	// Target is the endpoint that was scanned.
	Target Target

	// StartedAt records when the scan began.
	StartedAt time.Time

	// FinishedAt records when the scan completed.
	FinishedAt time.Time

	// Duration is the wall-clock time of the scan.
	Duration time.Duration

	// Results holds all individual detection outcomes, sorted by
	// confidence descending.
	Results []Result

	// BestMatch is the highest-confidence matched result, or a
	// ProtocolUnknown result if nothing matched.
	BestMatch Result
}

// Scan runs a full detection sweep and returns a structured ScanReport.
func (e *Engine) Scan(ctx context.Context, target Target) ScanReport {
	start := time.Now()
	results := e.DetectAll(ctx, target)
	end := time.Now()

	best := Result{
		Protocol:    ProtocolUnknown,
		Matched:     false,
		Confidence:  0.0,
		Details:     "No OT protocol detected",
		DetectionID: generateDetectionID(),
		Timestamp:   time.Now(),
	}
	for _, r := range results {
		if r.Matched && r.Confidence > best.Confidence {
			best = r
		}
	}

	return ScanReport{
		Target:     target,
		StartedAt:  start,
		FinishedAt: end,
		Duration:   end.Sub(start),
		Results:    results,
		BestMatch:  best,
	}
}

// DetectAll runs all registered fingerprinters against the target and returns
// all results sorted by confidence (highest first).
func (e *Engine) DetectAll(ctx context.Context, target Target) []Result {
	fps := e.registry.All()
	if len(fps) == 0 {
		return nil
	}

	if e.config.Parallel {
		return e.detectParallel(ctx, target, fps)
	}
	return e.detectSequential(ctx, target, fps)
}

// Detect runs all fingerprinters and returns the best match.
// If no protocol is detected, it returns a Result with Protocol=ProtocolUnknown.
func (e *Engine) Detect(ctx context.Context, target Target) Result {
	results := e.DetectAll(ctx, target)

	// Filter matched results.
	var matched []Result
	for _, r := range results {
		if r.Matched {
			matched = append(matched, r)
		}
	}

	if len(matched) == 0 {
		return Result{
			Protocol:    ProtocolUnknown,
			Matched:     false,
			Confidence:  0.0,
			Details:     "No OT protocol detected",
			DetectionID: generateDetectionID(),
			Timestamp:   time.Now(),
		}
	}

	// Return highest confidence.
	return matched[0]
}

// DetectProtocol runs a specific named fingerprinter against the target.
func (e *Engine) DetectProtocol(ctx context.Context, target Target, protocol Protocol) (Result, error) {
	fp := e.registry.Get(protocol)
	if fp == nil {
		return Result{}, &ProtocolNotFoundError{Protocol: protocol}
	}
	return fp.Detect(ctx, target)
}

// ProtocolNotFoundError is returned when a requested protocol is not registered.
type ProtocolNotFoundError struct {
	Protocol Protocol
}

func (e *ProtocolNotFoundError) Error() string {
	return "protocol not registered: " + e.Protocol.String()
}

func (e *Engine) detectSequential(ctx context.Context, target Target, fps []Fingerprinter) []Result {
	var results []Result

	for i, fp := range fps {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		// Enforce inter-probe delay.
		if e.config.MinInterval > 0 && i > 0 {
			select {
			case <-ctx.Done():
				return results
			case <-time.After(e.config.MinInterval):
			}
		}

		if e.config.Observer != nil {
			e.config.Observer.OnStart(fp.Name(), target)
		}

		result, err := fp.Detect(ctx, target)
		if err != nil {
			result = ErrorResult(fp.Name(), err)
		}

		if e.config.Observer != nil {
			e.config.Observer.OnResult(result)
		}

		results = append(results, result)

		if e.config.EarlyStop && result.Matched && result.Confidence >= e.config.HighConfidenceThreshold {
			break
		}
	}

	sortResults(results)
	return results
}

func (e *Engine) detectParallel(ctx context.Context, target Target, fps []Fingerprinter) []Result {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type indexedResult struct {
		result Result
		index  int
	}

	ch := make(chan indexedResult, len(fps))
	var wg sync.WaitGroup

	// Semaphore for concurrency limiting. Nil channel = unbounded.
	var sem chan struct{}
	if e.config.MaxConcurrency > 0 {
		sem = make(chan struct{}, e.config.MaxConcurrency)
	}

	for i, fp := range fps {
		// Stagger goroutine launches when MinInterval is set.
		if e.config.MinInterval > 0 && i > 0 {
			select {
			case <-ctx.Done():
				break
			case <-time.After(e.config.MinInterval):
			}
		}

		wg.Add(1)
		go func(idx int, fp Fingerprinter) {
			defer wg.Done()

			// Acquire semaphore slot if bounded.
			if sem != nil {
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					ch <- indexedResult{result: ErrorResult(fp.Name(), ctx.Err()), index: idx}
					return
				}
			}

			if e.config.Observer != nil {
				e.config.Observer.OnStart(fp.Name(), target)
			}

			result, err := fp.Detect(ctx, target)
			if err != nil {
				result = ErrorResult(fp.Name(), err)
			}

			if e.config.Observer != nil {
				e.config.Observer.OnResult(result)
			}

			ch <- indexedResult{result: result, index: idx}

			// Signal early stop if high confidence match.
			if e.config.EarlyStop && result.Matched && result.Confidence >= e.config.HighConfidenceThreshold {
				cancel()
			}
		}(i, fp)
	}

	// Close channel once all goroutines complete.
	go func() {
		wg.Wait()
		close(ch)
	}()

	results := make([]Result, 0, len(fps))
	for ir := range ch {
		results = append(results, ir.result)
	}

	sortResults(results)
	return results
}

func sortResults(results []Result) {
	sort.Slice(results, func(i, j int) bool {
		// Matched results first, then by confidence descending.
		if results[i].Matched != results[j].Matched {
			return results[i].Matched
		}
		return results[i].Confidence > results[j].Confidence
	})
}
