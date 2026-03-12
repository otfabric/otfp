package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/otfabric/otfp/core"
)

// Exit codes — stable numeric API for callers.
const (
	exitDetected  = 0
	exitUnknown   = 1
	exitConnError = 2
	exitBadParams = 3
	exitPartial   = 4 // matched but below high-confidence threshold
)

// jsonOutput is the machine-readable result envelope.
type jsonOutput struct {
	Target          string            `json:"target"`
	Protocol        string            `json:"protocol"`
	Matched         bool              `json:"matched"`
	Confidence      float64           `json:"confidence"`
	ConfidenceLevel string            `json:"confidence_level"`
	Details         string            `json:"details,omitempty"`
	Error           *jsonError        `json:"error,omitempty"`
	Fingerprint     *core.Fingerprint `json:"fingerprint,omitempty"`
	DetectionID     string            `json:"detection_id"`
	Timestamp       string            `json:"timestamp"`
}

// jsonError provides structured error information for machine consumers.
type jsonError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// classifyError returns a structured jsonError from a core result error.
func classifyError(err error) *jsonError {
	if err == nil {
		return nil
	}
	errType := "unknown"
	switch err.(type) {
	case *core.TimeoutError:
		errType = "timeout"
	case *core.ConnectionError:
		errType = "connection"
	case *core.InvalidResponseError:
		errType = "invalid_response"
	case *core.DetectError:
		errType = "detection"
	}
	return &jsonError{Type: errType, Message: err.Error()}
}

func writeJSON(w io.Writer, target core.Target, r core.Result) int {
	out := jsonOutput{
		Target:          target.Addr(),
		Protocol:        r.Protocol.String(),
		Matched:         r.Matched,
		Confidence:      float64(r.Confidence),
		ConfidenceLevel: ConfidenceLevel(r.Confidence),
		Details:         r.Details,
		Error:           classifyError(r.Error),
		Fingerprint:     r.Fingerprint,
		DetectionID:     r.DetectionID,
		Timestamp:       r.Timestamp.Format(time.RFC3339Nano),
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out) //nolint:errcheck

	return exitCodeForResult(r)
}

func writeTextResult(w io.Writer, target core.Target, r core.Result, verbose bool, allResults []core.Result) int {
	_, _ = fmt.Fprintf(w, "Target: %s\n", target.Addr())

	if !r.Matched {
		_, _ = fmt.Fprintln(w, "Detected: Unknown")
		return exitUnknown
	}

	_, _ = fmt.Fprintf(w, "Detected: %s\n", r.Protocol)
	_, _ = fmt.Fprintf(w, "Confidence: %.2f (%s)\n", r.Confidence, ConfidenceLevel(r.Confidence))

	if verbose {
		_, _ = fmt.Fprintf(w, "Details: %s\n", r.Details)

		if len(allResults) > 1 {
			_, _ = fmt.Fprintln(w, "\nAll results:")
			for _, ar := range allResults {
				status := "no match"
				if ar.Matched {
					status = fmt.Sprintf("matched (%.2f)", ar.Confidence)
				}
				_, _ = fmt.Fprintf(w, "  %-20s %s\n", ar.Protocol, status)
			}
		}
	}

	// Ambiguity warning: multiple medium-confidence matches.
	var mediumMatches []core.Result
	for _, ar := range allResults {
		if ar.Matched && !ar.Confidence.IsHigh(0.9) {
			mediumMatches = append(mediumMatches, ar)
		}
	}
	if len(mediumMatches) >= 2 {
		_, _ = fmt.Fprintf(w, "\nWarning: %d protocols matched with medium confidence — manual review recommended\n", len(mediumMatches))
		for _, ar := range mediumMatches {
			_, _ = fmt.Fprintf(w, "  %-20s %.2f (%s)\n", ar.Protocol, ar.Confidence, ConfidenceLevel(ar.Confidence))
		}
	}

	return exitCodeForResult(r)
}

func writeTextSpecific(w io.Writer, protocol string, r core.Result) int {
	if r.Matched {
		_, _ = fmt.Fprintf(w, "%s: true\n", capitalizeFirst(protocol))
		_, _ = fmt.Fprintf(w, "Confidence: %.2f (%s)\n", r.Confidence, ConfidenceLevel(r.Confidence))
		_, _ = fmt.Fprintf(w, "Details: %s\n", r.Details)
		return exitCodeForResult(r)
	}
	_, _ = fmt.Fprintf(w, "%s: false\n", capitalizeFirst(protocol))
	return exitUnknown
}

// exitCodeForResult returns the appropriate exit code based on result.
func exitCodeForResult(r core.Result) int {
	if !r.Matched {
		return exitUnknown
	}
	if r.Confidence.IsHigh(0.9) {
		return exitDetected
	}
	return exitPartial
}

func capitalizeFirst(s string) string {
	if len(s) == 0 {
		return s
	}
	return string(s[0]-32) + s[1:]
}

// writeExchanges prints hex dumps of probe/response exchanges for a result.
func writeExchanges(w io.Writer, r core.Result) {
	if len(r.Exchanges) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "\n[debug] %s (matched=%v confidence=%.2f)\n", r.Protocol, r.Matched, r.Confidence)
	for _, ex := range r.Exchanges {
		_, _ = fmt.Fprintf(w, "  %s probe (%d bytes):\n", ex.Label, len(ex.Probe))
		_, _ = fmt.Fprint(w, indentHexDump(ex.Probe))
		_, _ = fmt.Fprintf(w, "  %s response (%d bytes):\n", ex.Label, len(ex.Response))
		_, _ = fmt.Fprint(w, indentHexDump(ex.Response))
	}
}

// indentHexDump returns a hex.Dump string with each line indented by 4 spaces.
func indentHexDump(data []byte) string {
	if len(data) == 0 {
		return "    (empty)\n"
	}
	dump := hex.Dump(data)
	var out string
	for _, line := range splitLines(dump) {
		if line != "" {
			out += "    " + line + "\n"
		}
	}
	return out
}

// splitLines splits a string into lines without importing strings.
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
