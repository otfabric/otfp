package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/otfabric/otfp/core"
)

// protocolAliases maps short CLI names to typed Protocol identifiers.
var protocolAliases = map[string]core.Protocol{
	"modbus":   core.ProtocolModbus,
	"mms":      core.ProtocolMMS,
	"s7":       core.ProtocolS7,
	"opcua":    core.ProtocolOPCUA,
	"bacnet":   core.ProtocolBACnet,
	"can":      core.ProtocolCAN,
	"profinet": core.ProtocolPROFINET,
	"dnp3":     core.ProtocolDNP3,
	"iec104":   core.ProtocolIEC104,
	"enip":     core.ProtocolENIP,
}

// aliasForProtocol returns the short CLI alias for a protocol.
func aliasForProtocol(p core.Protocol) string {
	for alias, proto := range protocolAliases {
		if proto == p {
			return alias
		}
	}
	return p.String()
}

// runList prints all registered protocols with priorities.
func runList(w io.Writer, registry *core.Registry) int {
	for _, fp := range registry.All() {
		_, _ = fmt.Fprintf(w, "  %-12s %s (priority %d)\n",
			aliasForProtocol(fp.Name()), fp.Name(), fp.Priority())
	}
	return exitDetected
}

// runDryRun prints the detection plan without sending any traffic.
func runDryRun(w io.Writer, cfg CLIConfig, registry *core.Registry) int {
	_, _ = fmt.Fprintf(w, "Dry-run: no network traffic will be sent\n\n")
	_, _ = fmt.Fprintf(w, "Target:          %s:%d\n", cfg.IP, cfg.Port)
	_, _ = fmt.Fprintf(w, "Timeout:         %v\n", cfg.Timeout)
	_, _ = fmt.Fprintf(w, "Global Timeout:  %v\n", cfg.GlobalTimeout)
	_, _ = fmt.Fprintf(w, "Parallel:        %v\n", cfg.Parallel)
	_, _ = fmt.Fprintf(w, "Safe mode:       %v\n", cfg.Safe)
	_, _ = fmt.Fprintf(w, "Max concurrency: %d\n", cfg.MaxConcurrency)

	if cfg.Check != "" {
		_, _ = fmt.Fprintf(w, "\nProtocol filter: %s\n", cfg.Check)
	} else {
		_, _ = fmt.Fprintf(w, "\nProtocol detection order:\n")
		for i, fp := range registry.All() {
			_, _ = fmt.Fprintf(w, "  %2d. %-12s %s (priority %d)\n",
				i+1, aliasForProtocol(fp.Name()), fp.Name(), fp.Priority())
		}
	}
	return exitDetected
}

// runSpecificCheck runs detection for a single named protocol.
func runSpecificCheck(ctx context.Context, logger *slog.Logger, engine *core.Engine, target core.Target, protocol, format string, debug bool, w io.Writer) int {
	lower := strings.ToLower(protocol)
	proto := protocolAliases[lower]

	logger.Info("checking specific protocol", "protocol", proto)

	result, err := engine.DetectProtocol(ctx, target, proto)
	if err != nil {
		logger.Error("detection error", "protocol", proto, "error", err)
		var pnf *core.ProtocolNotFoundError
		if errors.As(err, &pnf) {
			return exitBadParams
		}
		return exitConnError
	}

	if format == "json" {
		return writeJSON(w, target, result)
	}

	if debug {
		writeExchanges(w, result)
	}

	return writeTextSpecific(w, lower, result)
}

// runFullDetection runs all registered fingerprinters against the target.
func runFullDetection(ctx context.Context, logger *slog.Logger, engine *core.Engine, target core.Target, verbose, debug bool, format string, w io.Writer) int {
	results := engine.DetectAll(ctx, target)
	best := bestMatch(results)

	logger.Info("detection complete",
		"protocol", best.Protocol,
		"matched", best.Matched,
		"confidence", best.Confidence)

	if format == "json" {
		return writeJSON(w, target, best)
	}

	if debug {
		for _, r := range results {
			writeExchanges(w, r)
		}
	}

	return writeTextResult(w, target, best, verbose, results)
}

// bestMatch returns the highest-confidence matched result, or an Unknown result.
func bestMatch(results []core.Result) core.Result {
	for _, r := range results {
		if r.Matched {
			return r
		}
	}
	return core.NoMatch(core.ProtocolUnknown)
}
