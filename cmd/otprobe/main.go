package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/otfabric/otfp/core"
	"github.com/otfabric/otfp/protocols/bacnet"
	"github.com/otfabric/otfp/protocols/can"
	"github.com/otfabric/otfp/protocols/dnp3"
	"github.com/otfabric/otfp/protocols/enip"
	"github.com/otfabric/otfp/protocols/iec104"
	"github.com/otfabric/otfp/protocols/mms"
	"github.com/otfabric/otfp/protocols/modbus"
	"github.com/otfabric/otfp/protocols/opcua"
	"github.com/otfabric/otfp/protocols/profinet"
	"github.com/otfabric/otfp/protocols/s7"
	"github.com/spf13/cobra"
)

// Build-time variables injected via ldflags.
var (
	Version   = "dev"
	Branch    = "unknown"
	Revision  = "unknown"
	BuildUser = "unknown"
	BuildDate = "unknown"
)

func main() {
	os.Exit(run(os.Stdout, os.Stderr))
}

// run builds the cobra command tree and executes. Returns exit code.
func run(stdout, stderr io.Writer) int {
	exitCode := exitDetected

	// ---- root command ----
	rootCmd := &cobra.Command{
		Use:   "otprobe",
		Short: "OT Protocol Fingerprinting Tool",
		Long:  "Detect industrial protocols on network endpoints using safe, connection-level probes.",
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: false,
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// ---- detect command ----
	var cfg CLIConfig
	detectCmd := &cobra.Command{
		Use:   "detect",
		Short: "Detect OT protocols on a target endpoint",
		Long: `Detect OT protocols on a target endpoint by sending minimal, standards-compliant
probes and analysing responses. Use --check to test a specific protocol, or
omit it to auto-detect all supported protocols.

Exit codes:
  0  Protocol detected (high confidence >= 0.9)
  1  Unknown protocol (no match)
  2  Connection error
  3  Invalid parameters
  4  Partial detection (matched but confidence < 0.9)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			code := runDetect(cfg, stdout, stderr)
			exitCode = code
			if code != exitDetected {
				return &silentExit{code: code}
			}
			return nil
		},
	}

	// detect flags
	detectCmd.Flags().StringVar(&cfg.IP, "ip", "", "Target IP address (required)")
	detectCmd.Flags().IntVar(&cfg.Port, "port", 0, "Target TCP port (required)")
	detectCmd.Flags().StringVar(&cfg.Check, "check", "", "Check specific protocol: modbus, mms, s7, opcua, bacnet, can, profinet, dnp3, iec104, enip")
	detectCmd.Flags().DurationVar(&cfg.Timeout, "timeout", 5*time.Second, "Per-protocol connection timeout")
	detectCmd.Flags().DurationVar(&cfg.GlobalTimeout, "global-timeout", 0, "Overall timeout for the entire run (0 = unlimited)")
	detectCmd.Flags().BoolVar(&cfg.Verbose, "verbose", false, "Show detailed detection results")
	detectCmd.Flags().BoolVar(&cfg.Debug, "debug", false, "Enable debug logging (per-protocol timings, connection errors)")
	detectCmd.Flags().BoolVar(&cfg.Quiet, "quiet", false, "Suppress non-error log output")
	detectCmd.Flags().BoolVar(&cfg.Parallel, "parallel", false, "Run protocol checks in parallel")
	detectCmd.Flags().BoolVar(&cfg.Safe, "safe", false, "OT-safe mode: sequential, min-interval=200ms, max-concurrency=1")
	detectCmd.Flags().IntVar(&cfg.MaxConcurrency, "max-concurrency", 0, "Maximum parallel goroutines (0 = unbounded)")
	detectCmd.Flags().StringVar(&cfg.Output, "output", "text", "Output format: text or json")
	detectCmd.Flags().BoolVar(&cfg.DryRun, "dry-run", false, "Show detection plan without sending network traffic")
	_ = detectCmd.MarkFlagRequired("ip")
	_ = detectCmd.MarkFlagRequired("port")

	// ---- list command ----
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List supported protocols with priorities",
		Run: func(cmd *cobra.Command, args []string) {
			registry := defaultRegistry()
			exitCode = runList(stdout, registry)
		},
	}

	// ---- version command ----
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			build := NewBuildInfo()
			_, _ = fmt.Fprintf(stdout, "otprobe %s\n", build.String())
		},
	}

	rootCmd.AddCommand(detectCmd, listCmd, versionCmd)

	if err := rootCmd.Execute(); err != nil {
		var se *silentExit
		if ok := errorAs(err, &se); ok {
			return se.code
		}
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitBadParams
	}
	return exitCode
}

// runDetect is the main detection orchestration.
func runDetect(cfg CLIConfig, stdout, stderr io.Writer) int {
	// ---- logger ----
	logger := initLogger(stderr, cfg.Verbose, cfg.Debug, cfg.Quiet)

	build := NewBuildInfo()
	logger.Info("starting otprobe", "version", build.Short())

	// ---- validate ----
	target := core.Target{
		IP:      cfg.IP,
		Port:    cfg.Port,
		Timeout: cfg.Timeout,
	}
	if err := target.Validate(); err != nil {
		logger.Error("invalid target", "error", err)
		return exitBadParams
	}
	if cfg.Check != "" {
		lower := strings.ToLower(cfg.Check)
		if _, ok := protocolAliases[lower]; !ok {
			logger.Error("unknown protocol", "check", cfg.Check,
				"supported", "modbus, mms, s7, opcua, bacnet, can, profinet, dnp3, iec104, enip")
			return exitBadParams
		}
	}
	if cfg.Output != "text" && cfg.Output != "json" {
		logger.Error("--output must be text or json", "output", cfg.Output)
		return exitBadParams
	}

	// ---- safe mode hardening ----
	if cfg.Safe {
		logger.Info("OT-safe profile active: sequential, min-interval=200ms, max-concurrency=1")
		cfg.Parallel = false
		cfg.MaxConcurrency = 1
	}

	// ---- registry ----
	registry := defaultRegistry()

	// ---- dry-run ----
	if cfg.DryRun {
		return runDryRun(stdout, cfg, registry)
	}

	// ---- engine config ----
	config := core.EngineConfig{
		Parallel:                cfg.Parallel,
		EarlyStop:               true,
		HighConfidenceThreshold: 0.9,
		MaxConcurrency:          cfg.MaxConcurrency,
	}
	if cfg.Safe {
		config = core.SafeEngineConfig()
		config.EarlyStop = true
		config.MinInterval = 200 * time.Millisecond
	}
	engine := core.NewEngine(registry, config)

	// ---- context with signal handling ----
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.GlobalTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.GlobalTimeout)
		defer cancel()
	}

	logger.Info("scanning target", "ip", cfg.IP, "port", cfg.Port, "parallel", cfg.Parallel)

	// ---- run detection ----
	if cfg.Check != "" {
		return runSpecificCheck(ctx, logger, engine, target, cfg.Check, cfg.Output, cfg.Debug, stdout)
	}
	return runFullDetection(ctx, logger, engine, target, cfg.Verbose, cfg.Debug, cfg.Output, stdout)
}

// defaultRegistry returns a registry pre-loaded with all known protocols.
func defaultRegistry() *core.Registry {
	registry := core.NewRegistry()
	_ = registry.Register(mms.New())
	_ = registry.Register(s7.New())
	_ = registry.Register(enip.New())
	_ = registry.Register(iec104.New())
	_ = registry.Register(dnp3.New())
	_ = registry.Register(modbus.New())
	_ = registry.Register(opcua.New())
	_ = registry.Register(bacnet.New())
	_ = registry.Register(can.New())
	_ = registry.Register(profinet.New())
	return registry
}

func initLogger(w io.Writer, verbose, debug, quiet bool) *slog.Logger {
	level := slog.LevelInfo
	if quiet {
		level = slog.LevelError
	}
	if verbose {
		level = slog.LevelDebug
	}
	if debug {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: level,
	}))
}

// silentExit is used to propagate a non-zero exit code through cobra without
// printing an additional error message.
type silentExit struct {
	code int
}

func (e *silentExit) Error() string {
	return fmt.Sprintf("exit code %d", e.code)
}

// errorAs is a type-safe errors.As wrapper that avoids issues with
// the linter complaining about target types.
func errorAs(err error, target interface{}) bool {
	switch t := target.(type) {
	case **silentExit:
		se, ok := err.(*silentExit) //nolint:errorlint
		if ok {
			*t = se
		}
		return ok
	default:
		return false
	}
}
