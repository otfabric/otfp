package main

import (
	"time"

	"github.com/otfabric/otfp/core"
)

// CLIConfig holds the resolved CLI configuration after flag parsing.
type CLIConfig struct {
	IP             string
	Port           int
	Check          string
	CheckProtocol  core.Protocol
	Timeout        time.Duration
	GlobalTimeout  time.Duration
	Parallel       bool
	Safe           bool
	Output         string
	Verbose        bool
	Debug          bool
	Quiet          bool
	MaxConcurrency int
	DryRun         bool
	List           bool
	ShowVersion    bool
}

// ConfidenceLevel returns a human-readable confidence tier string.
func ConfidenceLevel(c core.Confidence) string {
	v := float64(c)
	switch {
	case v >= 0.9:
		return "high"
	case v >= 0.5:
		return "medium"
	case v > 0:
		return "low"
	default:
		return "none"
	}
}
