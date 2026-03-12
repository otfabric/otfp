package main

import (
	"fmt"
	"runtime"
)

// BuildInfo holds version metadata injected at compile time via ldflags.
type BuildInfo struct {
	Version   string
	Branch    string
	Revision  string
	BuildUser string
	BuildDate string
	GoVersion string
	Platform  string
}

// NewBuildInfo creates a BuildInfo populated from ldflags and runtime.
func NewBuildInfo() BuildInfo {
	return BuildInfo{
		Version:   Version,
		Branch:    Branch,
		Revision:  Revision,
		BuildUser: BuildUser,
		BuildDate: BuildDate,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
}

// String returns a multi-line human-readable version summary.
func (b BuildInfo) String() string {
	return fmt.Sprintf(
		"version %s\n  branch:     %s\n  revision:   %s\n  build user: %s\n  build date: %s\n  go version: %s\n  platform:   %s",
		b.Version, b.Branch, b.Revision, b.BuildUser, b.BuildDate, b.GoVersion, b.Platform)
}

// Short returns a single-line version string suitable for log headers.
func (b BuildInfo) Short() string {
	return fmt.Sprintf("%s (%s/%s)", b.Version, b.Branch, b.Revision)
}
