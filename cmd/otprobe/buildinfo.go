// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"runtime"
)

// BuildInfo holds version metadata injected at compile time via ldflags.
type BuildInfo struct {
	Version   string
	Tag       string
	Commit    string
	BuildDate string
	GoVersion string
	Platform  string
}

// NewBuildInfo creates a BuildInfo populated from ldflags and runtime.
func NewBuildInfo() BuildInfo {
	return BuildInfo{
		Version:   version,
		Tag:       tag,
		Commit:    commit,
		BuildDate: buildDate,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
}

// String returns a multi-line human-readable version summary.
func (b BuildInfo) String() string {
	tagLine := b.Tag
	if tagLine == "" {
		tagLine = "(none)"
	}
	return fmt.Sprintf(
		"version %s\n  tag:        %s\n  commit:     %s\n  build date: %s\n  go version: %s\n  platform:   %s",
		b.Version, tagLine, b.Commit, b.BuildDate, b.GoVersion, b.Platform)
}

// Short returns a single-line version string suitable for log headers.
func (b BuildInfo) Short() string {
	if b.Tag != "" {
		return fmt.Sprintf("%s (%s)", b.Version, b.Tag)
	}
	return fmt.Sprintf("%s (%s)", b.Version, b.Commit)
}
