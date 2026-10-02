// Package version holds the single source of truth for the agent version.
package version

// Version is the version of every binary built from this module. The build
// scripts read the default from this file and inject it again with
//
//	-ldflags "-X github.com/Happymining-eu/firmware_happymining/agent/internal/version.Version=<v>"
//
// so that a release build can override it without editing the source.
var Version = "0.1.0"
