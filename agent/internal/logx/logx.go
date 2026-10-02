// Package logx builds the agent's structured JSON logger. Output goes to
// stdout (journald under systemd) through the redaction layer, so that no
// bearer token, pairing code or credential-shaped string reaches the journal.
package logx

import (
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/redact"
)

// ParseLevel converts a configuration value to a slog level.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "", "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("unknown log level %q (want debug, info, warn or error)", s)
}

// New returns a JSON logger writing redacted records to w.
func New(w io.Writer, level slog.Level, r *redact.Redactor) *slog.Logger {
	if r == nil {
		r = redact.New()
	}
	h := slog.NewJSONHandler(r.Writer(w), &slog.HandlerOptions{
		Level: level,
		// Timestamps in UTC, like every timestamp of the protocol.
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey && a.Value.Kind() == slog.KindTime {
				a.Value = slog.TimeValue(a.Value.Time().UTC())
			}
			return a
		},
	})
	return slog.New(h)
}

// Discard returns a logger that drops everything (for tests and libraries).
func Discard() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 100}))
}
