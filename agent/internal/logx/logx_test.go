package logx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/redact"
)

const (
	token   = "hmd_0123456789abcdef0123456789abcdef.Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmF"
	secret  = "Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmF"
	pairing = "HM-7K2M9Q-4F8T-ZP3D-W6NH-R5XA"
)

type stringer struct{}

func (stringer) String() string { return "stringer with " + token }

func TestLogOutputNeverContainsSecrets(t *testing.T) {
	var buf bytes.Buffer
	r := redact.New()
	log := New(&buf, slog.LevelDebug, r)

	log.Info("message with "+token, "attr", "Bearer "+token)
	log.Error("wrapped error", "error", fmt.Errorf("request failed: %w", errors.New("Authorization: Bearer "+token)))
	log.Warn("pairing", "code", pairing, "typed", "hm 7k2m9q 4f8t zp3d w6nh r5xa")
	log.Debug("any value", "struct", struct{ Token string }{token}, "stringer", stringer{})
	log.With("bound", token).Info("with bound attribute", slog.Group("g", slog.String("inner", token)))
	r.AddSecret(token)
	log.Info("secret part only: " + secret)

	out := buf.String()
	for _, leak := range []string{token, secret, "0123456789abcdef0123456789abcdef", "7K2M9Q", "7k2m9q", "R5XA", "r5xa"} {
		if strings.Contains(out, leak) {
			t.Errorf("log output leaks %q:\n%s", leak, out)
		}
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 6 {
		t.Fatalf("want 6 records, got %d", len(lines))
	}
	for _, line := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("not JSON: %v: %s", err, line)
		}
		for _, key := range []string{"time", "level", "msg"} {
			if _, ok := rec[key]; !ok {
				t.Errorf("record without %q: %s", key, line)
			}
		}
	}
}

func TestLevels(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, slog.LevelWarn, nil)
	log.Info("hidden")
	log.Warn("shown")
	if strings.Contains(buf.String(), "hidden") || !strings.Contains(buf.String(), "shown") {
		t.Fatalf("level filtering is wrong: %s", buf.String())
	}
	for _, name := range []string{"debug", "info", "warn", "error", ""} {
		if _, err := ParseLevel(name); err != nil {
			t.Errorf("ParseLevel(%q): %v", name, err)
		}
	}
	if _, err := ParseLevel("loud"); err == nil {
		t.Error("unknown level must be an error")
	}
}
