// Package redact removes secrets from everything the agent logs or sends back
// in operation acknowledgements: bearer tokens, anything in the device
// credential format, pairing codes, and exact secret values registered at run
// time (the current token and its secret part).
package redact

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"sync"
)

// Replacement markers.
const (
	MarkCredential  = "[REDACTED-CREDENTIAL]"
	MarkPairingCode = "[REDACTED-PAIRING-CODE]"
	MarkSecret      = "[REDACTED]"
)

var (
	// "Bearer <anything token-like>", as found in an Authorization header.
	reBearer = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+`)
	// Anything that starts like a device credential. Deliberately broader than
	// the exact format so that truncated or malformed tokens are caught too.
	reCredential = regexp.MustCompile(`hmd_[A-Za-z0-9._-]+`)
	// Pairing codes as typed: HM, 6 locator characters, 16 secret characters,
	// with optional hyphens or spaces, any case, before normalisation.
	rePairing = regexp.MustCompile(`(?i)\bHM[- ]?[0-9A-Z]{6}(?:[- ]?[0-9A-Z]{4}){4}\b`)
	// Object keys whose scalar values are always removed from results.
	reSensitiveKey = regexp.MustCompile(`(?i)(token|secret|passw|authorization|pairing[_-]?code|api[_-]?key|private[_-]?key|cookie)`)
)

// minSecretLen is the shortest registered secret that is honoured. Shorter
// strings would make ordinary log text unreadable.
const minSecretLen = 8

// Redactor is safe for concurrent use.
type Redactor struct {
	mu      sync.RWMutex
	secrets []string
}

// New returns a Redactor with the built-in patterns and no registered secrets.
func New() *Redactor { return &Redactor{} }

// AddSecret registers an exact value that must never appear in output. For a
// device credential the secret part after the dot is registered as well.
func (r *Redactor) AddSecret(s string) {
	s = strings.TrimSpace(s)
	if len(s) < minSecretLen {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.addLocked(s)
	if i := strings.LastIndexByte(s, '.'); strings.HasPrefix(s, "hmd_") && i >= 0 && len(s)-i-1 >= minSecretLen {
		r.addLocked(s[i+1:])
	}
}

func (r *Redactor) addLocked(s string) {
	for _, have := range r.secrets {
		if have == s {
			return
		}
	}
	r.secrets = append(r.secrets, s)
}

// String returns s with every secret removed.
func (r *Redactor) String(s string) string {
	if s == "" {
		return s
	}
	s = reBearer.ReplaceAllString(s, "Bearer "+MarkSecret)
	s = reCredential.ReplaceAllString(s, MarkCredential)
	s = rePairing.ReplaceAllString(s, MarkPairingCode)
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, secret := range r.secrets {
		if strings.Contains(s, secret) {
			s = strings.ReplaceAll(s, secret, MarkSecret)
		}
	}
	return s
}

// Bytes is String for byte slices.
func (r *Redactor) Bytes(b []byte) []byte { return []byte(r.String(string(b))) }

// Value walks a decoded JSON value (as produced by encoding/json into `any`)
// and redacts every string, every object key, and the scalar value of every
// key that looks sensitive.
func (r *Redactor) Value(v any) any {
	switch t := v.(type) {
	case string:
		return r.String(t)
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = r.Value(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			key := r.String(k)
			if reSensitiveKey.MatchString(k) {
				switch e.(type) {
				case map[string]any, []any:
					out[key] = r.Value(e)
				case nil:
					out[key] = nil
				default:
					out[key] = MarkSecret
				}
				continue
			}
			out[key] = r.Value(e)
		}
		return out
	default:
		return v
	}
}

// JSON marshals v, redacts it structurally and returns the redacted JSON.
func (r *Redactor) JSON(v any) (json.RawMessage, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var generic any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	out, err := json.Marshal(r.Value(generic))
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Writer returns a writer that redacts every Write before passing it on. It is
// meant to wrap the log output: log/slog handlers emit one record per Write, so
// a secret cannot straddle two calls.
func (r *Redactor) Writer(w io.Writer) io.Writer { return &writer{r: r, w: w} }

type writer struct {
	r *Redactor
	w io.Writer
}

func (w *writer) Write(p []byte) (int, error) {
	if _, err := w.w.Write(w.r.Bytes(p)); err != nil {
		return 0, err
	}
	// Report the caller's length: the redacted text may be shorter or longer.
	return len(p), nil
}
