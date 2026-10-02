// Package backoff implements the retry timing of the protocol: exponential
// backoff with full jitter (base 5 s, cap 15 min) and Retry-After handling.
package backoff

import (
	"math/rand/v2"
	"strconv"
	"strings"
	"time"
)

// Protocol defaults.
const (
	DefaultBase = 5 * time.Second
	DefaultCap  = 15 * time.Minute
	// MaxRetryAfter bounds how long a server can make the agent wait.
	MaxRetryAfter = time.Hour
)

// Backoff produces delays for consecutive failures. It is not safe for
// concurrent use.
type Backoff struct {
	Base time.Duration
	Cap  time.Duration
	// Rand returns a uniform integer in [0, n). Nil means math/rand/v2.
	Rand     func(n int64) int64
	attempts int
}

// New returns a Backoff with the protocol defaults.
func New() *Backoff { return &Backoff{Base: DefaultBase, Cap: DefaultCap} }

func (b *Backoff) rnd(n int64) int64 {
	if n <= 0 {
		return 0
	}
	if b.Rand != nil {
		return b.Rand(n)
	}
	return rand.Int64N(n)
}

// Ceiling returns the upper bound of the next delay: min(cap, base * 2^n).
func (b *Backoff) Ceiling() time.Duration {
	base, limit := b.Base, b.Cap
	if base <= 0 {
		base = DefaultBase
	}
	if limit <= 0 {
		limit = DefaultCap
	}
	ceiling := base
	for i := 0; i < b.attempts; i++ {
		ceiling *= 2
		if ceiling >= limit || ceiling <= 0 {
			return limit
		}
	}
	if ceiling > limit {
		return limit
	}
	return ceiling
}

// Next returns the delay before the next attempt, uniformly distributed in
// [0, Ceiling()] (full jitter), and counts one more failure.
func (b *Backoff) Next() time.Duration {
	ceiling := b.Ceiling()
	if b.attempts < 62 {
		b.attempts++
	}
	return time.Duration(b.rnd(int64(ceiling) + 1))
}

// Jitter returns a uniform delay in [0, Base], used after a Retry-After wait.
func (b *Backoff) Jitter() time.Duration {
	base := b.Base
	if base <= 0 {
		base = DefaultBase
	}
	return time.Duration(b.rnd(int64(base) + 1))
}

// Attempts returns the number of consecutive failures counted so far.
func (b *Backoff) Attempts() int { return b.attempts }

// Reset forgets all failures after a success.
func (b *Backoff) Reset() { b.attempts = 0 }

// ParseRetryAfter parses a Retry-After header given in seconds, as the
// protocol specifies. The result is bounded by MaxRetryAfter.
func ParseRetryAfter(header string) (time.Duration, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(header, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	if n > int64(MaxRetryAfter/time.Second) {
		return MaxRetryAfter, true
	}
	return time.Duration(n) * time.Second, true
}
