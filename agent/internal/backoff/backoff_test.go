package backoff

import (
	"testing"
	"time"
)

func TestCeilingGrowsExponentiallyToTheCap(t *testing.T) {
	b := New()
	b.Rand = func(n int64) int64 { return n - 1 } // always the maximum
	want := []time.Duration{
		5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second,
		160 * time.Second, 320 * time.Second, 640 * time.Second, 15 * time.Minute, 15 * time.Minute,
	}
	for i, w := range want {
		if got := b.Next(); got != w {
			t.Fatalf("attempt %d: got %v, want %v", i, got, w)
		}
	}
	for i := 0; i < 200; i++ {
		if got := b.Next(); got != 15*time.Minute {
			t.Fatalf("must stay at the cap, got %v", got)
		}
	}
	b.Reset()
	if got := b.Next(); got != 5*time.Second {
		t.Fatalf("after Reset: %v", got)
	}
}

func TestFullJitterStaysInBounds(t *testing.T) {
	b := New()
	sawSmall, sawLarge := false, false
	for round := 0; round < 200; round++ {
		b.Reset()
		for i := 0; i < 15; i++ {
			ceiling := b.Ceiling()
			d := b.Next()
			if d < 0 || d > ceiling {
				t.Fatalf("delay %v outside [0, %v]", d, ceiling)
			}
			if ceiling > DefaultCap {
				t.Fatalf("ceiling %v above the cap", ceiling)
			}
			if i == 12 {
				if d < ceiling/4 {
					sawSmall = true
				}
				if d > ceiling/2 {
					sawLarge = true
				}
			}
		}
	}
	if !sawSmall || !sawLarge {
		t.Fatal("jitter does not cover the range: it should be uniform in [0, ceiling]")
	}
}

func TestMinimumJitterIsZero(t *testing.T) {
	b := New()
	b.Rand = func(int64) int64 { return 0 }
	if got := b.Next(); got != 0 {
		t.Fatalf("full jitter lower bound must be 0, got %v", got)
	}
}

func TestParseRetryAfter(t *testing.T) {
	cases := map[string]struct {
		want time.Duration
		ok   bool
	}{
		"":                              {0, false},
		"0":                             {0, true},
		"7":                             {7 * time.Second, true},
		" 120 ":                         {120 * time.Second, true},
		"-1":                            {0, false},
		"soon":                          {0, false},
		"1.5":                           {0, false},
		"999999999":                     {MaxRetryAfter, true},
		"Wed, 21 Oct 2026 07:28:00 GMT": {0, false},
	}
	for in, c := range cases {
		got, ok := ParseRetryAfter(in)
		if got != c.want || ok != c.ok {
			t.Errorf("ParseRetryAfter(%q) = %v, %v; want %v, %v", in, got, ok, c.want, c.ok)
		}
	}
}
