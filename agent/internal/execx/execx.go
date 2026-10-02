// Package execx runs external commands safely: absolute paths only, argv
// arrays (never a shell), a minimal environment, a timeout and bounded output.
// The Runner interface lets every caller be tested with a fake.
package execx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// MaxOutputBytes bounds captured stdout and stderr (each).
const MaxOutputBytes = 1024 * 1024

// Result is the outcome of a command that could be started.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Runner runs a command. A non-zero exit code is reported in Result, not as
// an error; err is non-nil when the command could not run or timed out.
type Runner interface {
	Run(ctx context.Context, timeout time.Duration, path string, args ...string) (Result, error)
}

// ErrNotFound is returned by FindAbs when no candidate exists.
var ErrNotFound = errors.New("executable not found")

// FindAbs returns the first candidate that is an executable regular file.
// Candidates must be absolute paths; $PATH is never consulted.
func FindAbs(root string, candidates ...string) (string, error) {
	for _, c := range candidates {
		if !filepath.IsAbs(c) {
			continue
		}
		fi, err := os.Stat(filepath.Join(root, c))
		if err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return c, nil
		}
	}
	return "", ErrNotFound
}

type limitedBuffer struct {
	buf bytes.Buffer
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := MaxOutputBytes - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
		} else {
			b.buf.Write(p)
		}
	}
	return len(p), nil
}

// OS is the real Runner.
type OS struct{}

// Run implements Runner.
func (OS) Run(ctx context.Context, timeout time.Duration, path string, args ...string) (Result, error) {
	if !filepath.IsAbs(path) {
		return Result{}, fmt.Errorf("refusing to run %q: not an absolute path", path)
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C"}
	cmd.Stdin = nil
	var stdout, stderr limitedBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	res := Result{Stdout: stdout.buf.Bytes(), Stderr: stderr.buf.Bytes()}
	if err == nil {
		return res, nil
	}
	if ctx.Err() != nil {
		return res, fmt.Errorf("%s: timed out or cancelled: %w", filepath.Base(path), ctx.Err())
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() >= 0 {
		res.ExitCode = exitErr.ExitCode()
		return res, nil
	}
	return res, fmt.Errorf("%s: %w", filepath.Base(path), err)
}

// Fake is a Runner for tests. Commands are looked up by "path arg1 arg2 ...".
type Fake struct {
	mu sync.Mutex
	// Responses maps a full command line to its result.
	Responses map[string]FakeResponse
	// Calls records every command line in order.
	Calls []string
}

// FakeResponse is a canned command result.
type FakeResponse struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

// NewFake returns an empty Fake.
func NewFake() *Fake { return &Fake{Responses: map[string]FakeResponse{}} }

// On registers a response for a command line.
func (f *Fake) On(cmdline string, r FakeResponse) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Responses[cmdline] = r
	return f
}

// Run implements Runner.
func (f *Fake) Run(_ context.Context, _ time.Duration, path string, args ...string) (Result, error) {
	line := strings.Join(append([]string{path}, args...), " ")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, line)
	r, ok := f.Responses[line]
	if !ok {
		return Result{}, fmt.Errorf("fake runner: no response registered for %q", line)
	}
	if r.Err != nil {
		return Result{}, r.Err
	}
	return Result{Stdout: []byte(r.Stdout), Stderr: []byte(r.Stderr), ExitCode: r.ExitCode}, nil
}

// CallLog returns a copy of the recorded command lines.
func (f *Fake) CallLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.Calls...)
}
