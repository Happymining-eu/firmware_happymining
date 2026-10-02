package execx

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func script(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunRequiresAbsolutePath(t *testing.T) {
	for _, path := range []string{"sh", "./tool", "bin/tool", ""} {
		if _, err := (OS{}).Run(context.Background(), time.Second, path); err == nil {
			t.Errorf("%q must be refused: only absolute paths are run", path)
		}
	}
}

func TestRunCapturesOutputAndExitCode(t *testing.T) {
	res, err := (OS{}).Run(context.Background(), 5*time.Second, script(t, `echo "out:$1:$2"; echo err >&2; exit 3`), "a b", "$(id)")
	if err != nil {
		t.Fatal(err)
	}
	// Arguments are passed as an argv array: no word splitting, no expansion.
	if strings.TrimSpace(string(res.Stdout)) != "out:a b:$(id)" || strings.TrimSpace(string(res.Stderr)) != "err" || res.ExitCode != 3 {
		t.Fatalf("%q %q %d", res.Stdout, res.Stderr, res.ExitCode)
	}
}

func TestRunUsesAMinimalEnvironment(t *testing.T) {
	t.Setenv("HM_TEST_SECRET", "must-not-leak")
	t.Setenv("LD_PRELOAD", "/tmp/evil.so")
	res, err := (OS{}).Run(context.Background(), 5*time.Second, "/usr/bin/env")
	if err != nil {
		t.Skipf("/usr/bin/env not usable: %v", err)
	}
	env := string(res.Stdout)
	if strings.Contains(env, "HM_TEST_SECRET") || strings.Contains(env, "LD_PRELOAD") {
		t.Fatalf("the caller's environment leaked into the child:\n%s", env)
	}
	if !strings.Contains(env, "PATH=/usr/sbin:/usr/bin:/sbin:/bin") || !strings.Contains(env, "LC_ALL=C") {
		t.Fatalf("unexpected environment:\n%s", env)
	}
}

func TestRunTimesOut(t *testing.T) {
	start := time.Now()
	_, err := (OS{}).Run(context.Background(), 200*time.Millisecond, script(t, "sleep 30"))
	if err == nil {
		t.Fatal("a hanging command must be an error")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("the command was not killed at the timeout: %v", time.Since(start))
	}
}

func TestRunBoundsOutput(t *testing.T) {
	res, err := (OS{}).Run(context.Background(), 20*time.Second, script(t, "head -c 3000000 /dev/zero"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Stdout) != MaxOutputBytes {
		t.Fatalf("captured %d bytes, want exactly the %d-byte limit", len(res.Stdout), MaxOutputBytes)
	}
}

func TestRunMissingProgram(t *testing.T) {
	if _, err := (OS{}).Run(context.Background(), time.Second, filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("a missing program must be an error")
	}
}

func TestFindAbs(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "usr/bin"), 0o755)
	_ = os.MkdirAll(filepath.Join(root, "usr/local/bin/tool-dir"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "usr/bin/tool"), []byte("x"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "usr/bin/not-executable"), []byte("x"), 0o644)
	if got, err := FindAbs(root, "/usr/local/bin/tool", "/usr/bin/tool"); err != nil || got != "/usr/bin/tool" {
		t.Fatalf("%q %v", got, err)
	}
	for _, candidates := range [][]string{{"/usr/bin/missing"}, {"/usr/bin/not-executable"}, {"/usr/local/bin/tool-dir"}, {"tool"}, {"usr/bin/tool"}, nil} {
		if got, err := FindAbs(root, candidates...); err == nil {
			t.Errorf("%v: found %q", candidates, got)
		}
	}
}

func TestFake(t *testing.T) {
	f := NewFake().On("/bin/x a b", FakeResponse{Stdout: "ok", ExitCode: 2})
	res, err := f.Run(context.Background(), time.Second, "/bin/x", "a", "b")
	if err != nil || string(res.Stdout) != "ok" || res.ExitCode != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err := f.Run(context.Background(), time.Second, "/bin/y"); err == nil {
		t.Fatal("an unregistered command must fail")
	}
	if calls := f.CallLog(); len(calls) != 2 || calls[0] != "/bin/x a b" {
		t.Fatalf("%v", calls)
	}
}
