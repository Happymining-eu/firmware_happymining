package ctl

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/localui"
)

func TestUIUnlockWritesAHashedCodeAndLockRemovesIt(t *testing.T) {
	f := newFixture(t)
	if exit := f.run("ui", "unlock", "--minutes", "3"); exit != ExitOK {
		t.Fatalf("%d %s", exit, f.output())
	}
	out := f.output()
	m := regexp.MustCompile(`Unlock code:\s+(\d{6})`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no code in output:\n%s", out)
	}
	for _, want := range []string{"valid 3 minute(s)", ":8080/", "read-only"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	data, err := os.ReadFile(localui.UnlockPath(f.stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), m[1]) {
		t.Error("the file stores the code in clear")
	}
	uf, err := localui.ReadUnlock(f.stateDir, time.Now())
	if err != nil || !uf.Matches(m[1]) {
		t.Fatalf("stored code does not match: %v %v", uf, err)
	}
	if _, err := localui.ReadUnlock(f.stateDir, time.Now().Add(4*time.Minute)); err != localui.ErrNoUnlock {
		t.Errorf("expiry not honoured: %v", err)
	}

	if exit := f.run("ui", "unlock"); exit != ExitOK {
		t.Fatalf("%d %s", exit, f.output())
	}
	if exit := f.run("ui", "lock"); exit != ExitOK {
		t.Fatalf("%d %s", exit, f.output())
	}
	if _, err := os.Stat(localui.UnlockPath(f.stateDir)); !os.IsNotExist(err) {
		t.Error("lock left the unlock file")
	}
	if exit := f.run("ui", "unlock", "--minutes", "0"); exit != ExitUsage {
		t.Errorf("--minutes 0: exit %d", exit)
	}
	if exit := f.run("ui", "dance"); exit != ExitUsage {
		t.Errorf("unknown subcommand: exit %d", exit)
	}
}
