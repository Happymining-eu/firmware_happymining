package helper

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/execx"
)

func ptr(n int64) *int64 { return &n }

type fixture struct {
	deps   Deps
	runner *execx.Fake
	audit  []string
	mu     sync.Mutex
	conf   string
}

func newFixture(t *testing.T, conf string) *fixture {
	t.Helper()
	f := &fixture{runner: execx.NewFake()}
	f.conf = filepath.Join(t.TempDir(), "helper.conf")
	if conf != "-" {
		if err := os.WriteFile(f.conf, []byte(conf), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f.runner.On("/usr/bin/systemctl restart vastai.service", execx.FakeResponse{})
	f.runner.On("/usr/sbin/shutdown -r +2 "+RebootMessage, execx.FakeResponse{})
	f.deps = Deps{ConfPath: f.conf, ConfOwnerUID: uint32(os.Getuid()), Runner: f.runner, Audit: func(line string) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.audit = append(f.audit, line)
	}}
	return f
}

func TestParseArgsAcceptsOnlyTheTwoShapes(t *testing.T) {
	good := map[string][]string{
		"restart-vast-daemon": {"restart-vast-daemon"},
		"reboot":              {"reboot", "--delay-s", "60"},
	}
	for want, args := range good {
		req, err := ParseArgs(args)
		if err != nil || req.Action != want {
			t.Errorf("%v: %+v %v", args, req, err)
		}
	}
	if req, _ := ParseArgs([]string{"reboot", "--delay-s", "3600"}); req.DelayS == nil || *req.DelayS != 3600 {
		t.Fatalf("3600 must be accepted: %+v", req)
	}
	bad := [][]string{
		nil,
		{},
		{"reboot"},
		{"reboot", "--delay-s"},
		{"reboot", "--delay-s", "59"},
		{"reboot", "--delay-s", "3601"},
		{"reboot", "--delay-s", "0"},
		{"reboot", "--delay-s", "-60"},
		{"reboot", "--delay-s", "60s"},
		{"reboot", "--delay-s", "1e2"},
		{"reboot", "--delay-s", "120 ; rm -rf /"},
		{"reboot", "--delay-s", "$(id)"},
		{"reboot", "--delay-s=120"},
		{"reboot", "-delay-s", "120"},
		{"reboot", "--delay-s", "120", "--force"},
		{"reboot", "now"},
		{"restart-vast-daemon", "ssh.service"},
		{"restart-vast-daemon", "--unit", "ssh"},
		{"restart", "vastai"},
		{"restart-docker"},
		{"shell"},
		{"sh", "-c", "id"},
		{"poweroff"},
		{"serve", "extra"},
		{""},
	}
	for _, args := range bad {
		if req, err := ParseArgs(args); err == nil {
			t.Errorf("%q must be refused, got %+v", args, req)
		}
	}
}

func TestEverythingIsDisabledByDefault(t *testing.T) {
	// Missing file, empty file, explicit zeros: all disabled.
	for name, conf := range map[string]string{"missing": "-", "empty": "", "zeros": "ALLOW_REBOOT=0\nALLOW_RESTART_VAST_DAEMON=0\n", "comments": "# ALLOW_REBOOT=1\n"} {
		f := newFixture(t, conf)
		for _, req := range []Request{{Action: ActionRestartVastDaemon}, {Action: ActionReboot, DelayS: ptr(120)}} {
			resp := Execute(context.Background(), req, f.deps)
			if resp.OK || resp.Code != CodeDisabled {
				t.Errorf("%s/%s: %+v", name, req.Action, resp)
			}
		}
		if calls := f.runner.CallLog(); len(calls) != 0 {
			t.Errorf("%s: commands were run: %v", name, calls)
		}
		if len(f.audit) != 2 {
			t.Errorf("%s: every invocation must be audited: %v", name, f.audit)
		}
	}
}

func TestSwitchesAreIndependent(t *testing.T) {
	f := newFixture(t, "ALLOW_REBOOT=1\n")
	if resp := Execute(context.Background(), Request{Action: ActionRestartVastDaemon}, f.deps); resp.OK {
		t.Fatalf("restart must stay disabled: %+v", resp)
	}
	resp := Execute(context.Background(), Request{Action: ActionReboot, DelayS: ptr(61)}, f.deps)
	if !resp.OK || !strings.Contains(resp.Detail, "2 minute") {
		t.Fatalf("reboot: %+v", resp)
	}
	if calls := f.runner.CallLog(); len(calls) != 1 || calls[0] != "/usr/sbin/shutdown -r +2 "+RebootMessage {
		t.Fatalf("exactly one fixed command line must run: %q", calls)
	}

	f = newFixture(t, "ALLOW_RESTART_VAST_DAEMON=1\n")
	if resp := Execute(context.Background(), Request{Action: ActionReboot, DelayS: ptr(120)}, f.deps); resp.OK {
		t.Fatalf("reboot must stay disabled: %+v", resp)
	}
	if resp := Execute(context.Background(), Request{Action: ActionRestartVastDaemon}, f.deps); !resp.OK {
		t.Fatalf("restart: %+v", resp)
	}
	if calls := f.runner.CallLog(); len(calls) != 1 || calls[0] != "/usr/bin/systemctl restart vastai.service" {
		t.Fatalf("exactly one fixed command line must run: %q", calls)
	}
}

func TestRebootMinutesNeverEarlierThanAsked(t *testing.T) {
	for delay, want := range map[int64]int64{60: 1, 61: 2, 119: 2, 120: 2, 121: 3, 3600: 60} {
		if got := RebootMinutes(delay); got != want || got*60 < delay {
			t.Errorf("RebootMinutes(%d) = %d, want %d", delay, got, want)
		}
	}
}

func TestInvalidRequestsNeverReachACommand(t *testing.T) {
	f := newFixture(t, "ALLOW_REBOOT=1\nALLOW_RESTART_VAST_DAEMON=1\n")
	bad := []Request{
		{},
		{Action: "poweroff"},
		{Action: ActionReboot},
		{Action: ActionReboot, DelayS: ptr(59)},
		{Action: ActionReboot, DelayS: ptr(3601)},
		{Action: ActionReboot, DelayS: ptr(-1)},
		{Action: ActionRestartVastDaemon, DelayS: ptr(120)},
		{Action: "restart-vast-daemon; reboot"},
	}
	for _, req := range bad {
		if resp := Execute(context.Background(), req, f.deps); resp.OK || resp.Code != CodeInvalid {
			t.Errorf("%+v: %+v", req, resp)
		}
	}
	if calls := f.runner.CallLog(); len(calls) != 0 {
		t.Fatalf("commands were run: %v", calls)
	}
}

func TestSwitchFileMustBeTrustworthy(t *testing.T) {
	enabled := "ALLOW_REBOOT=1\nALLOW_RESTART_VAST_DAEMON=1\n"
	req := Request{Action: ActionRestartVastDaemon}

	f := newFixture(t, enabled)
	if err := os.Chmod(f.conf, 0o666); err != nil {
		t.Fatal(err)
	}
	if resp := Execute(context.Background(), req, f.deps); resp.OK {
		t.Fatal("a world-writable switch file must be refused")
	}
	_ = os.Chmod(f.conf, 0o664)
	if resp := Execute(context.Background(), req, f.deps); resp.OK {
		t.Fatal("a group-writable switch file must be refused")
	}

	f = newFixture(t, enabled)
	f.deps.ConfOwnerUID = uint32(os.Getuid()) + 1
	if resp := Execute(context.Background(), req, f.deps); resp.OK {
		t.Fatal("a switch file owned by someone else must be refused")
	}

	f = newFixture(t, "-")
	real := filepath.Join(t.TempDir(), "real.conf")
	_ = os.WriteFile(real, []byte(enabled), 0o644)
	if err := os.Symlink(real, f.conf); err != nil {
		t.Fatal(err)
	}
	if resp := Execute(context.Background(), req, f.deps); resp.OK {
		t.Fatal("a symlinked switch file must be refused")
	}

	// A FIFO or a directory in place of the file must not hang or be read.
	f = newFixture(t, "-")
	if err := os.Mkdir(f.conf, 0o755); err != nil {
		t.Fatal(err)
	}
	if resp := Execute(context.Background(), req, f.deps); resp.OK {
		t.Fatal("a directory in place of the switch file must be refused")
	}
	f = newFixture(t, "-")
	if err := syscall.Mkfifo(f.conf, 0o644); err == nil {
		done := make(chan Response, 1)
		go func() { done <- Execute(context.Background(), req, f.deps) }()
		select {
		case resp := <-done:
			if resp.OK {
				t.Fatal("a FIFO in place of the switch file must be refused")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the helper hangs on a FIFO in place of the switch file")
		}
	}

	for _, broken := range []string{"ALLOW_REBOOT=yes\n", "ALLOW_SHELL=1\n", "garbage\n"} {
		f = newFixture(t, broken+"ALLOW_RESTART_VAST_DAEMON=1\n")
		if resp := Execute(context.Background(), req, f.deps); resp.OK {
			t.Errorf("a switch file with %q must disable everything", broken)
		}
	}
}

func TestCommandFailureIsReported(t *testing.T) {
	f := newFixture(t, "ALLOW_RESTART_VAST_DAEMON=1\n")
	f.runner.On("/usr/bin/systemctl restart vastai.service", execx.FakeResponse{ExitCode: 5, Stderr: "Failed to restart vastai.service: Unit vastai.service not found.\n"})
	resp := Execute(context.Background(), Request{Action: ActionRestartVastDaemon}, f.deps)
	if resp.OK || resp.Code != CodeFailed || !strings.Contains(resp.Detail, "not found") {
		t.Fatalf("%+v", resp)
	}
}

func TestDecodeRequestIsStrict(t *testing.T) {
	if req, err := DecodeRequest(strings.NewReader(`{"action":"reboot","delay_s":120}` + "\n")); err != nil || *req.DelayS != 120 {
		t.Fatalf("%+v %v", req, err)
	}
	bad := []string{
		``,
		`{}`,
		`{"action":"reboot","delay_s":120,"cmd":"id"}`,
		`{"action":"reboot","delay_s":"120"}`,
		`{"action":"reboot","delay_s":120} {"action":"restart-vast-daemon"}`,
		`{"action":"restart-vast-daemon","unit":"ssh.service"}`,
		`["reboot"]`,
		`{"action":"reboot","delay_s":120,"pad":"` + strings.Repeat("x", 400) + `"}`,
	}
	for _, in := range bad {
		if req, err := DecodeRequest(strings.NewReader(in)); err == nil {
			t.Errorf("%q must be refused, got %+v", in, req)
		}
	}
}

// serveOnce runs the socket protocol end to end over a real unix socket,
// including the SO_PEERCRED check.
func serveOnce(t *testing.T, f *fixture, allowed []uint32) (*Client, func()) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "helper.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			uc := conn.(*net.UnixConn)
			uid, err := PeerUID(uc)
			if err != nil {
				t.Errorf("PeerUID: %v", err)
			}
			ServeConn(context.Background(), uc, uid, allowed, f.deps)
			_ = conn.Close()
		}
	}()
	return &Client{SocketPath: sock, Timeout: 5 * time.Second}, func() { _ = ln.Close(); <-done }
}

func TestSocketRoundTrip(t *testing.T) {
	f := newFixture(t, "ALLOW_REBOOT=1\n")
	client, stop := serveOnce(t, f, []uint32{uint32(os.Getuid())})
	defer stop()

	detail, err := client.Invoke(context.Background(), Request{Action: ActionReboot, DelayS: ptr(120)})
	if err != nil || !strings.Contains(detail, "reboot scheduled") {
		t.Fatalf("%q %v", detail, err)
	}
	if _, err := client.Invoke(context.Background(), Request{Action: ActionRestartVastDaemon}); err == nil || !strings.Contains(err.Error(), CodeDisabled) {
		t.Fatalf("a disabled action must be refused through the socket too: %v", err)
	}
	if calls := f.runner.CallLog(); len(calls) != 1 {
		t.Fatalf("commands: %v", calls)
	}
	f.mu.Lock()
	audit := strings.Join(f.audit, "\n")
	f.mu.Unlock()
	if !strings.Contains(audit, fmt.Sprintf("request from uid %d: action=reboot", os.Getuid())) {
		t.Fatalf("the peer and the action must be audited:\n%s", audit)
	}
}

func TestSocketRefusesOtherUsers(t *testing.T) {
	f := newFixture(t, "ALLOW_REBOOT=1\nALLOW_RESTART_VAST_DAEMON=1\n")
	// The peer (this test process) is not in the allowed list.
	client, stop := serveOnce(t, f, []uint32{uint32(os.Getuid()) + 12345})
	defer stop()
	resp, err := client.Do(context.Background(), Request{Action: ActionRestartVastDaemon})
	if err != nil || resp.OK || resp.Code != CodeUnauthorized {
		t.Fatalf("%+v %v", resp, err)
	}
	if calls := f.runner.CallLog(); len(calls) != 0 {
		t.Fatalf("commands were run for an unauthorised peer: %v", calls)
	}
}

func TestSocketRefusesMalformedRequests(t *testing.T) {
	f := newFixture(t, "ALLOW_REBOOT=1\nALLOW_RESTART_VAST_DAEMON=1\n")
	client, stop := serveOnce(t, f, []uint32{uint32(os.Getuid())})
	defer stop()
	for _, raw := range []string{
		"reboot\n",
		`{"action":"reboot","delay_s":120,"extra":true}` + "\n",
		`{"action":"sh","delay_s":120}` + "\n",
		strings.Repeat("x", 1000) + "\n",
	} {
		conn, err := net.Dial("unix", client.SocketPath)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = conn.Write([]byte(raw))
		buf := make([]byte, 1024)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _ := conn.Read(buf)
		_ = conn.Close()
		if !strings.Contains(string(buf[:n]), `"ok":false`) {
			t.Errorf("%q: response %q", raw, buf[:n])
		}
	}
	if calls := f.runner.CallLog(); len(calls) != 0 {
		t.Fatalf("commands were run: %v", calls)
	}
}

func TestClientReportsUnavailableHelper(t *testing.T) {
	c := &Client{SocketPath: filepath.Join(t.TempDir(), "missing.sock"), Timeout: time.Second}
	if _, err := c.Invoke(context.Background(), Request{Action: ActionRestartVastDaemon}); err == nil {
		t.Fatal("a missing socket must be an error")
	}
	if _, err := c.Invoke(context.Background(), Request{Action: "nonsense"}); err == nil {
		t.Fatal("the client must validate before connecting")
	}
}
