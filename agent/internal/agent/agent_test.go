package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/client"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/credential"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/enroll"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/fsx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/helper"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/logx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/redact"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/spool"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/testapi"
)

// syncBuffer is a log sink that can be read while the agent runs.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// fakeCollector returns a small fixed sample and counts calls.
type fakeCollector struct {
	n    atomic.Int64
	hook func(n int64)
}

func p[T any](v T) *T { return &v }

func (f *fakeCollector) Collect(context.Context) (protocol.Sample, []string) {
	n := f.n.Add(1)
	if f.hook != nil {
		f.hook(n)
	}
	return protocol.Sample{
		UptimeS: p(uint64(1000 + n)),
		CPU:     protocol.CPU{Model: "Test CPU", Cores: p(8), Load1: p(0.5)},
		Memory:  protocol.Memory{TotalBytes: p(uint64(64e9)), AvailableBytes: p(uint64(60e9))},
		Disks:   []protocol.Disk{{Mount: "/", FS: "ext4", TotalBytes: p(uint64(500e9)), AvailBytes: p(uint64(400e9))}},
		GPUs: []protocol.GPU{{Index: 0, UUID: "GPU-test", Name: "NVIDIA GeForce RTX 4090", DriverVersion: "550.120",
			VRAMTotalMiB: p(int64(24564)), VRAMUsedMiB: p(int64(12)), UtilPct: p(int64(0)), PowerW: p(34.8), TempC: p(int64(41))}},
		Services: map[string]string{"docker": "active", "vastai": "active", "nvidia-persistenced": "not-installed"},
		Vast:     protocol.Vast{DaemonInstalled: true},
	}, nil
}

type env struct {
	t        *testing.T
	api      *testapi.Server
	srv      *httptest.Server
	stateDir string
	client   *client.Client
	cred     *credential.File
	logs     *syncBuffer
	coll     *fakeCollector
	redactor *redact.Redactor
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, api: testapi.New(), stateDir: t.TempDir(), logs: &syncBuffer{}, coll: &fakeCollector{}, redactor: redact.New()}
	e.srv = httptest.NewServer(e.api.Handler())
	t.Cleanup(e.srv.Close)
	e.client = e.newClient(2 * time.Second)
	e.pair()
	return e
}

func (e *env) newClient(timeout time.Duration) *client.Client {
	c, err := client.New(client.Options{BaseURL: e.srv.URL, AllowInsecureLoopback: true, Timeout: timeout})
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

func (e *env) pair() {
	e.t.Helper()
	cred, err := enroll.Pair(context.Background(), enroll.Params{
		Client: e.client, StateDir: e.stateDir, Code: e.api.NewPairingCode(), Hostname: "gpu-01",
		OS: protocol.OSInfo{ID: "ubuntu", VersionID: "24.04", Kernel: "6.8.0", Arch: "amd64"},
	})
	if err != nil {
		e.t.Fatal(err)
	}
	e.cred = cred
}

func (e *env) agent(mod func(*Options)) *Agent {
	e.t.Helper()
	o := Options{
		StateDir: e.stateDir, SpoolDir: filepath.Join(e.stateDir, "spool"), SpoolQuotaBytes: 4 * 1024 * 1024,
		Interval: 5 * time.Millisecond, IgnoreServerInterval: true,
		BackoffBase: 5 * time.Millisecond, BackoffCap: 20 * time.Millisecond,
		Client: e.client, Collector: e.coll, BootID: "7f6b1f6e-3c1e-4a55-9a3b-0d6e2f1f6c11",
		Logger: logx.New(e.logs, slog.LevelDebug, e.redactor), Redactor: e.redactor,
	}
	if mod != nil {
		mod(&o)
	}
	a, err := New(o)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(a.Close)
	return a
}

func (e *env) device() testapi.DeviceSnapshot {
	e.t.Helper()
	d, ok := e.api.Device(e.cred.DeviceID)
	if !ok {
		e.t.Fatal("device unknown to the server")
	}
	return d
}

func sortedSeqs(d testapi.DeviceSnapshot) []uint64 {
	var out []uint64
	for seq := range d.Samples {
		out = append(out, seq)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func wantContiguous(t *testing.T, d testapi.DeviceSnapshot, from, to uint64) {
	t.Helper()
	got := sortedSeqs(d)
	if uint64(len(got)) != to-from+1 {
		t.Fatalf("server holds %d samples, want %d..%d: %v", len(got), from, to, got)
	}
	for i, seq := range got {
		if seq != from+uint64(i) {
			t.Fatalf("gap in the server's samples: %v", got)
		}
	}
}

func runFor(t *testing.T, a *Agent) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := a.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != nil {
		t.Fatal("the agent did not finish in time")
	}
}

// waitFor polls until cond is true.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// start runs the agent in the background and returns a stop function.
func start(t *testing.T, a *Agent) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	return func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("the agent did not stop")
		}
	}
}

func TestHealthyRunDeliversEverySampleOnce(t *testing.T) {
	e := newEnv(t)
	a := e.agent(func(o *Options) { o.StopAfterSamples = 12 })
	runFor(t, a)
	d := e.device()
	wantContiguous(t, d, 1, 12)
	if d.Duplicates != 0 || a.SpoolLen() != 0 {
		t.Fatalf("duplicates %d, spool %d", d.Duplicates, a.SpoolLen())
	}
	if d.SyntheticCount != 0 {
		t.Fatal("the real agent path must never mark samples synthetic")
	}
	for _, hb := range d.Heartbeats {
		if hb.BootID != "7f6b1f6e-3c1e-4a55-9a3b-0d6e2f1f6c11" {
			t.Fatalf("boot id: %q", hb.BootID)
		}
	}
	st, err := ReadState(e.stateDir)
	if err != nil || st.State != StateOnline || st.LastHeartbeatOK == "" || st.Seq != 12 || st.CredentialID != e.cred.CredentialID {
		t.Fatalf("status file: %+v %v", st, err)
	}
	raw, _ := os.ReadFile(StatePath(e.stateDir))
	if strings.Contains(string(raw), e.cred.Token) {
		t.Fatal("the status file contains the credential")
	}
}

func TestOfflineBufferingThenFlush(t *testing.T) {
	e := newEnv(t)
	var down atomic.Bool
	down.Store(true)
	e.api.SetHeartbeatFault(func(int) *testapi.Fault {
		if down.Load() {
			return &testapi.Fault{Status: 503}
		}
		return nil
	})
	// The API comes back when 250 samples are waiting: more than two batches.
	e.coll.hook = func(n int64) {
		if n == 250 {
			down.Store(false)
		}
	}
	a := e.agent(func(o *Options) { o.Interval = time.Millisecond; o.StopAfterSamples = 260 })
	runFor(t, a)

	d := e.device()
	wantContiguous(t, d, 1, 260)
	if d.Duplicates != 0 {
		t.Fatalf("duplicates: %d", d.Duplicates)
	}
	if a.SpoolLen() != 0 || a.Dropped() != 0 {
		t.Fatalf("spool %d dropped %d", a.SpoolLen(), a.Dropped())
	}
	// The backlog is flushed oldest first, in batches of at most 100.
	first := d.Heartbeats[0]
	if first.Seqs[0] != 1 || len(first.Seqs) != protocol.MaxSamplesPerRequest {
		t.Fatalf("first batch after the outage: %d samples starting at %d", len(first.Seqs), first.Seqs[0])
	}
	var last uint64
	for _, hb := range d.Heartbeats {
		if len(hb.Seqs) > protocol.MaxSamplesPerRequest {
			t.Fatalf("batch of %d samples", len(hb.Seqs))
		}
		for _, seq := range hb.Seqs {
			if seq <= last {
				t.Fatalf("samples were not sent oldest first: %d after %d", seq, last)
			}
			last = seq
		}
	}
	if !strings.Contains(e.logs.String(), "heartbeat failed; samples stay in the spool") {
		t.Fatal("the outage must be logged")
	}
}

func TestLostAcknowledgementLeadsToASafeResend(t *testing.T) {
	e := newEnv(t)
	// Request 2 is processed by the server, but the agent sees an error.
	e.api.SetHeartbeatFault(func(n int) *testapi.Fault {
		if n == 2 {
			return &testapi.Fault{ProcessThenFail: true}
		}
		return nil
	})
	a := e.agent(func(o *Options) { o.StopAfterSamples = 8 })
	runFor(t, a)
	d := e.device()
	wantContiguous(t, d, 1, 8)
	if d.Duplicates == 0 {
		t.Fatal("the unacknowledged batch must have been resent")
	}
	// The resend carries the very same sequence numbers as the lost batch.
	lost, resent := d.Heartbeats[1], d.Heartbeats[2]
	if fmt.Sprint(resent.Seqs[:len(lost.Seqs)]) != fmt.Sprint(lost.Seqs) || resent.Duplicates != len(lost.Seqs) {
		t.Fatalf("lost %v, resent %v (duplicates %d)", lost.Seqs, resent.Seqs, resent.Duplicates)
	}
	if a.SpoolLen() != 0 {
		t.Fatal("acknowledged samples must be deleted")
	}
}

func TestServerTimeoutAfterProcessingLeadsToASafeResend(t *testing.T) {
	e := newEnv(t)
	e.api.SetHeartbeatFault(func(n int) *testapi.Fault {
		if n == 1 {
			return &testapi.Fault{Hang: true}
		}
		return nil
	})
	e.client = e.newClient(150 * time.Millisecond)
	a := e.agent(func(o *Options) { o.StopAfterSamples = 5 })
	runFor(t, a)
	d := e.device()
	wantContiguous(t, d, 1, 5)
	if d.Duplicates != 1 || d.Heartbeats[1].Seqs[0] != 1 {
		t.Fatalf("seq 1 must be resent after the timeout: duplicates %d, heartbeats %+v", d.Duplicates, d.Heartbeats[:2])
	}
}

func TestMalformedAndOversizedResponsesDoNotCrashOrLoseData(t *testing.T) {
	e := newEnv(t)
	e.api.SetHeartbeatFault(func(n int) *testapi.Fault {
		switch n {
		case 1:
			return &testapi.Fault{RawBody: []byte("<html>200 but not JSON</html>")}
		case 2:
			return &testapi.Fault{RawBody: []byte(`{"accepted":`)}
		case 3:
			return &testapi.Fault{RawBody: []byte(`null`)}
		case 4:
			return &testapi.Fault{HugeBody: true}
		case 5:
			return &testapi.Fault{RawBody: []byte(`{"accepted":"one","operations":"none"}`)}
		case 6:
			return &testapi.Fault{RawBody: []byte(strings.Repeat("[", 200000))}
		}
		return nil
	})
	a := e.agent(func(o *Options) { o.StopAfterSamples = 10 })
	runFor(t, a)
	d := e.device()
	wantContiguous(t, d, 1, 10)
	if a.SpoolLen() != 0 || a.Dropped() != 0 {
		t.Fatalf("spool %d dropped %d", a.SpoolLen(), a.Dropped())
	}
	if e.api.HeartbeatRequests() < 7 {
		t.Fatalf("only %d heartbeat requests", e.api.HeartbeatRequests())
	}
}

func TestHostileOperationsInResponseDoNotCrash(t *testing.T) {
	e := newEnv(t)
	e.api.SetHeartbeatFault(func(n int) *testapi.Fault {
		if n == 1 {
			return &testapi.Fault{RawBody: []byte(`{"accepted":1,"duplicates":0,"rejected":0,"highest_seq":1,"next_interval_s":-5,"operations":[
				{"id":"../../x","type":"reboot","params":{},"nonce":"n"},
				{"id":"00000000-0000-4000-8000-000000000001","type":"run_shell","params":{"cmd":"id"},"issued_at":"2026-10-02T07:45:00Z","expires_at":"2999-01-01T00:00:00Z","nonce":"c29tZS1yYW5kb20tbm9uY2UtMTIz"},
				{"id":"00000000-0000-4000-8000-000000000002","type":"reboot","params":"not an object","issued_at":"x","expires_at":"y","nonce":""},
				{},
				{"id":17,"type":[1,2]}
			]}`)}
		}
		return nil
	})
	called := 0
	a := e.agent(func(o *Options) {
		o.StopAfterSamples = 4
		o.OpsEnabled = []string{"reboot"}
		o.Helper = helperFunc(func(helper.Request) (string, error) { called++; return "", nil })
	})
	runFor(t, a)
	if called != 0 {
		t.Fatal("a hostile response reached the privileged helper")
	}
}

type helperFunc func(helper.Request) (string, error)

func (f helperFunc) Invoke(_ context.Context, req helper.Request) (string, error) { return f(req) }

func TestRetryAfterIsHonoured(t *testing.T) {
	e := newEnv(t)
	var mu sync.Mutex
	var times []time.Time
	e.api.SetHeartbeatFault(func(n int) *testapi.Fault {
		mu.Lock()
		times = append(times, time.Now())
		mu.Unlock()
		if n == 1 {
			return &testapi.Fault{Status: 429, Code: protocol.CodeRateLimited, RetryAfter: "1"}
		}
		return nil
	})
	a := e.agent(func(o *Options) { o.StopAfterSamples = 3 })
	runFor(t, a)
	mu.Lock()
	gap := times[1].Sub(times[0])
	mu.Unlock()
	// Backoff alone would retry within 5 ms; Retry-After: 1 must win.
	if gap < time.Second {
		t.Fatalf("retried after %v, before Retry-After elapsed", gap)
	}
	if gap > 3*time.Second {
		t.Fatalf("waited %v for Retry-After: 1", gap)
	}
	wantContiguous(t, e.device(), 1, uint64(a.Collected()))
}

func TestUnauthorizedStopsSendingAndExposesRevoked(t *testing.T) {
	e := newEnv(t)
	a := e.agent(nil)
	stop := start(t, a)
	waitFor(t, "first samples", func() bool { return len(e.device().Samples) >= 3 })

	e.api.Revoke(e.cred.DeviceID)
	waitFor(t, "revoked state", func() bool {
		st, err := ReadState(e.stateDir)
		return err == nil && st.State == StateRevoked
	})
	requests := e.api.HeartbeatRequests()
	st, _ := ReadState(e.stateDir)
	spooled := st.SpoolSamples
	// The agent keeps collecting and buffering, but must not hammer the API.
	waitFor(t, "buffering while revoked", func() bool {
		st, err := ReadState(e.stateDir)
		return err == nil && st.SpoolSamples >= spooled+20
	})
	if got := e.api.HeartbeatRequests(); got != requests {
		t.Fatalf("%d heartbeat requests were sent after the 401", got-requests)
	}
	stop()

	// A restart with the same revoked credential must not send either.
	a2 := e.agent(nil)
	stop = start(t, a2)
	time.Sleep(100 * time.Millisecond)
	stop()
	if got := e.api.HeartbeatRequests(); got != requests {
		t.Fatalf("%d heartbeat requests were sent after a restart in revoked state", got-requests)
	}
	st, _ = ReadState(e.stateDir)
	if st.State != StateRevoked || st.RevokedCredentialID != e.cred.CredentialID {
		t.Fatalf("status file: %+v", st)
	}
	if !strings.Contains(e.logs.String(), "the API rejected the device credential") {
		t.Fatal("the revocation must be logged")
	}
}

func TestRepairAfterRevocationResumesAndDropsOldSamples(t *testing.T) {
	e := newEnv(t)
	oldDevice := e.cred.DeviceID
	a := e.agent(nil)
	stop := start(t, a)
	defer stop()
	waitFor(t, "first samples", func() bool { return len(e.device().Samples) >= 2 })
	e.api.Revoke(oldDevice)
	waitFor(t, "revoked state", func() bool {
		st, err := ReadState(e.stateDir)
		return err == nil && st.State == StateRevoked && st.SpoolSamples >= 5
	})
	old, _ := e.api.Device(oldDevice)
	highestOld := old.HighestSeq

	// happyminingctl unpair, then pair with a new code (a new device).
	if err := credential.Delete(credential.Path(e.stateDir)); err != nil {
		t.Fatal(err)
	}
	e.pair()
	if e.cred.DeviceID == oldDevice {
		t.Fatal("the fixture did not create a new device")
	}
	waitFor(t, "samples on the new device", func() bool { return len(e.device().Samples) >= 3 })
	for _, seq := range sortedSeqs(e.device()) {
		// Samples collected for the old device while revoked must not be
		// attributed to the new one.
		st, _ := ReadState(e.stateDir)
		if seq <= highestOld {
			t.Fatalf("sample %d of the old device was sent to the new device (state %+v)", seq, st)
		}
	}
	if !strings.Contains(e.logs.String(), "spooled samples of the previous device were dropped") {
		t.Fatal("dropping the old samples must be logged")
	}
}

func TestInvalidRequestIsDroppedNotResent(t *testing.T) {
	e := newEnv(t)
	e.api.SetHeartbeatFault(func(n int) *testapi.Fault {
		if n == 1 {
			return &testapi.Fault{Status: 422, Code: protocol.CodeInvalidRequest}
		}
		return nil
	})
	a := e.agent(func(o *Options) { o.StopAfterSamples = 6 })
	runFor(t, a)
	d := e.device()
	if _, resent := d.Samples[1]; resent {
		t.Fatal("a payload refused as invalid_request must not be resent")
	}
	if a.Dropped() == 0 || a.SpoolLen() != 0 {
		t.Fatalf("dropped %d spool %d", a.Dropped(), a.SpoolLen())
	}
	if d.HighestSeq != 6 {
		t.Fatalf("later samples must still arrive: highest %d", d.HighestSeq)
	}
}

func TestErrorsWithoutEnvelopeNeverDropData(t *testing.T) {
	e := newEnv(t)
	e.api.SetHeartbeatFault(func(n int) *testapi.Fault {
		switch n {
		case 1:
			return &testapi.Fault{Status: 400} // a proxy's error page, not our API
		case 2:
			return &testapi.Fault{Status: 401}
		case 3:
			return &testapi.Fault{Status: 404}
		case 4:
			return &testapi.Fault{Status: 403, Code: protocol.CodeForbidden}
		}
		return nil
	})
	a := e.agent(func(o *Options) { o.StopAfterSamples = 6 })
	runFor(t, a)
	wantContiguous(t, e.device(), 1, 6)
	if st, _ := ReadState(e.stateDir); st.State == StateRevoked {
		t.Fatal("a 401 without the protocol's error envelope must not mark the device revoked")
	}
}

func TestPayloadTooLargeSplitsTheBatch(t *testing.T) {
	e := newEnv(t)
	var down atomic.Bool
	down.Store(true)
	var splitOnce atomic.Bool
	e.api.SetHeartbeatFault(func(int) *testapi.Fault {
		if down.Load() {
			return &testapi.Fault{Status: 503}
		}
		if splitOnce.CompareAndSwap(false, true) {
			return &testapi.Fault{Status: 413, Code: protocol.CodePayloadTooLarge}
		}
		return nil
	})
	e.coll.hook = func(n int64) {
		if n == 40 {
			down.Store(false)
		}
	}
	a := e.agent(func(o *Options) { o.Interval = time.Millisecond; o.StopAfterSamples = 45 })
	runFor(t, a)
	d := e.device()
	wantContiguous(t, d, 1, 45)
	if a.Dropped() != 0 {
		t.Fatalf("a 413 must split, not drop: %d dropped", a.Dropped())
	}
	if !strings.Contains(e.logs.String(), "batch too large; splitting") {
		t.Fatal("the split must be logged")
	}
}

func TestSpoolQuotaDropsOldestAndCountsThem(t *testing.T) {
	e := newEnv(t)
	var down atomic.Bool
	down.Store(true)
	e.api.SetHeartbeatFault(func(int) *testapi.Fault {
		if down.Load() {
			return &testapi.Fault{Status: 503}
		}
		return nil
	})
	const total = 400
	e.coll.hook = func(n int64) {
		if n == total {
			down.Store(false)
		}
	}
	a := e.agent(func(o *Options) {
		o.Interval = time.Millisecond
		o.StopAfterSamples = total
		o.SpoolQuotaBytes = spool.MaxSampleBytes // 64 KiB: roughly a hundred test samples
	})
	runFor(t, a)
	d := e.device()
	got := sortedSeqs(d)
	if a.Dropped() == 0 || uint64(len(got))+a.Dropped() != total {
		t.Fatalf("delivered %d + dropped %d != %d", len(got), a.Dropped(), total)
	}
	// What survives is the newest contiguous tail.
	if got[len(got)-1] != total || got[0] != total-uint64(len(got))+1 {
		t.Fatalf("the oldest samples must be dropped first: delivered %d..%d (%d samples)", got[0], got[len(got)-1], len(got))
	}
	logs := e.logs.String()
	if !strings.Contains(logs, "spool quota reached; oldest samples dropped") || !strings.Contains(logs, `"dropped_total"`) {
		t.Fatal("the drop counter must be reported in the logs")
	}
	st, _ := ReadState(e.stateDir)
	if st.DroppedSamples != a.Dropped() {
		t.Fatalf("status file drop counter %d != %d", st.DroppedSamples, a.Dropped())
	}
}

func TestSequenceContinuesAcrossRestart(t *testing.T) {
	e := newEnv(t)
	a := e.agent(func(o *Options) { o.StopAfterSamples = 4 })
	runFor(t, a)
	a.Close()
	b := e.agent(func(o *Options) { o.StopAfterSamples = 4 })
	runFor(t, b)
	d := e.device()
	wantContiguous(t, d, 1, 8)
	if d.Duplicates != 0 {
		t.Fatalf("a restart must not reuse sequence numbers: %d duplicates", d.Duplicates)
	}
}

func TestUnsentSamplesSurviveRestart(t *testing.T) {
	e := newEnv(t)
	var down atomic.Bool
	down.Store(true)
	e.api.SetHeartbeatFault(func(int) *testapi.Fault {
		if down.Load() {
			return &testapi.Fault{Status: 503}
		}
		return nil
	})
	a := e.agent(nil)
	stop := start(t, a)
	waitFor(t, "buffered samples", func() bool {
		st, err := ReadState(e.stateDir)
		return err == nil && st.SpoolSamples >= 10
	})
	stop() // "crash" with a full spool while the API is down
	a.Close()
	if len(e.device().Samples) != 0 {
		t.Fatal("nothing can have been delivered yet")
	}
	down.Store(false)
	b := e.agent(func(o *Options) { o.StopAfterSamples = 2 })
	runFor(t, b)
	d := e.device()
	wantContiguous(t, d, 1, d.HighestSeq)
	if len(d.Samples) < 12 {
		t.Fatalf("only %d samples delivered after the restart", len(d.Samples))
	}
}

func TestLostLocalStateRecoversFromHighestSeq(t *testing.T) {
	e := newEnv(t)
	a := e.agent(func(o *Options) { o.StopAfterSamples = 5 })
	runFor(t, a)
	a.Close()
	// The state directory is wiped except for the credential (worst case).
	_ = os.Remove(filepath.Join(e.stateDir, spool.SequenceFileName))
	_ = os.RemoveAll(filepath.Join(e.stateDir, "spool"))
	b := e.agent(func(o *Options) { o.StopAfterSamples = 4 })
	runFor(t, b)
	d := e.device()
	if d.HighestSeq <= 5 {
		t.Fatalf("new samples were swallowed as duplicates forever: highest %d", d.HighestSeq)
	}
	if !strings.Contains(e.logs.String(), "sequence counter advanced to the server's highest sequence") {
		t.Fatal("the recovery must be logged")
	}
}

func TestStaleSamplesAreDroppedNotSent(t *testing.T) {
	e := newEnv(t)
	sp, err := spool.Open(filepath.Join(e.stateDir, "spool"), 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	old := fmt.Sprintf(`{"seq":1,"collected_at":%q,"synthetic":false}`, protocol.FormatTime(time.Now().Add(-30*24*time.Hour)))
	if _, err := sp.Put(1, []byte(old)); err != nil {
		t.Fatal(err)
	}
	a := e.agent(func(o *Options) { o.StopAfterSamples = 3; o.MaxSampleAge = 7 * 24 * time.Hour })
	runFor(t, a)
	d := e.device()
	if _, sent := d.Samples[1]; sent {
		t.Fatal("a sample older than the maximum age was sent")
	}
	wantContiguous(t, d, 2, 4)
	if a.Dropped() != 1 {
		t.Fatalf("dropped %d", a.Dropped())
	}
}

func TestUnpairedAgentWaitsAndSendsNothing(t *testing.T) {
	e := newEnv(t)
	if err := credential.Delete(credential.Path(e.stateDir)); err != nil {
		t.Fatal(err)
	}
	a := e.agent(func(o *Options) { o.StopAfterSamples = 3 })
	if err := a.Run(context.Background()); !errors.Is(err, ErrNotPaired) {
		t.Fatalf("a bounded run without a credential must fail: %v", err)
	}
	b := e.agent(nil)
	stop := start(t, b)
	time.Sleep(60 * time.Millisecond)
	stop()
	if e.api.HeartbeatRequests() != 0 || e.coll.n.Load() != 0 {
		t.Fatalf("an unpaired agent must neither collect nor send: %d requests, %d collections", e.api.HeartbeatRequests(), e.coll.n.Load())
	}
	if st, _ := ReadState(e.stateDir); st.State != StateUnpaired {
		t.Fatalf("state %q", st.State)
	}
	if n := strings.Count(e.logs.String(), "not paired: nothing is collected or sent"); n != 1 {
		t.Fatalf("the unpaired state must be logged exactly once, got %d", n)
	}
}

func TestGracefulShutdownIsPrompt(t *testing.T) {
	e := newEnv(t)
	e.api.SetHeartbeatFault(func(int) *testapi.Fault { return &testapi.Fault{Hang: true} })
	e.client = e.newClient(30 * time.Second)
	a := e.agent(nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	waitFor(t, "a request in flight", func() bool { return e.api.HeartbeatRequests() >= 1 })
	begin := time.Now()
	cancel() // SIGTERM
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown hangs on an in-flight request")
	}
	if time.Since(begin) > 2*time.Second {
		t.Fatalf("shutdown took %v", time.Since(begin))
	}
	// The sample that was in flight is still in the spool for the next start.
	if n, _, _ := spool.Stat(filepath.Join(e.stateDir, "spool")); n == 0 {
		t.Fatal("the unacknowledged sample was lost on shutdown")
	}
}

func TestLogsAndSpoolNeverContainTheCredential(t *testing.T) {
	e := newEnv(t)
	e.api.SetHeartbeatFault(func(n int) *testapi.Fault {
		switch n {
		case 1:
			return &testapi.Fault{Status: 503}
		case 2:
			return &testapi.Fault{Status: 429, Code: protocol.CodeRateLimited, RetryAfter: "0"}
		case 3:
			return &testapi.Fault{RawBody: []byte("garbage")}
		}
		return nil
	})
	e.api.QueueOperation(e.cred.DeviceID, protocol.Operation{Type: protocol.OpRotateCredential})
	e.api.QueueOperation(e.cred.DeviceID, protocol.Operation{Type: protocol.OpCollectDiagnostics,
		Params: json.RawMessage(`{"sections":["services","gpu","disk","network","agent"]}`)})
	a := e.agent(func(o *Options) { o.StopAfterSamples = 8 })
	runFor(t, a)

	newCred, err := credential.Load(credential.Path(e.stateDir))
	if err != nil {
		t.Fatal(err)
	}
	secrets := []string{e.cred.Token, newCred.Token,
		e.cred.Token[strings.IndexByte(e.cred.Token, '.')+1:], newCred.Token[strings.IndexByte(newCred.Token, '.')+1:]}
	haystacks := map[string]string{"logs": e.logs.String()}
	d := e.device()
	for i, ack := range d.Acks {
		haystacks[fmt.Sprintf("ack %d", i)] = ack.Body.Detail + string(ack.Body.Result)
	}
	for _, name := range []string{StateFileName, "ops.journal", "seq"} {
		data, _ := os.ReadFile(filepath.Join(e.stateDir, name))
		haystacks[name] = string(data)
	}
	for where, text := range haystacks {
		for _, s := range secrets {
			if strings.Contains(text, s) {
				t.Errorf("%s contains a credential secret", where)
			}
		}
		if strings.Contains(text, "Bearer hmd_") {
			t.Errorf("%s contains a bearer token", where)
		}
	}
	if !strings.Contains(e.logs.String(), "credential rotated") {
		t.Fatal("the test did not exercise rotation")
	}
	// Every bearer token the server saw was well-formed and current.
	for _, h := range e.api.AuthorizationHeaders() {
		if h != "Bearer "+e.cred.Token && h != "Bearer "+newCred.Token {
			t.Fatalf("unexpected Authorization header sent")
		}
	}
}

func TestServerIntervalIsClamped(t *testing.T) {
	e := newEnv(t)
	a := e.agent(func(o *Options) {
		o.IgnoreServerInterval = false
		o.Interval = 60 * time.Second
		o.MinInterval = 15 * time.Second
		o.MaxInterval = time.Hour
	})
	steps := []struct {
		in   int
		want time.Duration
	}{
		{1, 15 * time.Second},  // below the minimum: clamped up
		{30, 30 * time.Second}, // in range: taken
		{999999, time.Hour},    // above the maximum: clamped down
		{0, time.Hour},         // absent: unchanged
		{-5, time.Hour},        // nonsense: unchanged
	}
	for _, step := range steps {
		a.onAcknowledged(context.Background(), &protocol.HeartbeatResponse{Accepted: 1, NextIntervalS: step.in}, 1)
		if a.interval != step.want {
			t.Errorf("next_interval_s=%d: interval %v, want %v", step.in, a.interval, step.want)
		}
	}
}

func TestNormalizeEnforcesProtocolBounds(t *testing.T) {
	s := protocol.Sample{Services: map[string]string{}}
	long := strings.Repeat("é", 300)
	s.CPU.Model = long
	for i := 0; i < 50; i++ {
		s.GPUs = append(s.GPUs, protocol.GPU{Index: i, Name: long})
		s.Disks = append(s.Disks, protocol.Disk{Mount: long})
		s.Services[fmt.Sprintf("unit-%02d", i)] = "reloading"
	}
	hint := long
	s.Vast.MachineIDHint = &hint
	Normalize(&s)
	if len(s.GPUs) != 32 || len(s.Disks) != 16 || len(s.Services) != 16 {
		t.Fatalf("%d GPUs, %d disks, %d services", len(s.GPUs), len(s.Disks), len(s.Services))
	}
	if len([]rune(s.CPU.Model)) != 128 || len([]rune(s.GPUs[0].Name)) != 128 || len([]rune(s.Disks[0].Mount)) != 128 {
		t.Fatal("strings must be cut to 128 characters")
	}
	for name, state := range s.Services {
		if state != protocol.ServiceUnknown {
			t.Fatalf("%s: unknown state %q must become \"unknown\"", name, state)
		}
	}
	var empty protocol.Sample
	Normalize(&empty)
	raw, _ := json.Marshal(empty)
	for _, want := range []string{`"disks":[]`, `"gpus":[]`, `"services":{}`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("want %s in %s", want, raw)
		}
	}
}

func TestOperationsEndToEnd(t *testing.T) {
	e := newEnv(t)
	dev := e.cred.DeviceID
	refresh := e.api.QueueOperation(dev, protocol.Operation{Type: protocol.OpRefreshInventory})
	diag := e.api.QueueOperation(dev, protocol.Operation{Type: protocol.OpCollectDiagnostics, Params: json.RawMessage(`{"sections":["gpu","agent"]}`)})
	pre := e.api.QueueOperation(dev, protocol.Operation{Type: protocol.OpRunPreflight})
	reboot := e.api.QueueOperation(dev, protocol.Operation{Type: protocol.OpReboot, Params: json.RawMessage(`{"delay_s":120}`)})
	restart := e.api.QueueOperation(dev, protocol.Operation{Type: protocol.OpRestartVastDaemon})
	bench := e.api.QueueOperation(dev, protocol.Operation{Type: protocol.OpRunBenchmark, Params: json.RawMessage(`{"duration_s":60}`)})
	profile := e.api.QueueOperation(dev, protocol.Operation{Type: protocol.OpApplyHardwareProfile, Params: json.RawMessage(`{"profile_id":"eco"}`)})
	unknown := e.api.QueueOperation(dev, protocol.Operation{Type: "run_shell", Params: json.RawMessage(`{"cmd":"id"}`)})
	badParams := e.api.QueueOperation(dev, protocol.Operation{Type: protocol.OpRefreshInventory, Params: json.RawMessage(`{"x":1}`)})
	expired := e.api.QueueOperation(dev, protocol.Operation{Type: protocol.OpRefreshInventory, ExpiresAt: protocol.FormatTime(time.Now().Add(-time.Minute))})

	helperCalls := 0
	a := e.agent(func(o *Options) {
		o.StopAfterSamples = 6
		o.Helper = helperFunc(func(helper.Request) (string, error) { helperCalls++; return "done", nil })
		o.Preflight = func(context.Context) (string, any, error) {
			return "WARN", map[string]any{"overall": "WARN", "checks": []any{}}, nil
		}
	})
	runFor(t, a)
	d := e.device()
	want := map[string]string{
		refresh.ID: protocol.AckSucceeded, diag.ID: protocol.AckSucceeded, pre.ID: protocol.AckSucceeded,
		reboot.ID: protocol.AckRejected, restart.ID: protocol.AckRejected,
		bench.ID: protocol.AckRejected, profile.ID: protocol.AckRejected,
		unknown.ID: protocol.AckRejected, badParams.ID: protocol.AckRejected,
		expired.ID: "expired", // the fake API answers 410 to the acknowledgement
	}
	for id, status := range want {
		if d.FinalOperations[id] != status {
			t.Errorf("operation %s: final %q, want %q", id, d.FinalOperations[id], status)
		}
	}
	if d.PendingOps != 0 {
		t.Errorf("%d operations still pending", d.PendingOps)
	}
	if helperCalls != 0 {
		t.Fatal("disabled-by-default operations reached the privileged helper")
	}
	details := map[string]string{}
	for _, ack := range d.Acks {
		details[ack.OperationID] = ack.Body.Detail
		if !json.Valid(ack.Body.Result) {
			t.Errorf("result is not JSON: %s", ack.Body.Result)
		}
	}
	for id, wantDetail := range map[string]string{
		reboot.ID: "disabled by local configuration", restart.ID: "disabled by local configuration",
		bench.ID: "not implemented in this agent version", profile.ID: "not implemented in this agent version",
		unknown.ID: "unknown operation type", badParams.ID: "invalid params", expired.ID: "operation expired",
	} {
		if !strings.Contains(details[id], wantDetail) {
			t.Errorf("operation %s: detail %q, want %q", id, details[id], wantDetail)
		}
	}
	// Each acknowledgement echoed the operation's own nonce (the fake API
	// answers 403 otherwise and the operation would still be pending).
	for _, ack := range d.Acks {
		if ack.OperationID == diag.ID {
			var result map[string]any
			_ = json.Unmarshal(ack.Body.Result, &result)
			if _, ok := result["gpu"]; !ok {
				t.Errorf("diagnostics result lacks the gpu section: %s", ack.Body.Result)
			}
			if _, ok := result["services"]; ok {
				t.Errorf("diagnostics returned a section that was not requested")
			}
		}
	}
}

func TestOptInOperationReachesTheHelperExactlyOnce(t *testing.T) {
	e := newEnv(t)
	op := e.api.QueueOperation(e.cred.DeviceID, protocol.Operation{Type: protocol.OpReboot, Params: json.RawMessage(`{"delay_s":300}`)})
	var got []helper.Request
	a := e.agent(func(o *Options) {
		o.StopAfterSamples = 5
		o.OpsEnabled = []string{protocol.OpReboot}
		o.Helper = helperFunc(func(req helper.Request) (string, error) {
			got = append(got, req)
			return "reboot scheduled in 5 minute(s)", nil
		})
	})
	runFor(t, a)
	if len(got) != 1 || got[0].Action != helper.ActionReboot || *got[0].DelayS != 300 {
		t.Fatalf("helper calls: %+v", got)
	}
	d := e.device()
	if d.FinalOperations[op.ID] != protocol.AckSucceeded {
		t.Fatalf("final status %q", d.FinalOperations[op.ID])
	}
	var statuses []string
	for _, ack := range d.Acks {
		statuses = append(statuses, ack.Body.Status)
	}
	if fmt.Sprint(statuses) != "[accepted succeeded]" {
		t.Fatalf("acks: %v", statuses)
	}
}

func TestLostAckIsRepeatedWithoutExecutingAgain(t *testing.T) {
	e := newEnv(t)
	op := e.api.QueueOperation(e.cred.DeviceID, protocol.Operation{Type: protocol.OpReboot, Params: json.RawMessage(`{"delay_s":60}`)})
	calls := 0
	// First run: the helper is called, but every acknowledgement is lost
	// because the device gets revoked... simulated by a client whose acks fail.
	failing, err := client.New(client.Options{BaseURL: e.srv.URL, AllowInsecureLoopback: true, Timeout: time.Second,
		WrapTransport: dropAcks})
	if err != nil {
		t.Fatal(err)
	}
	good := e.client
	e.client = failing
	a := e.agent(func(o *Options) {
		o.StopAfterSamples = 2
		o.OpsEnabled = []string{protocol.OpReboot}
		o.Helper = helperFunc(func(helper.Request) (string, error) { calls++; return "reboot scheduled", nil })
	})
	runFor(t, a)
	a.Close()
	if calls != 1 {
		t.Fatalf("helper calls after the first run: %d", calls)
	}
	if _, final := e.device().FinalOperations[op.ID]; final {
		t.Fatal("the fixture did not lose the acknowledgement")
	}
	// Second run (after the "reboot"): the server still lists the operation.
	e.client = good
	b := e.agent(func(o *Options) {
		o.StopAfterSamples = 2
		o.OpsEnabled = []string{protocol.OpReboot}
		o.Helper = helperFunc(func(helper.Request) (string, error) { calls++; return "reboot scheduled", nil })
	})
	runFor(t, b)
	if calls != 1 {
		t.Fatalf("the operation was executed again after a lost acknowledgement: %d calls", calls)
	}
	if got := e.device().FinalOperations[op.ID]; got != protocol.AckSucceeded {
		t.Fatalf("the recorded outcome must reach the server: %q", got)
	}
}

func TestCredentialRotation(t *testing.T) {
	e := newEnv(t)
	op := e.api.QueueOperation(e.cred.DeviceID, protocol.Operation{Type: protocol.OpRotateCredential})
	a := e.agent(func(o *Options) { o.StopAfterSamples = 6 })
	runFor(t, a)
	d := e.device()
	if d.FinalOperations[op.ID] != protocol.AckSucceeded || d.Rotations != 1 {
		t.Fatalf("final %q rotations %d", d.FinalOperations[op.ID], d.Rotations)
	}
	stored, err := credential.Load(credential.Path(e.stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if stored.Token == e.cred.Token || stored.CredentialID != d.CredentialID || stored.DeviceID != e.cred.DeviceID || stored.RotatedAt == "" {
		t.Fatalf("stored credential not rotated: %+v", stored.CredentialID)
	}
	fi, _ := os.Stat(credential.Path(e.stateDir))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("rotated credential mode %04o", fi.Mode().Perm())
	}
	wantContiguous(t, d, 1, 6) // heartbeats continued with the new credential
	headers := e.api.AuthorizationHeaders()
	if headers[len(headers)-1] != "Bearer "+stored.Token {
		t.Fatal("the agent did not switch to the new credential")
	}
	// The old credential stopped working once the new one was used.
	if _, err := e.client.Self(context.Background(), e.cred.Token); err == nil {
		t.Fatal("the fixture should have invalidated the old credential")
	}
}

func TestRotationWriteFailureKeepsTheOldCredential(t *testing.T) {
	e := newEnv(t)
	op := e.api.QueueOperation(e.cred.DeviceID, protocol.Operation{Type: protocol.OpRotateCredential})
	a := e.agent(func(o *Options) {
		o.StopAfterSamples = 6
		o.SaveCredential = func(string, *credential.File, *fsx.Owner) error { return errors.New("disk full") }
	})
	runFor(t, a)
	d := e.device()
	if d.FinalOperations[op.ID] != protocol.AckFailed {
		t.Fatalf("final %q", d.FinalOperations[op.ID])
	}
	stored, err := credential.Load(credential.Path(e.stateDir))
	if err != nil || stored.Token != e.cred.Token {
		t.Fatalf("the old credential must stay on disk: %v", err)
	}
	// The agent kept using the old credential, and it kept working.
	wantContiguous(t, d, 1, 6)
	for _, h := range e.api.AuthorizationHeaders() {
		if h != "Bearer "+e.cred.Token {
			t.Fatal("a credential that was never stored was used")
		}
	}
	if strings.Contains(e.logs.String(), "credential rotated") {
		t.Fatal("rotation must not be reported as done")
	}
}

func TestClockSkewIsReportedOncePerHour(t *testing.T) {
	e := newEnv(t)
	now := time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)
	a := e.agent(func(o *Options) { o.Now = func() time.Time { return now } })
	ack := func(server time.Time) {
		a.onAcknowledged(context.Background(), &protocol.HeartbeatResponse{Accepted: 1, ServerTime: protocol.FormatTime(server)}, 1)
	}
	count := func() int { return strings.Count(e.logs.String(), "the local clock and the API clock differ") }
	ack(now.Add(2 * time.Minute))
	ack(now)
	a.onAcknowledged(context.Background(), &protocol.HeartbeatResponse{Accepted: 1, ServerTime: "garbage"}, 1)
	if count() != 0 {
		t.Fatal("a small difference or an unparseable server time must not warn")
	}
	ack(now.Add(-20 * time.Minute))
	ack(now.Add(20 * time.Minute))
	if count() != 1 {
		t.Fatalf("want one warning, got %d", count())
	}
	now = now.Add(2 * time.Hour)
	ack(now.Add(20 * time.Minute))
	if count() != 2 {
		t.Fatalf("want a second warning after an hour, got %d", count())
	}
}

func TestPairAndUnpairTakeEffectWithoutWaitingForTheInterval(t *testing.T) {
	e := newEnv(t)
	// A long interval, as the API may set it: pairing changes must not wait
	// for the next sample.
	a := e.agent(func(o *Options) { o.Interval = time.Hour; o.CredentialPoll = 10 * time.Millisecond })
	stop := start(t, a)
	defer stop()
	waitFor(t, "the first sample", func() bool { return len(e.device().Samples) == 1 })

	if err := credential.Delete(credential.Path(e.stateDir)); err != nil { // happyminingctl unpair
		t.Fatal(err)
	}
	waitFor(t, "the unpaired state", func() bool {
		st, err := ReadState(e.stateDir)
		return err == nil && st.State == StateUnpaired
	})
	old := e.cred.DeviceID
	e.pair() // happyminingctl pair
	waitFor(t, "a sample for the new device", func() bool { return len(e.device().Samples) >= 1 })
	if d, _ := e.api.Device(old); len(d.Samples) != 1 {
		t.Fatalf("the old device received %d samples", len(d.Samples))
	}
}
