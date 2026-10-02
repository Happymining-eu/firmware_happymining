package sim

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/testapi"
)

func fixedNow() time.Time { return time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC) }

func TestSyntheticTelemetryIsReproducible(t *testing.T) {
	model, err := LookupModel("RTX4090")
	if err != nil {
		t.Fatal(err)
	}
	run := func(seed uint64) string {
		c := NewSynthetic(model, 4, seed, fixedNow)
		var out []protocol.Sample
		for i := 0; i < 20; i++ {
			s, _ := c.Collect(context.Background())
			out = append(out, s)
		}
		raw, _ := json.Marshal(out)
		return string(raw)
	}
	if run(42) != run(42) {
		t.Fatal("the same seed must give the same telemetry")
	}
	if run(42) == run(43) {
		t.Fatal("different seeds must give different telemetry")
	}
	if _, err := LookupModel("gtx-nothing"); err == nil {
		t.Fatal("unknown model accepted")
	}
}

func TestSyntheticSamplesAreValidProtocolSamples(t *testing.T) {
	for name, model := range Models {
		c := NewSynthetic(model, 8, 7, fixedNow)
		for i := 0; i < 50; i++ {
			s, _ := c.Collect(context.Background())
			s.Seq, s.CollectedAt, s.Synthetic = uint64(i+1), "2026-10-02T08:00:00Z", true
			raw, _ := json.Marshal(s)
			var decoded protocol.Sample
			if err := testapi.ValidateSample(raw, &decoded); err != nil {
				t.Fatalf("%s: %v: %s", name, err, raw)
			}
			for _, g := range s.GPUs {
				if *g.UtilPct < 0 || *g.UtilPct > 100 || *g.VRAMUsedMiB > *g.VRAMTotalMiB || *g.PowerW < model.IdleW || *g.PowerW > model.MaxW {
					t.Fatalf("%s: implausible GPU values: %s", name, raw)
				}
			}
			if s.Vast.MachineIDHint != nil {
				t.Fatal("a simulated machine must not invent a Vast machine id hint")
			}
		}
	}
}

func TestSimulatorEndToEnd(t *testing.T) {
	api := testapi.New()
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	const machines, samples = 3, 30
	var codes []string
	for i := 0; i < machines; i++ {
		// Operators type codes in lower case with spaces: the simulator
		// goes through the same normalisation as happyminingctl.
		codes = append(codes, strings.ToLower(strings.ReplaceAll(api.NewPairingCode(), "-", " ")))
	}
	stateDir := t.TempDir()
	opts := Options{
		APIURL: srv.URL, AllowInsecureLoopback: true,
		Machines: machines, PairingCodes: codes, StateDir: stateDir,
		GPUModel: "rtx4090", GPUs: 2, Interval: 2 * time.Millisecond, Samples: samples, Seed: 7,
		OutageAfter: 5, OutageFor: 10, DuplicateEvery: 4,
		BackoffBase: 2 * time.Millisecond, BackoffCap: 10 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	summary, err := Run(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !summary.Synthetic || len(summary.Machines) != machines {
		t.Fatalf("summary: %+v", summary)
	}
	for _, m := range summary.Machines {
		if m.SamplesCollected != samples || m.SpoolLeft != 0 || m.SamplesDropped != 0 || m.Error != "" {
			t.Errorf("%s: %+v", m.Hostname, m)
		}
		if m.FailedRequests == 0 {
			t.Errorf("%s: the simulated outage did not block any request", m.Hostname)
		}
		if m.LostResponses == 0 {
			t.Errorf("%s: no response was lost", m.Hostname)
		}
		d, ok := api.Device(m.DeviceID)
		if !ok {
			t.Fatalf("%s: device %s unknown to the server", m.Hostname, m.DeviceID)
		}
		if len(d.Samples) != samples || d.HighestSeq != samples {
			t.Errorf("%s: server holds %d samples, highest %d", m.Hostname, len(d.Samples), d.HighestSeq)
		}
		// "synthetic": true in every sample is mandatory.
		if d.SyntheticCount != samples {
			t.Errorf("%s: %d of %d samples are marked synthetic", m.Hostname, d.SyntheticCount, samples)
		}
		for seq, raw := range d.Samples {
			if !strings.Contains(string(raw), `"synthetic":true`) {
				t.Fatalf("%s: sample %d is not marked synthetic: %s", m.Hostname, seq, raw)
			}
		}
		if d.Duplicates == 0 {
			t.Errorf("%s: duplicate sends were not exercised", m.Hostname)
		}
		// The outage produced a backlog that was flushed in one request.
		maxBatch := 0
		for _, hb := range d.Heartbeats {
			maxBatch = max(maxBatch, len(hb.Seqs))
		}
		if maxBatch < 5 {
			t.Errorf("%s: largest batch %d: the outage backlog was not flushed as a batch", m.Hostname, maxBatch)
		}
		if d.Hostname != m.Hostname {
			t.Errorf("hostname %q vs %q", d.Hostname, m.Hostname)
		}
	}
	for _, d := range api.Summarize().Devices {
		if !d.Contiguous {
			t.Errorf("device %s has gaps", d.DeviceID)
		}
	}

	// A second run reuses the stored credentials (no codes needed) and
	// continues the sequence numbers.
	opts.PairingCodes = nil
	opts.OutageFor, opts.DuplicateEvery, opts.Samples = 0, 0, 5
	summary, err = Run(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range summary.Machines {
		d, _ := api.Device(m.DeviceID)
		if d.HighestSeq != samples+5 || len(d.Samples) != samples+5 {
			t.Errorf("%s: after the second run the server holds %d samples, highest %d", m.Hostname, len(d.Samples), d.HighestSeq)
		}
	}

	// The credential files are private.
	for i := 1; i <= machines; i++ {
		matches, _ := filepath.Glob(filepath.Join(stateDir, "machine-00*", "credential.json"))
		if len(matches) != machines {
			t.Fatalf("credential files: %v", matches)
		}
		fi, _ := os.Stat(matches[i-1])
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s has mode %04o", matches[i-1], fi.Mode().Perm())
		}
	}
}

func TestSimulatorRefusedInLiveMode(t *testing.T) {
	api := testapi.New()
	api.RefuseSynthetic = true // what the real API does in LIVE mode
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	summary, err := Run(ctx, Options{
		APIURL: srv.URL, AllowInsecureLoopback: true, Machines: 1, PairingCodes: []string{api.NewPairingCode()},
		StateDir: t.TempDir(), GPUModel: "rtx3090", GPUs: 1, Interval: 2 * time.Millisecond, Samples: 3,
		BackoffBase: time.Millisecond, BackoffCap: 2 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := api.Device(summary.Machines[0].DeviceID)
	if len(d.Samples) != 0 {
		t.Fatal("synthetic samples were accepted by a LIVE-mode API")
	}
	if summary.Machines[0].SamplesDropped == 0 {
		t.Fatal("the refusal must be visible in the summary")
	}
}

func TestSimulatorInputValidation(t *testing.T) {
	api := testapi.New()
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()
	base := Options{APIURL: srv.URL, AllowInsecureLoopback: true, Machines: 1, StateDir: t.TempDir(),
		GPUModel: "rtx4090", GPUs: 1, Interval: time.Millisecond, Samples: 2}
	cases := map[string]func(o *Options){
		"no code for an unpaired machine": func(o *Options) {},
		"wrong code":                      func(o *Options) { o.PairingCodes = []string{"HM-000000-0000-0000-0000-0000"} },
		"malformed code":                  func(o *Options) { o.PairingCodes = []string{"not a code"} },
		"unknown model":                   func(o *Options) { o.GPUModel = "voodoo2" },
		"zero machines":                   func(o *Options) { o.Machines = 0 },
		"endless outage":                  func(o *Options) { o.OutageAfter, o.OutageFor = 1, 5 },
		"plain http to a non-loopback":    func(o *Options) { o.APIURL = "http://192.0.2.1:9" },
		"http without the loopback flag":  func(o *Options) { o.AllowInsecureLoopback = false },
	}
	for name, mod := range cases {
		o := base
		o.StateDir = t.TempDir()
		mod(&o)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := Run(ctx, o)
		cancel()
		if err == nil {
			t.Errorf("%s: expected an error", name)
		} else if strings.Contains(err.Error(), "HM-000000") {
			t.Errorf("%s: the error echoes a pairing code: %v", name, err)
		}
	}
}
