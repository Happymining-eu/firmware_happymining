// Package agent is the runtime loop shared by happymining-agent and the
// simulator: collect a sample every interval, append it to the disk spool,
// send spooled samples oldest first, delete what the API acknowledged and
// handle the typed operations of the response.
//
// The loop runs in a single goroutine. It only observes and reports; nothing
// in it can affect renter workloads, and an unreachable API only makes it
// buffer and retry.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/backoff"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/client"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/collector"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/credential"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/fsx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/helper"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/ops"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/redact"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/spool"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/version"
)

// ErrNotPaired is returned by Run when a bounded run (StopAfterSamples) has no
// credential to work with.
var ErrNotPaired = errors.New("no device credential: pair first")

// defaultCredentialPoll is how often the agent re-reads the credential file,
// so that `happyminingctl pair` and `unpair` take effect within seconds
// whatever the heartbeat interval or the current backoff is.
const defaultCredentialPoll = 10 * time.Second

// maxBatchBytes leaves room for the heartbeat envelope inside the 256 KiB
// request limit.
const maxBatchBytes = protocol.MaxRequestBodyBytes - 1024

// HelperInvoker reaches the privileged helper.
type HelperInvoker interface {
	Invoke(ctx context.Context, req helper.Request) (string, error)
}

// Options configures an Agent.
type Options struct {
	StateDir        string
	SpoolDir        string
	SpoolQuotaBytes int64
	MaxSampleAge    time.Duration
	Interval        time.Duration
	// MinInterval and MaxInterval clamp the interval the server may ask for.
	MinInterval time.Duration
	MaxInterval time.Duration
	// CredentialPoll is how often the credential file is re-read (default 10 s).
	CredentialPoll time.Duration
	// IgnoreServerInterval keeps Interval whatever the server answers (used
	// by the simulator, which runs faster than a real agent).
	IgnoreServerInterval bool
	BackoffBase          time.Duration
	BackoffCap           time.Duration
	Client               *client.Client
	Collector            collector.Collector
	// Synthetic marks every sample as simulator output. The real agent never
	// sets it.
	Synthetic bool
	BootID    string
	Logger    *slog.Logger
	Redactor  *redact.Redactor
	// OpsEnabled lists the opt-in operation types enabled locally.
	OpsEnabled []string
	Helper     HelperInvoker
	// Preflight runs the read-only preflight for the run_preflight operation.
	Preflight func(ctx context.Context) (overall string, report any, err error)
	// StopAfterSamples makes Run return once that many samples were collected
	// and the spool is empty. 0 means run until the context is cancelled.
	StopAfterSamples int
	// SaveCredential stores a rotated credential; nil means credential.Save.
	SaveCredential func(path string, f *credential.File, owner *fsx.Owner) error
	Now            func() time.Time
	// Rand returns a uniform integer in [0, n) for jitter; nil is random.
	Rand func(n int64) int64
}

// Agent is one running agent instance.
type Agent struct {
	o        Options
	log      *slog.Logger
	spool    *spool.Spool
	seq      *spool.Sequence
	journal  *ops.Journal
	handler  *ops.Handler
	backoff  *backoff.Backoff
	cred     *credential.File
	interval time.Duration

	revokedID  string
	credErr    string
	lastOK     time.Time
	lastErr    string
	failures   int
	collected  int
	kick       bool
	started    time.Time
	lastPrune  time.Time
	lastState  string
	lastStateT time.Time
	warned     map[string]bool
	waiting    bool
	lastSkew   time.Time
}

// New prepares the state directory, spool, sequence counter and journal.
func New(o Options) (*Agent, error) {
	if o.Client == nil || o.Collector == nil {
		return nil, errors.New("agent: Client and Collector are required")
	}
	if o.Logger == nil || o.Redactor == nil {
		return nil, errors.New("agent: Logger and Redactor are required")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Interval <= 0 {
		return nil, errors.New("agent: Interval must be positive")
	}
	if o.MinInterval <= 0 {
		o.MinInterval = 15 * time.Second
	}
	if o.MaxInterval <= 0 {
		o.MaxInterval = time.Hour
	}
	if o.CredentialPoll <= 0 {
		o.CredentialPoll = defaultCredentialPoll
	}
	if o.MaxSampleAge <= 0 {
		o.MaxSampleAge = 7 * 24 * time.Hour
	}
	if o.SaveCredential == nil {
		o.SaveCredential = credential.Save
	}
	if err := os.MkdirAll(o.StateDir, 0o750); err != nil {
		return nil, fmt.Errorf("state directory: %w", err)
	}
	sp, err := spool.Open(o.SpoolDir, o.SpoolQuotaBytes)
	if err != nil {
		return nil, err
	}
	a := &Agent{
		o: o, log: o.Logger, spool: sp, interval: o.Interval,
		backoff: &backoff.Backoff{Base: o.BackoffBase, Cap: o.BackoffCap, Rand: o.Rand},
		started: o.Now(), lastPrune: o.Now(), warned: map[string]bool{},
	}
	seq, err := spool.OpenSequence(filepath.Join(o.StateDir, spool.SequenceFileName), sp.HighestSeq())
	if err != nil {
		// The counter still starts at the newest spooled sequence, and the
		// server's highest_seq corrects it after the first heartbeat.
		a.log.Error("sequence counter problem", "error", err.Error())
	}
	a.seq = seq
	journal, err := ops.OpenJournal(filepath.Join(o.StateDir, ops.JournalFileName), o.Now)
	if err != nil {
		return nil, err
	}
	a.journal = journal
	a.handler = ops.NewHandler(journal, a, a, o.Redactor, a.log, o.Now, o.OpsEnabled)
	if st, err := ReadState(o.StateDir); err == nil {
		a.revokedID = st.RevokedCredentialID
	}
	return a, nil
}

func (a *Agent) now() time.Time { return a.o.Now() }

func (a *Agent) revoked() bool {
	return a.cred != nil && a.revokedID != "" && a.revokedID == a.cred.CredentialID
}

// Close releases the journal file.
func (a *Agent) Close() { _ = a.journal.Close() }

// Run executes the loop until ctx is cancelled (or, with StopAfterSamples,
// until the requested samples were collected and delivered).
func (a *Agent) Run(ctx context.Context) error {
	a.log.Info("agent loop starting", "version", version.Version, "interval_s", int(a.interval/time.Second),
		"spool_samples", a.spool.Len(), "seq", a.seq.Last(), "synthetic", a.o.Synthetic,
		"ops_enabled", a.handler.EnabledTypes())
	nextCollect := a.now()
	var nextSend time.Time
	for {
		if ctx.Err() != nil {
			a.persistState(true)
			a.log.Info("agent loop stopping", "spool_samples", a.spool.Len())
			return nil
		}
		previous := a.cred
		a.reloadCredential()
		if a.cred == nil {
			a.persistState(false)
			if a.o.StopAfterSamples > 0 {
				return ErrNotPaired
			}
			if !a.waiting {
				a.waiting = true
				a.log.Info("not paired: nothing is collected or sent until `happyminingctl pair` has been run")
			}
			a.sleep(ctx, min(a.interval, a.o.CredentialPoll))
			nextCollect = a.now()
			continue
		}
		a.waiting = false
		if previous == nil || previous.CredentialID != a.cred.CredentialID {
			nextSend = time.Time{}
		}

		done := a.o.StopAfterSamples > 0 && a.collected >= a.o.StopAfterSamples
		if now := a.now(); !done && (a.kick || !now.Before(nextCollect)) {
			if !a.kick {
				nextCollect = nextCollect.Add(a.interval)
				if !nextCollect.After(now) {
					nextCollect = now.Add(a.interval)
				}
			}
			a.kick = false
			a.collectOnce(ctx)
			done = a.o.StopAfterSamples > 0 && a.collected >= a.o.StopAfterSamples
		}

		if !a.revoked() && a.spool.Len() > 0 && !a.now().Before(nextSend) {
			if delay, ok := a.flush(ctx); ok {
				nextSend = time.Time{}
			} else {
				nextSend = a.now().Add(delay)
			}
		}

		a.maintenance()
		a.persistState(false)
		if a.kick && !done {
			continue
		}
		if done && (a.spool.Len() == 0 || a.revoked()) {
			return nil
		}
		wake := nextCollect
		if done {
			wake = a.now().Add(a.interval)
		}
		if !a.revoked() && a.spool.Len() > 0 && nextSend.Before(wake) {
			wake = nextSend
		}
		a.sleep(ctx, min(wake.Sub(a.now()), a.o.CredentialPoll))
	}
}

// sleep waits for d or until ctx is cancelled.
func (a *Agent) sleep(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func (a *Agent) maintenance() {
	if a.now().Sub(a.lastPrune) < 24*time.Hour {
		return
	}
	a.lastPrune = a.now()
	if err := a.journal.Prune(); err != nil {
		a.log.Error("operation journal pruning failed", "error", err.Error())
	}
}

// reloadCredential picks up pairing, unpairing and re-pairing done by
// happyminingctl while the agent runs.
func (a *Agent) reloadCredential() {
	cred, err := credential.Load(credential.Path(a.o.StateDir))
	switch {
	case errors.Is(err, credential.ErrNotPaired):
		if a.cred != nil {
			a.log.Warn("credential removed; the agent is unpaired and stops collecting")
		}
		a.cred, a.credErr = nil, ""
	case err != nil:
		if msg := err.Error(); msg != a.credErr {
			a.credErr = msg
			a.log.Error("credential file is unusable", "error", msg)
		}
	default:
		a.credErr = ""
		if a.cred == nil || a.cred.CredentialID != cred.CredentialID || a.cred.Token != cred.Token {
			a.adopt(cred)
		}
	}
}

func (a *Agent) adopt(cred *credential.File) {
	a.o.Redactor.AddSecret(cred.Token)
	if cred.APIURL != "" && cred.APIURL != a.o.Client.BaseURL() {
		a.log.Warn("the credential was issued by a different API URL than the configured one; the configured URL is used",
			"configured", a.o.Client.BaseURL(), "paired_with", cred.APIURL)
	}
	if dev := a.spool.Device(); dev != cred.DeviceID {
		if dev != "" && a.spool.Len() > 0 {
			n := a.spool.Len()
			if err := a.spool.Purge(); err != nil {
				a.log.Error("cannot purge samples of the previous device", "error", err.Error())
			}
			a.log.Warn("device identity changed; spooled samples of the previous device were dropped", "dropped", n)
		}
		if err := a.spool.SetDevice(cred.DeviceID); err != nil {
			a.log.Error("cannot record the spool owner", "error", err.Error())
		}
	}
	if a.revokedID != "" && a.revokedID != cred.CredentialID {
		a.log.Info("new credential found; sending resumes")
		a.revokedID = ""
	}
	a.cred = cred
	a.backoff.Reset()
	a.failures, a.lastErr = 0, ""
	a.log.Info("credential loaded", "device_id", cred.DeviceID, "credential_id", cred.CredentialID, "revoked", a.revoked())
}

// collectOnce takes one sample and spools it.
func (a *Agent) collectOnce(ctx context.Context) {
	sample, warnings := a.o.Collector.Collect(ctx)
	if ctx.Err() != nil {
		return // shutting down: do not spool a possibly truncated sample
	}
	for _, w := range warnings {
		if len(a.warned) < 64 && !a.warned[w] {
			a.warned[w] = true
			a.log.Warn("collector warning (reported once)", "warning", w)
		}
	}
	seq, err := a.seq.Next()
	if err != nil {
		a.log.Error("cannot persist the sequence counter; sample discarded", "error", err.Error())
		return
	}
	sample.Seq = seq
	sample.CollectedAt = protocol.FormatTime(a.now())
	sample.Synthetic = a.o.Synthetic
	Normalize(&sample)
	data, err := json.Marshal(sample)
	if err != nil {
		a.log.Error("cannot encode sample; sample discarded", "error", err.Error())
		return
	}
	evicted, err := a.spool.Put(seq, data)
	if evicted > 0 {
		a.log.Warn("spool quota reached; oldest samples dropped",
			"dropped_now", evicted, "dropped_total", a.spool.Dropped(), "quota_bytes", a.spool.Quota())
	}
	if err != nil {
		a.log.Error("cannot spool sample; sample discarded", "error", err.Error())
		return
	}
	a.collected++
}

// Normalize enforces the protocol bounds on a sample: arrays are never null,
// at most 32 GPUs, 16 disks and 16 services, strings of at most 128
// characters, and only known service states.
func Normalize(s *protocol.Sample) {
	cut := func(v string) string { return protocol.Truncate(v, protocol.MaxStringLen) }
	s.CPU.Model = cut(s.CPU.Model)
	if s.Disks == nil {
		s.Disks = []protocol.Disk{}
	}
	if len(s.Disks) > protocol.MaxDisks {
		s.Disks = s.Disks[:protocol.MaxDisks]
	}
	for i := range s.Disks {
		s.Disks[i].Mount, s.Disks[i].FS = cut(s.Disks[i].Mount), cut(s.Disks[i].FS)
	}
	if s.GPUs == nil {
		s.GPUs = []protocol.GPU{}
	}
	if len(s.GPUs) > protocol.MaxGPUs {
		s.GPUs = s.GPUs[:protocol.MaxGPUs]
	}
	for i := range s.GPUs {
		g := &s.GPUs[i]
		g.UUID, g.Name, g.DriverVersion = cut(g.UUID), cut(g.Name), cut(g.DriverVersion)
	}
	services := make(map[string]string, len(s.Services))
	names := make([]string, 0, len(s.Services))
	for name := range s.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > protocol.MaxServices {
		names = names[:protocol.MaxServices]
	}
	for _, name := range names {
		state := s.Services[name]
		switch state {
		case protocol.ServiceActive, protocol.ServiceInactive, protocol.ServiceFailed,
			protocol.ServiceActivating, protocol.ServiceNotInstalled, protocol.ServiceUnknown:
		default:
			state = protocol.ServiceUnknown
		}
		services[cut(name)] = state
	}
	s.Services = services
	if s.Vast.MachineIDHint != nil {
		hint := cut(*s.Vast.MachineIDHint)
		s.Vast.MachineIDHint = &hint
	}
}

// nextBatch returns the oldest sendable samples. Samples older than
// MaxSampleAge are dropped on the way (the API would reject them anyway).
func (a *Agent) nextBatch(limit int) []spool.Entry {
	entries := a.spool.Peek(limit, maxBatchBytes)
	cutoff := a.now().Add(-a.o.MaxSampleAge)
	var fresh []spool.Entry
	var stale []uint64
	for _, e := range entries {
		var meta struct {
			CollectedAt string `json:"collected_at"`
		}
		if err := json.Unmarshal(e.Data, &meta); err != nil {
			stale = append(stale, e.Seq)
			continue
		}
		t, err := time.Parse(time.RFC3339, meta.CollectedAt)
		if err != nil || t.Before(cutoff) {
			stale = append(stale, e.Seq)
			continue
		}
		fresh = append(fresh, e)
	}
	if len(stale) > 0 {
		if err := a.spool.Drop(stale); err != nil {
			a.log.Error("cannot drop expired samples", "error", err.Error())
		}
		a.log.Warn("samples older than the maximum age were dropped",
			"dropped_now", len(stale), "dropped_total", a.spool.Dropped())
	}
	return fresh
}

// flush sends the spool, oldest first. It returns ok when the spool is empty,
// otherwise the delay before the next attempt.
func (a *Agent) flush(ctx context.Context) (retryIn time.Duration, ok bool) {
	limit := protocol.MaxSamplesPerRequest
	for a.spool.Len() > 0 {
		if ctx.Err() != nil {
			return 0, false
		}
		before := a.spool.Len()
		batch := a.nextBatch(limit)
		if len(batch) == 0 {
			if a.spool.Len() >= before {
				return a.backoff.Next(), false // nothing sendable and nothing dropped
			}
			continue
		}
		req := &protocol.HeartbeatRequest{
			SentAt:       protocol.FormatTime(a.now()),
			BootID:       a.o.BootID,
			AgentVersion: version.Version,
			Samples:      make([]json.RawMessage, len(batch)),
		}
		seqs := make([]uint64, len(batch))
		for i, e := range batch {
			req.Samples[i], seqs[i] = e.Data, e.Seq
		}
		resp, err := a.o.Client.Heartbeat(ctx, a.cred.Token, req)
		if err == nil {
			if derr := a.spool.Delete(seqs); derr != nil {
				a.log.Error("cannot delete acknowledged samples", "error", derr.Error())
				return a.backoff.Next(), false
			}
			a.onAcknowledged(ctx, resp, len(batch))
			continue
		}
		if ctx.Err() != nil {
			return 0, false
		}
		a.failures++
		a.lastErr = a.o.Redactor.String(err.Error())
		action := client.Classify(err)
		if errors.Is(err, client.ErrRequestTooLarge) {
			action = client.ActionSplit
		}
		switch action {
		case client.ActionUnauthorized:
			a.revokedID = a.cred.CredentialID
			a.log.Error("the API rejected the device credential; sending stops until the device is paired again",
				"credential_id", a.cred.CredentialID, "error", a.lastErr)
			return 0, false
		case client.ActionSplit:
			if len(batch) > 1 {
				limit = len(batch) / 2
				a.log.Warn("batch too large; splitting", "new_limit", limit)
				continue
			}
			a.log.Error("a single sample is too large for the API; dropped", "seq", seqs[0])
			if derr := a.spool.Drop(seqs); derr != nil {
				return a.backoff.Next(), false
			}
			continue
		case client.ActionDropPayload:
			a.log.Error("the API refused the batch as invalid; it is dropped and not resent",
				"samples", len(batch), "first_seq", seqs[0], "last_seq", seqs[len(seqs)-1], "error", a.lastErr)
			if derr := a.spool.Drop(seqs); derr != nil {
				a.log.Error("cannot drop refused samples", "error", derr.Error())
			}
			return a.backoff.Next(), false
		case client.ActionRetryAfter:
			var api *client.APIError
			if errors.As(err, &api) && api.HasRetry {
				delay := api.RetryAfter + a.backoff.Jitter()
				a.log.Warn("rate limited; honouring Retry-After", "retry_in_s", int(delay/time.Second))
				return delay, false
			}
			fallthrough
		default:
			delay := a.backoff.Next()
			a.log.Warn("heartbeat failed; samples stay in the spool", "error", a.lastErr,
				"consecutive_failures", a.failures, "retry_in_ms", delay.Milliseconds(), "spool_samples", a.spool.Len())
			return delay, false
		}
	}
	return 0, true
}

// onAcknowledged handles a 200 heartbeat response.
func (a *Agent) onAcknowledged(ctx context.Context, resp *protocol.HeartbeatResponse, sent int) {
	if a.failures > 0 {
		a.log.Info("heartbeat delivery recovered", "after_failures", a.failures)
	}
	a.backoff.Reset()
	a.failures, a.lastErr = 0, ""
	a.lastOK = a.now()
	if resp.Accepted+resp.Duplicates+resp.Rejected != sent {
		a.log.Warn("the acknowledgement does not add up to the batch size",
			"sent", sent, "accepted", resp.Accepted, "duplicates", resp.Duplicates, "rejected", resp.Rejected)
	}
	if resp.Rejected > 0 {
		a.log.Warn("the API dropped samples of this batch", "rejected", resp.Rejected)
	}
	a.log.Debug("heartbeat acknowledged", "sent", sent, "accepted", resp.Accepted,
		"duplicates", resp.Duplicates, "spool_samples", a.spool.Len())
	a.checkClock(resp.ServerTime)
	if resp.HighestSeq > a.seq.Last() {
		// The server has seen higher numbers than the local counter knows:
		// local state was lost. Jump ahead so new samples are not duplicates.
		if err := a.seq.AdvanceTo(resp.HighestSeq); err != nil {
			a.log.Error("cannot advance the sequence counter", "error", err.Error())
		} else {
			a.log.Warn("sequence counter advanced to the server's highest sequence", "seq", resp.HighestSeq)
		}
	}
	if !a.o.IgnoreServerInterval && resp.NextIntervalS > 0 {
		next := time.Duration(resp.NextIntervalS) * time.Second
		next = max(a.o.MinInterval, min(a.o.MaxInterval, next))
		if next != a.interval {
			a.log.Info("heartbeat interval changed by the API", "interval_s", int(next/time.Second))
			a.interval = next
		}
	}
	if len(resp.Operations) > 0 {
		a.handler.HandleAll(ctx, resp.Operations)
	}
}

// maxClockSkew is the difference to the API's clock that is worth a warning:
// the API drops samples collected more than 10 minutes in its future.
const maxClockSkew = 5 * time.Minute

// checkClock warns (at most once an hour) when the local clock and the API's
// clock disagree. It never changes the clock.
func (a *Agent) checkClock(serverTime string) {
	server, err := time.Parse(time.RFC3339, serverTime)
	if err != nil {
		return
	}
	skew := a.now().Sub(server)
	if skew < 0 {
		skew = -skew
	}
	if skew <= maxClockSkew || (!a.lastSkew.IsZero() && a.now().Sub(a.lastSkew) < time.Hour) {
		return
	}
	a.lastSkew = a.now()
	a.log.Warn("the local clock and the API clock differ; check time synchronisation",
		"difference_s", int(skew/time.Second), "server_time", protocol.Truncate(serverTime, 40))
}

// persistState writes the status file when something changed.
func (a *Agent) persistState(force bool) {
	st := State{
		AgentVersion:        version.Version,
		PID:                 os.Getpid(),
		RevokedCredentialID: a.revokedID,
		LastError:           protocol.Truncate(a.lastErr, 300),
		ConsecutiveFailures: a.failures,
		SpoolSamples:        a.spool.Len(),
		SpoolBytes:          a.spool.Size(),
		DroppedSamples:      a.spool.Dropped(),
		Seq:                 a.seq.Last(),
		IntervalS:           int(a.interval / time.Second),
	}
	if !a.lastOK.IsZero() {
		st.LastHeartbeatOK = protocol.FormatTime(a.lastOK)
	}
	switch {
	case a.cred == nil:
		st.State = StateUnpaired
	case a.revoked():
		st.State = StateRevoked
	case a.failures > 0:
		st.State = StateOffline
	case a.lastOK.IsZero():
		st.State = StateStarting
	default:
		st.State = StateOnline
	}
	if a.cred != nil {
		st.DeviceID, st.CredentialID = a.cred.DeviceID, a.cred.CredentialID
	}
	fingerprint, _ := json.Marshal(st)
	if !force && string(fingerprint) == a.lastState && a.now().Sub(a.lastStateT) < 5*time.Minute {
		return
	}
	st.UpdatedAt = protocol.FormatTime(a.now())
	if err := writeState(a.o.StateDir, &st); err != nil {
		a.log.Error("cannot write the status file", "error", err.Error())
		return
	}
	a.lastState, a.lastStateT = string(fingerprint), a.now()
}

// Snapshot returns the current status (for tests and the simulator).
func (a *Agent) Snapshot() State {
	st, err := ReadState(a.o.StateDir)
	if err != nil {
		return State{}
	}
	return *st
}

// Collected returns how many samples this run has spooled.
func (a *Agent) Collected() int { return a.collected }

// SpoolLen returns the number of samples waiting in the spool.
func (a *Agent) SpoolLen() int { return a.spool.Len() }

// Dropped returns how many samples were dropped since start.
func (a *Agent) Dropped() uint64 { return a.spool.Dropped() }
