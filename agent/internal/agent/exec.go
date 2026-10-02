package agent

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/credential"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/helper"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/version"
)

// This file implements ops.Executor and ops.Acker: the fixed set of actions
// behind the typed operations. There is no generic command execution here.

// Ack implements ops.Acker.
func (a *Agent) Ack(ctx context.Context, id string, ack *protocol.AckRequest) error {
	if a.cred == nil {
		return errors.New("not paired")
	}
	return a.o.Client.AckOperation(ctx, a.cred.Token, id, ack)
}

// RefreshInventory implements ops.Executor. The collector re-reads the whole
// inventory for every sample, so refreshing means taking a sample now.
func (a *Agent) RefreshInventory(context.Context) (string, error) {
	a.kick = true
	return "hardware inventory is re-read now and sent with the next heartbeat", nil
}

// CollectDiagnostics implements ops.Executor. Every section is read-only and
// contains only the whitelisted telemetry fields or agent counters.
func (a *Agent) CollectDiagnostics(ctx context.Context, sections []string) (any, error) {
	sample, warnings := a.o.Collector.Collect(ctx)
	Normalize(&sample)
	out := map[string]any{}
	for _, section := range sections {
		switch section {
		case "services":
			out["services"] = sample.Services
		case "gpu":
			out["gpu"] = sample.GPUs
		case "disk":
			out["disk"] = sample.Disks
		case "network":
			network := map[string]any{
				"consecutive_failures": a.failures,
				"last_error":           a.lastErr,
			}
			if u, err := url.Parse(a.o.Client.BaseURL()); err == nil {
				network["api_host"] = u.Host
				network["api_scheme"] = u.Scheme
			}
			if !a.lastOK.IsZero() {
				network["last_heartbeat_ok"] = protocol.FormatTime(a.lastOK)
			}
			out["network"] = network
		case "agent":
			out["agent"] = map[string]any{
				"version":            version.Version,
				"synthetic":          a.o.Synthetic,
				"boot_id":            a.o.BootID,
				"started_at":         protocol.FormatTime(a.started),
				"interval_s":         int(a.interval / time.Second),
				"seq":                a.seq.Last(),
				"spool_samples":      a.spool.Len(),
				"spool_bytes":        a.spool.Size(),
				"spool_quota_bytes":  a.spool.Quota(),
				"dropped_samples":    a.spool.Dropped(),
				"ops_enabled":        a.handler.EnabledTypes(),
				"journal_entries":    a.journal.Len(),
				"collector_warnings": warnings,
			}
		default:
			return nil, fmt.Errorf("unknown diagnostics section %q", section)
		}
	}
	return out, nil
}

// RunPreflight implements ops.Executor.
func (a *Agent) RunPreflight(ctx context.Context) (string, any, error) {
	if a.o.Preflight == nil {
		return "", nil, errors.New("preflight is not available in this build")
	}
	overall, report, err := a.o.Preflight(ctx)
	if err != nil {
		return "", nil, err
	}
	return "preflight overall: " + overall + " (advisory; does not guarantee Vast verification)", report, nil
}

// RotateCredential implements ops.Executor: ask for a new credential, write
// it atomically, and only then switch to it. If the write fails the agent
// keeps using the old credential, which the API keeps valid until the new one
// is first used.
func (a *Agent) RotateCredential(ctx context.Context) (string, error) {
	if a.cred == nil {
		return "", errors.New("not paired")
	}
	issued, err := a.o.Client.RotateCredential(ctx, a.cred.Token)
	if err != nil {
		return "", fmt.Errorf("rotation request failed: %w", err)
	}
	// From here on the new secret exists: make sure it can never be logged.
	a.o.Redactor.AddSecret(issued.Token)
	next := *a.cred
	next.CredentialID = issued.ID
	next.Token = issued.Token
	next.ExpiresAt = issued.ExpiresAt
	next.RotatedAt = protocol.FormatTime(a.now())
	if err := a.o.SaveCredential(credential.Path(a.o.StateDir), &next, nil); err != nil {
		return "", fmt.Errorf("the new credential could not be stored; the old credential stays in use: %w", err)
	}
	a.cred = &next
	a.log.Info("credential rotated", "credential_id", next.CredentialID)
	return "credential rotated; new credential id " + next.CredentialID, nil
}

func (a *Agent) helperCall(ctx context.Context, req helper.Request) (string, error) {
	if a.o.Helper == nil {
		return "", errors.New("the privileged helper is not available in this build")
	}
	return a.o.Helper.Invoke(ctx, req)
}

// RestartVastDaemon implements ops.Executor through the privileged helper.
func (a *Agent) RestartVastDaemon(ctx context.Context) (string, error) {
	return a.helperCall(ctx, helper.Request{Action: helper.ActionRestartVastDaemon})
}

// Reboot implements ops.Executor through the privileged helper.
func (a *Agent) Reboot(ctx context.Context, delayS int) (string, error) {
	delay := int64(delayS)
	return a.helperCall(ctx, helper.Request{Action: helper.ActionReboot, DelayS: &delay})
}
