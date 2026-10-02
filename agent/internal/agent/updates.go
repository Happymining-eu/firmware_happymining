package agent

// Firmware updates, the agent's part (docs/appliance.md, sections 6.6 and 9,
// and the helper interface, "Updates").
//
// The agent asks the API what it may install (GET /api/v1/device/update):
//   - when the schedule job update_check runs, or an appliance_run_job
//     operation asks for it;
//   - every 6 hours on its own, while the helper reports that updates are
//     allowed, and at the start of the update window when an automatic update
//     is waiting for it;
//   - when an install_update operation arrives.
//
// It installs only in two cases: an install_update operation asked for that
// exact version (installed now), or the policy is "auto" and the local time is
// inside the window, before the download and again after it. Installing
// means: download the package into <StateDir>/updates/ (created 0600, never
// through a symbolic link, at most the size the release states, SHA-256
// checked while writing, a partial file removed on failure), then hand it to
// the helper (update-install), which verifies the signature against the keys
// installed on the machine, the version, the size and the hash again, keeps
// the current package for a rollback and installs.
//
// The agent trusts nothing of the offer: it builds the download path itself
// from a validated version, checks that the unsigned manifest it forwards
// says what the offer says, and never runs dpkg or anything else itself.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/fsx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/helper"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/release"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/schedule"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/version"
)

// UpdatesDirName is the agent's download directory inside the state directory.
const UpdatesDirName = "updates"

// Timing of the automatic update check.
const (
	// UpdateCheckEvery is the period of the automatic update check.
	UpdateCheckEvery = 6 * time.Hour
	// updateFirstCheckAfter delays the first automatic check after start.
	updateFirstCheckAfter = 2 * time.Minute
	// updateFlowTimeout bounds one check with its download and hand-off.
	updateFlowTimeout = 45 * time.Minute
	// installingOverlayFor is how long the agent reports "installing" for a
	// package it handed over, until the helper reports on it.
	installingOverlayFor = 30 * time.Minute
)

type updateKind int

const (
	// updateCheck installs only with policy auto, inside the window.
	updateCheck updateKind = iota
	// updateInstall installs the requested version now (install_update).
	updateInstall
)

type updateRequest struct {
	kind    updateKind
	version string // updateInstall
	// onDone is called on the agent loop goroutine when the flow ends.
	onDone func(detail string, err error)
}

// skipError means the flow does not apply on this machine now: nothing was
// attempted.
type skipError struct{ reason string }

func (e *skipError) Error() string { return e.reason }

// updater is the state shared between the agent loop and the background
// update flow.
type updater struct {
	mu      sync.Mutex
	busy    bool
	overlay *appliance.UpdateState
	setAt   time.Time
	// windowAt is the next start of the update window when an automatic
	// update is waiting for it.
	windowAt time.Time
	// nextAuto is the next automatic check (agent loop only).
	nextAuto time.Time
}

func (u *updater) tryStart() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.busy {
		return false
	}
	u.busy = true
	return true
}

func (u *updater) finish() {
	u.mu.Lock()
	u.busy = false
	u.mu.Unlock()
}

func (u *updater) set(state, target, detail string, now time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.overlay = &appliance.UpdateState{CurrentVersion: version.Version, State: state, TargetVersion: target, Detail: detail}
	u.setAt = now
}

func (u *updater) setWindow(at time.Time) {
	u.mu.Lock()
	u.windowAt = at
	u.mu.Unlock()
}

func (u *updater) takeWindow() time.Time {
	u.mu.Lock()
	defer u.mu.Unlock()
	at := u.windowAt
	u.windowAt = time.Time{}
	return at
}

// merge combines the helper's update state with what the agent is doing:
// while the agent downloads, or after its own attempt failed, its state is
// the one that counts; once the helper reports on the package it was handed,
// the helper's state does.
func (u *updater) merge(h appliance.UpdateState, now time.Time) appliance.UpdateState {
	if h.CurrentVersion == "" {
		h.CurrentVersion = version.Version
	}
	if h.State == "" {
		h.State = appliance.UpdateIdle
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.overlay == nil {
		return h
	}
	if u.overlay.State == appliance.UpdateInstalling &&
		((h.TargetVersion == u.overlay.TargetVersion && h.State != appliance.UpdateIdle) || now.Sub(u.setAt) > installingOverlayFor) {
		u.overlay = nil
		return h
	}
	return *u.overlay
}

// post runs f on the agent loop goroutine. It gives up when the agent stops.
func (a *Agent) post(ctx context.Context, f func()) {
	select {
	case a.events <- f:
	case <-ctx.Done():
	}
}

// drainEvents runs what background work posted.
func (a *Agent) drainEvents() {
	for {
		select {
		case f := <-a.events:
			f()
		default:
			return
		}
	}
}

// startUpdate starts an update flow in the background. It returns a
// *skipError when the flow does not apply now, another error when it cannot
// start, nil when it started (req.onDone then follows).
func (a *Agent) startUpdate(req updateRequest) error {
	switch {
	case a.cred == nil || a.revoked():
		return &skipError{"the machine is not paired with a usable credential"}
	case a.o.Appliance == nil:
		return &skipError{"the privileged helper is not available in this build"}
	case !a.capabilities().Update:
		return &skipError{"updates are not allowed on this machine (the helper reports the update capability off: ALLOW_UPDATE, or the helper is not reachable)"}
	case a.bgCtx == nil || a.bgCtx.Err() != nil:
		return errors.New("the agent is stopping")
	case !a.upd.tryStart():
		return &skipError{"an update check or download is already running"}
	}
	token, ctx := a.cred.Token, a.bgCtx
	a.bg.Add(1)
	go func() {
		defer a.bg.Done()
		detail, err := a.runUpdate(ctx, token, req)
		a.upd.finish()
		a.post(ctx, func() {
			if err != nil {
				a.log.Warn("update flow failed", "error", protocol.Truncate(a.o.Redactor.String(err.Error()), 500))
			} else {
				a.log.Info("update flow finished", "detail", protocol.Truncate(a.o.Redactor.String(detail), 500))
			}
			if req.onDone != nil {
				req.onDone(detail, err)
			}
		})
	}()
	return nil
}

// autoUpdateCheck starts the periodic check while updates are allowed.
func (a *Agent) autoUpdateCheck(now time.Time) {
	if a.cred == nil || !a.capabilities().Update {
		return
	}
	if at := a.upd.takeWindow(); !at.IsZero() && (a.upd.nextAuto.IsZero() || at.Before(a.upd.nextAuto)) {
		a.upd.nextAuto = at
	}
	if a.upd.nextAuto.IsZero() {
		a.upd.nextAuto = now.Add(updateFirstCheckAfter)
		return
	}
	if now.Before(a.upd.nextAuto) {
		return
	}
	a.upd.nextAuto = now.Add(UpdateCheckEvery)
	if err := a.startUpdate(updateRequest{kind: updateCheck}); err != nil {
		a.log.Debug("automatic update check not started", "reason", err.Error())
	}
}

// ApplianceRunJob implements ops.Executor: update_check runs in the agent,
// the other jobs are started by the helper.
func (a *Agent) ApplianceRunJob(ctx context.Context, job, plugin string) (string, error) {
	if job == appliance.JobUpdateCheck {
		if err := a.startUpdate(updateRequest{kind: updateCheck}); err != nil {
			return "", fmt.Errorf("update check not started: %w", err)
		}
		return "update check started; the outcome is in the reported update state", nil
	}
	resp, err := a.helperDo(ctx, applianceCallTimeout, helper.Request{Action: ActionApplianceRunJob, Job: job, Plugin: plugin})
	if err != nil {
		return "", fmt.Errorf("the privileged helper is not reachable: %w", err)
	}
	if !resp.OK {
		return "", fmt.Errorf("the helper refused (%s): %s", protocol.Truncate(resp.Code, 40), resp.Detail)
	}
	return "job " + job + " started: " + resp.Detail, nil
}

// InstallUpdate implements ops.Executor: download and install that release now.
func (a *Agent) InstallUpdate(_ context.Context, ver string, done func(string, error)) error {
	return a.startUpdate(updateRequest{kind: updateInstall, version: ver, onDone: done})
}

var (
	reSHA256    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reSignature = regexp.MustCompile(`^[A-Za-z0-9+/]{1,200}={0,2}$`)
	reFilename  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,120}\.deb$`)
)

// offeredRelease is an offer that passed the agent's checks.
type offeredRelease struct {
	rel      protocol.UpdateRelease
	filename string
}

// checkOffer validates an offered release. The manifest is not verified here
// (the helper does that with the installed keys); it is only checked to say
// what the offer says, so that the agent downloads exactly that file.
func checkOffer(rel *protocol.UpdateRelease) (*offeredRelease, error) {
	if _, err := release.ParseVersion(rel.Version); err != nil {
		return nil, errors.New("the offered version is not MAJOR.MINOR.PATCH")
	}
	if rel.ArtifactPath != protocol.UpdateArtifactPath(rel.Version) {
		return nil, errors.New("the offered artifact path is not the device artifact path of that version")
	}
	if rel.Size <= 0 || rel.Size > release.MaxArtifactBytes || !reSHA256.MatchString(rel.SHA256) {
		return nil, errors.New("the offered size or SHA-256 is not acceptable")
	}
	if !reSignature.MatchString(rel.SignatureB64) {
		return nil, errors.New("the offered signature is not base64")
	}
	if len(rel.ManifestB64) > 2*release.MaxManifestBytes {
		return nil, errors.New("the offered manifest is too large")
	}
	raw, err := base64.StdEncoding.DecodeString(rel.ManifestB64)
	if err != nil || len(raw) == 0 || len(raw) > release.MaxManifestBytes {
		return nil, errors.New("the offered manifest is not base64 of at most 16 KiB")
	}
	var m struct {
		Product  string `json:"product"`
		Version  string `json:"version"`
		Artifact struct {
			Filename string      `json:"filename"`
			Size     json.Number `json:"size"`
			SHA256   string      `json:"sha256"`
		} `json:"artifact"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, errors.New("the offered manifest is not a JSON object")
	}
	switch {
	case m.Product != release.Product:
		return nil, errors.New("the offered manifest is not for this product")
	case m.Version != rel.Version:
		return nil, errors.New("the offered manifest is for another version")
	case !reFilename.MatchString(m.Artifact.Filename):
		return nil, errors.New("the package file name in the manifest is not a plain .deb name")
	case m.Artifact.Size.String() != fmt.Sprint(rel.Size) || m.Artifact.SHA256 != rel.SHA256:
		return nil, errors.New("the manifest and the offer disagree on the package size or SHA-256")
	}
	return &offeredRelease{rel: *rel, filename: m.Artifact.Filename}, nil
}

func (a *Agent) location() *time.Location {
	if a.o.Location != nil {
		return a.o.Location
	}
	return time.Local
}

// inWindow reports whether the local time lies in the update window, and the
// next start of the window. A window that is not valid is never open.
func (a *Agent) inWindow(w *protocol.UpdateWindow, now time.Time) (bool, time.Time) {
	if w == nil || w.StartHour < 0 || w.StartHour > 23 || w.EndHour < 0 || w.EndHour > 23 || w.StartHour == w.EndHour {
		return false, time.Time{}
	}
	local := now.In(a.location())
	start := w.StartHour
	next := schedule.Spec{Every: schedule.Daily, Hour: &start, Minute: 0}.Next(local)
	return appliance.Window{StartHour: w.StartHour, EndHour: w.EndHour}.Contains(local.Hour()), next
}

// runUpdate is the update flow. It runs in the background: it may only use
// what is safe there (the client, the helper, the updater, the logger).
func (a *Agent) runUpdate(ctx context.Context, token string, req updateRequest) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, updateFlowTimeout)
	defer cancel()
	offer, err := a.o.Client.GetUpdate(ctx, token)
	if err != nil {
		return "", fmt.Errorf("the update offer could not be read: %w", err)
	}
	rel := offer.Release
	if req.kind == updateInstall {
		switch {
		case rel == nil:
			return "", fmt.Errorf("release %s is not offered to this machine (channel %q)", req.version, protocol.Truncate(offer.Channel, 20))
		case rel.Version != req.version:
			return "", fmt.Errorf("the API offers release %s to this machine, not the requested %s; nothing was installed",
				protocol.Truncate(rel.Version, 24), req.version)
		}
	} else {
		if rel == nil {
			return "no newer release is offered on channel " + protocol.Truncate(offer.Channel, 20), nil
		}
		if offer.Policy != appliance.PolicyAuto {
			return fmt.Sprintf("release %s is available; the update policy is %q, so it is installed only on request",
				protocol.Truncate(rel.Version, 24), protocol.Truncate(offer.Policy, 20)), nil
		}
		open, next := a.inWindow(offer.Window, a.now())
		if !open {
			a.upd.setWindow(next)
			return fmt.Sprintf("release %s is installed automatically in the update window", protocol.Truncate(rel.Version, 24)), nil
		}
	}
	offered, err := checkOffer(rel)
	if err != nil {
		return "", fmt.Errorf("the offered release is refused: %w", err)
	}
	target := offered.rel.Version
	have, _ := release.ParseVersion(version.Version)
	if want, _ := release.ParseVersion(target); want.Compare(have) <= 0 {
		return "", fmt.Errorf("release %s is not newer than the installed %s; nothing to install", target, version.Version)
	}

	a.upd.set(appliance.UpdateDownloading, target, "", a.now())
	path, err := a.downloadRelease(ctx, token, offered)
	if err != nil {
		a.upd.set(appliance.UpdateError, target, "download failed: "+a.o.Redactor.String(err.Error()), a.now())
		return "", fmt.Errorf("the package of release %s could not be downloaded: %w", target, err)
	}
	if req.kind == updateCheck {
		if open, next := a.inWindow(offer.Window, a.now()); !open {
			// The download outlasted the window: never install outside it.
			a.upd.setWindow(next)
			a.upd.set(appliance.UpdateIdle, target, "the download finished after the update window closed; it is installed in the next window", a.now())
			return "release " + target + " downloaded after the window closed; installed in the next window", nil
		}
	}
	a.upd.set(appliance.UpdateInstalling, target, "", a.now())
	resp, err := a.helperDo(ctx, applianceCallTimeout, helper.Request{
		Action: ActionUpdateInstall, Version: target,
		ManifestB64: offered.rel.ManifestB64, SignatureB64: offered.rel.SignatureB64, ArtifactPath: path,
	})
	if err == nil && !resp.OK {
		err = fmt.Errorf("the helper refused the package (%s): %s", protocol.Truncate(resp.Code, 40), resp.Detail)
	}
	if err != nil {
		a.upd.set(appliance.UpdateError, target, a.o.Redactor.String(err.Error()), a.now())
		return "", fmt.Errorf("release %s was not installed: %w", target, err)
	}
	return "release " + target + " downloaded, checked and handed to the helper for installation: " + resp.Detail, nil
}

// downloadRelease writes the package to <StateDir>/updates/<filename> and
// returns that path. Earlier downloads are removed first. The file is written
// under a temporary name created exclusively (O_EXCL, O_NOFOLLOW, 0600),
// hashed while it is written and renamed into place only when size and
// SHA-256 match; on any failure nothing is left behind.
func (a *Agent) downloadRelease(ctx context.Context, token string, offered *offeredRelease) (string, error) {
	dir := filepath.Join(a.o.StateDir, UpdatesDirName)
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", fmt.Errorf("create %s: %w", dir, err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("%s is not a directory (a symbolic link is not accepted)", dir)
	}
	if fi.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return "", fmt.Errorf("%s: %w", dir, err)
		}
	}
	if err := clearDownloads(dir); err != nil {
		return "", err
	}
	final := filepath.Join(dir, offered.filename)
	tmp := filepath.Join(dir, "."+offered.filename+".part")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", fmt.Errorf("create the download file: %w", err)
	}
	fail := func(err error) (string, error) {
		_ = f.Close()
		_ = os.Remove(tmp)
		return "", err
	}
	hash := sha256.New()
	if err := a.o.Client.DownloadArtifact(ctx, token, offered.rel.Version, offered.rel.Size, io.MultiWriter(f, hash)); err != nil {
		return fail(err)
	}
	if hex.EncodeToString(hash.Sum(nil)) != offered.rel.SHA256 {
		return fail(errors.New("the downloaded package does not have the SHA-256 of the release"))
	}
	if err := f.Sync(); err != nil {
		return fail(fmt.Errorf("fsync the download: %w", err))
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("close the download: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("move the download into place: %w", err)
	}
	if err := fsx.SyncDir(dir); err != nil {
		return "", err
	}
	return final, nil
}

// clearDownloads removes what an earlier download left in dir: files and
// symbolic links directly inside it (a link is removed, never followed).
func clearDownloads(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Type().IsRegular() || e.Type()&os.ModeSymlink != 0 {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
				return fmt.Errorf("remove an earlier download: %w", err)
			}
		}
	}
	return nil
}
