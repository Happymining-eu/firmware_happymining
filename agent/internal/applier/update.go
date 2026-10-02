package applier

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/fsx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/release"
)

// UnitUpdateGuard is the service the guard timer starts.
const UnitUpdateGuard = "happymining-update-guard.service"

// guardDelay is how long the new agent has to complete a heartbeat (the
// timer's OnActiveSec).
const guardDelay = 10 * time.Minute

// UpdateRequest is what update-install carries.
type UpdateRequest struct {
	Version      string
	ManifestB64  string
	SignatureB64 string
	ArtifactPath string
}

// staged is updates/staged.json: the verified release waiting for
// install-staged, re-verified there from these root-owned copies.
type staged struct {
	Version      string `json:"version"`
	Filename     string `json:"filename"`
	ManifestB64  string `json:"manifest_b64"`
	SignatureB64 string `json:"signature_b64"`
	StagedAt     string `json:"staged_at"`
}

// dpkgInstall is the only dpkg command line: install one package file.
// --force-confdef --force-confold keep a configuration file the owner changed
// (helper.conf in particular) instead of asking on a terminal that is not
// there.
func argvDpkgInstall(deb string) []string {
	return []string{"--force-confdef", "--force-confold", "-i", deb}
}

// verifyManifest decodes and verifies a manifest against the installed
// release keys and checks that it is an upgrade of the installed version.
func (e *Env) verifyManifest(version, manifestB64, signatureB64 string) (*release.Manifest, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(manifestB64)
	if err != nil || len(raw) == 0 || len(raw) > release.MaxManifestBytes {
		return nil, fmt.Errorf("the manifest is not valid base64 of at most %d bytes", release.MaxManifestBytes)
	}
	keys, err := release.LoadKeysOwnedBy(e.Paths.ReleaseKeysDir, e.OwnerUID)
	if err != nil {
		return nil, fmt.Errorf("the installed release keys cannot be used: %w", err)
	}
	m, err := release.Verify(raw, signatureB64, keys)
	if err != nil {
		return nil, err
	}
	if m.Version != version {
		return nil, fmt.Errorf("the manifest is for version %s, not %s", m.Version, version)
	}
	if err := release.CheckUpgrade(e.Version, m); err != nil {
		return nil, err
	}
	return m, nil
}

func (e *Env) setUpdate(change func(*UpdateRecord)) {
	_, _ = e.updateState(func(st *State) { change(&st.Update) })
}

// QuickUpdateInstall is the socket action update-install: verify the signed
// manifest, check the agent's download, copy it into the root-only staging
// directory while checking its size and SHA-256, and start
// happymining-update-install.service.
func QuickUpdateInstall(ctx context.Context, e *Env, req UpdateRequest) Outcome {
	if err := e.check(); err != nil {
		return refused(CodeFailed, err.Error())
	}
	if !e.Switches.AllowUpdate {
		return refused(CodeDisabled, "installing releases is disabled in helper.conf (ALLOW_UPDATE)")
	}
	m, err := e.verifyManifest(req.Version, req.ManifestB64, req.SignatureB64)
	if err != nil {
		return refused(CodeInvalid, "release refused: "+clipText(err.Error(), 300))
	}
	st, err := e.loadState()
	if err != nil {
		return refused(CodeFailed, err.Error())
	}
	if st.Update.RolledBackVersion == m.Version {
		return refused(CodeInvalid, "release "+m.Version+" was rolled back on this machine; it is not installed again")
	}
	if err := e.ensureStateDir(); err != nil {
		return refused(CodeFailed, err.Error())
	}
	// Held while staging; install-staged waits for it.
	ul, err := tryLock(e.Paths.state(updateLockFile))
	if err != nil {
		return refused(CodeBusy, "an installation is already in progress")
	}
	defer ul.release()
	if err := e.checkDownload(req.ArtifactPath, m); err != nil {
		return refused(CodeInvalid, "the downloaded package cannot be used: "+err.Error())
	}
	e.adoptInstallerPackage()
	if !regularFileExists(filepath.Join(e.Paths.packagesDir(), currentDeb)) && !e.Switches.AllowUpdateWithoutRollback {
		return refused(CodeFailed, "no copy of the installed package is kept ("+filepath.Join(e.Paths.packagesDir(), currentDeb)+
			"), so a failed update could not be rolled back; helper.conf does not allow updates without rollback (ALLOW_UPDATE_WITHOUT_ROLLBACK)")
	}
	e.clearStaging()
	stagedPath, err := release.StageArtifact(req.ArtifactPath, e.Paths.stagingDir(), m)
	if err != nil {
		return refused(CodeInvalid, "the downloaded package does not match the manifest")
	}
	info, _ := json.Marshal(staged{Version: m.Version, Filename: m.Filename, ManifestB64: req.ManifestB64,
		SignatureB64: req.SignatureB64, StagedAt: appliance.FormatTime(e.now())})
	if err := writeFile(e.Paths.stagingDir(), stagedFile, append(info, '\n'), 0o600); err != nil {
		_ = os.Remove(stagedPath)
		return refused(CodeFailed, "the staged release cannot be recorded")
	}
	e.setUpdate(func(u *UpdateRecord) {
		*u = UpdateRecord{State: appliance.UpdateInstalling, TargetVersion: m.Version, FromVersion: e.Version,
			RolledBackVersion: u.RolledBackVersion}
	})
	if err := e.startUnit(ctx, UnitUpdateInstall); err != nil {
		e.setUpdate(func(u *UpdateRecord) { u.State, u.Detail = appliance.UpdateError, clipText(err.Error(), 300) })
		return refused(CodeFailed, err.Error())
	}
	e.audit("update-install: release %s verified (key %s) and staged; %s started", m.Version, m.KeyID, UnitUpdateInstall)
	return Outcome{OK: true, Detail: "release " + m.Version + " verified and staged; installing"}
}

// checkDownload checks the agent's download: a regular file directly inside
// the agent's download directory, named as the manifest says, owned by the
// agent, not a symbolic link (and neither is the directory).
func (e *Env) checkDownload(path string, m *release.Manifest) error {
	dir := e.Paths.agentDownloadDir()
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) != dir {
		return fmt.Errorf("it is not directly inside %s", dir)
	}
	if filepath.Base(path) != m.Filename {
		return fmt.Errorf("its name is not the manifest's file name")
	}
	dfi, err := os.Lstat(dir)
	if err != nil || dfi.Mode()&fs.ModeSymlink != 0 || !dfi.IsDir() {
		return fmt.Errorf("the download directory is missing or is a symbolic link")
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("it is missing")
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("it is not a regular file (a symbolic link is refused)")
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != e.AgentUID {
		return fmt.Errorf("it is not owned by the agent's user")
	}
	if fi.Size() != m.Size {
		return fmt.Errorf("its size is not the manifest's")
	}
	return nil
}

// clearStaging removes earlier staged packages and staged.json.
func (e *Env) clearStaging() {
	entries, err := os.ReadDir(e.Paths.stagingDir())
	if err != nil {
		return
	}
	for _, ent := range entries {
		if ent.Type().IsRegular() || ent.Type()&fs.ModeSymlink != 0 {
			_ = removeFile(e.Paths.stagingDir(), ent.Name())
		}
	}
}

// InstallStaged is `hm-helper install-staged`, run by
// happymining-update-install.service.
func InstallStaged(ctx context.Context, e *Env) error {
	if err := e.check(); err != nil {
		return err
	}
	if err := e.ensureStateDir(); err != nil {
		return err
	}
	l, err := takeLock(e.Paths.state(updateLockFile))
	if err != nil {
		return err
	}
	defer l.release()
	fail := func(detail string) error {
		detail = clipText(detail, 400)
		e.setUpdate(func(u *UpdateRecord) { u.State, u.Detail = appliance.UpdateError, detail })
		e.audit("install-staged: %s", detail)
		return errors.New(detail)
	}
	data, err := readFile(filepath.Join(e.Paths.stagingDir(), stagedFile), 64*1024, &e.OwnerUID)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // nothing staged
	}
	defer e.clearStaging()
	if !e.Switches.AllowUpdate {
		return fail("installing releases is disabled in helper.conf (ALLOW_UPDATE)")
	}
	var sg staged
	if err != nil || json.Unmarshal(data, &sg) != nil {
		return fail("the staged release record cannot be read")
	}
	// Everything again, from the root-owned copies.
	m, err := e.verifyManifest(sg.Version, sg.ManifestB64, sg.SignatureB64)
	if err != nil {
		return fail("the staged release is refused: " + err.Error())
	}
	pkg := filepath.Join(e.Paths.stagingDir(), m.Filename)
	if err := release.CheckArtifact(pkg, m); err != nil {
		return fail("the staged package does not match its manifest")
	}
	e.adoptInstallerPackage()
	current := filepath.Join(e.Paths.packagesDir(), currentDeb)
	previous := filepath.Join(e.Paths.packagesDir(), previousDeb)
	rollback := false
	switch {
	case regularFileExists(current):
		if err := copyFile(current, e.Paths.packagesDir(), previousDeb); err != nil {
			return fail("the installed package could not be kept for a rollback")
		}
		rollback = true
	case e.Switches.AllowUpdateWithoutRollback:
		// previous.deb would not be the installed version: never install it.
		_ = removeFile(e.Paths.packagesDir(), previousDeb)
	default:
		return fail("no copy of the installed package is kept, so a failed update could not be rolled back")
	}
	startedAt := e.now()
	e.setUpdate(func(u *UpdateRecord) {
		u.State, u.TargetVersion, u.Detail = appliance.UpdateInstalling, m.Version, ""
		u.FromVersion, u.InstallStartedAt, u.InstalledAt, u.GuardDone = e.Version, appliance.FormatTime(startedAt), "", false
	})
	e.audit("install-staged: installing release %s over %s", m.Version, e.Version)
	res := e.run(ctx, timeoutDpkg, DpkgPath, argvDpkgInstall(pkg)...)
	if !res.ok {
		detail := "dpkg failed: " + res.describe(nil)
		if rollback {
			back := e.run(context.WithoutCancel(ctx), timeoutDpkg, DpkgPath, argvDpkgInstall(previous)...)
			if back.ok {
				detail += "; the previous package was installed again"
			} else {
				detail += "; installing the previous package again failed too: " + back.describe(nil)
			}
		} else {
			detail += "; no previous package was kept"
		}
		return fail(detail)
	}
	if err := os.Rename(pkg, current); err != nil {
		e.audit("install-staged: the installed package could not be kept as current.deb")
	} else {
		_ = fsx.SyncDir(e.Paths.packagesDir())
	}
	detail := ""
	if !rollback {
		detail = "installed without a rollback package"
	}
	e.setUpdate(func(u *UpdateRecord) {
		u.State, u.Detail, u.InstalledAt = appliance.UpdateInstalled, detail, appliance.FormatTime(e.now())
	})
	// restart (not start) re-arms OnActiveSec when an earlier timer elapsed.
	if res := e.run(ctx, timeoutSystemctl, SystemctlPath, "restart", UnitUpdateGuardTimer); !res.ok {
		e.setUpdate(func(u *UpdateRecord) {
			u.Detail = joinDetails([]string{u.Detail, "the rollback guard could not be armed"}, 300)
		})
	}
	e.audit("install-staged: release %s installed", m.Version)
	return nil
}

// UpdateGuard is `hm-helper update-guard`, run by the guard timer about 10
// minutes after an installation: if the new agent has completed a heartbeat
// since dpkg started, the release stays; otherwise previous.deb is installed
// again. It never installs anything else.
func UpdateGuard(ctx context.Context, e *Env) error {
	if err := e.check(); err != nil {
		return err
	}
	if err := e.ensureStateDir(); err != nil {
		return err
	}
	l, err := takeLock(e.Paths.state(updateLockFile))
	if err != nil {
		return err
	}
	defer l.release()
	st, err := e.loadState()
	if err != nil {
		return err
	}
	u := st.Update
	if u.State != appliance.UpdateInstalled || u.GuardDone || u.InstallStartedAt == "" {
		return nil
	}
	since, err := time.Parse(time.RFC3339, u.InstallStartedAt)
	if err != nil {
		return fmt.Errorf("the installation time is not readable")
	}
	if as, err := e.readAgentState(); err == nil {
		if hb, err := time.Parse(time.RFC3339, as.LastHeartbeatOK); err == nil && hb.After(since) && as.AgentVersion == u.TargetVersion {
			e.setUpdate(func(u *UpdateRecord) { u.GuardDone, u.Detail = true, "" })
			e.audit("update-guard: release %s confirmed by a heartbeat", u.TargetVersion)
			return nil
		}
	}
	previous := filepath.Join(e.Paths.packagesDir(), previousDeb)
	if !regularFileExists(previous) {
		e.setUpdate(func(u *UpdateRecord) {
			u.State, u.GuardDone = appliance.UpdateError, true
			u.Detail = "the new agent has not completed a heartbeat and there is no previous package to roll back to"
		})
		return errors.New("no heartbeat and no rollback package")
	}
	e.audit("update-guard: no heartbeat from release %s; rolling back", u.TargetVersion)
	res := e.run(ctx, timeoutDpkg, DpkgPath, argvDpkgInstall(previous)...)
	if !res.ok {
		detail := clipText("the new agent has not completed a heartbeat and the rollback failed: "+res.describe(nil), 400)
		e.setUpdate(func(u *UpdateRecord) { u.State, u.Detail, u.GuardDone = appliance.UpdateError, detail, true })
		return errors.New(detail)
	}
	_ = copyFile(previous, e.Paths.packagesDir(), currentDeb)
	target := u.TargetVersion
	e.setUpdate(func(u *UpdateRecord) {
		u.State, u.GuardDone, u.RolledBackVersion = appliance.UpdateRolledBack, true, target
		u.Detail = "the new agent did not complete a heartbeat within 10 minutes; the previous package was installed again"
	})
	return nil
}

// copyFile copies src (not a link) to dir/name atomically, mode 0600.
// adoptInstallerPackage gives a machine installed from the image a rollback
// package for its first update. The image's installer leaves the package it
// installed in InstallerCache with its SHA-256 and a file "current" naming
// it. When packages/current.deb is missing, that package is copied there, but
// only if it is the version that is installed now (its file name says so),
// every file is a regular file owned by root and writable by nobody else,
// and its SHA-256 matches. Anything else leaves current.deb missing: the
// update is then refused unless ALLOW_UPDATE_WITHOUT_ROLLBACK, as before.
func (e *Env) adoptInstallerPackage() {
	if e.Paths.InstallerCache == "" || regularFileExists(filepath.Join(e.Paths.packagesDir(), currentDeb)) {
		return
	}
	owner := e.OwnerUID
	nameRaw, err := readFile(filepath.Join(e.Paths.InstallerCache, "current"), 256, &owner)
	if err != nil {
		return
	}
	name := string(trimLineEnd(nameRaw))
	if !reInstallerPackage.MatchString(name) || !strings.HasPrefix(name, "happymining-agent_"+e.Version+"_") {
		e.audit("installer package %q is not the installed version %s; not kept for a rollback", clipText(name, 80), e.Version)
		return
	}
	sumRaw, err := readFile(filepath.Join(e.Paths.InstallerCache, name+".sha256"), 512, &owner)
	if err != nil {
		return
	}
	fields := strings.Fields(string(sumRaw))
	if len(fields) != 2 || !reSHA256Hex.MatchString(fields[0]) || strings.TrimPrefix(fields[1], "*") != name {
		e.audit("installer package checksum file is not in the expected form; not kept for a rollback")
		return
	}
	pkg := filepath.Join(e.Paths.InstallerCache, name)
	if err := checkOwnedRegular(pkg, owner); err != nil {
		e.audit("installer package %s: %v; not kept for a rollback", name, err)
		return
	}
	sum, err := sha256File(pkg)
	if err != nil || sum != fields[0] {
		e.audit("installer package %s does not match its checksum; not kept for a rollback", name)
		return
	}
	if err := e.ensureStateDir(); err != nil {
		return
	}
	if err := copyFile(pkg, e.Paths.packagesDir(), currentDeb); err != nil {
		e.audit("installer package %s could not be kept for a rollback: %v", name, err)
		return
	}
	e.audit("the installer's package %s is kept as the rollback package", name)
}

var (
	reInstallerPackage = regexp.MustCompile(`^happymining-agent_[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}_[a-z0-9]{1,16}\.deb$`)
	reSHA256Hex        = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// checkOwnedRegular: a regular file (not a link) owned by uid and writable by
// nobody else.
func checkOwnedRegular(path string, uid uint32) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("not a regular file")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uid {
		return fmt.Errorf("not owned by uid %d", uid)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("writable by group or others")
	}
	return nil
}

// sha256File hashes a file without following a link in its last component.
func sha256File(path string) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyFile(src, dir, name string) error {
	in, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	if fi, err := in.Stat(); err != nil || !fi.Mode().IsRegular() {
		return fmt.Errorf("not a regular file")
	}
	out, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return err
	}
	tmp := out.Name()
	fail := func(err error) error { _ = out.Close(); _ = os.Remove(tmp); return err }
	if err := out.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		return fail(err)
	}
	if err := out.Sync(); err != nil {
		return fail(err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return fsx.SyncDir(dir)
}
