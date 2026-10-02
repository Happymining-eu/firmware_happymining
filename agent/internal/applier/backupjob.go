package applier

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/backup"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/seal"
)

// agentState is the part of the agent's agent-state.json the helper reads:
// the machine id (backup archive names) and the last successful heartbeat
// with the version that made it (update guard). The helper never reads the
// agent's credential file.
type agentState struct {
	MachineID       string `json:"machine_id"`
	LastHeartbeatOK string `json:"last_heartbeat_ok"`
	AgentVersion    string `json:"agent_version"`
}

func (e *Env) readAgentState() (*agentState, error) {
	data, err := readFile(e.Paths.agentStatePath(), 64*1024, nil)
	if err != nil {
		return nil, err
	}
	var s agentState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("agent-state.json cannot be read")
	}
	return &s, nil
}

// backupRun is the backup_run job (docs/appliance.md, 10), under the
// appliance lock.
func (e *Env) backupRun(ctx context.Context, instance string) error {
	setBackup := func(change func(*BackupRecord)) {
		_, _ = e.updateState(func(st *State) { change(&st.Backup) })
	}
	fail := func(detail string) error {
		detail = clipText(detail, 400)
		setBackup(func(b *BackupRecord) { b.State, b.Detail = appliance.BackupError, detail })
		return e.recordJob(instance, appliance.RunFailed, detail)
	}
	eff, err := e.resolve()
	if err != nil {
		return fail(err.Error())
	}
	if eff.Problem != "" || eff.Doc == nil || eff.Doc.Backup == nil || !eff.Doc.Backup.Enabled {
		setBackup(func(b *BackupRecord) { b.State, b.Detail = appliance.BackupDisabled, "" })
		return e.recordJob(instance, appliance.RunSkipped, "backups are not configured")
	}
	cfg := eff.Doc.Backup
	key, err := backup.LoadKey(e.Paths.backupKeyPath(), e.OwnerUID)
	if errors.Is(err, backup.ErrNoKey) {
		setBackup(func(b *BackupRecord) {
			b.State, b.Detail = appliance.BackupNoKey, "no backup key on this machine (sudo happyminingctl backup init)"
		})
		return e.recordJob(instance, appliance.RunFailed, "no backup key")
	}
	if err != nil {
		return fail("the backup key file cannot be used")
	}
	defer func() { key = backup.Key{} }()
	as, err := e.readAgentState()
	if err != nil || !backup.ValidMachineID(as.MachineID) {
		return fail("the machine id is not known yet (the agent has not written it to agent-state.json)")
	}
	st, err := e.loadState()
	if err != nil {
		return fail(err.Error())
	}
	op := e.newScrubbingOpener(eff.Secrets)

	// The destination.
	var dest backup.Destination
	switch cfg.Destination.Kind {
	case appliance.DestinationNAS:
		id := cfg.Destination.NASID
		if !ValidID(id) {
			return fail("the backup destination is not a valid NAS entry")
		}
		if err := e.mountedReadWrite(id, st); err != nil {
			return fail("the backup destination cannot be used: " + err.Error())
		}
		d, err := backup.OpenDirDestination(e.Paths.mountPoint(id), cfg.Destination.Subpath)
		if err != nil {
			return fail("the backup directory on NAS entry " + id + " cannot be opened")
		}
		defer d.Close()
		dest = d
	case appliance.DestinationS3:
		plain, err := op.open(cfg.Destination.Secret)
		if err != nil {
			return fail("secret " + cfg.Destination.Secret + " is " + err.Error())
		}
		// The S3 destination keeps the secret key for the duration of the run
		// (a Go string cannot be wiped); the plaintext buffer is wiped now.
		s3, err := backup.NewS3Destination(backup.S3Config{
			Endpoint: cfg.Destination.Endpoint, Region: cfg.Destination.Region, Bucket: cfg.Destination.Bucket,
			Prefix: cfg.Destination.Prefix, AccessKeyID: cfg.Destination.AccessKeyID, SecretAccessKey: string(plain),
		})
		seal.Wipe(plain)
		if err != nil {
			return fail("the S3 destination is not valid")
		}
		dest = s3
	default:
		return fail("unknown backup destination")
	}

	// What is saved: the document in force with its sealed secrets as they
	// are, the profile and the locally entered (sealed) secrets, and the
	// plugin volumes the catalog says to save.
	var items []backup.Item
	for _, f := range []struct{ name, path string }{
		{"document", e.Paths.appliedPath()},
		{"profile", e.Paths.ProfilePath},
		{"local-secrets", e.Paths.localSecretsPath()},
	} {
		if regularFileExists(f.path) {
			items = append(items, backup.Item{Name: f.name, Path: f.path})
		}
	}
	steps := appliance.Plan(eff.Doc, eff.Catalog)
	var withVolumes []string
	for _, step := range steps {
		entry, ok := eff.Catalog.Plugin(step.ID)
		if !ok || !pluginEnabled(eff.Doc, step.ID) {
			continue
		}
		saved := false
		for _, v := range entry.Volumes {
			if v.Backup == appliance.VolumeBackupNever || (v.Backup == appliance.VolumeBackupModels && !cfg.IncludeModels) {
				continue
			}
			path, ok, err := e.volumePath(ctx, step.ID, v.Name)
			if err != nil {
				return fail(err.Error())
			}
			if !ok {
				continue // never created
			}
			items = append(items, backup.Item{Name: "volumes/" + step.ID + "/" + v.Name, Path: path})
			saved = true
		}
		if saved {
			withVolumes = append(withVolumes, step.ID)
		}
	}

	now := e.now()
	setBackup(func(b *BackupRecord) {
		b.State, b.Detail, b.LastRunAt = appliance.BackupRunning, "", appliance.FormatTime(now)
	})

	// Stop each running plugin whose volumes are saved (dependents first),
	// and start it again afterwards, also when the backup fails.
	var stopped []string
	var restartProblems []string
	defer func() {
		for _, id := range stopped { // requirements first
			if res := e.docker(context.WithoutCancel(ctx), timeoutComposeDown, argvComposeStart(id)...); !res.ok {
				restartProblems = append(restartProblems, "plugin "+id+" could not be started again: "+res.describe(op.scrub))
			}
		}
		if len(restartProblems) > 0 {
			detail := joinDetails(restartProblems, 400)
			setBackup(func(b *BackupRecord) { b.Detail = joinDetails([]string{b.Detail, detail}, 450) })
			e.audit("backup: %s", detail)
		}
		e.refreshPlugins(context.WithoutCancel(ctx))
	}()
	for i := len(withVolumes) - 1; i >= 0; i-- {
		id := withVolumes[i]
		state, _, err := e.projectState(ctx, id)
		if err != nil {
			return fail("the state of plugin " + id + " cannot be read, so its volumes are not saved")
		}
		if state != appliance.PluginRunning && state != appliance.PluginStarting && state != appliance.PluginError {
			continue
		}
		res := e.docker(ctx, timeoutComposeDown, argvComposeStop(id)...)
		// Started again even if stop reported a failure: it may have
		// stopped some services.
		stopped = append([]string{id}, stopped...)
		if !res.ok {
			return fail("plugin " + id + " could not be stopped for the backup: " + res.describe(op.scrub))
		}
	}

	result, err := backup.Run(ctx, backup.RunOptions{Key: key, Destination: dest, MachineID: as.MachineID,
		AgentVersion: e.Version, Items: items, Now: now})
	if err != nil {
		return fail("the backup failed: " + op.scrub.scrub(err.Error()))
	}
	detail := ""
	if deleted, err := backup.Prune(ctx, dest, as.MachineID, cfg.Keep); err != nil {
		detail = fmt.Sprintf("the archive was stored; removing old archives failed after %d: %s", len(deleted),
			clipText(op.scrub.scrub(err.Error()), 200))
	}
	okAt := appliance.FormatTime(e.now())
	setBackup(func(b *BackupRecord) {
		b.State, b.LastOKAt, b.LastSizeBytes, b.Detail = appliance.BackupOK, okAt, result.Size, detail
	})
	e.audit("backup: stored an archive of %d bytes (key %s)", result.Size, result.KeyID)
	return e.recordJob(instance, appliance.RunOK, detail)
}

func pluginEnabled(doc *appliance.Document, id string) bool {
	for _, p := range doc.Plugins {
		if p.ID == id {
			return p.Enabled
		}
	}
	return false
}

// BackupInit is `hm-helper backup-init`: create the backup key and print
// the recovery key once. An existing key is never replaced.
func BackupInit(e *Env, out io.Writer) error {
	if err := e.check(); err != nil {
		return err
	}
	if err := e.ensureStateDir(); err != nil {
		return err
	}
	key, err := backup.NewKey()
	if err != nil {
		return err
	}
	defer func() { key = backup.Key{} }()
	if err := backup.SaveKey(e.Paths.backupKeyPath(), key); err != nil {
		if errors.Is(err, backup.ErrKeyExists) {
			return fmt.Errorf("a backup key already exists on this machine; it is not replaced (that would make every archive unreadable)")
		}
		return err
	}
	e.audit("backup key created (key id %s)", backup.KeyID(key))
	fmt.Fprintf(out, "Backup key created. Key id: %s\n\n", backup.KeyID(key))
	fmt.Fprintf(out, "Recovery key (shown once; write it down and keep it away from this machine):\n\n    %s\n\n", backup.FormatRecoveryKey(key))
	fmt.Fprintln(out, "Without it no backup of this machine can be restored, by anyone.")
	return nil
}

// BackupRestore is `hm-helper backup-restore --from <file> [--to <dir>]`: ask
// the recovery key on in, then restore the archive into a new directory
// (or into to, where nothing existing is overwritten).
func BackupRestore(ctx context.Context, e *Env, from, to string, in io.Reader, prompt, out io.Writer) error {
	if err := e.check(); err != nil {
		return err
	}
	if !filepath.IsAbs(from) || (to != "" && !filepath.IsAbs(to)) {
		return fmt.Errorf("--from and --to take absolute paths")
	}
	f, err := os.OpenFile(from, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("the archive cannot be opened (a symbolic link is refused)")
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return fmt.Errorf("the archive is not a regular file")
	}
	fmt.Fprint(prompt, "Recovery key: ")
	line, err := bufio.NewReaderSize(io.LimitReader(in, 512), 512).ReadString('\n')
	if err != nil && line == "" {
		return fmt.Errorf("no recovery key was given")
	}
	key, err := backup.ParseRecoveryKey(line)
	line = ""
	if err != nil {
		return err
	}
	defer func() { key = backup.Key{} }()
	dest := to
	if dest == "" {
		if err := e.ensureStateDir(); err != nil {
			return err
		}
		root := e.Paths.state("restore")
		if err := ensureDir(root, 0o700, e.OwnerUID); err != nil {
			return err
		}
		dest = filepath.Join(root, e.now().Format("20060102T150405Z"))
		if _, err := os.Lstat(dest); err == nil {
			return fmt.Errorf("%s already exists", dest)
		}
	}
	res, err := backup.Restore(ctx, backup.RestoreOptions{Key: key, Source: f, DestDir: dest,
		Extract: backup.ExtractOptions{RestoreOwnership: true}})
	if err != nil {
		if errors.Is(err, backup.ErrWrongKey) {
			return fmt.Errorf("this recovery key is not the key of the archive")
		}
		return fmt.Errorf("the restore failed and %s holds an incomplete copy to discard: %v", dest, err)
	}
	e.audit("backup restored into %s (%d files)", dest, res.Files)
	fmt.Fprintf(out, "Restored %d files, %d directories (%d bytes) of machine %s from %s into %s\n",
		res.Files, res.Dirs, res.Bytes, res.Manifest.MachineID, res.Manifest.CreatedAt.UTC().Format("2006-01-02 15:04:05Z"), dest)
	return nil
}
