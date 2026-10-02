package applier

import (
	"context"
	"fmt"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
)

const (
	timeoutVectorizeSync = 12 * time.Hour
	timeoutRestart       = 10 * time.Minute
)

// vectorizerSyncArgv is the vectorizer's own command line for one sync
// (appliance/vectorizer/hm_vectorizer/__main__.py, run with the image's own
// interpreter as its README says: `/opt/venv/bin/python -m hm_vectorizer
// sync`; exit 0 done, 1 the run ended in error, 2 configuration refused,
// 3 a sync is already running).
var vectorizerSyncArgv = []string{"/opt/venv/bin/python", "-m", "hm_vectorizer", "sync"}

// QuickRunJob is the socket action appliance-run-job: check the switch and
// the job, then start happymining-appliance-job@<instance>.service.
func QuickRunJob(ctx context.Context, e *Env, job, plugin string) Outcome {
	if err := e.check(); err != nil {
		return refused(CodeFailed, err.Error())
	}
	switch job {
	case JobVectorizeSync, JobPluginRestart:
		if !e.Switches.AllowPlugins {
			return refused(CodeDisabled, "plugins are disabled in helper.conf (ALLOW_PLUGINS)")
		}
	case JobBackupRun:
		if !e.Switches.AllowBackup {
			return refused(CodeDisabled, "backups are disabled in helper.conf (ALLOW_BACKUP)")
		}
	default:
		return refused(CodeInvalid, "unknown job")
	}
	instance, err := JobInstance(job, plugin)
	if err != nil {
		return refused(CodeInvalid, err.Error())
	}
	if job == JobPluginRestart {
		eff, err := e.resolve()
		if err != nil || eff.Doc == nil {
			return refused(CodeFailed, "the document in force cannot be read")
		}
		found := false
		for _, p := range eff.Doc.Plugins {
			found = found || p.ID == plugin
		}
		if !found {
			return refused(CodeInvalid, "plugin "+plugin+" is not in the document in force")
		}
	}
	if err := e.startUnit(ctx, JobUnit(instance)); err != nil {
		return refused(CodeFailed, err.Error())
	}
	e.audit("appliance-run-job: %s started", JobUnit(instance))
	return Outcome{OK: true, Detail: "job " + instance + " started"}
}

// RunJob is `hm-helper run-job <instance>`, run by
// happymining-appliance-job@.service.
func RunJob(ctx context.Context, e *Env, instance string) error {
	if err := e.check(); err != nil {
		return err
	}
	job, plugin, err := ParseJobInstance(instance)
	if err != nil {
		return err
	}
	if err := e.ensureStateDir(); err != nil {
		return err
	}
	switch job {
	case JobStatusRefresh:
		// Read-only towards Docker; no lock, so that it never waits behind a
		// long backup.
		e.refreshPlugins(ctx)
		return nil
	case JobVectorizeSync:
		if !e.Switches.AllowPlugins {
			return e.recordJob(instance, appliance.RunSkipped, "plugins are disabled in helper.conf (ALLOW_PLUGINS)")
		}
		// No appliance lock either: a sync takes hours and must not hold up
		// an apply (a change to vast mode in particular). The vectorizer has
		// its own lock (exit status 3), and an apply that stops it ends the
		// sync.
		return e.vectorizeSync(ctx, instance)
	case JobPluginRestart:
		if !e.Switches.AllowPlugins {
			return e.recordJob(instance, appliance.RunSkipped, "plugins are disabled in helper.conf (ALLOW_PLUGINS)")
		}
		l, err := takeLock(e.Paths.state(lockFile))
		if err != nil {
			return err
		}
		defer l.release()
		return e.pluginRestart(ctx, instance, plugin)
	case JobBackupRun:
		if !e.Switches.AllowBackup {
			return e.recordJob(instance, appliance.RunSkipped, "backups are disabled in helper.conf (ALLOW_BACKUP)")
		}
		l, err := takeLock(e.Paths.state(lockFile))
		if err != nil {
			return err
		}
		defer l.release()
		return e.backupRun(ctx, instance)
	}
	return fmt.Errorf("unknown job")
}

// recordJob stores the outcome of a job run.
func (e *Env) recordJob(instance, status, detail string) error {
	now := appliance.FormatTime(e.now())
	_, err := e.updateState(func(st *State) {
		j := st.job(instance)
		j.LastRunAt, j.LastStatus, j.Detail = now, status, clipText(detail, 400)
	})
	e.audit("job %s: %s %s", instance, status, clipText(detail, 200))
	if err != nil {
		return err
	}
	if status == appliance.RunFailed {
		return fmt.Errorf("job %s failed: %s", instance, clipText(detail, 200))
	}
	return nil
}

// runs reports whether the document in force wants plugin id running.
func runs(eff *effective, id string) bool {
	if eff == nil || eff.Doc == nil || eff.Problem != "" {
		return false
	}
	for _, step := range appliance.Plan(eff.Doc, eff.Catalog) {
		if step.ID == id {
			return step.Run
		}
	}
	return false
}

func (e *Env) vectorizeSync(ctx context.Context, instance string) error {
	eff, err := e.resolve()
	if err != nil || !runs(eff, vectorizerPlugin) {
		return e.recordJob(instance, appliance.RunSkipped, "the vectorizer is not configured to run")
	}
	state, _, err := e.projectState(ctx, vectorizerPlugin)
	if err != nil || state != appliance.PluginRunning {
		return e.recordJob(instance, appliance.RunSkipped, "the vectorizer is not running")
	}
	op := e.newScrubbingOpener(eff.Secrets)
	res := e.docker(ctx, timeoutVectorizeSync, argvComposeExec(vectorizerPlugin, vectorizerPlugin, vectorizerSyncArgv)...)
	defer e.refreshPlugins(ctx)
	switch {
	case res.ok:
		return e.recordJob(instance, appliance.RunOK, "")
	case res.err == nil && res.code == 3:
		return e.recordJob(instance, appliance.RunSkipped, "a sync is already running")
	}
	return e.recordJob(instance, appliance.RunFailed, "the sync failed: "+res.describe(op.scrub))
}

func (e *Env) pluginRestart(ctx context.Context, instance, id string) error {
	eff, err := e.resolve()
	if err != nil || !runs(eff, id) {
		return e.recordJob(instance, appliance.RunSkipped, "plugin "+id+" is not configured to run")
	}
	st, err := e.loadState()
	if err != nil {
		return err
	}
	if rec, ok := st.findPlugin(id); !ok || !rec.Started {
		return e.recordJob(instance, appliance.RunSkipped, "plugin "+id+" was not started by HappyMining")
	}
	op := e.newScrubbingOpener(eff.Secrets)
	res := e.docker(ctx, timeoutRestart, argvComposeRestart(id)...)
	defer e.refreshPlugins(ctx)
	if !res.ok {
		return e.recordJob(instance, appliance.RunFailed, "restart failed: "+res.describe(op.scrub))
	}
	return e.recordJob(instance, appliance.RunOK, "")
}
