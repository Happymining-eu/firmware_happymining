package applier

import (
	"fmt"
	"path/filepath"
	"regexp"
)

// Fixed command paths. Only these programs are ever run, always with an argv
// array built here (never a shell line).
const (
	DockerPath    = "/usr/bin/docker"
	MountPath     = "/usr/bin/mount"
	UmountPath    = "/usr/bin/umount"
	DpkgPath      = "/usr/bin/dpkg"
	SystemctlPath = "/usr/bin/systemctl"
)

// Units started by the quick socket helper or by the heavy units. The names
// are fixed; an instance name is built only from the fixed job set and a
// validated plugin id (see JobInstance).
const (
	UnitApply            = "happymining-appliance-apply.service"
	UnitUpdateInstall    = "happymining-update-install.service"
	UnitUpdateGuardTimer = "happymining-update-guard.timer"
	unitJobPrefix        = "happymining-appliance-job@"
	unitJobSuffix        = ".service"
)

// Docker names. Everything HappyMining starts is a Compose project named
// ProjectPrefix + plugin id, whose services carry PluginLabel. Nothing else is
// ever stopped, removed or changed.
const (
	ProjectPrefix = "hm-"
	PluginLabel   = "eu.happymining.plugin"
	NetworkName   = "hm-appliance"
)

// Jobs the heavy unit happymining-appliance-job@.service runs. The first
// three can be asked for over the socket (appliance-run-job); StatusRefresh is
// started by the helper itself when the plugin states it holds are old.
const (
	JobVectorizeSync = "vectorize_sync"
	JobBackupRun     = "backup_run"
	JobPluginRestart = "plugin_restart"
	JobStatusRefresh = "status_refresh"
)

// File names inside StateDir.
const (
	appliedFile      = "applied.json"
	stateFile        = "state.json"
	sealKeyFile      = "seal.key"
	localSecretsFile = "local-secrets.json"
	backupKeyFile    = "backup.key"
	lockFile         = "appliance.lock"
	stateLockFile    = "state.lock"
	updateLockFile   = "update.lock"
	pluginsDir       = "plugins"
	nasCredDir       = "nas"
	updatesDir       = "updates"
	packagesDir      = "packages"
	stagedFile       = "staged.json"
	currentDeb       = "current.deb"
	previousDeb      = "previous.deb"
	agentStateFile   = "agent-state.json"
	vectorizerConfig = "config"
	vectorizerJSON   = "vectorizer.json"
	vectorizerToken  = "token"
)

// Paths are every file-system location the helper uses. Production code uses
// DefaultPaths; tests point every root at a temporary directory, so that
// nothing under test can reach a real system path.
type Paths struct {
	// StateDir is the root-only state directory (0700).
	StateDir string
	// PluginDataRoot holds one directory per plugin (HM_PLUGIN_DATA).
	PluginDataRoot string
	// NASRoot holds one mount point per NAS entry.
	NASRoot string
	// CatalogDir is the installed plugin catalog.
	CatalogDir string
	// BuildRoot holds the build contexts of plugins built on the machine.
	BuildRoot string
	// ReleaseKeysDir holds the trusted release public keys.
	ReleaseKeysDir string
	// ProfilePath is the local profile (docs/appliance.md, 6.4).
	ProfilePath string
	// AgentStateDir is the agent's state directory: agent-state.json and
	// the agent's download directory "updates".
	AgentStateDir string
	// MountInfo is the mount table of the helper's mount namespace.
	MountInfo string
	// BootID identifies the current boot (a reboot loses every mount).
	BootID string
	// DockerVolumes is the only place a plugin volume may be found.
	DockerVolumes string
	// InstallerCache is where the image's installer keeps the package it
	// installed (happymining-agent_<version>_<arch>.deb, its .sha256 and a
	// file "current" naming it): the copy a first update rolls back to.
	InstallerCache string
}

// DefaultPaths returns the locations of docs/appliance.md and of the helper
// interface.
func DefaultPaths() Paths {
	return Paths{
		StateDir:       "/var/lib/happymining-helper",
		PluginDataRoot: "/var/lib/happymining-plugins",
		NASRoot:        "/srv/happymining/nas",
		CatalogDir:     "/usr/share/happymining/catalog",
		BuildRoot:      "/usr/share/happymining",
		ReleaseKeysDir: "/usr/share/happymining/release-keys",
		ProfilePath:    "/etc/happymining/appliance.json",
		AgentStateDir:  "/var/lib/happymining",
		MountInfo:      "/proc/self/mountinfo",
		BootID:         "/proc/sys/kernel/random/boot_id",
		DockerVolumes:  "/var/lib/docker/volumes",
		InstallerCache: "/var/cache/happymining",
	}
}

// Check refuses a Paths value with an empty or relative location: a zero
// Paths must never silently mean "the real system".
func (p Paths) Check() error {
	for name, v := range map[string]string{
		"StateDir": p.StateDir, "PluginDataRoot": p.PluginDataRoot, "NASRoot": p.NASRoot,
		"CatalogDir": p.CatalogDir, "BuildRoot": p.BuildRoot, "ReleaseKeysDir": p.ReleaseKeysDir,
		"ProfilePath": p.ProfilePath, "AgentStateDir": p.AgentStateDir, "MountInfo": p.MountInfo,
		"BootID": p.BootID, "DockerVolumes": p.DockerVolumes,
	} {
		if v == "" || !filepath.IsAbs(v) || filepath.Clean(v) != v {
			return fmt.Errorf("helper path %s is not a clean absolute path", name)
		}
	}
	return nil
}

func (p Paths) state(name string) string    { return filepath.Join(p.StateDir, name) }
func (p Paths) appliedPath() string         { return p.state(appliedFile) }
func (p Paths) statePath() string           { return p.state(stateFile) }
func (p Paths) sealKeyPath() string         { return p.state(sealKeyFile) }
func (p Paths) localSecretsPath() string    { return p.state(localSecretsFile) }
func (p Paths) backupKeyPath() string       { return p.state(backupKeyFile) }
func (p Paths) pluginsEnvDir() string       { return p.state(pluginsDir) }
func (p Paths) nasCredDir() string          { return p.state(nasCredDir) }
func (p Paths) stagingDir() string          { return p.state(updatesDir) }
func (p Paths) packagesDir() string         { return p.state(packagesDir) }
func (p Paths) agentStatePath() string      { return filepath.Join(p.AgentStateDir, agentStateFile) }
func (p Paths) agentDownloadDir() string    { return filepath.Join(p.AgentStateDir, updatesDir) }
func (p Paths) envFile(id string) string    { return filepath.Join(p.pluginsEnvDir(), id+".env") }
func (p Paths) credFile(id string) string   { return filepath.Join(p.nasCredDir(), id+".cred") }
func (p Paths) mountPoint(id string) string { return filepath.Join(p.NASRoot, id) }
func (p Paths) pluginData(id string) string { return filepath.Join(p.PluginDataRoot, id) }
func (p Paths) vectorizerConfigDir() string {
	return filepath.Join(p.pluginData(vectorizerPlugin), vectorizerConfig)
}

const vectorizerPlugin = "vectorizer"

// reID is the id rule of docs/appliance.md, 4.1 (plugins, NAS entries).
var reID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

// ValidID reports whether id is a plugin or NAS id.
func ValidID(id string) bool { return reID.MatchString(id) }

// JobInstance returns the instance name of happymining-appliance-job@.service
// for a job, or an error. plugin is required for JobPluginRestart only.
func JobInstance(job, plugin string) (string, error) {
	switch job {
	case JobVectorizeSync, JobBackupRun, JobStatusRefresh:
		if plugin != "" {
			return "", fmt.Errorf("job %s takes no plugin", job)
		}
		return job, nil
	case JobPluginRestart:
		if !ValidID(plugin) {
			return "", fmt.Errorf("job %s needs a valid plugin id", job)
		}
		return job + "-" + plugin, nil
	}
	return "", fmt.Errorf("unknown job")
}

// ParseJobInstance is the inverse of JobInstance. It accepts exactly the
// names JobInstance produces.
func ParseJobInstance(instance string) (job, plugin string, err error) {
	switch instance {
	case JobVectorizeSync, JobBackupRun, JobStatusRefresh:
		return instance, "", nil
	}
	const prefix = JobPluginRestart + "-"
	if len(instance) > len(prefix) && instance[:len(prefix)] == prefix && ValidID(instance[len(prefix):]) {
		return JobPluginRestart, instance[len(prefix):], nil
	}
	return "", "", fmt.Errorf("not a job instance")
}

// JobUnit returns the unit name of a job instance.
func JobUnit(instance string) string { return unitJobPrefix + instance + unitJobSuffix }

// projectName is the Compose project of a plugin.
func projectName(id string) string { return ProjectPrefix + id }
