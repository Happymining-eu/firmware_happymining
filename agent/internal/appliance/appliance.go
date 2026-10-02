// Package appliance holds the machine's side of the appliance contract
// (docs/appliance.md): the plugin catalog installed with the firmware, the
// desired-state document the cloud or the local profile supplies, the plan
// that follows from both, and the state the machine reports back.
//
// It is a library without side effects. It reads the catalog and the profile
// file, and otherwise works on bytes and values: it mounts nothing, starts
// nothing and opens no secret. The privileged helper and the agent do that
// with what this package has validated.
//
// The rule that shapes everything here: the cloud names things and the
// machine holds the definitions. A document can ask for plugin "ollama" with
// typed settings; it cannot bring an image name, a command, a path to execute
// or a mount option. Whatever is not known is an error, and a document that
// fails any check is refused as a whole.
package appliance

// Modes of a machine (section 2).
const (
	// ModeVast reserves the machine for Vast hosting: no plugin runs.
	ModeVast = "vast"
	// ModePrivateAI runs every enabled plugin.
	ModePrivateAI = "private_ai"
	// ModeVectorize runs only the plugins whose catalog entry lists it.
	ModeVectorize = "vectorize"
)

// Who decides what the machine runs (section 6.4).
const (
	ControlCloud = "cloud"
	ControlLocal = "local"
)

// Jobs a schedule or an appliance_run_job operation may name (sections 4.6
// and 6.5).
const (
	JobVectorizeSync = "vectorize_sync"
	JobBackupRun     = "backup_run"
	JobUpdateCheck   = "update_check"
	JobPluginRestart = "plugin_restart"
)

// Kinds and access levels of a NAS entry (section 4.3).
const (
	NASKindSMB = "smb"
	NASKindNFS = "nfs"

	AccessRead  = "read"
	AccessWrite = "write"
)

// Answer providers of the vectorizer (section 4.4).
const (
	AnswerNone             = "none"
	AnswerLocal            = "local"
	AnswerOpenAICompatible = "openai_compatible"
	AnswerAnthropic        = "anthropic"

	// DefaultAnthropicBaseURL is used when an anthropic answer has no base_url.
	DefaultAnthropicBaseURL = "https://api.anthropic.com"
)

// Backup destination kinds (section 4.5).
const (
	DestinationNAS = "nas"
	DestinationS3  = "s3"
)

// Update channels and policies (section 4.7).
const (
	ChannelStable = "stable"
	ChannelBeta   = "beta"
	ChannelNone   = "none"

	PolicyManual = "manual"
	PolicyAuto   = "auto"
)

// Secret names the document refers to (section 4.8). NAS passwords and plugin
// secrets are named by NASSecretName and Plugin.SecretName.
const (
	SecretAnswerAPIKey = "ai.answer.api_key"
	SecretBackupS3Key  = "backup.s3.secret_key"
)

// PluginVectorizer is the id of the plugin that needs the document's
// "vectorizer" object.
const PluginVectorizer = "vectorizer"

// Setting types of a catalog entry (section 7).
const (
	SettingBool       = "bool"
	SettingInt        = "int"
	SettingEnum       = "enum"
	SettingString     = "string"
	SettingStringList = "string_list"
)

// When a plugin volume is part of a backup (section 7).
const (
	VolumeBackupAlways = "always"
	VolumeBackupModels = "models"
	VolumeBackupNever  = "never"
)

// Values of Reported.ApplyStatus (section 6.1).
const (
	ApplyApplied  = "applied"
	ApplyPartial  = "partial"
	ApplyRejected = "rejected"
	ApplyDisabled = "disabled"
	ApplyPending  = "pending"
)

// Plugin states (section 6.1).
const (
	PluginRunning      = "running"
	PluginStarting     = "starting"
	PluginStopped      = "stopped"
	PluginBlocked      = "blocked"
	PluginError        = "error"
	PluginNotInCatalog = "not_in_catalog"
)

// NAS states (section 6.1).
const (
	NASMounted   = "mounted"
	NASUnmounted = "unmounted"
	NASError     = "error"
)

// Secret states (section 6.1).
const (
	SecretOK         = "ok"
	SecretUnreadable = "unreadable"
	SecretMissing    = "missing"
)

// Vectorizer states (section 6.1).
const (
	VectorizerDisabled = "disabled"
	VectorizerIdle     = "idle"
	VectorizerRunning  = "running"
	VectorizerError    = "error"
)

// Backup states (section 6.1).
const (
	BackupDisabled = "disabled"
	BackupNoKey    = "no_key"
	BackupNever    = "never"
	BackupRunning  = "running"
	BackupOK       = "ok"
	BackupError    = "error"
)

// Update states (section 6.1).
const (
	UpdateIdle        = "idle"
	UpdateDownloading = "downloading"
	UpdateInstalling  = "installing"
	UpdateInstalled   = "installed"
	UpdateRolledBack  = "rolled_back"
	UpdateError       = "error"
)

// Results of a scheduled run (section 6.1).
const (
	RunOK      = "ok"
	RunFailed  = "failed"
	RunSkipped = "skipped"
	RunNever   = "never"
)

// StateUnknown replaces, in Reported.Sanitize, a value that is not one the
// contract lists, in the fields whose list has no "error".
const StateUnknown = "unknown"

// Bounds fixed by the contract.
const (
	// DocumentSchema is the only document, profile, catalog and report schema.
	DocumentSchema = 1
	// MaxDocumentBytes bounds a serialised document and the profile file.
	MaxDocumentBytes = 64 * 1024
	// MaxPlugins bounds the document's plugin list.
	MaxPlugins = 32
	// MaxNAS bounds the document's NAS list.
	MaxNAS = 8
	// MaxSchedules bounds the document's schedule list.
	MaxSchedules = 16
	// MaxSecrets bounds the document's secrets.
	MaxSecrets = 32
	// MaxReportedList bounds every list of the reported state.
	MaxReportedList = 32
	// MaxReportedString bounds every string of the reported state but details.
	MaxReportedString = 128
	// MaxReportedDetail bounds the details of the reported state.
	MaxReportedDetail = 500
)
