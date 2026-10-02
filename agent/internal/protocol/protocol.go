// Package protocol contains the wire types of the HappyMining agent ⇄ API
// contract (docs/agent-protocol.md, v1). These are HappyMining's own
// endpoints; nothing in this package talks to Vast.ai.
package protocol

import (
	"encoding/json"
	"time"
)

// Paths, relative to the configured base URL.
const (
	PathEnroll     = "/api/v1/devices/enroll"
	PathHeartbeat  = "/api/v1/device/heartbeat"
	PathOperations = "/api/v1/device/operations"
	PathRotate     = "/api/v1/device/credential/rotate"
	PathSelf       = "/api/v1/device/self"
)

// Limits fixed by the contract.
const (
	MaxRequestBodyBytes  = 256 * 1024
	MaxSamplesPerRequest = 100
	MaxGPUs              = 32
	MaxDisks             = 16
	MaxServices          = 16
	MaxStringLen         = 128
	MaxDetailLen         = 2000
	MaxResultBytes       = 64 * 1024
)

// Error codes of the error envelope.
const (
	CodeInvalidRequest     = "invalid_request"
	CodePairingFailed      = "pairing_failed"
	CodeDeviceUnauthorized = "device_unauthorized"
	CodeForbidden          = "forbidden"
	CodeNotFound           = "not_found"
	CodeConflict           = "conflict"
	CodeExpired            = "expired"
	CodePayloadTooLarge    = "payload_too_large"
	CodeRateLimited        = "rate_limited"
)

// Service states allowed in a sample.
const (
	ServiceActive       = "active"
	ServiceInactive     = "inactive"
	ServiceFailed       = "failed"
	ServiceActivating   = "activating"
	ServiceNotInstalled = "not-installed"
	ServiceUnknown      = "unknown"
)

// Operation types.
const (
	OpRefreshInventory     = "refresh_inventory"
	OpCollectDiagnostics   = "collect_diagnostics"
	OpRunPreflight         = "run_preflight"
	OpRotateCredential     = "rotate_credential"
	OpRestartVastDaemon    = "restart_vast_daemon"
	OpReboot               = "reboot"
	OpRunBenchmark         = "run_benchmark"
	OpApplyHardwareProfile = "apply_hardware_profile"
)

// Acknowledgement statuses.
const (
	AckAccepted  = "accepted"
	AckRejected  = "rejected"
	AckSucceeded = "succeeded"
	AckFailed    = "failed"
)

// TimeFormat is RFC 3339 in UTC with second precision.
const TimeFormat = "2006-01-02T15:04:05Z"

// FormatTime renders t as the contract requires.
func FormatTime(t time.Time) string { return t.UTC().Format(TimeFormat) }

// ErrorEnvelope is the body of every non-2xx response.
type ErrorEnvelope struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}

// OSInfo describes the operating system in an enrollment request.
type OSInfo struct {
	ID        string `json:"id"`
	VersionID string `json:"version_id"`
	Kernel    string `json:"kernel"`
	Arch      string `json:"arch"`
}

// EnrollRequest is the body of POST /api/v1/devices/enroll.
type EnrollRequest struct {
	PairingCode        string `json:"pairing_code"`
	Hostname           string `json:"hostname"`
	MachineFingerprint string `json:"machine_fingerprint"`
	AgentVersion       string `json:"agent_version"`
	OS                 OSInfo `json:"os"`
}

// Credential is a device credential as issued by the API.
type Credential struct {
	ID        string  `json:"id"`
	Token     string  `json:"token"`
	ExpiresAt *string `json:"expires_at"`
}

// EnrollResponse is the 201 body of the enrollment endpoint.
type EnrollResponse struct {
	DeviceID           string     `json:"device_id"`
	MachineID          string     `json:"machine_id"`
	Credential         Credential `json:"credential"`
	HeartbeatIntervalS int        `json:"heartbeat_interval_s"`
	ServerTime         string     `json:"server_time"`
}

// RotateResponse is the 200 body of the credential rotation endpoint.
type RotateResponse struct {
	Credential Credential `json:"credential"`
}

// SelfResponse is the 200 body of GET /api/v1/device/self.
type SelfResponse struct {
	DeviceID   string `json:"device_id"`
	MachineID  string `json:"machine_id"`
	Status     string `json:"status"`
	ServerTime string `json:"server_time"`
}

// CPU is the cpu object of a sample. Unknown numbers are null, never 0.
type CPU struct {
	Model   string   `json:"model"`
	Cores   *int     `json:"cores"`
	Load1   *float64 `json:"load1"`
	UtilPct *float64 `json:"util_pct"`
}

// Memory is the memory object of a sample.
type Memory struct {
	TotalBytes     *uint64 `json:"total_bytes"`
	AvailableBytes *uint64 `json:"available_bytes"`
}

// Disk is one entry of the disks array.
type Disk struct {
	Mount      string  `json:"mount"`
	FS         string  `json:"fs"`
	TotalBytes *uint64 `json:"total_bytes"`
	AvailBytes *uint64 `json:"avail_bytes"`
}

// GPU is one entry of the gpus array.
type GPU struct {
	Index         int      `json:"index"`
	UUID          string   `json:"uuid"`
	Name          string   `json:"name"`
	DriverVersion string   `json:"driver_version"`
	VRAMTotalMiB  *int64   `json:"vram_total_mib"`
	VRAMUsedMiB   *int64   `json:"vram_used_mib"`
	UtilPct       *int64   `json:"util_pct"`
	PowerW        *float64 `json:"power_w"`
	TempC         *int64   `json:"temp_c"`
	FanPct        *int64   `json:"fan_pct"`
}

// Vast is the vast object of a sample. MachineIDHint is only ever a SHA-256.
type Vast struct {
	DaemonInstalled bool    `json:"daemon_installed"`
	MachineIDHint   *string `json:"machine_id_hint"`
}

// Sample is one telemetry sample. The set of keys is a privacy boundary:
// nothing about renter workloads is ever part of it.
type Sample struct {
	Seq         uint64            `json:"seq"`
	CollectedAt string            `json:"collected_at"`
	UptimeS     *uint64           `json:"uptime_s"`
	Synthetic   bool              `json:"synthetic"`
	CPU         CPU               `json:"cpu"`
	Memory      Memory            `json:"memory"`
	Disks       []Disk            `json:"disks"`
	GPUs        []GPU             `json:"gpus"`
	Services    map[string]string `json:"services"`
	Vast        Vast              `json:"vast"`
}

// HeartbeatRequest is the body of POST /api/v1/device/heartbeat. Samples are
// kept as raw JSON so that a resent sample is byte-identical to the spooled one.
type HeartbeatRequest struct {
	SentAt       string            `json:"sent_at"`
	BootID       string            `json:"boot_id"`
	AgentVersion string            `json:"agent_version"`
	Samples      []json.RawMessage `json:"samples"`
}

// HeartbeatResponse is the 200 body of the heartbeat endpoint.
type HeartbeatResponse struct {
	Accepted      int         `json:"accepted"`
	Duplicates    int         `json:"duplicates"`
	Rejected      int         `json:"rejected"`
	HighestSeq    uint64      `json:"highest_seq"`
	ServerTime    string      `json:"server_time"`
	NextIntervalS int         `json:"next_interval_s"`
	Operations    []Operation `json:"operations"`
}

// Operation is a typed operation requested by the server.
type Operation struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Params    json.RawMessage `json:"params"`
	IssuedAt  string          `json:"issued_at"`
	ExpiresAt string          `json:"expires_at"`
	Nonce     string          `json:"nonce"`
}

// OperationsResponse is the 200 body of GET /api/v1/device/operations.
type OperationsResponse struct {
	Operations []Operation `json:"operations"`
}

// AckRequest is the body of POST /api/v1/device/operations/{id}/ack.
type AckRequest struct {
	Status      string          `json:"status"`
	Nonce       string          `json:"nonce"`
	Detail      string          `json:"detail"`
	Result      json.RawMessage `json:"result"`
	CompletedAt string          `json:"completed_at"`
}

// Truncate shortens s to at most n runes.
func Truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	count := 0
	for i := range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}
