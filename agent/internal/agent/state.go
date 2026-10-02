package agent

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/fsx"
)

// StateFileName is the status file the agent maintains for happyminingctl.
const StateFileName = "agent-state.json"

// Connection states exposed locally.
const (
	StateUnpaired = "unpaired"
	StateStarting = "starting"
	StateOnline   = "online"
	StateOffline  = "offline"
	StateRevoked  = "revoked"
)

// State is the content of the status file. It never contains a secret.
type State struct {
	State               string `json:"state"`
	UpdatedAt           string `json:"updated_at"`
	AgentVersion        string `json:"agent_version"`
	PID                 int    `json:"pid"`
	DeviceID            string `json:"device_id,omitempty"`
	CredentialID        string `json:"credential_id,omitempty"`
	RevokedCredentialID string `json:"revoked_credential_id,omitempty"`
	LastHeartbeatOK     string `json:"last_heartbeat_ok,omitempty"`
	LastError           string `json:"last_error,omitempty"`
	ConsecutiveFailures int    `json:"consecutive_failures"`
	SpoolSamples        int    `json:"spool_samples"`
	SpoolBytes          int64  `json:"spool_bytes"`
	DroppedSamples      uint64 `json:"dropped_samples"`
	Seq                 uint64 `json:"seq"`
	IntervalS           int    `json:"interval_s"`
}

// StatePath returns the status file path for a state directory.
func StatePath(stateDir string) string { return filepath.Join(stateDir, StateFileName) }

// ReadState loads the status file.
func ReadState(stateDir string) (*State, error) {
	data, err := os.ReadFile(StatePath(stateDir))
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func writeState(stateDir string, s *State) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return fsx.WriteFileAtomic(StatePath(stateDir), append(data, '\n'), 0o600, nil)
}
