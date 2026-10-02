package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseAgentDefaultsAndValues(t *testing.T) {
	cfg, err := ParseAgent(strings.NewReader(`
# comment
HM_API_URL=https://api.example.test
HM_HEARTBEAT_INTERVAL_S=30
HM_STATE_DIR=/srv/hm
HM_SPOOL_QUOTA_MIB=8
HM_ALLOW_INSECURE_LOOPBACK=1
HM_OPS_ENABLED="reboot, restart_vast_daemon"
HM_LOG_LEVEL='debug'
HM_EXTRA_MOUNTS=/data,/scratch
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIURL != "https://api.example.test" || cfg.HeartbeatInterval != 30*time.Second {
		t.Fatalf("unexpected: %+v", cfg)
	}
	if cfg.StateDir != "/srv/hm" || cfg.SpoolDir != "/srv/hm/spool" {
		t.Fatalf("spool dir must follow the state dir: %+v", cfg)
	}
	if cfg.SpoolQuotaBytes != 8*1024*1024 || !cfg.AllowInsecureLoopback || cfg.LogLevel != "debug" {
		t.Fatalf("unexpected: %+v", cfg)
	}
	if len(cfg.OpsEnabled) != 2 || cfg.OpsEnabled[0] != "reboot" || cfg.OpsEnabled[1] != "restart_vast_daemon" {
		t.Fatalf("ops: %v", cfg.OpsEnabled)
	}
	if len(cfg.ExtraMounts) != 2 || cfg.VastMachineIDFile != DefaultVastMachineIDFile {
		t.Fatalf("unexpected: %+v", cfg)
	}
}

func TestDefaults(t *testing.T) {
	cfg, err := ParseAgent(strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HeartbeatInterval != 60*time.Second || cfg.StateDir != "/var/lib/happymining" ||
		cfg.SpoolQuotaBytes != 64*1024*1024 || cfg.AllowInsecureLoopback || len(cfg.OpsEnabled) != 0 ||
		cfg.SpoolDir != "/var/lib/happymining/spool" || cfg.MaxSampleAge != 168*time.Hour {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestParseAgentStrictness(t *testing.T) {
	bad := map[string]string{
		"unknown key":            "HM_UNKNOWN=1\n",
		"typo key":               "HM_API_URl=https://x\n",
		"lowercase key":          "hm_api_url=https://x\n",
		"no equals":              "HM_API_URL\n",
		"export":                 "export HM_API_URL=https://x\n",
		"duplicate":              "HM_LOG_LEVEL=info\nHM_LOG_LEVEL=debug\n",
		"interval below minimum": "HM_HEARTBEAT_INTERVAL_S=14\n",
		"interval not a number":  "HM_HEARTBEAT_INTERVAL_S=1m\n",
		"interval too large":     "HM_HEARTBEAT_INTERVAL_S=999999\n",
		"quota zero":             "HM_SPOOL_QUOTA_MIB=0\n",
		"relative state dir":     "HM_STATE_DIR=var/lib\n",
		"bool word":              "HM_ALLOW_INSECURE_LOOPBACK=true\n",
		"bad log level":          "HM_LOG_LEVEL=verbose\n",
		"unknown op":             "HM_OPS_ENABLED=run_shell\n",
		"default op listed":      "HM_OPS_ENABLED=refresh_inventory\n",
		"op twice":               "HM_OPS_ENABLED=reboot,reboot\n",
		"unterminated quote":     "HM_API_URL=\"https://x\n",
		"quote in the middle":    "HM_API_URL=https://x\"y\n",
		"space around value":     "HM_API_URL= https://x\n",
		"space before equals":    "HM_API_URL =https://x\n",
		"relative extra mount":   "HM_EXTRA_MOUNTS=data\n",
		"relative CA file":       "HM_CA_FILE=ca.pem\n",
		"long line":              "HM_API_URL=" + strings.Repeat("a", 5000) + "\n",
	}
	for name, input := range bad {
		if _, err := ParseAgent(strings.NewReader(input)); err == nil {
			t.Errorf("%s: expected an error for %q", name, input)
		}
	}
}

func TestMinimumIntervalAccepted(t *testing.T) {
	cfg, err := ParseAgent(strings.NewReader("HM_HEARTBEAT_INTERVAL_S=15\n"))
	if err != nil || cfg.HeartbeatInterval != MinHeartbeatInterval {
		t.Fatalf("15 s must be accepted: %v %v", cfg.HeartbeatInterval, err)
	}
}

func TestLoadAgentOptional(t *testing.T) {
	cfg, err := LoadAgentOptional(filepath.Join(t.TempDir(), "missing.env"))
	if err != nil || cfg.StateDir != DefaultStateDir {
		t.Fatalf("missing file must give defaults: %+v %v", cfg, err)
	}
	path := filepath.Join(t.TempDir(), "agent.env")
	if err := os.WriteFile(path, []byte("BROKEN\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAgentOptional(path); err == nil {
		t.Fatal("a broken file must be an error, not defaults")
	}
	if _, err := LoadAgent(filepath.Join(t.TempDir(), "missing.env")); err == nil {
		t.Fatal("LoadAgent must fail on a missing file")
	}
}

func TestParseHelper(t *testing.T) {
	h, err := ParseHelper(strings.NewReader(""))
	if err != nil || h.AllowReboot || h.AllowRestartVastDaemon {
		t.Fatalf("empty file must disable everything: %+v %v", h, err)
	}
	h, err = ParseHelper(strings.NewReader("ALLOW_REBOOT=1\nALLOW_RESTART_VAST_DAEMON=0\n"))
	if err != nil || !h.AllowReboot || h.AllowRestartVastDaemon {
		t.Fatalf("unexpected: %+v %v", h, err)
	}
	for _, bad := range []string{"ALLOW_SHELL=1\n", "ALLOW_REBOOT=yes\n", "ALLOW_REBOOT=1\nALLOW_REBOOT=1\n"} {
		if _, err := ParseHelper(strings.NewReader(bad)); err == nil {
			t.Errorf("expected an error for %q", bad)
		}
	}
}

func TestParseHelperApplianceSwitches(t *testing.T) {
	// Each key sets exactly its own field.
	keys := map[string]func(Helper) bool{
		"ALLOW_PLUGINS":                 func(h Helper) bool { return h.AllowPlugins },
		"ALLOW_NAS":                     func(h Helper) bool { return h.AllowNAS },
		"ALLOW_BACKUP":                  func(h Helper) bool { return h.AllowBackup },
		"ALLOW_UPDATE":                  func(h Helper) bool { return h.AllowUpdate },
		"ALLOW_UNPINNED_IMAGES":         func(h Helper) bool { return h.AllowUnpinnedImages },
		"ALLOW_FOREIGN_CONTAINERS":      func(h Helper) bool { return h.AllowForeignContainers },
		"ALLOW_UPDATE_WITHOUT_ROLLBACK": func(h Helper) bool { return h.AllowUpdateWithoutRollback },
		"ALLOW_REBOOT":                  func(h Helper) bool { return h.AllowReboot },
		"ALLOW_RESTART_VAST_DAEMON":     func(h Helper) bool { return h.AllowRestartVastDaemon },
	}
	for key := range keys {
		h, err := ParseHelper(strings.NewReader(key + "=1\n"))
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		for other, get := range keys {
			if get(h) != (other == key) {
				t.Errorf("%s=1 sets %s to %v", key, other, get(h))
			}
		}
		h, err = ParseHelper(strings.NewReader(key + "=0\n"))
		if err != nil || h != (Helper{}) {
			t.Errorf("%s=0: %+v %v", key, h, err)
		}
		for _, bad := range []string{key + "=true\n", key + "=yes\n", key + "=2\n", key + "=1\n" + key + "=1\n", key + " = 1\n"} {
			if _, err := ParseHelper(strings.NewReader(bad)); err == nil {
				t.Errorf("expected an error for %q", bad)
			}
		}
	}
	// Close relatives of the real keys are unknown keys, not switches.
	for _, bad := range []string{"ALLOW_PLUGIN=1\n", "ALLOW_NAS_MOUNT=1\n", "ALLOW_UPDATES=1\n", "allow_plugins=1\n", "ALLOW_SHELL_PLUGINS=1\n"} {
		if _, err := ParseHelper(strings.NewReader(bad)); err == nil {
			t.Errorf("expected an error for %q", bad)
		}
	}
}

func TestVastKeyFileIsRejectedAsMachineIDFile(t *testing.T) {
	if !IsVastSecretFile("/var/lib/vastai_kaalia/machine_id") || !IsVastSecretFile("/x/vastai_kaalia/./machine_id") {
		t.Fatal("the Vast key file must be recognised")
	}
	if IsVastSecretFile("/var/lib/vastai_kaalia/machine_num_id") || IsVastSecretFile("/etc/machine_id") {
		t.Fatal("unrelated files must not be flagged")
	}
	if IsVastSecretFile(DefaultVastMachineIDFile) {
		t.Fatal("the default must not be the key file")
	}
}
