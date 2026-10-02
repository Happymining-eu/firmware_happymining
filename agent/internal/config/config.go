// Package config parses the agent's configuration file
// (/etc/happymining/agent.env) and the privileged helper's switch file
// (/etc/happymining/helper.conf). Both use the same deliberately small and
// strict format: one KEY=VALUE per line, `#` comment lines, blank lines.
// Unknown keys, duplicate keys and malformed lines are errors.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
)

// Default locations.
const (
	DefaultAgentConfigPath  = "/etc/happymining/agent.env"
	DefaultHelperConfigPath = "/etc/happymining/helper.conf"
	DefaultStateDir         = "/var/lib/happymining"
	DefaultHelperSocket     = "/run/happymining-helper.sock"
	// DefaultVastMachineIDFile is the file believed to hold the NUMERIC Vast
	// machine id (the number shown in the Vast console). The path comes from
	// reading Vast's host installer and is not confirmed by Vast documentation
	// (docs/integration-evidence.md, E17). It is only a default for
	// HM_VAST_MACHINE_ID_FILE.
	//
	// It is deliberately NOT ".../machine_id": that file holds the machine's
	// host API key (a secret), and this agent never reads it. See
	// IsVastSecretFile.
	DefaultVastMachineIDFile = "/var/lib/vastai_kaalia/machine_num_id"
)

// Bounds.
const (
	MinHeartbeatInterval = 15 * time.Second
	MaxHeartbeatInterval = time.Hour
	DefaultInterval      = 60 * time.Second
	DefaultSpoolQuotaMiB = 64
	MaxSpoolQuotaMiB     = 4096
	DefaultMaxSampleAgeH = 168 // 7 days: the API drops older samples anyway
	maxConfigFileBytes   = 64 * 1024
	maxExtraMounts       = protocol.MaxDisks - 2
)

// OptInOperations are the operation types that are disabled by default and
// that a local administrator may list in HM_OPS_ENABLED.
var OptInOperations = []string{
	protocol.OpRestartVastDaemon,
	protocol.OpReboot,
	protocol.OpRunBenchmark,
	protocol.OpApplyHardwareProfile,
}

// Agent is the parsed agent configuration.
type Agent struct {
	APIURL                string
	HeartbeatInterval     time.Duration
	StateDir              string
	SpoolDir              string
	SpoolQuotaBytes       int64
	CAFile                string
	AllowInsecureLoopback bool
	OpsEnabled            []string
	LogLevel              string
	VastMachineIDFile     string
	ExtraMounts           []string
	MaxSampleAge          time.Duration
	HelperSocket          string
}

// DefaultAgent returns the configuration used when a key is absent.
func DefaultAgent() Agent {
	return Agent{
		HeartbeatInterval: DefaultInterval,
		StateDir:          DefaultStateDir,
		SpoolDir:          filepath.Join(DefaultStateDir, "spool"),
		SpoolQuotaBytes:   DefaultSpoolQuotaMiB * 1024 * 1024,
		LogLevel:          "info",
		VastMachineIDFile: DefaultVastMachineIDFile,
		MaxSampleAge:      DefaultMaxSampleAgeH * time.Hour,
		HelperSocket:      DefaultHelperSocket,
	}
}

var reKey = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// ParseKV parses the KEY=VALUE format. Values may be wrapped in one matching
// pair of single or double quotes; there are no escapes, no variable
// expansion, no `export` and no inline comments.
func ParseKV(r io.Reader) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(io.LimitReader(r, maxConfigFileBytes+1))
	sc.Buffer(make([]byte, 0, 4096), 4096)
	line := 0
	total := 0
	for sc.Scan() {
		line++
		raw := sc.Text()
		total += len(raw) + 1
		if total > maxConfigFileBytes {
			return nil, fmt.Errorf("configuration larger than %d bytes", maxConfigFileBytes)
		}
		text := strings.TrimSpace(raw)
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		key, value, ok := strings.Cut(text, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected KEY=VALUE", line)
		}
		if !reKey.MatchString(key) {
			return nil, fmt.Errorf("line %d: invalid key %q", line, key)
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("line %d: duplicate key %s", line, key)
		}
		value, err := unquote(value)
		if err != nil {
			return nil, fmt.Errorf("line %d: %s: %w", line, key, err)
		}
		out[key] = value
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("line %d: line too long", line+1)
		}
		return nil, err
	}
	return out, nil
}

func unquote(v string) (string, error) {
	if strings.TrimSpace(v) != v {
		return "", errors.New("whitespace around the value is not allowed")
	}
	for _, q := range []string{`"`, `'`} {
		if strings.HasPrefix(v, q) {
			if len(v) < 2 || !strings.HasSuffix(v, q) {
				return "", errors.New("unterminated quote")
			}
			v = v[1 : len(v)-1]
			if strings.Contains(v, q) {
				return "", errors.New("quote inside quoted value")
			}
			return v, nil
		}
	}
	if strings.ContainsAny(v, `"'`) {
		return "", errors.New("unexpected quote")
	}
	for _, c := range v {
		if c < 0x20 || c == 0x7f {
			return "", errors.New("control character in value")
		}
	}
	return v, nil
}

// LoadAgent reads and validates the agent configuration at path.
func LoadAgent(path string) (Agent, error) {
	f, err := os.Open(path)
	if err != nil {
		return Agent{}, err
	}
	defer f.Close()
	cfg, err := ParseAgent(f)
	if err != nil {
		return Agent{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// LoadAgentOptional is LoadAgent, except that a missing file yields the
// defaults. It is used by happyminingctl, which must work before the
// configuration exists.
func LoadAgentOptional(path string) (Agent, error) {
	cfg, err := LoadAgent(path)
	if errors.Is(err, fs.ErrNotExist) {
		return DefaultAgent(), nil
	}
	return cfg, err
}

// ParseAgent parses and validates an agent configuration.
func ParseAgent(r io.Reader) (Agent, error) {
	kv, err := ParseKV(r)
	if err != nil {
		return Agent{}, err
	}
	cfg := DefaultAgent()
	spoolSet := false
	for key, value := range kv {
		switch key {
		case "HM_API_URL":
			cfg.APIURL = value
		case "HM_HEARTBEAT_INTERVAL_S":
			n, err := parseInt(key, value, int64(MinHeartbeatInterval/time.Second), int64(MaxHeartbeatInterval/time.Second))
			if err != nil {
				return Agent{}, err
			}
			cfg.HeartbeatInterval = time.Duration(n) * time.Second
		case "HM_STATE_DIR":
			if err := absPath(key, value); err != nil {
				return Agent{}, err
			}
			cfg.StateDir = filepath.Clean(value)
		case "HM_SPOOL_DIR":
			if err := absPath(key, value); err != nil {
				return Agent{}, err
			}
			cfg.SpoolDir = filepath.Clean(value)
			spoolSet = true
		case "HM_SPOOL_QUOTA_MIB":
			n, err := parseInt(key, value, 1, MaxSpoolQuotaMiB)
			if err != nil {
				return Agent{}, err
			}
			cfg.SpoolQuotaBytes = n * 1024 * 1024
		case "HM_CA_FILE":
			if value != "" {
				if err := absPath(key, value); err != nil {
					return Agent{}, err
				}
			}
			cfg.CAFile = value
		case "HM_ALLOW_INSECURE_LOOPBACK":
			b, err := parseBool(key, value)
			if err != nil {
				return Agent{}, err
			}
			cfg.AllowInsecureLoopback = b
		case "HM_OPS_ENABLED":
			ops, err := parseOps(value)
			if err != nil {
				return Agent{}, err
			}
			cfg.OpsEnabled = ops
		case "HM_LOG_LEVEL":
			switch value {
			case "debug", "info", "warn", "error":
				cfg.LogLevel = value
			default:
				return Agent{}, fmt.Errorf("HM_LOG_LEVEL: %q is not one of debug, info, warn, error", value)
			}
		case "HM_VAST_MACHINE_ID_FILE":
			if err := absPath(key, value); err != nil {
				return Agent{}, err
			}
			if IsVastSecretFile(value) {
				return Agent{}, fmt.Errorf("%s: %q is Vast's host API key file, not an identifier; the agent never reads it", key, value)
			}
			cfg.VastMachineIDFile = filepath.Clean(value)
		case "HM_EXTRA_MOUNTS":
			mounts, err := parseMounts(value)
			if err != nil {
				return Agent{}, err
			}
			cfg.ExtraMounts = mounts
		case "HM_MAX_SAMPLE_AGE_H":
			n, err := parseInt(key, value, 1, 24*30)
			if err != nil {
				return Agent{}, err
			}
			cfg.MaxSampleAge = time.Duration(n) * time.Hour
		case "HM_HELPER_SOCKET":
			if err := absPath(key, value); err != nil {
				return Agent{}, err
			}
			cfg.HelperSocket = filepath.Clean(value)
		default:
			return Agent{}, fmt.Errorf("unknown configuration key %s", key)
		}
	}
	if !spoolSet {
		cfg.SpoolDir = filepath.Join(cfg.StateDir, "spool")
	}
	return cfg, nil
}

func parseInt(key, value string, lo, hi int64) (int64, error) {
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not an integer", key, value)
	}
	if n < lo || n > hi {
		return 0, fmt.Errorf("%s: %d is outside %d..%d", key, n, lo, hi)
	}
	return n, nil
}

func parseBool(key, value string) (bool, error) {
	switch value {
	case "1":
		return true, nil
	case "0", "":
		return false, nil
	}
	return false, fmt.Errorf("%s: %q is not 0 or 1", key, value)
}

func absPath(key, value string) error {
	if !filepath.IsAbs(value) {
		return fmt.Errorf("%s: %q is not an absolute path", key, value)
	}
	if strings.ContainsRune(value, 0) {
		return fmt.Errorf("%s: invalid path", key)
	}
	return nil
}

func parseOps(value string) ([]string, error) {
	var out []string
	if strings.TrimSpace(value) == "" {
		return out, nil
	}
	seen := map[string]bool{}
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		ok := false
		for _, allowed := range OptInOperations {
			if item == allowed {
				ok = true
			}
		}
		if !ok {
			return nil, fmt.Errorf("HM_OPS_ENABLED: %q is not an opt-in operation type (allowed: %s)",
				item, strings.Join(OptInOperations, ", "))
		}
		if seen[item] {
			return nil, fmt.Errorf("HM_OPS_ENABLED: %q listed twice", item)
		}
		seen[item] = true
		out = append(out, item)
	}
	return out, nil
}

func parseMounts(value string) ([]string, error) {
	var out []string
	if strings.TrimSpace(value) == "" {
		return out, nil
	}
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if err := absPath("HM_EXTRA_MOUNTS", item); err != nil {
			return nil, err
		}
		out = append(out, filepath.Clean(item))
	}
	if len(out) > maxExtraMounts {
		return nil, fmt.Errorf("HM_EXTRA_MOUNTS: at most %d extra mounts", maxExtraMounts)
	}
	return out, nil
}

// Helper is the parsed privileged-helper switch file. Everything is disabled
// unless the root-owned file says otherwise.
type Helper struct {
	AllowRestartVastDaemon bool
	AllowReboot            bool
	// AllowPlugins: start and stop catalog plugins (docs/appliance.md, 8).
	AllowPlugins bool
	// AllowNAS: mount and unmount the document's NAS entries.
	AllowNAS bool
	// AllowBackup: run backups (and stop and start the plugins whose
	// volumes are saved, for the duration of the backup).
	AllowBackup bool
	// AllowUpdate: install signed firmware releases.
	AllowUpdate bool
	// AllowUnpinnedImages: start a plugin whose images are not all pinned
	// to a digest read from the registry.
	AllowUnpinnedImages bool
	// AllowForeignContainers: start GPU plugins while containers that
	// HappyMining did not start are running.
	AllowForeignContainers bool
	// AllowUpdateWithoutRollback: install a release although no copy of the
	// installed package is kept for a rollback.
	AllowUpdateWithoutRollback bool
}

// ParseHelper parses a helper switch file.
func ParseHelper(r io.Reader) (Helper, error) {
	kv, err := ParseKV(r)
	if err != nil {
		return Helper{}, err
	}
	var h Helper
	for key, value := range kv {
		b, err := parseBool(key, value)
		if err != nil {
			return Helper{}, err
		}
		switch key {
		case "ALLOW_RESTART_VAST_DAEMON":
			h.AllowRestartVastDaemon = b
		case "ALLOW_REBOOT":
			h.AllowReboot = b
		case "ALLOW_PLUGINS":
			h.AllowPlugins = b
		case "ALLOW_NAS":
			h.AllowNAS = b
		case "ALLOW_BACKUP":
			h.AllowBackup = b
		case "ALLOW_UPDATE":
			h.AllowUpdate = b
		case "ALLOW_UNPINNED_IMAGES":
			h.AllowUnpinnedImages = b
		case "ALLOW_FOREIGN_CONTAINERS":
			h.AllowForeignContainers = b
		case "ALLOW_UPDATE_WITHOUT_ROLLBACK":
			h.AllowUpdateWithoutRollback = b
		default:
			return Helper{}, fmt.Errorf("unknown helper configuration key %s", key)
		}
	}
	return h, nil
}

// IsVastSecretFile reports whether path is the Vast host daemon's key file.
//
// Vast's installer stores the machine's API key (64 hex characters, mode
// 0600) in a file named "machine_id" inside its "vastai_kaalia" data
// directory. Despite the name it is a credential. The HappyMining agent must
// never read it, hash it, or send anything derived from it.
func IsVastSecretFile(path string) bool {
	clean := filepath.Clean(path)
	return filepath.Base(clean) == "machine_id" && filepath.Base(filepath.Dir(clean)) == "vastai_kaalia"
}
