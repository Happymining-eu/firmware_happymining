// Package ctl implements happyminingctl, the local operator command.
package ctl

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/agent"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/client"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/collector"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/config"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/credential"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/enroll"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/execx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/fsx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/identity"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/pairing"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/preflight"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/redact"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/spool"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/version"
)

// Exit codes. For `preflight`: 0 means no check failed, 1 means at least one
// check failed, 2 means preflight could not run (usage, configuration or
// requirements file error).
const (
	ExitOK    = 0
	ExitFail  = 1
	ExitUsage = 2
)

// Env holds everything the command touches so tests can replace it.
type Env struct {
	Stdout io.Writer
	Stderr io.Writer
	// ReadCode prompts for the pairing code (terminal, no echo).
	ReadCode func() (string, error)
	// Confirm asks the operator to type word; it returns false when the
	// input is not interactive or the answer differs.
	Confirm func(prompt, word string) bool
	Runner  execx.Runner
	// PreflightEnv builds the preflight environment for the host.
	PreflightEnv func(api *client.Client, offline bool) preflight.Env
	// Root is prepended to the paths ctl reads from the host (tests).
	Root string
}

// DefaultEnv returns the Env of a real invocation.
func DefaultEnv() Env {
	return Env{
		Stdout:   os.Stdout,
		Stderr:   os.Stderr,
		ReadCode: func() (string, error) { return ReadSecretFromTerminal("Pairing code: ") },
		Confirm: func(prompt, word string) bool {
			if !IsTerminal(os.Stdin) {
				return false
			}
			fmt.Fprint(os.Stderr, prompt)
			line, err := readLine(os.Stdin)
			return err == nil && strings.TrimSpace(line) == word
		},
		Runner:       execx.OS{},
		PreflightEnv: preflight.HostEnv,
	}
}

const usage = `happyminingctl ` + "%s" + ` - local operator command of the HappyMining agent

Usage: happyminingctl [--config FILE] <command> [options]

Commands:
  identity init      create the random install identity if it does not exist
  pair               pair this machine with a pairing code from HappyMining
  status             show pairing, heartbeat, spool, API and service status
  unpair             delete the local device credential
  preflight          read-only host checks (PASS / WARN / FAIL)
  vast-enroll-help   how to install the official Vast host software by hand
  version            print the version

Run "happyminingctl <command> --help" for the options of a command.
`

type app struct {
	env        Env
	configPath string
}

// Run executes happyminingctl with args (without the program name).
func Run(args []string, env Env) int {
	global := flag.NewFlagSet("happyminingctl", flag.ContinueOnError)
	global.SetOutput(env.Stderr)
	global.Usage = func() { fmt.Fprintf(env.Stderr, usage, version.Version) }
	configPath := global.String("config", config.DefaultAgentConfigPath, "agent configuration file")
	showVersion := global.Bool("version", false, "print the version and exit")
	if err := global.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if *showVersion {
		fmt.Fprintln(env.Stdout, "happyminingctl "+version.Version)
		return ExitOK
	}
	rest := global.Args()
	if len(rest) == 0 {
		global.Usage()
		return ExitUsage
	}
	a := &app{env: env, configPath: *configPath}
	switch rest[0] {
	case "identity":
		if len(rest) < 2 || rest[1] != "init" {
			fmt.Fprintln(env.Stderr, "usage: happyminingctl identity init [--force-regenerate --i-understand-this-requires-re-enrollment]")
			return ExitUsage
		}
		return a.identityInit(rest[2:])
	case "pair":
		return a.pair(rest[1:])
	case "status":
		return a.status(rest[1:])
	case "unpair":
		return a.unpair(rest[1:])
	case "preflight":
		return a.preflight(rest[1:])
	case "vast-enroll-help":
		fmt.Fprint(env.Stdout, VastEnrollHelp)
		return ExitOK
	case "version":
		fmt.Fprintln(env.Stdout, "happyminingctl "+version.Version)
		return ExitOK
	case "help":
		global.Usage()
		return ExitOK
	}
	fmt.Fprintf(env.Stderr, "unknown command %q\n\n", rest[0])
	global.Usage()
	return ExitUsage
}

func (a *app) flagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("happyminingctl "+name, flag.ContinueOnError)
	fs.SetOutput(a.env.Stderr)
	return fs
}

// parse returns (exit code, false) when the command must stop.
func (a *app) parse(fs *flag.FlagSet, args []string) (int, bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK, false
		}
		return ExitUsage, false
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(a.env.Stderr, "unexpected argument %q\n", fs.Arg(0))
		return ExitUsage, false
	}
	return ExitOK, true
}

func (a *app) fail(format string, args ...any) int {
	fmt.Fprintf(a.env.Stderr, "error: "+format+"\n", args...)
	return ExitFail
}

func (a *app) config() (config.Agent, error) {
	return config.LoadAgentOptional(a.configPath)
}

// agentUser is the unprivileged account the agent service runs as.
const agentUser = "happymining"

// lookupAgentOwner resolves the agent account. It is a variable for tests.
var lookupAgentOwner = func() (*fsx.Owner, error) {
	u, err := user.Lookup(agentUser)
	if err != nil {
		return nil, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return nil, err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return nil, err
	}
	return &fsx.Owner{UID: uid, GID: gid}, nil
}

// ensureStateDir creates the state directory when it is missing. It normally
// exists (the package's postinst creates it). When root has to create it, for
// example after a clone was sanitised, it is handed to the agent account so
// that the unprivileged service can use what `pair` writes into it.
func ensureStateDir(dir string) error {
	_, statErr := os.Stat(dir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("state directory %s: %w (run with sudo?)", dir, err)
	}
	if errors.Is(statErr, fs.ErrNotExist) && os.Geteuid() == 0 {
		if owner, err := lookupAgentOwner(); err == nil {
			if err := os.Chown(dir, owner.UID, owner.GID); err != nil {
				return fmt.Errorf("state directory %s: %w", dir, err)
			}
		}
	}
	return nil
}

func (a *app) identityInit(args []string) int {
	fs := a.flagSet("identity init")
	force := fs.Bool("force-regenerate", false, "replace an existing identity (the machine must be enrolled again)")
	confirm := fs.Bool("i-understand-this-requires-re-enrollment", false, "required together with --force-regenerate")
	if code, ok := a.parse(fs, args); !ok {
		return code
	}
	if *force != *confirm {
		fmt.Fprintln(a.env.Stderr, "--force-regenerate and --i-understand-this-requires-re-enrollment must be given together")
		return ExitUsage
	}
	cfg, err := a.config()
	if err != nil {
		return a.fail("%v", err)
	}
	if err := ensureStateDir(cfg.StateDir); err != nil {
		return a.fail("%v", err)
	}
	owner, err := fsx.OwnerForNewFiles(cfg.StateDir)
	if err != nil {
		return a.fail("%v", err)
	}
	created, err := identity.Init(identity.Path(cfg.StateDir), *force, owner)
	if err != nil {
		return a.fail("%v", err)
	}
	switch {
	case created && *force:
		fmt.Fprintln(a.env.Stdout, "install identity regenerated; enroll this machine again")
	case created:
		fmt.Fprintln(a.env.Stdout, "install identity created")
	default:
		fmt.Fprintln(a.env.Stdout, "install identity already exists; left unchanged")
	}
	return ExitOK
}

func (a *app) client(cfg config.Agent, apiURL string) (*client.Client, error) {
	if apiURL == "" {
		apiURL = cfg.APIURL
	}
	return client.New(client.Options{
		BaseURL:               apiURL,
		CAFile:                cfg.CAFile,
		AllowInsecureLoopback: cfg.AllowInsecureLoopback,
		Timeout:               30 * time.Second,
	})
}

// hostOS reads the OS description sent at enrollment.
func (a *app) hostOS() protocol.OSInfo {
	info := protocol.OSInfo{Arch: runtime.GOARCH}
	if data, err := os.ReadFile(a.env.Root + "/etc/os-release"); err == nil {
		kv := preflight.ParseOSRelease(data)
		info.ID = protocol.Truncate(kv["ID"], 64)
		info.VersionID = protocol.Truncate(kv["VERSION_ID"], 64)
	}
	if data, err := os.ReadFile(a.env.Root + "/proc/sys/kernel/osrelease"); err == nil {
		info.Kernel = protocol.Truncate(strings.TrimSpace(string(data)), protocol.MaxStringLen)
	}
	if info.ID == "" {
		info.ID = "unknown"
	}
	return info
}

func (a *app) pair(args []string) int {
	fs := a.flagSet("pair")
	apiURL := fs.String("api-url", "", "API base URL (default: HM_API_URL from the configuration)")
	code := fs.String("code", "", "pairing code; for automated tests only, because command lines are visible to other users. Without it the code is read from the terminal")
	if c, ok := a.parse(fs, args); !ok {
		return c
	}
	cfg, err := a.config()
	if err != nil {
		return a.fail("%v", err)
	}
	if enroll.Paired(cfg.StateDir) {
		return a.fail("%v", enroll.ErrAlreadyPaired)
	}
	api, err := a.client(cfg, *apiURL)
	if err != nil {
		return a.fail("%v", err)
	}
	input := *code
	if input == "" {
		input, err = a.env.ReadCode()
		if err != nil {
			return a.fail("no pairing code was entered")
		}
	}
	canonical, err := pairing.Normalize(input)
	if err != nil {
		return a.fail("%v", err)
	}
	fmt.Fprintf(a.env.Stderr, "Pairing with code %s at %s ...\n", pairing.Mask(canonical), api.BaseURL())
	if err := ensureStateDir(cfg.StateDir); err != nil {
		return a.fail("%v", err)
	}
	owner, err := fsx.OwnerForNewFiles(cfg.StateDir)
	if err != nil {
		return a.fail("%v", err)
	}
	hostname, _ := os.Hostname()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cred, err := enroll.Pair(ctx, enroll.Params{
		Client: api, StateDir: cfg.StateDir, Code: canonical, Hostname: hostname, OS: a.hostOS(), Owner: owner,
	})
	if err != nil {
		// Belt and braces: an error text must never carry the code.
		r := redact.New()
		r.AddSecret(canonical)
		r.AddSecret(input)
		return a.fail("%s", r.String(err.Error()))
	}
	fmt.Fprintln(a.env.Stdout, "Paired.")
	fmt.Fprintln(a.env.Stdout, "  device id:     "+cred.DeviceID)
	fmt.Fprintln(a.env.Stdout, "  machine id:    "+cred.MachineID)
	fmt.Fprintln(a.env.Stdout, "  credential id: "+cred.CredentialID)
	fmt.Fprintln(a.env.Stdout, "The agent picks the credential up within about ten seconds (happyminingctl status).")
	if cfg.APIURL != "" && *apiURL != "" {
		if u, err := client.ValidateBaseURL(cfg.APIURL, cfg.AllowInsecureLoopback); err != nil || u.String() != api.BaseURL() {
			fmt.Fprintln(a.env.Stderr, "warning: --api-url differs from HM_API_URL in "+a.configPath+"; the agent service uses HM_API_URL.")
		}
	}
	return ExitOK
}

func (a *app) unpair(args []string) int {
	fs := a.flagSet("unpair")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	if c, ok := a.parse(fs, args); !ok {
		return c
	}
	cfg, err := a.config()
	if err != nil {
		return a.fail("%v", err)
	}
	if !enroll.Paired(cfg.StateDir) {
		fmt.Fprintln(a.env.Stdout, "this machine is not paired; nothing to do")
		return ExitOK
	}
	if !*yes && !a.env.Confirm("This deletes the device credential. Pairing again needs a new pairing code.\nType 'unpair' to continue: ", "unpair") {
		fmt.Fprintln(a.env.Stderr, "not confirmed; nothing was changed (use --yes in scripts)")
		return ExitFail
	}
	if err := credential.Delete(credential.Path(cfg.StateDir)); err != nil {
		return a.fail("%v (run with sudo?)", err)
	}
	fmt.Fprintln(a.env.Stdout, "Device credential deleted. The agent stops reporting within about ten seconds.")
	fmt.Fprintln(a.env.Stdout, "Vast software and Docker were not touched. Ask HappyMining to revoke the old credential on the server side as well.")
	return ExitOK
}

// StatusReport is the output of `happyminingctl status --json`. It never
// contains the credential secret.
type StatusReport struct {
	Version         string            `json:"version"`
	Paired          bool              `json:"paired"`
	DeviceID        string            `json:"device_id,omitempty"`
	MachineID       string            `json:"machine_id,omitempty"`
	CredentialID    string            `json:"credential_id,omitempty"`
	CredentialError string            `json:"credential_error,omitempty"`
	APIURL          string            `json:"api_url,omitempty"`
	AgentState      string            `json:"agent_state"`
	LastHeartbeatOK string            `json:"last_heartbeat_ok,omitempty"`
	LastError       string            `json:"last_error,omitempty"`
	SpoolSamples    int               `json:"spool_samples"`
	SpoolBytes      int64             `json:"spool_bytes"`
	SpoolQuotaBytes int64             `json:"spool_quota_bytes"`
	DroppedSamples  uint64            `json:"dropped_samples"`
	APIReachable    bool              `json:"api_reachable"`
	APIDetail       string            `json:"api_detail"`
	Services        map[string]string `json:"services"`
}

// statusUnits are the units shown by `status`: the agent itself and the
// collector's allowlist.
var statusUnits = append([]string{"happymining-agent"}, collector.ServiceUnits...)

func (a *app) status(args []string) int {
	flags := a.flagSet("status")
	asJSON := flags.Bool("json", false, "print JSON")
	if c, ok := a.parse(flags, args); !ok {
		return c
	}
	cfg, err := a.config()
	if err != nil {
		return a.fail("%v", err)
	}
	rep := StatusReport{
		Version: version.Version, APIURL: cfg.APIURL, AgentState: "unknown",
		SpoolQuotaBytes: cfg.SpoolQuotaBytes, Services: map[string]string{},
	}
	redactor := redact.New()

	cred, err := credential.Load(credential.Path(cfg.StateDir))
	switch {
	case err == nil:
		redactor.AddSecret(cred.Token)
		rep.Paired = true
		rep.DeviceID, rep.MachineID, rep.CredentialID = cred.DeviceID, cred.MachineID, cred.CredentialID
	case errors.Is(err, credential.ErrNotPaired):
	case errors.Is(err, fs.ErrPermission):
		rep.CredentialError = "cannot read the credential file (run with sudo)"
	default:
		rep.CredentialError = redactor.String(err.Error())
	}

	if st, err := agent.ReadState(cfg.StateDir); err == nil {
		rep.AgentState = st.State
		rep.LastHeartbeatOK = st.LastHeartbeatOK
		rep.LastError = redactor.String(st.LastError)
		rep.DroppedSamples = st.DroppedSamples
	}
	if n, bytes, err := spool.Stat(cfg.SpoolDir); err == nil {
		rep.SpoolSamples, rep.SpoolBytes = n, bytes
	}

	if api, err := a.client(cfg, ""); err != nil {
		rep.APIDetail = err.Error()
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		if cred != nil {
			self, err := api.Self(ctx, cred.Token)
			var apiErr *client.APIError
			switch {
			case err == nil:
				rep.APIReachable = true
				rep.APIDetail = "credential accepted; device status: " + protocol.Truncate(self.Status, 64)
			case errors.As(err, &apiErr):
				rep.APIReachable = true
				rep.APIDetail = redactor.String(apiErr.Error())
			default:
				rep.APIDetail = redactor.String(err.Error())
			}
		} else if status, err := api.Probe(ctx); err == nil {
			rep.APIReachable = true
			rep.APIDetail = fmt.Sprintf("reachable (HTTP %d without credentials)", status)
		} else {
			rep.APIDetail = redactor.String(err.Error())
		}
		cancel()
	}

	systemctl, err := execx.FindAbs(a.env.Root, collector.SystemctlCandidates...)
	for _, unit := range statusUnits {
		if err != nil {
			rep.Services[unit] = protocol.ServiceUnknown
			continue
		}
		rep.Services[unit] = collector.UnitState(context.Background(), a.env.Runner, systemctl, unit)
	}

	if *asJSON {
		enc := json.NewEncoder(a.env.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return ExitOK
	}
	w := a.env.Stdout
	fmt.Fprintf(w, "happyminingctl %s\n\n", rep.Version)
	if rep.Paired {
		fmt.Fprintf(w, "Pairing:        paired\n  device id:     %s\n  machine id:    %s\n  credential id: %s\n",
			rep.DeviceID, rep.MachineID, rep.CredentialID)
	} else {
		fmt.Fprintln(w, "Pairing:        not paired (run: sudo happyminingctl pair)")
	}
	if rep.CredentialError != "" {
		fmt.Fprintf(w, "  credential problem: %s\n", rep.CredentialError)
	}
	fmt.Fprintf(w, "Agent state:    %s\n", rep.AgentState)
	last := rep.LastHeartbeatOK
	if last == "" {
		last = "never (since the agent started)"
	}
	fmt.Fprintf(w, "Last heartbeat: %s\n", last)
	if rep.LastError != "" {
		fmt.Fprintf(w, "Last error:     %s\n", rep.LastError)
	}
	fmt.Fprintf(w, "Spool:          %d sample(s), %d of %d bytes, %d dropped\n",
		rep.SpoolSamples, rep.SpoolBytes, rep.SpoolQuotaBytes, rep.DroppedSamples)
	reach := "NOT reachable"
	if rep.APIReachable {
		reach = "reachable"
	}
	fmt.Fprintf(w, "API:            %s %s - %s\n", rep.APIURL, reach, rep.APIDetail)
	fmt.Fprintln(w, "Services:")
	for _, unit := range statusUnits {
		fmt.Fprintf(w, "  %-22s %s\n", unit, rep.Services[unit])
	}
	return ExitOK
}

func (a *app) preflight(args []string) int {
	fs := a.flagSet("preflight")
	asJSON := fs.Bool("json", false, "print JSON")
	reqPath := fs.String("requirements", "", "requirements file overriding the embedded one")
	offline := fs.Bool("offline", false, "skip the network checks")
	if c, ok := a.parse(fs, args); !ok {
		return c
	}
	requirements := preflight.EmbeddedRequirements()
	if *reqPath != "" {
		var err error
		if requirements, err = preflight.LoadRequirements(*reqPath); err != nil {
			fmt.Fprintf(a.env.Stderr, "error: %v\n", err)
			return ExitUsage
		}
	}
	cfg, err := a.config()
	if err != nil {
		// Exit status 1 is reserved for "a check failed".
		fmt.Fprintf(a.env.Stderr, "error: %v\n", err)
		return ExitUsage
	}
	var api *client.Client
	if cfg.APIURL != "" {
		if api, err = a.client(cfg, ""); err != nil {
			fmt.Fprintf(a.env.Stderr, "warning: API URL unusable, API check skipped: %v\n", err)
			api = nil
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	report := preflight.Run(ctx, a.env.PreflightEnv(api, *offline), requirements)
	if *asJSON {
		enc := json.NewEncoder(a.env.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	} else {
		preflight.Render(a.env.Stdout, report)
	}
	if report.Overall == preflight.Fail {
		return ExitFail
	}
	return ExitOK
}
