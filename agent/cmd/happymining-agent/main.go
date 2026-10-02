// Command happymining-agent is the HappyMining monitoring agent. It runs as
// the unprivileged user `happymining` under systemd, collects host telemetry,
// buffers it on disk and reports it to HappyMining's own API. It never talks
// to Vast.ai and never touches renter workloads.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/agent"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/client"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/collector"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/config"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/helper"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/logx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/preflight"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/redact"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/version"
)

// exitConfig is EX_CONFIG: the unit does not restart the agent on it.
const exitConfig = 78

func main() { os.Exit(run()) }

func run() int {
	fs := flag.NewFlagSet("happymining-agent", flag.ContinueOnError)
	configPath := fs.String("config", config.DefaultAgentConfigPath, "path of the agent configuration file")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Println("happymining-agent " + version.Version)
		return 0
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "happymining-agent takes no arguments")
		return 2
	}

	redactor := redact.New()
	log := logx.New(os.Stdout, 0, redactor)

	cfg, err := config.LoadAgent(*configPath)
	if err != nil {
		log.Error("invalid configuration", "error", err.Error())
		return exitConfig
	}
	level, err := logx.ParseLevel(cfg.LogLevel)
	if err != nil {
		log.Error("invalid configuration", "error", err.Error())
		return exitConfig
	}
	log = logx.New(os.Stdout, level, redactor)

	api, err := client.New(client.Options{
		BaseURL:               cfg.APIURL,
		CAFile:                cfg.CAFile,
		AllowInsecureLoopback: cfg.AllowInsecureLoopback,
	})
	if err != nil {
		log.Error("invalid API configuration", "error", err.Error())
		return exitConfig
	}

	bootID := "unknown"
	if data, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		if id := strings.TrimSpace(string(data)); id != "" {
			bootID = id
		}
	} else {
		log.Warn("cannot read the boot id", "error", err.Error())
	}

	requirements := preflight.EmbeddedRequirements()
	// One client for both: the two typed actions of agent 0.1.0 and the
	// appliance actions (docs/appliance.md). The helper decides with its own
	// switches what it does; with none on it only reports.
	privileged := &helper.Client{SocketPath: cfg.HelperSocket}
	a, err := agent.New(agent.Options{
		StateDir:        cfg.StateDir,
		SpoolDir:        cfg.SpoolDir,
		SpoolQuotaBytes: cfg.SpoolQuotaBytes,
		MaxSampleAge:    cfg.MaxSampleAge,
		Interval:        cfg.HeartbeatInterval,
		MinInterval:     config.MinHeartbeatInterval,
		MaxInterval:     config.MaxHeartbeatInterval,
		Client:          api,
		Collector:       collector.NewReal(cfg.ExtraMounts, cfg.VastMachineIDFile),
		Synthetic:       false,
		BootID:          bootID,
		Logger:          log,
		Redactor:        redactor,
		OpsEnabled:      cfg.OpsEnabled,
		Helper:          privileged,
		Appliance:       privileged,
		Preflight: func(ctx context.Context) (string, any, error) {
			report := preflight.Run(ctx, preflight.HostEnv(api, false), requirements)
			return report.Overall, report, nil
		},
	})
	if err != nil {
		log.Error("cannot start", "error", err.Error())
		return 1
	}
	defer a.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	log.Info("happymining-agent started", "version", version.Version, "api_url", api.BaseURL(),
		"state_dir", cfg.StateDir, "boot_id", bootID)
	if err := a.Run(ctx); err != nil {
		log.Error("agent stopped with an error", "error", err.Error())
		return 1
	}
	log.Info("happymining-agent stopped")
	return 0
}
