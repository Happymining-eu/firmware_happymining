// Command happymining-ui serves the machine's local web page (status, GPUs,
// preflight, pairing) on the LAN. It runs as the unprivileged user
// `happymining` under systemd next to the agent, reads the same files, and
// runs no command on behalf of the browser. See internal/localui.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/client"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/collector"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/config"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/localui"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/logx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/preflight"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/redact"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/version"
)

// DefaultListen is where the page is served. 8080 needs no privilege; an
// administrator overrides it with --listen in a systemd drop-in.
const DefaultListen = ":8080"

// exitConfig is EX_CONFIG: the unit does not restart the service on it.
const exitConfig = 78

func main() { os.Exit(run()) }

func run() int {
	fs := flag.NewFlagSet("happymining-ui", flag.ContinueOnError)
	configPath := fs.String("config", config.DefaultAgentConfigPath, "path of the agent configuration file")
	listen := fs.String("listen", DefaultListen, "address to listen on (host:port; an empty host means every address)")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Println("happymining-ui " + version.Version)
		return 0
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "happymining-ui takes no arguments")
		return 2
	}

	redactor := redact.New()
	log := logx.New(os.Stdout, 0, redactor)
	cfg, err := config.LoadAgentOptional(*configPath)
	if err != nil {
		log.Error("invalid configuration", "error", err.Error())
		return exitConfig
	}
	if level, err := logx.ParseLevel(cfg.LogLevel); err == nil {
		log = logx.New(os.Stdout, level, redactor)
	}

	var api *client.Client
	if cfg.APIURL != "" {
		api, err = client.New(client.Options{
			BaseURL: cfg.APIURL, CAFile: cfg.CAFile, AllowInsecureLoopback: cfg.AllowInsecureLoopback, Timeout: 30 * time.Second,
		})
		if err != nil {
			log.Warn("API URL unusable; the page works without the API", "error", err.Error())
			api = nil
		}
	}
	requirements := preflight.EmbeddedRequirements()
	srv := localui.New(localui.Options{
		StateDir: cfg.StateDir, SpoolDir: cfg.SpoolDir, SpoolQuotaBytes: cfg.SpoolQuotaBytes,
		Client:    api,
		Collector: collector.NewReal(cfg.ExtraMounts, cfg.VastMachineIDFile),
		Preflight: func(ctx context.Context) preflight.Report {
			return preflight.Run(ctx, preflight.HostEnv(api, false), requirements)
		},
		HostOS:  hostOS(),
		Version: version.Version,
		Logger:  log,
	})

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Error("cannot listen", "listen", *listen, "error", err.Error())
		return exitConfig
	}
	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      3 * time.Minute, // preflight may take two
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go srv.Run(ctx)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()
	log.Info("happymining-ui started", "version", version.Version, "listen", ln.Addr().String(), "state_dir", cfg.StateDir)
	if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server stopped with an error", "error", err.Error())
		return 1
	}
	log.Info("happymining-ui stopped")
	return 0
}

// hostOS reads the OS description sent at enrollment (as happyminingctl does).
func hostOS() protocol.OSInfo {
	info := protocol.OSInfo{Arch: runtime.GOARCH, ID: "unknown"}
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		kv := preflight.ParseOSRelease(data)
		if kv["ID"] != "" {
			info.ID = protocol.Truncate(kv["ID"], 64)
		}
		info.VersionID = protocol.Truncate(kv["VERSION_ID"], 64)
	}
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		info.Kernel = protocol.Truncate(strings.TrimSpace(string(data)), protocol.MaxStringLen)
	}
	return info
}
