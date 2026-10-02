// Command hm-simulator simulates machines without NVIDIA hardware against a
// HappyMining API URL. It pairs each machine with a pairing code and sends
// synthetic telemetry through the same client, spool and retry code as the
// real agent. Every sample carries "synthetic": true.
//
// A passing simulator run is not proof that real hardware works.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/logx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/redact"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/sim"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/version"
)

func main() { os.Exit(run()) }

func readCodes(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}

func run() int {
	fs := flag.NewFlagSet("hm-simulator", flag.ContinueOnError)
	var o sim.Options
	fs.StringVar(&o.APIURL, "api-url", "", "HappyMining API base URL (required)")
	fs.StringVar(&o.CAFile, "ca-file", "", "extra CA bundle for the API certificate")
	fs.BoolVar(&o.AllowInsecureLoopback, "allow-insecure-loopback", false, "allow plain HTTP to 127.0.0.1, ::1 or localhost")
	fs.IntVar(&o.Machines, "machines", 1, "number of simulated machines")
	codes := fs.String("codes", "", "comma-separated pairing codes, one per machine that is not paired yet")
	codesFile := fs.String("codes-file", "", "file with one pairing code per line")
	fs.StringVar(&o.StateDir, "state-dir", "", "directory for the simulated machines' state (required)")
	fs.StringVar(&o.GPUModel, "gpu-model", "rtx4090", "GPU model: "+strings.Join(sim.ModelNames(), ", "))
	fs.IntVar(&o.GPUs, "gpus", 2, "GPUs per machine")
	fs.DurationVar(&o.Interval, "interval", 5*time.Second, "time between samples")
	fs.IntVar(&o.Samples, "samples", 0, "samples per machine, then exit (0 = run until interrupted)")
	fs.Uint64Var(&o.Seed, "seed", 1, "random seed for reproducible telemetry")
	fs.IntVar(&o.OutageAfter, "outage-after", 0, "simulate an API outage after this many samples")
	fs.IntVar(&o.OutageFor, "outage-for", 0, "length of the simulated outage in samples (0 = no outage)")
	fs.IntVar(&o.DuplicateEvery, "duplicate-every", 0, "lose the response of every Nth heartbeat so that samples are resent (0 = never)")
	fs.DurationVar(&o.BackoffBase, "backoff-base", 0, "retry backoff base (default: the agent's 5s)")
	fs.DurationVar(&o.BackoffCap, "backoff-cap", 0, "retry backoff cap (default: the agent's 15m)")
	logLevel := fs.String("log-level", "info", "debug, info, warn or error")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Println("hm-simulator " + version.Version)
		return 0
	}
	if o.APIURL == "" || o.StateDir == "" {
		fmt.Fprintln(os.Stderr, "hm-simulator: --api-url and --state-dir are required")
		return 2
	}
	redactor := redact.New()
	for _, c := range strings.Split(*codes, ",") {
		if c = strings.TrimSpace(c); c != "" {
			o.PairingCodes = append(o.PairingCodes, c)
		}
	}
	if *codesFile != "" {
		fromFile, err := readCodes(*codesFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "hm-simulator: cannot read the codes file:", err)
			return 2
		}
		o.PairingCodes = append(o.PairingCodes, fromFile...)
	}
	for _, c := range o.PairingCodes {
		redactor.AddSecret(c)
	}
	level, err := logx.ParseLevel(*logLevel)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hm-simulator:", err)
		return 2
	}
	o.Logger = logx.New(os.Stderr, level, redactor)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	o.Logger.Info("simulator starting: all telemetry is synthetic", slog.Int("machines", o.Machines),
		slog.String("gpu_model", o.GPUModel), slog.Int("gpus", o.GPUs))
	summary, err := sim.Run(ctx, o)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(summary)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hm-simulator:", redactor.String(err.Error()))
		return 1
	}
	return 0
}
