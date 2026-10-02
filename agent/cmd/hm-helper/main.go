// Command hm-helper is the narrowly scoped privileged helper of the
// HappyMining agent. It is installed root-owned at
// /usr/lib/happymining/hm-helper and refuses to run without root privileges.
//
// Socket (happymining-helper@.service, one process per connection):
//
//	hm-helper serve
//
// reads one request from the connection on stdin, checks the peer's uid and
// performs one of the socket actions of package helper (restart the Vast
// daemon, delayed reboot, and the quick appliance actions).
//
// Command line, as root:
//
//	hm-helper restart-vast-daemon
//	hm-helper reboot --delay-s N            (60 <= N <= 3600)
//
//	hm-helper apply-stored                  happymining-appliance-apply.service
//	hm-helper run-job <instance>            happymining-appliance-job@<instance>.service
//	hm-helper install-staged                happymining-update-install.service
//	hm-helper update-guard                  happymining-update-guard.service
//
//	hm-helper appliance-status              print the appliance state (JSON)
//	hm-helper secret-set <name>             secret on stdin, sealed for this machine
//	hm-helper backup-init                   create the backup key, print the recovery key once
//	hm-helper backup-restore --from <file> [--to <dir>]   recovery key on stdin
//	hm-helper appliance-purge <plugin id>   delete a removed plugin's data (asks to confirm)
//	hm-helper vectorizer-token              create (if missing) and print the vectorizer token
//
// Each action is refused unless enabled in the root-owned file
// /etc/happymining/helper.conf where the contract gives it a switch. The
// paths of that file, of the state and of the commands it runs are compiled
// in; nothing can be changed from the command line.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/syslog"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/applier"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/config"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/execx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/helper"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/version"
)

// agentUser is the unprivileged account allowed to use the socket.
const agentUser = "happymining"

// Exit codes (sysexits.h where one fits).
const (
	exitOK      = 0
	exitRefused = 1
	exitUsage   = 64
	exitNoPerm  = 77
)

// cliEnv is what run needs from the process; tests inject it.
type cliEnv struct {
	Euid   int
	Uid    int
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Audit  func(string)
	// Deps builds the helper's dependencies (only called for an allowed
	// caller).
	Deps func(audit func(string)) helper.Deps
	// Serve handles `serve` (the socket on stdin).
	Serve func(ctx context.Context, deps helper.Deps) int
}

func main() { os.Exit(run(os.Args[1:], processEnv())) }

func processEnv() cliEnv {
	return cliEnv{
		Euid: os.Geteuid(), Uid: os.Getuid(), Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
		Audit: newAudit(),
		Deps: func(audit func(string)) helper.Deps {
			return helper.Deps{
				ConfPath:     config.DefaultHelperConfigPath,
				ConfOwnerUID: 0,
				Runner:       execx.OS{},
				Audit:        audit,
				Paths:        applier.DefaultPaths(),
				AgentUID:     agentUID(),
				Version:      version.Version,
			}
		},
		Serve: serve,
	}
}

// agentUID is the uid of the agent's account, or an impossible uid when the
// account does not exist (so that nothing is taken as the agent's).
func agentUID() uint32 {
	if u, err := user.Lookup(agentUser); err == nil {
		if uid, err := strconv.ParseUint(u.Uid, 10, 32); err == nil {
			return uint32(uid)
		}
	}
	return ^uint32(0)
}

// newAudit returns the audit sink: stderr when it is connected to the journal
// (systemd sets JOURNAL_STREAM), otherwise syslog, otherwise stderr.
func newAudit() func(string) {
	stderr := func(line string) { fmt.Fprintln(os.Stderr, "hm-helper: "+line) }
	if os.Getenv("JOURNAL_STREAM") != "" {
		return stderr
	}
	w, err := syslog.New(syslog.LOG_AUTHPRIV|syslog.LOG_NOTICE, "hm-helper")
	if err != nil {
		return stderr
	}
	return func(line string) {
		if err := w.Notice(line); err != nil {
			stderr(line)
		}
	}
}

// Time limits of the command-line actions (the units add their own).
var actionTimeouts = map[string]time.Duration{
	"serve":            3 * time.Minute,
	"apply-stored":     3 * time.Hour,
	"run-job":          13 * time.Hour,
	"install-staged":   time.Hour,
	"update-guard":     time.Hour,
	"appliance-status": 2 * time.Minute,
	"secret-set":       2 * time.Minute,
	"backup-init":      2 * time.Minute,
	"backup-restore":   48 * time.Hour,
	"appliance-purge":  30 * time.Minute,
	"vectorizer-token": 2 * time.Minute,
}

const usage = `usage: hm-helper restart-vast-daemon | reboot --delay-s N | serve
       hm-helper apply-stored | run-job <instance> | install-staged | update-guard
       hm-helper appliance-status | secret-set <name> | backup-init
       hm-helper backup-restore --from <file> [--to <dir>] | appliance-purge <plugin id> | vectorizer-token`

func run(args []string, env cliEnv) int {
	if len(args) == 1 && (args[0] == "version" || args[0] == "--version") {
		fmt.Fprintln(env.Stdout, "hm-helper "+version.Version)
		return exitOK
	}
	audit := env.Audit
	if audit == nil {
		audit = func(string) {}
	}
	if env.Euid != 0 {
		audit(fmt.Sprintf("refused: invoked by uid %d without root privileges", env.Uid))
		fmt.Fprintln(env.Stderr, "hm-helper must run as root")
		return exitNoPerm
	}
	deps := env.Deps(audit)
	name := ""
	if len(args) > 0 {
		name = args[0]
	}
	timeout, known := actionTimeouts[name]
	if !known {
		timeout = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	if len(args) == 1 && args[0] == "serve" {
		return env.Serve(ctx, deps)
	}
	if name == helper.ActionRestartVastDaemon || name == helper.ActionReboot {
		req, err := helper.ParseArgs(args)
		if err != nil {
			audit(fmt.Sprintf("refused invalid command line from uid %d", env.Uid))
			fmt.Fprintln(env.Stderr, err.Error())
			return exitUsage
		}
		audit(fmt.Sprintf("command line invocation by uid %d: action=%s", env.Uid, req.Action))
		resp := helper.Execute(ctx, req, deps)
		if !resp.OK {
			fmt.Fprintf(env.Stderr, "refused (%s): %s\n", resp.Code, resp.Detail)
			return exitRefused
		}
		fmt.Fprintln(env.Stdout, resp.Detail)
		return exitOK
	}
	if !known || !validShape(args) {
		audit(fmt.Sprintf("refused invalid command line from uid %d", env.Uid))
		fmt.Fprintln(env.Stderr, usage)
		return exitUsage
	}
	if err := deps.Paths.Check(); err != nil {
		fmt.Fprintln(env.Stderr, "hm-helper: "+err.Error())
		return exitRefused
	}
	conf, confErr := helper.LoadConf(deps.ConfPath, deps.ConfOwnerUID)
	if confErr != nil {
		// Every switch off; the heavy actions refuse below.
		audit(fmt.Sprintf("switch file unusable, every switch is off: %v", confErr))
		conf = config.Helper{}
	}
	engine := deps.Engine(conf)
	audit(fmt.Sprintf("command line invocation by uid %d: action=%s", env.Uid, name))
	err := dispatch(ctx, args, engine, env, confErr)
	if err != nil {
		audit(fmt.Sprintf("action=%s failed: %v", name, err))
		fmt.Fprintln(env.Stderr, "hm-helper: "+err.Error())
		return exitRefused
	}
	return exitOK
}

// validShape accepts exactly the documented argument shapes.
func validShape(args []string) bool {
	switch args[0] {
	case "apply-stored", "install-staged", "update-guard", "appliance-status", "backup-init", "vectorizer-token":
		return len(args) == 1
	case "run-job":
		if len(args) != 2 {
			return false
		}
		_, _, err := applier.ParseJobInstance(args[1])
		return err == nil
	case "secret-set", "appliance-purge":
		return len(args) == 2 && args[1] != "" && args[1][0] != '-'
	case "backup-restore":
		return (len(args) == 3 && args[1] == "--from") || (len(args) == 5 && args[1] == "--from" && args[3] == "--to")
	}
	return false
}

func dispatch(ctx context.Context, args []string, e *applier.Env, env cliEnv, confErr error) error {
	heavy := func() error {
		if confErr != nil {
			return fmt.Errorf("the switch file is unusable, so this action is disabled")
		}
		return nil
	}
	switch args[0] {
	case "apply-stored":
		if err := heavy(); err != nil {
			return err
		}
		return applier.ApplyStored(ctx, e)
	case "run-job":
		if err := heavy(); err != nil {
			return err
		}
		return applier.RunJob(ctx, e, args[1])
	case "install-staged":
		if err := heavy(); err != nil {
			return err
		}
		return applier.InstallStaged(ctx, e)
	case "update-guard":
		if err := heavy(); err != nil {
			return err
		}
		return applier.UpdateGuard(ctx, e)
	case "appliance-status":
		res, err := applier.Status(ctx, e)
		if err != nil {
			return err
		}
		out, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(env.Stdout, string(out))
		return nil
	case "secret-set":
		return applier.SecretSet(ctx, e, args[1], env.Stdin)
	case "backup-init":
		return applier.BackupInit(e, env.Stdout)
	case "backup-restore":
		to := ""
		if len(args) == 5 {
			to = args[4]
		}
		return applier.BackupRestore(ctx, e, args[2], to, env.Stdin, env.Stderr, env.Stdout)
	case "appliance-purge":
		return applier.Purge(ctx, e, args[1], env.Stdin, env.Stderr)
	case "vectorizer-token":
		return applier.VectorizerToken(e, env.Stdout)
	}
	return fmt.Errorf("unknown action")
}

// serve handles the single connection systemd passed on stdin.
func serve(ctx context.Context, deps helper.Deps) int {
	conn, err := net.FileConn(os.Stdin)
	if err != nil {
		deps.Audit("serve: stdin is not a socket")
		return exitUsage
	}
	defer conn.Close()
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		deps.Audit("serve: stdin is not a unix socket")
		return exitUsage
	}
	peer, err := helper.PeerUID(unixConn)
	if err != nil {
		deps.Audit("serve: cannot read peer credentials")
		return exitNoPerm
	}
	allowed := []uint32{0}
	if uid := deps.AgentUID; uid != ^uint32(0) {
		allowed = append(allowed, uid)
	}
	resp := helper.ServeConn(ctx, unixConn, peer, allowed, deps)
	if !resp.OK {
		return exitRefused
	}
	return exitOK
}
