// Command hm-helper is the narrowly scoped privileged helper of the
// HappyMining agent. It is installed root-owned at
// /usr/lib/happymining/hm-helper and knows exactly two actions:
//
//	hm-helper restart-vast-daemon
//	hm-helper reboot --delay-s N        (60 <= N <= 3600)
//
// plus `hm-helper serve`, used by the socket-activated systemd unit
// happymining-helper@.service: it reads one request from the connection on
// stdin, checks the peer's uid and performs the same two actions.
//
// Each action is refused unless enabled in the root-owned file
// /etc/happymining/helper.conf. The paths of that file and of the commands it
// runs are compiled in; nothing can be changed from the command line.
package main

import (
	"context"
	"fmt"
	"log/syslog"
	"net"
	"os"
	"os/user"
	"strconv"
	"time"

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

func main() { os.Exit(run(os.Args[1:])) }

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

func run(args []string) int {
	if len(args) == 1 && (args[0] == "version" || args[0] == "--version") {
		fmt.Println("hm-helper " + version.Version)
		return exitOK
	}
	audit := newAudit()
	if os.Geteuid() != 0 {
		audit(fmt.Sprintf("refused: invoked by uid %d without root privileges", os.Getuid()))
		fmt.Fprintln(os.Stderr, "hm-helper must run as root")
		return exitNoPerm
	}
	deps := helper.Deps{
		ConfPath:     config.DefaultHelperConfigPath,
		ConfOwnerUID: 0,
		Runner:       execx.OS{},
		Audit:        audit,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if len(args) == 1 && args[0] == "serve" {
		return serve(ctx, deps)
	}
	req, err := helper.ParseArgs(args)
	if err != nil {
		audit(fmt.Sprintf("refused invalid command line from uid %d", os.Getuid()))
		fmt.Fprintln(os.Stderr, err.Error())
		return exitUsage
	}
	audit(fmt.Sprintf("command line invocation by uid %d: action=%s", os.Getuid(), req.Action))
	resp := helper.Execute(ctx, req, deps)
	if !resp.OK {
		fmt.Fprintf(os.Stderr, "refused (%s): %s\n", resp.Code, resp.Detail)
		return exitRefused
	}
	fmt.Println(resp.Detail)
	return exitOK
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
	if u, err := user.Lookup(agentUser); err == nil {
		if uid, err := strconv.ParseUint(u.Uid, 10, 32); err == nil {
			allowed = append(allowed, uint32(uid))
		}
	}
	resp := helper.ServeConn(ctx, unixConn, peer, allowed, deps)
	if !resp.OK {
		return exitRefused
	}
	return exitOK
}
