package ctl

import (
	"fmt"
	"strings"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/fsx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/localui"
)

// uiPort is where happymining-ui listens unless its unit says otherwise.
const uiPort = "8080"

// ui handles `happyminingctl ui unlock|lock`: the console-side half of the
// local web page's only action. Unlock writes a hashed one-time code that
// the browser must type within a few minutes; lock removes it.
func (a *app) ui(args []string) int {
	if len(args) == 0 || (args[0] != "unlock" && args[0] != "lock") {
		fmt.Fprintln(a.env.Stderr, "usage: happyminingctl ui unlock [--minutes N]\n       happyminingctl ui lock")
		return ExitUsage
	}
	cfg, err := a.config()
	if err != nil {
		return a.fail("%v", err)
	}
	if args[0] == "lock" {
		fs := a.flagSet("ui lock")
		if c, ok := a.parse(fs, args[1:]); !ok {
			return c
		}
		if err := localui.DeleteUnlock(cfg.StateDir); err != nil {
			return a.fail("%v (run with sudo?)", err)
		}
		fmt.Fprintln(a.env.Stdout, "The web page is locked again (read-only).")
		return ExitOK
	}
	fs := a.flagSet("ui unlock")
	minutes := fs.Int("minutes", int(localui.DefaultUnlockTTL/time.Minute), "how long the code stays valid")
	if c, ok := a.parse(fs, args[1:]); !ok {
		return c
	}
	if *minutes < 1 || time.Duration(*minutes)*time.Minute > localui.MaxUnlockTTL {
		fmt.Fprintf(a.env.Stderr, "--minutes must be between 1 and %d\n", int(localui.MaxUnlockTTL/time.Minute))
		return ExitUsage
	}
	if err := ensureStateDir(cfg.StateDir); err != nil {
		return a.fail("%v", err)
	}
	owner, err := fsx.OwnerForNewFiles(cfg.StateDir)
	if err != nil {
		return a.fail("%v", err)
	}
	code, err := localui.NewUnlockCode()
	if err != nil {
		return a.fail("cannot draw a code: %v", err)
	}
	now := time.Now()
	expires := now.Add(time.Duration(*minutes) * time.Minute)
	if err := localui.WriteUnlock(cfg.StateDir, code, expires, owner); err != nil {
		return a.fail("%v (run with sudo?)", err)
	}
	w := a.env.Stdout
	fmt.Fprintf(w, "\n  Unlock code:  %s   (valid %d minute(s), one use, %d attempts)\n\n", code, *minutes, localui.MaxUnlockAttempts)
	fmt.Fprintln(w, "  Open the machine's page from a computer on the same network and type it:")
	addrs := localui.HostAddresses()
	if len(addrs) == 0 {
		fmt.Fprintf(w, "    http://<this machine's address>:%s/\n", uiPort)
	}
	for _, addr := range addrs {
		if strings.Contains(addr, ":") {
			fmt.Fprintf(w, "    http://[%s]:%s/\n", addr, uiPort)
		} else {
			fmt.Fprintf(w, "    http://%s:%s/\n", addr, uiPort)
		}
	}
	fmt.Fprintln(w, "\n  Until then the page is read-only. `happyminingctl ui lock` cancels the code.")
	return ExitOK
}
