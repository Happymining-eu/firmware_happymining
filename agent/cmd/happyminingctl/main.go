// Command happyminingctl is the local operator command of the HappyMining
// agent: identity, pairing, status, preflight. See `happyminingctl help`.
package main

import (
	"os"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/ctl"
)

func main() { os.Exit(ctl.Run(os.Args[1:], ctl.DefaultEnv())) }
