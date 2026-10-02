// Command hm-fakeapi runs the in-memory fake of the HappyMining device API on
// a loopback port, for local end-to-end runs of hm-simulator. It is test
// support only: it is not built by scripts/build.sh and not packaged.
//
// It prints the pairing codes it created (one per line) to stdout, then
// serves until interrupted. GET /_test/summary shows what it received.
package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/testapi"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:0", "loopback address to listen on")
	codes := flag.Int("codes", 1, "number of pairing codes to create")
	addrFile := flag.String("addr-file", "", "write the listening address to this file")
	flag.Parse()

	server := testapi.New()
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hm-fakeapi:", err)
		os.Exit(1)
	}
	if tcp, ok := ln.Addr().(*net.TCPAddr); !ok || !tcp.IP.IsLoopback() {
		fmt.Fprintln(os.Stderr, "hm-fakeapi: refusing to listen on a non-loopback address")
		os.Exit(1)
	}
	for i := 0; i < *codes; i++ {
		fmt.Println(server.NewPairingCode())
	}
	if *addrFile != "" {
		if err := os.WriteFile(*addrFile, []byte(ln.Addr().String()+"\n"), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "hm-fakeapi:", err)
			os.Exit(1)
		}
	}
	fmt.Fprintln(os.Stderr, "hm-fakeapi: listening on http://"+ln.Addr().String())
	srv := &http.Server{Handler: server.Handler(), ReadHeaderTimeout: 5 * time.Second}
	if err := srv.Serve(ln); err != nil {
		fmt.Fprintln(os.Stderr, "hm-fakeapi:", err)
		os.Exit(1)
	}
}
