package ctl

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"unsafe"
)

// maxSecretLine bounds what is read as a pairing code.
const maxSecretLine = 256

func getTermios(fd int) (*syscall.Termios, bool) {
	var t syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&t)))
	return &t, errno == 0
}

func setTermios(fd int, t *syscall.Termios) {
	_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(t)))
}

// IsTerminal reports whether f is a terminal.
func IsTerminal(f *os.File) bool {
	_, ok := getTermios(int(f.Fd()))
	return ok
}

// readLine reads one bounded line.
func readLine(r io.Reader) (string, error) {
	line, err := bufio.NewReaderSize(io.LimitReader(r, maxSecretLine), maxSecretLine).ReadString('\n')
	if err != nil && (line == "" || !errors.Is(err, io.EOF)) {
		return "", errors.New("no input")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// ReadSecretFromTerminal prompts on the terminal and reads one line with echo
// switched off. If stdin is not a terminal it reads one line from stdin
// (for example from a pipe). The value is returned to the caller only: it is
// not logged and not stored.
func ReadSecretFromTerminal(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	old, isTTY := getTermios(fd)
	if !isTTY {
		return readLine(os.Stdin)
	}
	fmt.Fprint(os.Stderr, prompt)
	noEcho := *old
	noEcho.Lflag &^= syscall.ECHO
	noEcho.Lflag |= syscall.ICANON | syscall.ISIG
	setTermios(fd, &noEcho)
	// Restore the terminal even if the operator presses Ctrl-C.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		select {
		case <-sig:
			setTermios(fd, old)
			fmt.Fprintln(os.Stderr)
			os.Exit(130)
		case <-done:
		}
	}()
	line, err := readLine(os.Stdin)
	close(done)
	signal.Stop(sig)
	setTermios(fd, old)
	fmt.Fprintln(os.Stderr)
	return line, err
}
