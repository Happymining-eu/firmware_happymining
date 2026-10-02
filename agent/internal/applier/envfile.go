package applier

import (
	"fmt"
	"regexp"
	"unicode/utf8"
)

// Env files for Docker Compose (--env-file).
//
// Docker Compose's env-file syntax (docs.docker.com, "Set, use, and manage
// variables in a Compose file with interpolation", .env syntax): lines are
// KEY=VALUE; an unquoted value is cut at " #" and interpolated; a single-quoted
// value is literal but cannot hold a single quote reliably, nor end with a
// backslash; a double-quoted value is interpolated and understands the escapes
// \n, \r, \t, \\ and \" (and \$ or $$ for a literal dollar sign).
//
// Every value here is written double-quoted, with exactly these
// substitutions: \ -> \\, " -> \", $ -> $$, newline -> \n, carriage return ->
// \r, tab -> \t. Every other character, including "=", "#", "'" and other
// control characters, is written as it is. A value with a NUL byte or
// invalid UTF-8 is refused (envValueProblem). TestEnvFileRoundTripsThroughDockerCompose
// proves the round trip with the real `docker compose config` where it is
// installed (that command reads files and starts nothing).

// reEnvName is what may be on the left of "=": the catalog's setting and
// secret variable rules and the helper's own variables.
var reEnvName = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

func utf8Valid(b []byte) bool { return utf8.Valid(b) }

// appendEnvValue appends the double-quoted form of value to dst.
func appendEnvValue(dst, value []byte) []byte {
	dst = append(dst, '"')
	for _, c := range value {
		switch c {
		case '\\':
			dst = append(dst, '\\', '\\')
		case '"':
			dst = append(dst, '\\', '"')
		case '$':
			dst = append(dst, '$', '$')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			// Bytes of multi-byte UTF-8 characters are never ASCII, so
			// copying byte by byte keeps them intact.
			dst = append(dst, c)
		}
	}
	return append(dst, '"')
}

// encodeEnvValue returns the double-quoted form of value.
func encodeEnvValue(value string) string { return string(appendEnvValue(nil, []byte(value))) }

// envFile accumulates the variables of one plugin's env file in a byte
// buffer that is wiped after it was written (it may hold secrets).
type envFile struct {
	names map[string]bool
	buf   []byte
}

func newEnvFile() *envFile {
	f := &envFile{names: map[string]bool{}, buf: make([]byte, 0, 4096)}
	f.buf = append(f.buf, "# Written by the HappyMining helper at every apply. Root only; do not edit.\n"...)
	return f
}

func (f *envFile) grow(n int) {
	if cap(f.buf)-len(f.buf) >= n {
		return
	}
	bigger := make([]byte, len(f.buf), 2*cap(f.buf)+n)
	copy(bigger, f.buf)
	wipeBytes(f.buf)
	f.buf = bigger
}

// add appends one variable whose value is not secret.
func (f *envFile) add(name, value string) error { return f.addBytes(name, []byte(value)) }

// addSecret appends a secret variable from its plaintext. The caller still
// owns plain and wipes it.
func (f *envFile) addSecret(name string, plain []byte) error { return f.addBytes(name, plain) }

// addBytes refuses a name that is not a variable name or is given twice, and
// a value that cannot be written; the error names the variable, never the
// value.
func (f *envFile) addBytes(name string, value []byte) error {
	if !reEnvName.MatchString(name) {
		return fmt.Errorf("variable %s: not a variable name", name)
	}
	if f.names[name] {
		return fmt.Errorf("variable %s: given twice", name)
	}
	if p := envValueProblem(value); p != "" {
		return fmt.Errorf("variable %s: the value %s", name, p)
	}
	f.names[name] = true
	f.grow(len(name) + 2*len(value) + 4)
	f.buf = append(f.buf, name...)
	f.buf = append(f.buf, '=')
	f.buf = appendEnvValue(f.buf, value)
	f.buf = append(f.buf, '\n')
	return nil
}

// wipe zeroes the buffer.
func (f *envFile) wipe() { wipeBytes(f.buf); f.buf = f.buf[:0] }

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
