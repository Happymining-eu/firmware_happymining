package applier

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/execx"
)

// hostileValues are the values an env file must carry verbatim.
var hostileValues = []string{
	"simple", "a b", " lead", "trail ", "x=y=z", "=", "it's", `say "hi"`, `back\slash`, `end\`, `\`,
	"$HOME", "${HOME}", "$$", "a$", "$(id)", "`id`", "${X:-def}", "#notcomment", "a #b", "multi\nline",
	"cr\rx", "tab\tx", `\n literal`, "ünïcødé ✓", `q'"\$` + "`", `\$x`, `\"`, "'", "''", "\x01ctl\x1b[0m\x7f",
	`\x41\u0041\0101`, "KEY=VALUE\nOTHER=1", "line\n# comment\n",
}

func TestEncodeEnvValue(t *testing.T) {
	cases := map[string]string{
		"plain":    `"plain"`,
		`a"b`:      `"a\"b"`,
		`a\b`:      `"a\\b"`,
		"a$b":      `"a$$b"`,
		"a\nb\r\t": `"a\nb\r\t"`,
		"x=y #z'":  `"x=y #z'"`,
	}
	for in, want := range cases {
		if got := encodeEnvValue(in); got != want {
			t.Errorf("%q: got %s, want %s", in, got, want)
		}
	}
	for _, v := range hostileValues {
		enc := encodeEnvValue(v)
		if strings.ContainsAny(enc, "\n\r") {
			t.Errorf("%q: the encoded value spans lines: %q", v, enc)
		}
		if got, ok := decodeDoubleQuoted(enc); !ok || got != v {
			t.Errorf("%q: decodes to %q (%v)", v, got, ok)
		}
	}
}

// decodeDoubleQuoted reads a double-quoted env-file value the way Compose
// does for the escapes the encoder writes; it fails on an unescaped quote
// before the end, an unknown escape or a lone "$".
func decodeDoubleQuoted(s string) (string, bool) {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return "", false
	}
	in := s[1 : len(s)-1]
	var b strings.Builder
	for i := 0; i < len(in); i++ {
		switch c := in[i]; c {
		case '"':
			return "", false
		case '\\':
			if i+1 >= len(in) {
				return "", false
			}
			i++
			switch in[i] {
			case '\\', '"':
				b.WriteByte(in[i])
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			default:
				return "", false
			}
		case '$':
			if i+1 >= len(in) || in[i+1] != '$' {
				return "", false
			}
			i++
			b.WriteByte('$')
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), true
}

func TestEnvFileRefusals(t *testing.T) {
	f := newEnvFile()
	if err := f.add("HM_BIND", "0.0.0.0"); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"HM_BIND": "again", "lower": "x", "1X": "x", "A-B": "x", "": "x", "A B": "x"} {
		if err := f.add(name, value); err == nil {
			t.Errorf("%q must be refused", name)
		}
	}
	for _, bad := range [][]byte{[]byte("nul\x00inside"), {0xff, 0xfe}, []byte("half\xe2\x82")} {
		err := f.addSecret("SECRET_X", bad)
		if err == nil {
			t.Errorf("%q must be refused", bad)
			continue
		}
		if strings.Contains(err.Error(), string(bad)) {
			t.Errorf("the error must not quote the value: %v", err)
		}
	}
	f.wipe()
	if len(f.buf) != 0 {
		t.Fatal("wipe")
	}
}

func TestEnvFileBufferIsWiped(t *testing.T) {
	f := newEnvFile()
	secret := []byte(strings.Repeat("s3cr3t!", 2000)) // forces the buffer to grow
	if err := f.addSecret("BIG_SECRET", secret); err != nil {
		t.Fatal(err)
	}
	backing := f.buf[:cap(f.buf)]
	f.wipe()
	if bytes.Contains(backing, []byte("s3cr3t!")) {
		t.Fatal("the buffer still holds the secret after wipe")
	}
}

// TestEnvFileRoundTripsThroughDockerCompose proves the env-file encoding with
// the real Docker Compose parser where it is installed: `docker compose
// config` reads the files and prints the resolved project; it starts nothing
// and does not need a Docker daemon. Compose prints a literal "$" as "$$" in
// its output, so the comparison undoes that.
func TestEnvFileRoundTripsThroughDockerCompose(t *testing.T) {
	if _, err := os.Stat(DockerPath); err != nil {
		t.Skip("docker is not installed here")
	}
	probe, err := execx.OS{}.Run(context.Background(), 20*time.Second, DockerPath, "compose", "version")
	if err != nil || probe.ExitCode != 0 {
		t.Skip("docker compose is not installed here")
	}
	dir := t.TempDir()
	compose := filepath.Join(dir, "compose.yaml")
	var b strings.Builder
	b.WriteString("services:\n  s:\n    image: example.invalid/x:1\n    environment:\n")
	f := newEnvFile()
	for i := range hostileValues {
		name := "PASS_" + string(rune('A'+i/26)) + string(rune('A'+i%26))
		b.WriteString("      - " + name + "\n")
		b.WriteString("      - INTERP_" + name[5:] + "=${" + name + "}\n")
		if err := f.add(name, hostileValues[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(compose, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(dir, "x.env")
	if err := os.WriteFile(envPath, f.buf, 0o600); err != nil {
		t.Fatal(err)
	}
	// A minimal environment, as execx.OS gives the helper's commands.
	cmd := exec.Command(DockerPath, "compose", "-p", "hm-roundtrip", "--env-file", envPath, "-f", compose, "config", "--format", "json")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C"}
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("docker compose config: %v", err)
	}
	var project struct {
		Services map[string]struct {
			Environment map[string]*string `json:"environment"`
		} `json:"services"`
	}
	if err := json.Unmarshal(out, &project); err != nil {
		t.Fatal(err)
	}
	env := project.Services["s"].Environment
	for i, want := range hostileValues {
		name := "PASS_" + string(rune('A'+i/26)) + string(rune('A'+i%26))
		for _, key := range []string{name, "INTERP_" + name[5:]} {
			got := env[key]
			if got == nil || strings.ReplaceAll(*got, "$$", "$") != want {
				t.Errorf("%s: got %q, want %q", key, deref(got), want)
			}
		}
	}
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}
