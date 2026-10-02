package redact

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const (
	token   = "hmd_0123456789abcdef0123456789abcdef.Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmF"
	secret  = "Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmF"
	pairing = "HM-7K2M9Q-4F8T-ZP3D-W6NH-R5XA"
)

func TestStringRedactsTokensBearerAndPairingCodes(t *testing.T) {
	r := New()
	inputs := []string{
		"Authorization: Bearer " + token,
		"authorization: bearer abc.def.ghi",
		"token=" + token + " trailing",
		"truncated hmd_0123456789abcdef",
		"code " + pairing + " entered",
		"code hm-7k2m9q-4f8t-zp3d-w6nh-r5xa entered",
		"code HM7K2M9Q4F8TZP3DW6NHR5XA entered",
		"code HM 7K2M9Q 4F8T ZP3D W6NH R5XA entered",
		`{"err":"Post \"https://x/api\": header Bearer ` + token + `"}`,
	}
	for _, in := range inputs {
		out := r.String(in)
		for _, leak := range []string{token, secret, "0123456789abcdef", "7K2M9Q", "7k2m9q", "R5XA", "abc.def.ghi"} {
			if strings.Contains(out, leak) {
				t.Errorf("leak of %q in %q (from %q)", leak, out, in)
			}
		}
	}
}

func TestRegisteredSecrets(t *testing.T) {
	r := New()
	r.AddSecret(token)
	// The secret part alone (without the hmd_ prefix) must be caught too.
	out := r.String("x " + secret + " y")
	if strings.Contains(out, secret) {
		t.Fatalf("secret part leaked: %q", out)
	}
	r.AddSecret("short") // ignored: would destroy ordinary text
	if got := r.String("a short text"); got != "a short text" {
		t.Fatalf("short secrets must be ignored: %q", got)
	}
}

func TestOrdinaryTextIsUntouched(t *testing.T) {
	r := New()
	for _, in := range []string{
		"heartbeat acknowledged", "device_id 2f1c6f0e-8f8a-4a57-9a3e-0d6e2f1f6c11",
		"sha256:0f3d2c1b0a99887766554433221100ffeeddccbbaa99887766554433221100ff",
		"NVIDIA GeForce RTX 4090", "HM OS", "thermal 41C",
	} {
		if got := r.String(in); got != in {
			t.Errorf("changed %q to %q", in, got)
		}
	}
}

func TestJSONRedactsStringsAndSensitiveKeys(t *testing.T) {
	r := New()
	in := map[string]any{
		"note":          "saw Bearer " + token,
		"token":         "anything",
		"api_key":       "k",
		"password":      12345,
		"nested":        map[string]any{"pairing_code": pairing, "ok": true, "list": []any{token, "fine"}},
		"credential_id": "2f1c6f0e-8f8a-4a57-9a3e-0d6e2f1f6c11",
		"count":         3,
	}
	raw, err := r.JSON(in)
	if err != nil {
		t.Fatal(err)
	}
	out := string(raw)
	for _, leak := range []string{token, secret, pairing, "anything", "12345", `"k"`} {
		if strings.Contains(out, leak) {
			t.Errorf("leak of %q in %s", leak, out)
		}
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["count"].(float64) != 3 || decoded["credential_id"] != "2f1c6f0e-8f8a-4a57-9a3e-0d6e2f1f6c11" {
		t.Fatalf("non-secret values must survive: %s", out)
	}
	if decoded["nested"].(map[string]any)["ok"] != true {
		t.Fatalf("non-secret values must survive: %s", out)
	}
}

func TestWriter(t *testing.T) {
	r := New()
	var buf bytes.Buffer
	w := r.Writer(&buf)
	line := []byte(`{"msg":"request failed","header":"Bearer ` + token + `","code":"` + pairing + `"}` + "\n")
	n, err := w.Write(line)
	if err != nil || n != len(line) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if strings.Contains(buf.String(), secret) || strings.Contains(buf.String(), "7K2M9Q") {
		t.Fatalf("leak: %s", buf.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("the redacted line must stay valid JSON: %v: %s", err, buf.String())
	}
}
