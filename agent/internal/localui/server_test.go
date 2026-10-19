package localui

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/client"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/credential"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/preflight"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/testapi"
)

type fakeCollector struct{ sample protocol.Sample }

func (f fakeCollector) Collect(context.Context) (protocol.Sample, []string) { return f.sample, nil }

type fixture struct {
	t        *testing.T
	api      *testapi.Server
	apiSrv   *httptest.Server
	stateDir string
	srv      *Server
	web      *httptest.Server
	now      time.Time
	jar      []*http.Cookie
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, api: testapi.New(), stateDir: filepath.Join(t.TempDir(), "state"), now: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)}
	if err := os.MkdirAll(f.stateDir, 0o750); err != nil {
		t.Fatal(err)
	}
	f.apiSrv = httptest.NewServer(f.api.Handler())
	t.Cleanup(f.apiSrv.Close)
	api, err := client.New(client.Options{BaseURL: f.apiSrv.URL, AllowInsecureLoopback: true, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	util := int64(42)
	f.srv = New(Options{
		StateDir: f.stateDir, SpoolDir: filepath.Join(f.stateDir, "spool"), SpoolQuotaBytes: 1024,
		Client:    api,
		Collector: fakeCollector{sample: protocol.Sample{GPUs: []protocol.GPU{{Index: 0, Name: "Fake GPU", UtilPct: &util}}, Services: map[string]string{"docker": "active"}}},
		Preflight: func(context.Context) preflight.Report {
			return preflight.Report{Overall: preflight.Pass, Checks: []preflight.Check{{ID: "x", Title: "x", Status: preflight.Pass}}}
		},
		HostOS:    protocol.OSInfo{ID: "ubuntu", VersionID: "24.04", Kernel: "6.8.0", Arch: "amd64"},
		Hostname:  func() string { return "gpu-01" },
		Addresses: func() []string { return []string{"192.168.1.42"} },
		Version:   "test",
		Now:       func() time.Time { return f.now },
	})
	f.web = httptest.NewServer(f.srv.Handler())
	t.Cleanup(f.web.Close)
	return f
}

func (f *fixture) do(method, path string, body any, host string) (*http.Response, map[string]any) {
	f.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req, err := http.NewRequest(method, f.web.URL+path, &buf)
	if err != nil {
		f.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if host != "" {
		req.Host = host
	}
	for _, c := range f.jar {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	f.jar = append(f.jar, resp.Cookies()...)
	var out map[string]any
	data, _ := readAll(resp)
	_ = json.Unmarshal(data, &out)
	return resp, out
}

func readAll(resp *http.Response) ([]byte, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(resp.Body)
	return buf.Bytes(), err
}

func (f *fixture) status() map[string]any {
	resp, out := f.do(http.MethodGet, "/api/status", nil, "")
	if resp.StatusCode != http.StatusOK {
		f.t.Fatalf("status: HTTP %d", resp.StatusCode)
	}
	return out
}

func TestPageAndStatusAreReadOnlyWithoutUnlock(t *testing.T) {
	f := newFixture(t)
	resp, _ := f.do(http.MethodGet, "/", nil, "")
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("index: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "script-src 'self'") || resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("security headers: csp=%q cache=%q", csp, resp.Header.Get("Cache-Control"))
	}
	for _, p := range []string{"/app.js", "/app.css"} {
		if r, _ := f.do(http.MethodGet, p, nil, ""); r.StatusCode != http.StatusOK {
			t.Errorf("%s: HTTP %d", p, r.StatusCode)
		}
	}
	f.srv.refreshSample(context.Background())
	st := f.status()
	if st["paired"] != false || st["unlocked"] != false || st["unlock_available"] != false || st["hostname"] != "gpu-01" {
		t.Errorf("status: %v", st)
	}
	if sample, ok := st["sample"].(map[string]any); !ok || len(sample["gpus"].([]any)) != 1 {
		t.Errorf("sample missing: %v", st["sample"])
	}
	// Pairing without a session is refused, whatever the code.
	resp, out := f.do(http.MethodPost, "/api/pair", map[string]string{"code": f.api.NewPairingCode()}, "")
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(out["error"].(string), "unlock") {
		t.Errorf("pair without session: %d %v", resp.StatusCode, out)
	}
	if _, err := os.Stat(credential.Path(f.stateDir)); err == nil {
		t.Error("a credential was written without a session")
	}
}

func TestUnlockThenPair(t *testing.T) {
	f := newFixture(t)
	if resp, out := f.do(http.MethodPost, "/api/unlock", map[string]string{"code": "123456"}, ""); resp.StatusCode != http.StatusLocked || !strings.Contains(out["error"].(string), "ui unlock") {
		t.Fatalf("unlock without a file: %d %v", resp.StatusCode, out)
	}
	if err := WriteUnlock(f.stateDir, "246810", f.now.Add(DefaultUnlockTTL), nil); err != nil {
		t.Fatal(err)
	}
	if st := f.status(); st["unlock_available"] != true {
		t.Fatalf("unlock_available: %v", st)
	}
	if resp, out := f.do(http.MethodPost, "/api/unlock", map[string]string{"code": "000000"}, ""); resp.StatusCode != http.StatusForbidden || !strings.Contains(out["error"].(string), "4 attempt") {
		t.Fatalf("wrong code: %d %v", resp.StatusCode, out)
	}
	resp, out := f.do(http.MethodPost, "/api/unlock", map[string]string{"code": " 246810 "}, "")
	if resp.StatusCode != http.StatusOK || out["unlocked"] != true {
		t.Fatalf("unlock: %d %v", resp.StatusCode, out)
	}
	if len(f.jar) != 1 || f.jar[0].Name != sessionCookie || !f.jar[0].HttpOnly || f.jar[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie: %+v", f.jar)
	}
	if _, err := os.Stat(UnlockPath(f.stateDir)); !os.IsNotExist(err) {
		t.Error("the unlock file must be deleted after one use")
	}
	if st := f.status(); st["unlocked"] != true {
		t.Errorf("status after unlock: %v", st)
	}

	code := f.api.NewPairingCode()
	resp, out = f.do(http.MethodPost, "/api/pair", map[string]string{"code": strings.ToLower(code)}, "")
	if resp.StatusCode != http.StatusOK || out["device_id"] == "" {
		t.Fatalf("pair: %d %v", resp.StatusCode, out)
	}
	cred, err := credential.Load(credential.Path(f.stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if cred.DeviceID != out["device_id"] {
		t.Errorf("device id %q != %q", cred.DeviceID, out["device_id"])
	}
	st := f.status()
	if st["paired"] != true || st["device_id"] != cred.DeviceID {
		t.Errorf("status after pair: %v", st)
	}
	raw, _ := json.Marshal(st)
	if strings.Contains(string(raw), cred.Token) || strings.Contains(string(raw), code[len("HM-XXXXXX-"):]) {
		t.Error("status leaks the credential token or the pairing code")
	}
	if resp, out := f.do(http.MethodPost, "/api/pair", map[string]string{"code": f.api.NewPairingCode()}, ""); resp.StatusCode != http.StatusConflict {
		t.Errorf("pair twice: %d %v", resp.StatusCode, out)
	}
	if resp, _ := f.do(http.MethodPost, "/api/lock", map[string]string{}, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("lock: %d", resp.StatusCode)
	}
}

func TestRepeatedWrongCodesBurnTheUnlock(t *testing.T) {
	f := newFixture(t)
	if err := WriteUnlock(f.stateDir, "111111", f.now.Add(DefaultUnlockTTL), nil); err != nil {
		t.Fatal(err)
	}
	var last map[string]any
	var status int
	for i := 0; i < MaxUnlockAttempts; i++ {
		resp, out := f.do(http.MethodPost, "/api/unlock", map[string]string{"code": "999999"}, "")
		status, last = resp.StatusCode, out
	}
	if status != http.StatusLocked || !strings.Contains(last["error"].(string), "too many") {
		t.Fatalf("after %d wrong codes: %d %v", MaxUnlockAttempts, status, last)
	}
	if _, err := os.Stat(UnlockPath(f.stateDir)); !os.IsNotExist(err) {
		t.Error("the unlock file must be deleted after too many attempts")
	}
	// The right code is useless now.
	if resp, _ := f.do(http.MethodPost, "/api/unlock", map[string]string{"code": "111111"}, ""); resp.StatusCode != http.StatusLocked {
		t.Errorf("burned code accepted: %d", resp.StatusCode)
	}
}

func TestExpiredUnlockAndSession(t *testing.T) {
	f := newFixture(t)
	if err := WriteUnlock(f.stateDir, "222222", f.now.Add(time.Minute), nil); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(2 * time.Minute)
	if resp, _ := f.do(http.MethodPost, "/api/unlock", map[string]string{"code": "222222"}, ""); resp.StatusCode != http.StatusLocked {
		t.Fatalf("expired unlock file accepted: %d", resp.StatusCode)
	}
	if err := WriteUnlock(f.stateDir, "333333", f.now.Add(time.Minute), nil); err != nil {
		t.Fatal(err)
	}
	if resp, _ := f.do(http.MethodPost, "/api/unlock", map[string]string{"code": "333333"}, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("unlock: %d", resp.StatusCode)
	}
	f.now = f.now.Add(SessionTTL + time.Second)
	if resp, _ := f.do(http.MethodPost, "/api/pair", map[string]string{"code": f.api.NewPairingCode()}, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expired session accepted: %d", resp.StatusCode)
	}
}

func TestHostHeaderAndCrossSiteGuards(t *testing.T) {
	f := newFixture(t)
	for host, want := range map[string]int{
		"192.168.1.42:8080": http.StatusOK, "[fe80::1]:8080": http.StatusOK, "localhost:8080": http.StatusOK,
		"gpu-01:8080": http.StatusOK, "GPU-01.local": http.StatusOK, "gpu-01.lan:8080": http.StatusOK,
		"evil.example.com": http.StatusMisdirectedRequest, "gpu-02:8080": http.StatusMisdirectedRequest,
	} {
		if resp, _ := f.do(http.MethodGet, "/api/status", nil, host); resp.StatusCode != want {
			t.Errorf("Host %q: HTTP %d, want %d", host, resp.StatusCode, want)
		}
	}
	req, _ := http.NewRequest(http.MethodPost, f.web.URL+"/api/unlock", strings.NewReader(`{"code":"1"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://evil.example.com")
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site POST: %v %d", err, resp.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodPost, f.web.URL+"/api/unlock", strings.NewReader("code=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("form POST: %v %d", err, resp.StatusCode)
	}
}

func TestPreflightIsCached(t *testing.T) {
	f := newFixture(t)
	calls := 0
	f.srv.opt.Preflight = func(context.Context) preflight.Report { calls++; return preflight.Report{Overall: preflight.Warn} }
	for i := 0; i < 3; i++ {
		if resp, out := f.do(http.MethodGet, "/api/preflight", nil, ""); resp.StatusCode != http.StatusOK || out["overall"] != preflight.Warn {
			t.Fatalf("preflight: %d %v", resp.StatusCode, out)
		}
	}
	f.now = f.now.Add(PreflightCache + time.Second)
	f.do(http.MethodGet, "/api/preflight", nil, "")
	if calls != 2 {
		t.Errorf("preflight ran %d times, want 2 (cached for %s)", calls, PreflightCache)
	}
}

func TestUnlockFileFormat(t *testing.T) {
	code, err := NewUnlockCode()
	if err != nil || len(code) != UnlockCodeDigits || strings.Trim(code, "0123456789") != "" {
		t.Fatalf("code %q %v", code, err)
	}
	dir := t.TempDir()
	exp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := WriteUnlock(dir, code, exp, nil); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(UnlockPath(dir))
	if strings.Contains(string(data), code) {
		t.Error("the unlock file stores the code in clear")
	}
	info, _ := os.Stat(UnlockPath(dir))
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode %o", info.Mode().Perm())
	}
	uf, err := ReadUnlock(dir, exp.Add(-time.Second))
	if err != nil || !uf.Matches(code) || uf.Matches("000000") {
		t.Errorf("read: %v %v", uf, err)
	}
	if _, err := ReadUnlock(dir, exp); err != ErrNoUnlock {
		t.Errorf("expired: %v", err)
	}
	if _, err := os.Stat(UnlockPath(dir)); !os.IsNotExist(err) {
		t.Error("expired file not removed")
	}
}
