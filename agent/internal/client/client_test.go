package client

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
)

const token = "hmd_0123456789abcdef0123456789abcdef.Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmF"

func newClient(t *testing.T, url string) *Client {
	t.Helper()
	c, err := New(Options{BaseURL: url, AllowInsecureLoopback: true, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func heartbeat() *protocol.HeartbeatRequest {
	return &protocol.HeartbeatRequest{SentAt: "2026-10-02T07:45:00Z", BootID: "b", AgentVersion: "0.1.0",
		Samples: []json.RawMessage{json.RawMessage(`{"seq":1}`)}}
}

func TestURLPolicy(t *testing.T) {
	good := []struct {
		url   string
		allow bool
	}{
		{"https://api.happymining.fr", false},
		{"https://api.happymining.fr/base/", false},
		{"http://127.0.0.1:8080", true},
		{"http://localhost:8080", true},
		{"http://[::1]:8080", true},
	}
	for _, c := range good {
		if _, err := ValidateBaseURL(c.url, c.allow); err != nil {
			t.Errorf("%s (allow=%v) must be accepted: %v", c.url, c.allow, err)
		}
	}
	bad := []struct {
		url   string
		allow bool
	}{
		{"", false},
		{"http://127.0.0.1:8080", false},              // plain HTTP not enabled
		{"http://api.happymining.fr", true},           // plain HTTP to a non-loopback host
		{"http://10.0.0.5:8080", true},                // private is not loopback
		{"http://localhost.example.com", true},        // not localhost
		{"ftp://api.happymining.fr", false},           // scheme
		{"https://user:pw@api.happymining.fr", false}, // credentials in the URL
		{"https://api.happymining.fr/?x=1", false},
		{"https://", false},
		{"api.happymining.fr", false},
	}
	for _, c := range bad {
		if _, err := ValidateBaseURL(c.url, c.allow); err == nil {
			t.Errorf("%s (allow=%v) must be refused", c.url, c.allow)
		}
	}
	u, _ := ValidateBaseURL("https://api.happymining.fr/base/", false)
	if u.String() != "https://api.happymining.fr/base" {
		t.Errorf("trailing slash not removed: %s", u)
	}
}

func TestTLSVerificationAndCAFile(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"device_id":"d","machine_id":"m","status":"active","server_time":"2026-10-02T07:45:00Z"}`)
	}))
	defer srv.Close()

	// Without the CA the certificate is unknown: the request must fail.
	c, err := New(Options{BaseURL: srv.URL, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Self(context.Background(), token); err == nil {
		t.Fatal("a certificate from an unknown CA must be rejected")
	}

	// With HM_CA_FILE pointing at the test CA it works.
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	c, err = New(Options{BaseURL: srv.URL, CAFile: caFile, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	self, err := c.Self(context.Background(), token)
	if err != nil || self.DeviceID != "d" {
		t.Fatalf("with the CA file: %+v %v", self, err)
	}

	if _, err := New(Options{BaseURL: srv.URL, CAFile: filepath.Join(t.TempDir(), "missing.pem")}); err == nil {
		t.Fatal("a missing CA file must be an error")
	}
	empty := filepath.Join(t.TempDir(), "empty.pem")
	_ = os.WriteFile(empty, []byte("not a certificate"), 0o644)
	if _, err := New(Options{BaseURL: srv.URL, CAFile: empty}); err == nil {
		t.Fatal("a CA file without certificates must be an error")
	}
}

func TestRequestShape(t *testing.T) {
	var got *http.Request
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(context.Background())
		body, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, `{"accepted":1,"duplicates":0,"rejected":0,"highest_seq":1,"next_interval_s":60,"operations":[]}`)
	}))
	defer srv.Close()
	c := newClient(t, srv.URL)
	resp, err := c.Heartbeat(context.Background(), token, heartbeat())
	if err != nil || resp.Accepted != 1 {
		t.Fatalf("%+v %v", resp, err)
	}
	if got.Method != http.MethodPost || got.URL.Path != "/api/v1/device/heartbeat" {
		t.Fatalf("%s %s", got.Method, got.URL.Path)
	}
	if got.Header.Get("Authorization") != "Bearer "+token || got.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("headers: %v", got.Header)
	}
	if !json.Valid(body) || !bytes.Contains(body, []byte(`"samples":[{"seq":1}]`)) {
		t.Fatalf("body: %s", body)
	}
}

func TestMalformedAndOversizedResponsesAreErrors(t *testing.T) {
	bodies := map[string]func(w http.ResponseWriter){
		"empty":        func(w http.ResponseWriter) {},
		"not json":     func(w http.ResponseWriter) { _, _ = io.WriteString(w, "<html>ok</html>") },
		"null":         func(w http.ResponseWriter) { _, _ = io.WriteString(w, "null") },
		"array":        func(w http.ResponseWriter) { _, _ = io.WriteString(w, "[1,2,3]") },
		"wrong types":  func(w http.ResponseWriter) { _, _ = io.WriteString(w, `{"accepted":"many","operations":{}}`) },
		"truncated":    func(w http.ResponseWriter) { _, _ = io.WriteString(w, `{"accepted":1,"operat`) },
		"deep nesting": func(w http.ResponseWriter) { _, _ = io.WriteString(w, strings.Repeat("[", 100000)) },
		"oversized": func(w http.ResponseWriter) {
			_, _ = io.WriteString(w, `{"accepted":1,"pad":"`)
			chunk := bytes.Repeat([]byte("x"), 64*1024)
			for i := 0; i < 64; i++ { // 4 MiB
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
			_, _ = io.WriteString(w, `"}`)
		},
	}
	for name, write := range bodies {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { write(w) }))
		c := newClient(t, srv.URL)
		resp, err := c.Heartbeat(context.Background(), token, heartbeat())
		if err == nil {
			t.Errorf("%s: expected an error, got %+v", name, resp)
		} else if Classify(err) != ActionRetry {
			t.Errorf("%s: a broken 2xx body must be retried (the server may have processed the batch), got %v", name, Classify(err))
		}
		if name == "oversized" && !errors.Is(err, ErrResponseTooLarge) {
			t.Errorf("oversized: want ErrResponseTooLarge, got %v", err)
		}
		srv.Close()
	}
}

func TestOversizedResponseIsNotBuffered(t *testing.T) {
	// An endless body must be cut off at the limit instead of filling memory.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := bytes.Repeat([]byte("x"), 64*1024)
		for {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	c := newClient(t, srv.URL)
	start := time.Now()
	_, err := c.Heartbeat(context.Background(), token, heartbeat())
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("want ErrResponseTooLarge, got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the client kept reading an endless body")
	}
}

func TestErrorEnvelopeAndClassification(t *testing.T) {
	cases := []struct {
		status     int
		body       string
		retryAfter string
		want       Action
	}{
		{400, `{"error":{"code":"invalid_request","message":"bad","request_id":"r1"}}`, "", ActionDropPayload},
		{422, `{"error":{"code":"invalid_request","message":"bad","request_id":"r1"}}`, "", ActionDropPayload},
		{401, `{"error":{"code":"device_unauthorized","message":"no","request_id":"r1"}}`, "", ActionUnauthorized},
		{401, `<html>login</html>`, "", ActionRetry}, // not our API: never treat as revoked
		{403, `{"error":{"code":"forbidden","message":"no","request_id":"r1"}}`, "", ActionHold},
		{404, `{"error":{"code":"not_found","message":"no","request_id":"r1"}}`, "", ActionHold},
		{404, `<html>nginx</html>`, "", ActionRetry},
		{400, `<html>bad gateway</html>`, "", ActionRetry}, // no envelope: never drop data
		{413, `{"error":{"code":"payload_too_large","message":"big","request_id":"r1"}}`, "", ActionSplit},
		{413, `<html>too large</html>`, "", ActionSplit},
		{429, `{"error":{"code":"rate_limited","message":"slow","request_id":"r1"}}`, "7", ActionRetryAfter},
		{500, `{"error":{"code":"internal","message":"x","request_id":"r1"}}`, "", ActionRetry},
		{502, `bad gateway`, "", ActionRetry},
		{503, ``, "", ActionRetry},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tc.retryAfter != "" {
				w.Header().Set("Retry-After", tc.retryAfter)
			}
			w.WriteHeader(tc.status)
			_, _ = io.WriteString(w, tc.body)
		}))
		c := newClient(t, srv.URL)
		_, err := c.Heartbeat(context.Background(), token, heartbeat())
		var api *APIError
		if !errors.As(err, &api) || api.Status != tc.status {
			t.Fatalf("%d: want APIError, got %v", tc.status, err)
		}
		if got := Classify(err); got != tc.want {
			t.Errorf("%d %q: Classify = %v, want %v", tc.status, tc.body, got, tc.want)
		}
		if tc.retryAfter != "" && (!api.HasRetry || api.RetryAfter != 7*time.Second) {
			t.Errorf("Retry-After not parsed: %+v", api)
		}
		if strings.Contains(err.Error(), token) {
			t.Errorf("error text leaks the token: %v", err)
		}
		srv.Close()
	}
}

func TestNetworkErrorsAndTimeoutsAreRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // connection refused
	c := newClient(t, url)
	_, err := c.Heartbeat(context.Background(), token, heartbeat())
	if err == nil || Classify(err) != ActionRetry {
		t.Fatalf("connection refused must be retryable: %v", err)
	}

	block := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer slow.Close()
	defer close(block)
	c, _ = New(Options{BaseURL: slow.URL, AllowInsecureLoopback: true, Timeout: 200 * time.Millisecond})
	start := time.Now()
	_, err = c.Heartbeat(context.Background(), token, heartbeat())
	if err == nil || Classify(err) != ActionRetry {
		t.Fatalf("a timeout must be retryable: %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("the request was not bounded by the timeout: %v", time.Since(start))
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var leaked string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization")
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/api/v1/device/self", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	c := newClient(t, srv.URL)
	_, err := c.Self(context.Background(), token)
	var api *APIError
	if !errors.As(err, &api) || api.Status != http.StatusTemporaryRedirect {
		t.Fatalf("a redirect must surface as an error, got %v", err)
	}
	if leaked != "" {
		t.Fatal("the bearer token followed a redirect to another host")
	}
}

func TestRequestBounds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the request must not be sent")
	}))
	defer srv.Close()
	c := newClient(t, srv.URL)
	big := heartbeat()
	big.Samples = []json.RawMessage{json.RawMessage(`"` + strings.Repeat("x", protocol.MaxRequestBodyBytes) + `"`)}
	if _, err := c.Heartbeat(context.Background(), token, big); !errors.Is(err, ErrRequestTooLarge) {
		t.Fatalf("want ErrRequestTooLarge, got %v", err)
	}
	many := heartbeat()
	many.Samples = make([]json.RawMessage, 101)
	for i := range many.Samples {
		many.Samples[i] = json.RawMessage(`{}`)
	}
	if _, err := c.Heartbeat(context.Background(), token, many); err == nil {
		t.Fatal("more than 100 samples must be refused")
	}
	none := heartbeat()
	none.Samples = nil
	if _, err := c.Heartbeat(context.Background(), token, none); err == nil {
		t.Fatal("zero samples must be refused")
	}
	if _, err := c.Self(context.Background(), "hmd_bad token\r\nX-Injected: 1"); err == nil {
		t.Fatal("a malformed token must never be sent")
	}
	if err := c.AckOperation(context.Background(), token, "../../enroll", &protocol.AckRequest{}); err == nil {
		t.Fatal("a non-UUID operation id must never reach a URL path")
	}
}

func TestEnrollValidatesTheResponse(t *testing.T) {
	responses := []string{
		`{}`,
		`{"device_id":"d","machine_id":"m","credential":{"id":"c","token":"not-a-token"}}`,
		`{"device_id":"","machine_id":"m","credential":{"id":"c","token":"` + token + `"}}`,
	}
	for _, body := range responses {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "" {
				t.Error("enrollment must not send an Authorization header")
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, body)
		}))
		c := newClient(t, srv.URL)
		if _, err := c.Enroll(context.Background(), &protocol.EnrollRequest{PairingCode: "x"}); !errors.Is(err, ErrMalformedResponse) {
			t.Errorf("%s: want ErrMalformedResponse, got %v", body, err)
		}
		srv.Close()
	}
}

func TestIsFinalForAck(t *testing.T) {
	if !IsFinalForAck(&APIError{Status: 409, Code: "conflict"}) || !IsFinalForAck(&APIError{Status: 410, Code: "expired"}) {
		t.Fatal("409 and 410 are final")
	}
	if IsFinalForAck(&APIError{Status: 500, Code: "x"}) || IsFinalForAck(&APIError{Status: 409}) || IsFinalForAck(errors.New("net")) {
		t.Fatal("5xx, envelope-less and network errors are not final")
	}
}
