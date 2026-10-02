package client

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
)

func TestGetUpdate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != protocol.PathUpdate || r.Header.Get("Authorization") != "Bearer "+token || r.Method != http.MethodGet {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		_, _ = w.Write([]byte(`{"channel":"stable","policy":"auto","window":{"start_hour":2,"end_hour":5},
			"release":{"version":"0.2.0","manifest_b64":"e30=","signature_b64":"c2ln","size":12,"sha256":"ab","artifact_path":"/api/v1/device/update/artifact/0.2.0"}}`))
	}))
	defer srv.Close()
	got, err := newClient(t, srv.URL).GetUpdate(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if got.Policy != "auto" || got.Window.EndHour != 5 || got.Release.Size != 12 || got.Release.Version != "0.2.0" {
		t.Fatalf("%+v", got)
	}

	nothing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"channel":"none","policy":"manual","window":null,"release":null}`))
	}))
	defer nothing.Close()
	if got, err := newClient(t, nothing.URL).GetUpdate(context.Background(), token); err != nil || got.Release != nil || got.Window != nil {
		t.Fatalf("%+v %v", got, err)
	}
	null := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`null`)) }))
	defer null.Close()
	if _, err := newClient(t, null.URL).GetUpdate(context.Background(), token); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("%v", err)
	}
}

// pkgServer serves body for the artifact of version 0.2.0.
func pkgServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/api/v1/device/update/artifact/0.2.0" || r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &requests
}

func TestDownloadArtifactAcceptsExactlyTheStatedSize(t *testing.T) {
	pkg := bytes.Repeat([]byte("p"), 10000)
	srv, _ := pkgServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(pkg) })
	var out bytes.Buffer
	if err := newClient(t, srv.URL).DownloadArtifact(context.Background(), token, "0.2.0", int64(len(pkg)), &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), pkg) {
		t.Fatal("content differs")
	}

	for name, body := range map[string][]byte{"longer": append(pkg, 'x'), "much longer": bytes.Repeat(pkg, 50), "shorter": pkg[:9999]} {
		srv, _ := pkgServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.(http.Flusher).Flush() // no Content-Length: only the byte count can tell
			_, _ = w.Write(body)
		})
		var out bytes.Buffer
		err := newClient(t, srv.URL).DownloadArtifact(context.Background(), token, "0.2.0", int64(len(pkg)), &out)
		if !errors.Is(err, ErrArtifactSize) {
			t.Errorf("%s: %v", name, err)
		}
		if out.Len() > len(pkg)+1 {
			t.Errorf("%s: %d bytes were written for a package of %d", name, out.Len(), len(pkg))
		}
	}
	wrongHeader, _ := pkgServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "5")
		_, _ = w.Write([]byte("12345"))
	})
	if err := newClient(t, wrongHeader.URL).DownloadArtifact(context.Background(), token, "0.2.0", 10, &bytes.Buffer{}); !errors.Is(err, ErrArtifactSize) {
		t.Fatalf("%v", err)
	}
}

func TestDownloadArtifactRefusesBadInputBeforeAnyRequest(t *testing.T) {
	srv, requests := pkgServer(t, func(w http.ResponseWriter, _ *http.Request) {})
	c := newClient(t, srv.URL)
	for _, tc := range []struct {
		version, token string
		size           int64
	}{
		{"0.2", token, 10}, {"../../x", token, 10}, {"0.2.0/../../device/self", token, 10},
		{"0.2.0", token, 0}, {"0.2.0", token, 600 << 20}, {"0.2.0", "not-a-token", 10},
	} {
		if err := c.DownloadArtifact(context.Background(), tc.token, tc.version, tc.size, &bytes.Buffer{}); err == nil {
			t.Errorf("%+v accepted", tc)
		}
	}
	if requests.Load() != 0 {
		t.Fatalf("%d requests were sent for refused input", requests.Load())
	}
}

func TestDownloadArtifactDoesNotFollowRedirects(t *testing.T) {
	var leaked atomic.Bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
		_, _ = w.Write([]byte("0123456789"))
	}))
	defer elsewhere.Close()
	srv, _ := pkgServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/pkg.deb", http.StatusFound)
	})
	err := newClient(t, srv.URL).DownloadArtifact(context.Background(), token, "0.2.0", 10, &bytes.Buffer{})
	var api *APIError
	if !errors.As(err, &api) || api.Status != http.StatusFound || leaked.Load() {
		t.Fatalf("redirect followed or token leaked: %v", err)
	}
}

func TestDownloadArtifactGivesUpWhenStalled(t *testing.T) {
	old := stallTimeout
	stallTimeout = 100 * time.Millisecond
	defer func() { stallTimeout = old }()
	release := make(chan struct{})
	defer close(release)
	srv, _ := pkgServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte("partial"))
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	started := time.Now()
	err := newClient(t, srv.URL).DownloadArtifact(context.Background(), token, "0.2.0", 100, &bytes.Buffer{})
	if !errors.Is(err, ErrDownloadStalled) || time.Since(started) > 5*time.Second {
		t.Fatalf("%v after %v", err, time.Since(started))
	}
	if !strings.Contains(err.Error(), "after 7 bytes") {
		t.Fatalf("%v", err)
	}
}
