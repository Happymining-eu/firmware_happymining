// Package localui serves the local web page of a HappyMining machine: the
// page an operator opens from a laptop on the same network to see the
// machine's state and to pair it. It runs as the unprivileged agent account,
// reads the same files as `happyminingctl status`, and has no shell, no
// command execution and no route that touches money.
//
// Reading is open to the network the page listens on. The one action, pairing,
// needs an unlock code that `happyminingctl ui unlock` prints on the machine
// itself (unlock.go), so reaching the page is never enough to pair it.
package localui

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/agent"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/client"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/collector"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/credential"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/enroll"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/fsx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/pairing"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/preflight"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/redact"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/spool"
)

//go:embed static/*
var static embed.FS

// Timing.
const (
	SampleRefresh    = 10 * time.Second
	APIProbeRefresh  = 60 * time.Second
	PreflightCache   = 60 * time.Second
	SessionTTL       = 30 * time.Minute
	pairTimeout      = 45 * time.Second
	probeTimeout     = 10 * time.Second
	maxBodyBytes     = 4 * 1024
	sessionCookie    = "hm_ui_session"
	sessionTokenSize = 32
)

// Options configures a Server. Everything that touches the host is injected so
// tests can run without a machine.
type Options struct {
	StateDir        string
	SpoolDir        string
	SpoolQuotaBytes int64
	// Client talks to the HappyMining API; nil means no API is configured.
	Client *client.Client
	// Collector produces the host sample shown on the page; nil shows none.
	Collector collector.Collector
	// Preflight runs the read-only host checks; nil disables the button.
	Preflight func(ctx context.Context) preflight.Report
	// Hostname and Addresses describe the machine on the page.
	Hostname  func() string
	Addresses func() []string
	// HostOS is sent at enrollment, as happyminingctl pair sends it.
	HostOS  protocol.OSInfo
	Version string
	Logger  *slog.Logger
	Now     func() time.Time
	// Owner, if set, becomes the owner of the files pairing creates.
	Owner *fsx.Owner
}

// Server is the HTTP handler plus its background refresh.
type Server struct {
	opt Options
	mux *http.ServeMux
	red *redact.Redactor

	mu             sync.Mutex
	sample         *protocol.Sample
	sampleAt       time.Time
	apiReachable   bool
	apiDetail      string
	apiAt          time.Time
	preflightRep   *preflight.Report
	preflightAt    time.Time
	preflightBusy  sync.Mutex
	sessions       map[string]time.Time
	unlockFailures int
}

// New builds a Server. It does not listen; see Handler and Run.
func New(opt Options) *Server {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Logger == nil {
		opt.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opt.Hostname == nil {
		opt.Hostname = func() string { h, _ := os.Hostname(); return h }
	}
	if opt.Addresses == nil {
		opt.Addresses = HostAddresses
	}
	s := &Server{opt: opt, mux: http.NewServeMux(), red: redact.New(), sessions: map[string]time.Time{}}
	s.mux.HandleFunc("GET /{$}", s.index)
	s.mux.HandleFunc("GET /app.js", s.asset("static/app.js", "text/javascript; charset=utf-8"))
	s.mux.HandleFunc("GET /app.css", s.asset("static/app.css", "text/css; charset=utf-8"))
	s.mux.HandleFunc("GET /api/status", s.status)
	s.mux.HandleFunc("GET /api/preflight", s.preflight)
	s.mux.HandleFunc("POST /api/unlock", s.unlock)
	s.mux.HandleFunc("POST /api/lock", s.lock)
	s.mux.HandleFunc("POST /api/pair", s.pair)
	return s
}

// Handler returns the HTTP handler with the security wrapper applied.
func (s *Server) Handler() http.Handler { return s.guard(s.mux) }

// Run refreshes the cached host sample and API probe until ctx ends.
func (s *Server) Run(ctx context.Context) {
	s.refreshSample(ctx)
	s.refreshAPI(ctx)
	sampleTick := time.NewTicker(SampleRefresh)
	apiTick := time.NewTicker(APIProbeRefresh)
	defer sampleTick.Stop()
	defer apiTick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-sampleTick.C:
			s.refreshSample(ctx)
		case <-apiTick.C:
			s.refreshAPI(ctx)
		}
	}
}

// HostAddresses lists the machine's non-loopback unicast IP addresses.
func HostAddresses() []string {
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, ipn.IP.String())
		}
	}
	return out
}

// guard applies to every request: a Host header that names this machine (an
// IP literal, localhost or the host name, so a web site that rebinds its DNS
// name to this address cannot reach the page), no caching, no sniffing, a
// strict content security policy, and no cross-site use of the API.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hostAllowed(r.Host) {
			http.Error(w, "this page is only served by the machine's own address", http.StatusMisdirectedRequest)
			return
		}
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'")
		if r.Method == http.MethodPost {
			if origin := r.Header.Get("Origin"); origin != "" && !s.originIsSelf(origin, r.Host) {
				http.Error(w, "cross-site request refused", http.StatusForbidden)
				return
			}
			if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				http.Error(w, "application/json expected", http.StatusUnsupportedMediaType)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) hostAllowed(host string) bool {
	h := host
	if hp, _, err := net.SplitHostPort(host); err == nil {
		h = hp
	}
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	if h == "" {
		return false
	}
	if net.ParseIP(h) != nil || strings.EqualFold(h, "localhost") {
		return true
	}
	name := strings.ToLower(s.opt.Hostname())
	h = strings.ToLower(h)
	return name != "" && (h == name || h == name+".local" || strings.HasPrefix(h, name+"."))
}

func (s *Server) originIsSelf(origin, host string) bool {
	origin = strings.TrimPrefix(strings.TrimPrefix(origin, "http://"), "https://")
	return strings.EqualFold(origin, host)
}

// --- static ---------------------------------------------------------------

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	s.asset("static/index.html", "text/html; charset=utf-8")(w, r)
}

func (s *Server) asset(name, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		data, err := fs.ReadFile(static, name)
		if err != nil {
			http.Error(w, "missing asset", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(data)
	}
}

// --- status ---------------------------------------------------------------

// Status is the body of GET /api/status. It never carries the credential
// secret, the pairing code or anything about renter workloads (the sample is
// the agent's own privacy-bounded sample).
type Status struct {
	Version         string           `json:"version"`
	GeneratedAt     string           `json:"generated_at"`
	Hostname        string           `json:"hostname"`
	Addresses       []string         `json:"addresses"`
	Paired          bool             `json:"paired"`
	DeviceID        string           `json:"device_id,omitempty"`
	MachineID       string           `json:"machine_id,omitempty"`
	CredentialID    string           `json:"credential_id,omitempty"`
	CredentialError string           `json:"credential_error,omitempty"`
	AgentState      string           `json:"agent_state"`
	LastHeartbeatOK string           `json:"last_heartbeat_ok,omitempty"`
	LastError       string           `json:"last_error,omitempty"`
	SpoolSamples    int              `json:"spool_samples"`
	SpoolBytes      int64            `json:"spool_bytes"`
	SpoolQuotaBytes int64            `json:"spool_quota_bytes"`
	APIURL          string           `json:"api_url,omitempty"`
	APIReachable    bool             `json:"api_reachable"`
	APIDetail       string           `json:"api_detail"`
	APICheckedAt    string           `json:"api_checked_at,omitempty"`
	Sample          *protocol.Sample `json:"sample,omitempty"`
	SampleAt        string           `json:"sample_at,omitempty"`
	Unlocked        bool             `json:"unlocked"`
	UnlockAvailable bool             `json:"unlock_available"`
	PreflightOK     bool             `json:"preflight_available"`
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	now := s.opt.Now()
	st := Status{
		Version: s.opt.Version, GeneratedAt: now.UTC().Format(time.RFC3339),
		Hostname: s.opt.Hostname(), Addresses: s.opt.Addresses(), AgentState: "unknown",
		SpoolQuotaBytes: s.opt.SpoolQuotaBytes, PreflightOK: s.opt.Preflight != nil,
	}
	if st.Addresses == nil {
		st.Addresses = []string{}
	}
	cred, err := credential.Load(credential.Path(s.opt.StateDir))
	switch {
	case err == nil:
		s.red.AddSecret(cred.Token)
		st.Paired = true
		st.DeviceID, st.MachineID, st.CredentialID = cred.DeviceID, cred.MachineID, cred.CredentialID
	case errors.Is(err, credential.ErrNotPaired):
	case errors.Is(err, fs.ErrPermission):
		st.CredentialError = "the UI service cannot read the credential file"
	default:
		st.CredentialError = s.red.String(err.Error())
	}
	if as, err := agent.ReadState(s.opt.StateDir); err == nil {
		st.AgentState = as.State
		st.LastHeartbeatOK = as.LastHeartbeatOK
		st.LastError = s.red.String(as.LastError)
	}
	if n, b, err := spool.Stat(s.opt.SpoolDir); err == nil {
		st.SpoolSamples, st.SpoolBytes = n, b
	}
	if s.opt.Client != nil {
		st.APIURL = s.opt.Client.BaseURL()
	}
	st.Unlocked = s.sessionValid(r, now)
	if _, err := ReadUnlock(s.opt.StateDir, now); err == nil {
		st.UnlockAvailable = true
	}

	s.mu.Lock()
	st.APIReachable, st.APIDetail = s.apiReachable, s.apiDetail
	if !s.apiAt.IsZero() {
		st.APICheckedAt = s.apiAt.UTC().Format(time.RFC3339)
	}
	if s.sample != nil {
		sample := *s.sample
		st.Sample = &sample
		st.SampleAt = s.sampleAt.UTC().Format(time.RFC3339)
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) refreshSample(ctx context.Context) {
	if s.opt.Collector == nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, SampleRefresh*3)
	defer cancel()
	sample, warnings := s.opt.Collector.Collect(cctx)
	for _, wmsg := range warnings {
		s.opt.Logger.Debug("collector warning", "warning", wmsg)
	}
	s.mu.Lock()
	s.sample, s.sampleAt = &sample, s.opt.Now()
	s.mu.Unlock()
}

func (s *Server) refreshAPI(ctx context.Context) {
	if s.opt.Client == nil {
		s.mu.Lock()
		s.apiReachable, s.apiDetail, s.apiAt = false, "no API URL configured", s.opt.Now()
		s.mu.Unlock()
		return
	}
	pctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	reachable, detail := false, ""
	if cred, err := credential.Load(credential.Path(s.opt.StateDir)); err == nil {
		s.red.AddSecret(cred.Token)
		self, err := s.opt.Client.Self(pctx, cred.Token)
		var apiErr *client.APIError
		switch {
		case err == nil:
			reachable, detail = true, "credential accepted; device status: "+protocol.Truncate(self.Status, 64)
		case errors.As(err, &apiErr):
			reachable, detail = true, s.red.String(apiErr.Error())
		default:
			detail = s.red.String(err.Error())
		}
	} else if code, err := s.opt.Client.Probe(pctx); err == nil {
		reachable, detail = true, fmt.Sprintf("reachable (HTTP %d without credentials)", code)
	} else {
		detail = s.red.String(err.Error())
	}
	s.mu.Lock()
	s.apiReachable, s.apiDetail, s.apiAt = reachable, detail, s.opt.Now()
	s.mu.Unlock()
}

// --- preflight ------------------------------------------------------------

func (s *Server) preflight(w http.ResponseWriter, r *http.Request) {
	if s.opt.Preflight == nil {
		writeError(w, http.StatusNotImplemented, "preflight is not available on this machine")
		return
	}
	s.preflightBusy.Lock()
	defer s.preflightBusy.Unlock()
	now := s.opt.Now()
	s.mu.Lock()
	cached, at := s.preflightRep, s.preflightAt
	s.mu.Unlock()
	if cached != nil && now.Sub(at) < PreflightCache {
		writeJSON(w, http.StatusOK, cached)
		return
	}
	rep := s.opt.Preflight(r.Context())
	s.mu.Lock()
	s.preflightRep, s.preflightAt = &rep, now
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, rep)
}

// --- unlock and sessions --------------------------------------------------

type codeRequest struct {
	Code string `json:"code"`
}

func (s *Server) unlock(w http.ResponseWriter, r *http.Request) {
	var req codeRequest
	if !readJSON(w, r, &req) {
		return
	}
	now := s.opt.Now()
	uf, err := ReadUnlock(s.opt.StateDir, now)
	if err != nil {
		if errors.Is(err, ErrNoUnlock) {
			writeError(w, http.StatusLocked, ErrNoUnlock.Error())
			return
		}
		s.opt.Logger.Warn("unlock file unreadable", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "the unlock file cannot be read")
		return
	}
	code := strings.TrimSpace(req.Code)
	s.mu.Lock()
	ok := uf.Matches(code)
	if !ok {
		s.unlockFailures++
		if s.unlockFailures >= MaxUnlockAttempts {
			_ = DeleteUnlock(s.opt.StateDir)
			s.unlockFailures = 0
			s.mu.Unlock()
			s.opt.Logger.Warn("unlock code burned after repeated wrong attempts")
			writeError(w, http.StatusLocked, "too many wrong codes: the unlock was cancelled. Run `sudo happyminingctl ui unlock` again")
			return
		}
		left := MaxUnlockAttempts - s.unlockFailures
		s.mu.Unlock()
		writeError(w, http.StatusForbidden, fmt.Sprintf("wrong code (%d attempt(s) left)", left))
		return
	}
	s.unlockFailures = 0
	token, err := newSessionToken()
	if err != nil {
		s.mu.Unlock()
		writeError(w, http.StatusInternalServerError, "cannot create a session")
		return
	}
	s.pruneSessionsLocked(now)
	s.sessions[token] = now.Add(SessionTTL)
	s.mu.Unlock()
	_ = DeleteUnlock(s.opt.StateDir) // single use
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
		MaxAge: int(SessionTTL / time.Second),
	})
	s.opt.Logger.Info("UI unlocked from the network", "remote", r.RemoteAddr)
	writeJSON(w, http.StatusOK, map[string]any{"unlocked": true, "expires_at": now.Add(SessionTTL).UTC().Format(time.RFC3339)})
}

func (s *Server) lock(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]any{"unlocked": false})
}

func (s *Server) sessionValid(r *http.Request, now time.Time) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[c.Value]
	return ok && now.Before(exp)
}

func (s *Server) pruneSessionsLocked(now time.Time) {
	for tok, exp := range s.sessions {
		if !now.Before(exp) {
			delete(s.sessions, tok)
		}
	}
}

func newSessionToken() (string, error) {
	b := make([]byte, sessionTokenSize)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// --- pairing --------------------------------------------------------------

func (s *Server) pair(w http.ResponseWriter, r *http.Request) {
	now := s.opt.Now()
	if !s.sessionValid(r, now) {
		writeError(w, http.StatusUnauthorized, "unlock the page first (sudo happyminingctl ui unlock on the machine)")
		return
	}
	var req codeRequest
	if !readJSON(w, r, &req) {
		return
	}
	if s.opt.Client == nil {
		writeError(w, http.StatusNotImplemented, "no API URL is configured on this machine")
		return
	}
	if enroll.Paired(s.opt.StateDir) {
		writeError(w, http.StatusConflict, enroll.ErrAlreadyPaired.Error())
		return
	}
	canonical, err := pairing.Normalize(req.Code)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.red.AddSecret(canonical)
	s.red.AddSecret(strings.TrimSpace(req.Code))
	ctx, cancel := context.WithTimeout(r.Context(), pairTimeout)
	defer cancel()
	cred, err := enroll.Pair(ctx, enroll.Params{
		Client: s.opt.Client, StateDir: s.opt.StateDir, Code: canonical, Hostname: s.opt.Hostname(),
		OS: s.opt.HostOS, Owner: s.opt.Owner, Now: s.opt.Now,
	})
	if err != nil {
		s.opt.Logger.Warn("pairing from the UI failed", "code", pairing.Mask(canonical), "error", s.red.String(err.Error()))
		writeError(w, http.StatusBadGateway, s.red.String(err.Error()))
		return
	}
	s.red.AddSecret(cred.Token)
	s.opt.Logger.Info("paired from the UI", "device_id", cred.DeviceID, "machine_id", cred.MachineID, "remote", r.RemoteAddr)
	go s.refreshAPI(context.Background())
	writeJSON(w, http.StatusOK, map[string]string{
		"device_id": cred.DeviceID, "machine_id": cred.MachineID, "credential_id": cred.CredentialID,
	})
}

// --- helpers --------------------------------------------------------------

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
