// Package testapi is a small in-memory implementation of the HappyMining
// device API (docs/agent-protocol.md) for tests and for local end-to-end runs
// of the simulator. It is test support: it is not part of any shipped binary
// and it is not the real API server.
//
// It validates requests strictly (unknown JSON fields, bounds, formats), so a
// client that drifts from the contract fails here.
package testapi

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// Fault describes how the server misbehaves for one heartbeat request.
type Fault struct {
	// Status, if non-zero, is returned instead of processing the request.
	Status int
	// Code is the error envelope code for Status ("" sends no envelope).
	Code string
	// RetryAfter is sent as the Retry-After header when not empty.
	RetryAfter string
	// ProcessThenFail processes the batch and then answers 500, like a
	// server that crashed after committing: the client must resend.
	ProcessThenFail bool
	// RawBody, if not nil, is sent as a 200 response body after processing.
	RawBody []byte
	// HugeBody sends a 200 response larger than the client's limit.
	HugeBody bool
	// Hang blocks until the client gives up (after processing).
	Hang bool
}

// AckRecord is one acknowledgement received by the server.
type AckRecord struct {
	OperationID string
	Body        protocol.AckRequest
}

// HeartbeatRecord is one heartbeat request that reached processing.
type HeartbeatRecord struct {
	Seqs       []uint64
	BootID     string
	Accepted   int
	Duplicates int
}

type enrollment struct {
	deviceID, machineID string
	expires             time.Time
	used                bool
}

type device struct {
	id, machineID string
	fingerprint   string
	hostname      string
	credID        string
	tokenHash     [32]byte
	prevTokenHash *[32]byte // still valid until the new one is first used
	revoked       bool
	samples       map[uint64]json.RawMessage
	highest       uint64
	duplicates    int
	synthetic     int
	heartbeats    []HeartbeatRecord
	pending       []protocol.Operation
	// accepted holds pending operations acknowledged "accepted": like the
	// real server, they are not sent again but still take a final status.
	accepted  map[string]bool
	final     map[string]string
	acks      []AckRecord
	rotations int
	// The appliance (docs/appliance.md, section 6).
	applianceRevision int64
	applianceDocument json.RawMessage
	applianceReports  []json.RawMessage
	documentsSent     []int64
	updateOffer       *protocol.UpdateResponse
	updateRequests    int
	artifactRequests  []string
}

// Server is the fake API. All methods are safe for concurrent use.
type Server struct {
	mu          sync.Mutex
	now         func() time.Time
	enrollments map[string]*enrollment
	devices     map[string]*device // by device id
	requests    int
	heartbeatN  int
	fault       func(n int) *Fault
	authHeaders []string
	// RefuseSynthetic makes the server reject synthetic samples (LIVE mode).
	RefuseSynthetic bool
	// artifacts holds release packages by version; artifactHandler, if set,
	// answers the artifact route instead (fault injection).
	artifacts       map[string][]byte
	artifactHandler http.HandlerFunc
}

// New returns an empty server.
func New() *Server {
	return &Server{now: time.Now, enrollments: map[string]*enrollment{}, devices: map[string]*device{}, artifacts: map[string][]byte{}}
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func newUUID() string {
	b := randomBytes(16)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func newToken(credID string) string {
	return "hmd_" + strings.ReplaceAll(credID, "-", "") + "." + base64.RawURLEncoding.EncodeToString(randomBytes(32))
}

// NewPairingCode creates an enrollment request and returns its pairing code
// in canonical form. The code is valid for 15 minutes and usable once.
func (s *Server) NewPairingCode() string {
	raw := randomBytes(22)
	chars := make([]byte, 22)
	for i, b := range raw {
		chars[i] = crockford[int(b)%len(crockford)]
	}
	code := fmt.Sprintf("HM-%s-%s-%s-%s-%s", chars[0:6], chars[6:10], chars[10:14], chars[14:18], chars[18:22])
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enrollments[code] = &enrollment{deviceID: newUUID(), machineID: newUUID(), expires: s.now().Add(15 * time.Minute)}
	return code
}

// ExpireCode makes a pairing code expired.
func (s *Server) ExpireCode(code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.enrollments[code]; e != nil {
		e.expires = s.now().Add(-time.Minute)
	}
}

// SetHeartbeatFault installs a fault function. It receives the 1-based number
// of the heartbeat request and returns nil for normal behaviour.
func (s *Server) SetHeartbeatFault(f func(n int) *Fault) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fault = f
}

// Revoke revokes a device's credential.
func (s *Server) Revoke(deviceID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := s.devices[deviceID]; d != nil {
		d.revoked = true
	}
}

// QueueOperation makes an operation pending for a device. Missing id, nonce
// and timestamps are filled in. It returns the operation as queued.
func (s *Server) QueueOperation(deviceID string, op protocol.Operation) protocol.Operation {
	s.mu.Lock()
	defer s.mu.Unlock()
	if op.ID == "" {
		op.ID = newUUID()
	}
	if op.Nonce == "" {
		op.Nonce = base64.RawURLEncoding.EncodeToString(randomBytes(18))
	}
	if op.IssuedAt == "" {
		op.IssuedAt = protocol.FormatTime(s.now())
	}
	if op.ExpiresAt == "" {
		op.ExpiresAt = protocol.FormatTime(s.now().Add(10 * time.Minute))
	}
	if op.Params == nil {
		op.Params = json.RawMessage(`{}`)
	}
	if d := s.devices[deviceID]; d != nil {
		d.pending = append(d.pending, op)
	}
	return op
}

// DeviceSnapshot is a copy of what the server knows about a device.
type DeviceSnapshot struct {
	ID, MachineID   string
	Fingerprint     string
	Hostname        string
	CredentialID    string
	Samples         map[uint64]json.RawMessage
	HighestSeq      uint64
	Duplicates      int
	SyntheticCount  int
	Heartbeats      []HeartbeatRecord
	Acks            []AckRecord
	PendingOps      int
	FinalOperations map[string]string
	Rotations       int
	// ApplianceReports are the appliance objects received, oldest first.
	ApplianceReports []json.RawMessage
	// DocumentsSent lists the revision of every document sent in a response.
	DocumentsSent    []int64
	UpdateRequests   int
	ArtifactRequests []string
}

// LastAppliance returns the last appliance object received, decoded (ok is
// false when none was received).
func (d DeviceSnapshot) LastAppliance() (appliance.Reported, bool) {
	if len(d.ApplianceReports) == 0 {
		return appliance.Reported{}, false
	}
	var r appliance.Reported
	if err := json.Unmarshal(d.ApplianceReports[len(d.ApplianceReports)-1], &r); err != nil {
		return appliance.Reported{}, false
	}
	return r, true
}

// Device returns a snapshot of one device (ok is false if unknown).
func (s *Server) Device(deviceID string) (DeviceSnapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.devices[deviceID]
	if d == nil {
		return DeviceSnapshot{}, false
	}
	snap := DeviceSnapshot{
		ID: d.id, MachineID: d.machineID, Fingerprint: d.fingerprint, Hostname: d.hostname,
		CredentialID: d.credID, Samples: map[uint64]json.RawMessage{}, HighestSeq: d.highest,
		Duplicates: d.duplicates, SyntheticCount: d.synthetic, PendingOps: len(d.pending),
		FinalOperations: map[string]string{}, Rotations: d.rotations,
	}
	for k, v := range d.samples {
		snap.Samples[k] = v
	}
	for k, v := range d.final {
		snap.FinalOperations[k] = v
	}
	snap.Heartbeats = append(snap.Heartbeats, d.heartbeats...)
	snap.Acks = append(snap.Acks, d.acks...)
	snap.ApplianceReports = append(snap.ApplianceReports, d.applianceReports...)
	snap.DocumentsSent = append(snap.DocumentsSent, d.documentsSent...)
	snap.UpdateRequests = d.updateRequests
	snap.ArtifactRequests = append(snap.ArtifactRequests, d.artifactRequests...)
	return snap, true
}

// SetApplianceDocument stores the desired-state document of a device (a
// complete section 4 document with "revision" and "secrets"). The revision of
// the response is the document's. It returns false for an unknown device or
// a document without a positive integer revision.
func (s *Server) SetApplianceDocument(deviceID string, document json.RawMessage) bool {
	var head struct {
		Revision int64 `json:"revision"`
	}
	if json.Unmarshal(document, &head) != nil || head.Revision < 1 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.devices[deviceID]
	if d == nil {
		return false
	}
	d.applianceRevision, d.applianceDocument = head.Revision, append(json.RawMessage(nil), document...)
	return true
}

// SetUpdateOffer sets what GET /api/v1/device/update answers to a device.
func (s *Server) SetUpdateOffer(deviceID string, offer protocol.UpdateResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := s.devices[deviceID]; d != nil {
		d.updateOffer = &offer
	}
}

// AddArtifact makes a release package downloadable.
func (s *Server) AddArtifact(version string, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.artifacts[version] = append([]byte(nil), data...)
}

// SetArtifactHandler answers the artifact route with h (after authentication)
// instead of the stored packages; nil restores the normal behaviour.
func (s *Server) SetArtifactHandler(h http.HandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.artifactHandler = h
}

// DeviceIDs lists the enrolled devices.
func (s *Server) DeviceIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for id := range s.devices {
		out = append(out, id)
	}
	return out
}

// HeartbeatRequests returns how many heartbeat requests arrived (including
// the ones answered with a fault).
func (s *Server) HeartbeatRequests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.heartbeatN
}

// AuthorizationHeaders returns every Authorization header value seen.
func (s *Server) AuthorizationHeaders() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.authHeaders...)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	var env protocol.ErrorEnvelope
	env.Error.Code, env.Error.Message, env.Error.RequestID = code, message, w.Header().Get("X-Request-ID")
	writeJSON(w, status, env)
}

// readBody enforces the 256 KiB request limit.
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	data, err := io.ReadAll(io.LimitReader(r.Body, protocol.MaxRequestBodyBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, protocol.CodeInvalidRequest, "Unreadable body.")
		return nil, false
	}
	if len(data) > protocol.MaxRequestBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, protocol.CodePayloadTooLarge, "Request body too large.")
		return nil, false
	}
	return data, true
}

func strictDecode(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing data")
	}
	return nil
}

// Handler returns the HTTP handler of the fake API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+protocol.PathEnroll, s.handleEnroll)
	mux.HandleFunc("POST "+protocol.PathHeartbeat, s.auth(s.handleHeartbeat))
	mux.HandleFunc("GET "+protocol.PathOperations, s.auth(s.handleOperations))
	mux.HandleFunc("POST "+protocol.PathOperations+"/{id}/ack", s.auth(s.handleAck))
	mux.HandleFunc("POST "+protocol.PathRotate, s.auth(s.handleRotate))
	mux.HandleFunc("GET "+protocol.PathSelf, s.auth(s.handleSelf))
	mux.HandleFunc("GET "+protocol.PathUpdate, s.auth(s.handleUpdate))
	mux.HandleFunc("GET "+protocol.PathUpdateArtifact+"/{version}", s.auth(s.handleArtifact))
	mux.HandleFunc("GET /_test/summary", s.handleSummary)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.requests++
		s.mu.Unlock()
		w.Header().Set("X-Request-ID", newUUID())
		if _, pattern := mux.Handler(r); pattern == "" {
			writeError(w, http.StatusNotFound, protocol.CodeNotFound, "Not found.")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

var (
	reCode        = regexp.MustCompile(`^HM-[0-9A-HJKMNP-TV-Z]{6}(-[0-9A-HJKMNP-TV-Z]{4}){4}$`)
	reFingerprint = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	reToken       = regexp.MustCompile(`^Bearer (hmd_[0-9a-f]{32}\.[A-Za-z0-9_-]{43})$`)
)

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	data, ok := readBody(w, r)
	if !ok {
		return
	}
	var req protocol.EnrollRequest
	if err := strictDecode(data, &req); err != nil {
		writeError(w, http.StatusUnprocessableEntity, protocol.CodeInvalidRequest, "Invalid request.")
		return
	}
	if !reFingerprint.MatchString(req.MachineFingerprint) || req.Hostname == "" || len(req.Hostname) > protocol.MaxStringLen ||
		req.AgentVersion == "" || req.OS.ID == "" || req.OS.Arch == "" {
		writeError(w, http.StatusUnprocessableEntity, protocol.CodeInvalidRequest, "Invalid request.")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// The server only accepts the canonical form here so that a client that
	// forgets to normalise is caught by the tests.
	e := s.enrollments[req.PairingCode]
	if !reCode.MatchString(req.PairingCode) || e == nil || e.used || !s.now().Before(e.expires) {
		writeError(w, http.StatusUnauthorized, protocol.CodePairingFailed, "Pairing failed.")
		return
	}
	e.used = true
	credID := newUUID()
	token := newToken(credID)
	s.devices[e.deviceID] = &device{
		id: e.deviceID, machineID: e.machineID, fingerprint: req.MachineFingerprint, hostname: req.Hostname,
		credID: credID, tokenHash: sha256.Sum256([]byte(token)),
		samples: map[uint64]json.RawMessage{}, final: map[string]string{},
	}
	writeJSON(w, http.StatusCreated, protocol.EnrollResponse{
		DeviceID: e.deviceID, MachineID: e.machineID,
		Credential:         protocol.Credential{ID: credID, Token: token},
		HeartbeatIntervalS: 60, ServerTime: protocol.FormatTime(s.now()),
	})
}

type deviceHandler func(w http.ResponseWriter, r *http.Request, d *device)

// auth resolves the bearer token to a device. It runs the handler with the
// server lock held.
func (s *Server) auth(next deviceHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		s.mu.Lock()
		defer s.mu.Unlock()
		s.authHeaders = append(s.authHeaders, header)
		m := reToken.FindStringSubmatch(header)
		if m == nil {
			writeError(w, http.StatusUnauthorized, protocol.CodeDeviceUnauthorized, "Device credential is not valid.")
			return
		}
		hash := sha256.Sum256([]byte(m[1]))
		for _, d := range s.devices {
			switch {
			case d.revoked:
				continue
			case d.tokenHash == hash:
				d.prevTokenHash = nil // first use of the current credential ends the old one
				next(w, r, d)
				return
			case d.prevTokenHash != nil && *d.prevTokenHash == hash:
				next(w, r, d)
				return
			}
		}
		writeError(w, http.StatusUnauthorized, protocol.CodeDeviceUnauthorized, "Device credential is not valid.")
	}
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request, d *device) {
	s.heartbeatN++
	var fault *Fault
	if s.fault != nil {
		fault = s.fault(s.heartbeatN)
	}
	if fault != nil && fault.Status != 0 {
		if fault.RetryAfter != "" {
			w.Header().Set("Retry-After", fault.RetryAfter)
		}
		if fault.Code == "" {
			w.WriteHeader(fault.Status)
			_, _ = io.WriteString(w, "<html>gateway error</html>")
			return
		}
		writeError(w, fault.Status, fault.Code, "Injected fault.")
		return
	}
	data, ok := readBody(w, r)
	if !ok {
		return
	}
	var req struct {
		SentAt       string            `json:"sent_at"`
		BootID       string            `json:"boot_id"`
		AgentVersion string            `json:"agent_version"`
		Samples      []json.RawMessage `json:"samples"`
		Appliance    json.RawMessage   `json:"appliance"`
	}
	if err := strictDecode(data, &req); err != nil {
		writeError(w, http.StatusUnprocessableEntity, protocol.CodeInvalidRequest, "Invalid request.")
		return
	}
	if _, err := time.Parse(protocol.TimeFormat, req.SentAt); err != nil || req.BootID == "" || req.AgentVersion == "" ||
		len(req.Samples) < 1 || len(req.Samples) > protocol.MaxSamplesPerRequest {
		writeError(w, http.StatusUnprocessableEntity, protocol.CodeInvalidRequest, "Invalid request.")
		return
	}
	var reported *appliance.Reported
	if len(req.Appliance) > 0 && string(req.Appliance) != "null" {
		r, err := ValidateAppliance(req.Appliance)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, protocol.CodeInvalidRequest, "Invalid appliance object: "+err.Error())
			return
		}
		reported = r
	}
	samples := make([]protocol.Sample, len(req.Samples))
	var last uint64
	for i, raw := range req.Samples {
		if err := ValidateSample(raw, &samples[i]); err != nil {
			writeError(w, http.StatusUnprocessableEntity, protocol.CodeInvalidRequest, "Invalid sample: "+err.Error())
			return
		}
		if i > 0 && samples[i].Seq <= last {
			writeError(w, http.StatusUnprocessableEntity, protocol.CodeInvalidRequest, "Samples are not oldest first.")
			return
		}
		last = samples[i].Seq
		if samples[i].Synthetic && s.RefuseSynthetic {
			writeError(w, http.StatusUnprocessableEntity, protocol.CodeInvalidRequest, "Synthetic samples are refused in LIVE mode.")
			return
		}
	}
	rec := HeartbeatRecord{BootID: req.BootID}
	for i, sample := range samples {
		rec.Seqs = append(rec.Seqs, sample.Seq)
		if _, dup := d.samples[sample.Seq]; dup {
			d.duplicates++
			rec.Duplicates++
			continue
		}
		d.samples[sample.Seq] = req.Samples[i]
		if sample.Synthetic {
			d.synthetic++
		}
		if sample.Seq > d.highest {
			d.highest = sample.Seq
		}
		rec.Accepted++
	}
	d.heartbeats = append(d.heartbeats, rec)
	// Section 6.2: only an agent that sent an appliance object hears about it,
	// and only once the cloud has a revision. The document goes along while
	// the machine has not applied that revision, never under local control.
	var applianceOut *protocol.ApplianceResponse
	if reported != nil {
		d.applianceReports = append(d.applianceReports, append(json.RawMessage(nil), req.Appliance...))
		if d.applianceRevision >= 1 {
			applianceOut = &protocol.ApplianceResponse{Revision: d.applianceRevision}
			if reported.Control != appliance.ControlLocal && reported.AppliedRevision != d.applianceRevision {
				applianceOut.Document = d.applianceDocument
				d.documentsSent = append(d.documentsSent, d.applianceRevision)
			}
		}
	}

	switch {
	case fault != nil && fault.ProcessThenFail:
		writeError(w, http.StatusInternalServerError, "internal_error", "Injected failure after processing.")
		return
	case fault != nil && fault.Hang:
		s.mu.Unlock()
		<-r.Context().Done()
		s.mu.Lock()
		return
	case fault != nil && fault.HugeBody:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"accepted":1,"padding":"`)
		chunk := bytes.Repeat([]byte("x"), 64*1024)
		for i := 0; i < 40; i++ { // 2.5 MiB
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
		_, _ = io.WriteString(w, `"}`)
		return
	case fault != nil && fault.RawBody != nil:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fault.RawBody)
		return
	}
	writeJSON(w, http.StatusOK, protocol.HeartbeatResponse{
		Accepted: rec.Accepted, Duplicates: rec.Duplicates, HighestSeq: d.highest,
		ServerTime: protocol.FormatTime(s.now()), NextIntervalS: 60,
		Operations: d.deliverable(),
		Appliance:  applianceOut,
	})
}

// ValidateAppliance strictly decodes the appliance object of a heartbeat
// (docs/appliance.md, section 6.1): exactly the contract's keys, schema 1,
// and already within the contract's bounds (sanitising it again changes
// nothing), which is what the agent promises to send.
func ValidateAppliance(raw json.RawMessage) (*appliance.Reported, error) {
	var r appliance.Reported
	if err := strictDecode(raw, &r); err != nil {
		return nil, fmt.Errorf("not the contract's object: %v", err)
	}
	if r.Schema != appliance.DocumentSchema {
		return nil, fmt.Errorf("schema must be %d", appliance.DocumentSchema)
	}
	if r.Catalog == nil || r.Plugins == nil || r.NAS == nil || r.Secrets == nil || r.Schedules == nil {
		return nil, fmt.Errorf("lists must be present (empty, not null)")
	}
	clean := r
	clean.Sanitize()
	a, _ := json.Marshal(r)
	b, _ := json.Marshal(clean)
	if !bytes.Equal(a, b) {
		return nil, fmt.Errorf("not sanitised: %s", b)
	}
	return &r, nil
}

func (s *Server) handleUpdate(w http.ResponseWriter, _ *http.Request, d *device) {
	d.updateRequests++
	offer := protocol.UpdateResponse{Channel: "none", Policy: "manual"}
	if d.updateOffer != nil {
		offer = *d.updateOffer
	}
	writeJSON(w, http.StatusOK, offer)
}

func (s *Server) handleArtifact(w http.ResponseWriter, r *http.Request, d *device) {
	version := r.PathValue("version")
	d.artifactRequests = append(d.artifactRequests, version)
	if s.artifactHandler != nil {
		s.artifactHandler(w, r)
		return
	}
	data, ok := s.artifacts[version]
	if !ok || d.updateOffer == nil || d.updateOffer.Channel == "none" {
		writeError(w, http.StatusNotFound, protocol.CodeNotFound, "No such release.")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprint(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// ValidateSample strictly decodes one sample and enforces the protocol
// bounds. Unknown keys anywhere in the sample are an error.
func ValidateSample(raw json.RawMessage, out *protocol.Sample) error {
	if err := strictDecode(raw, out); err != nil {
		return err
	}
	if out.Seq == 0 {
		return fmt.Errorf("seq missing")
	}
	if _, err := time.Parse(protocol.TimeFormat, out.CollectedAt); err != nil {
		return fmt.Errorf("collected_at is not RFC 3339 UTC")
	}
	if out.Disks == nil || out.GPUs == nil || out.Services == nil {
		return fmt.Errorf("disks, gpus and services are required")
	}
	if len(out.GPUs) > protocol.MaxGPUs || len(out.Disks) > protocol.MaxDisks || len(out.Services) > protocol.MaxServices {
		return fmt.Errorf("too many gpus, disks or services")
	}
	long := func(v string) bool { return len([]rune(v)) > protocol.MaxStringLen }
	if long(out.CPU.Model) {
		return fmt.Errorf("string too long")
	}
	for _, g := range out.GPUs {
		if long(g.UUID) || long(g.Name) || long(g.DriverVersion) {
			return fmt.Errorf("string too long")
		}
	}
	for _, disk := range out.Disks {
		if long(disk.Mount) || long(disk.FS) {
			return fmt.Errorf("string too long")
		}
	}
	for name, state := range out.Services {
		switch state {
		case protocol.ServiceActive, protocol.ServiceInactive, protocol.ServiceFailed,
			protocol.ServiceActivating, protocol.ServiceNotInstalled, protocol.ServiceUnknown:
		default:
			return fmt.Errorf("invalid service state")
		}
		if long(name) {
			return fmt.Errorf("string too long")
		}
	}
	if h := out.Vast.MachineIDHint; h != nil && !reFingerprint.MatchString(*h) {
		return fmt.Errorf("machine_id_hint is not a sha256")
	}
	return nil
}

// deliverable returns the operations to send: pending ones that were not
// acknowledged "accepted" yet.
func (d *device) deliverable() []protocol.Operation {
	out := []protocol.Operation{}
	for _, op := range d.pending {
		if !d.accepted[op.ID] {
			out = append(out, op)
		}
	}
	return out
}

func (s *Server) handleOperations(w http.ResponseWriter, _ *http.Request, d *device) {
	writeJSON(w, http.StatusOK, protocol.OperationsResponse{Operations: d.deliverable()})
}

func (s *Server) handleAck(w http.ResponseWriter, r *http.Request, d *device) {
	id := r.PathValue("id")
	data, ok := readBody(w, r)
	if !ok {
		return
	}
	var ack protocol.AckRequest
	if err := strictDecode(data, &ack); err != nil {
		writeError(w, http.StatusUnprocessableEntity, protocol.CodeInvalidRequest, "Invalid request.")
		return
	}
	switch ack.Status {
	case protocol.AckAccepted, protocol.AckRejected, protocol.AckSucceeded, protocol.AckFailed:
	default:
		writeError(w, http.StatusUnprocessableEntity, protocol.CodeInvalidRequest, "Invalid status.")
		return
	}
	if len([]rune(ack.Detail)) > protocol.MaxDetailLen || len(ack.Result) > protocol.MaxResultBytes {
		writeError(w, http.StatusUnprocessableEntity, protocol.CodeInvalidRequest, "Detail or result too large.")
		return
	}
	if _, err := time.Parse(protocol.TimeFormat, ack.CompletedAt); err != nil {
		writeError(w, http.StatusUnprocessableEntity, protocol.CodeInvalidRequest, "Invalid completed_at.")
		return
	}
	d.acks = append(d.acks, AckRecord{OperationID: id, Body: ack})
	if _, done := d.final[id]; done {
		writeError(w, http.StatusConflict, protocol.CodeConflict, "Operation already has a final acknowledgement.")
		return
	}
	index := -1
	for i, op := range d.pending {
		if op.ID == id {
			index = i
		}
	}
	if index < 0 {
		writeError(w, http.StatusNotFound, protocol.CodeNotFound, "Unknown operation.")
		return
	}
	op := d.pending[index]
	if ack.Nonce != op.Nonce {
		writeError(w, http.StatusForbidden, protocol.CodeForbidden, "Nonce mismatch.")
		return
	}
	if exp, err := time.Parse(time.RFC3339, op.ExpiresAt); err == nil && !s.now().Before(exp) {
		d.final[id] = "expired"
		d.pending = append(d.pending[:index], d.pending[index+1:]...)
		writeError(w, http.StatusGone, protocol.CodeExpired, "Operation expired.")
		return
	}
	if ack.Status != protocol.AckAccepted {
		d.final[id] = ack.Status
		d.pending = append(d.pending[:index], d.pending[index+1:]...)
		delete(d.accepted, id)
	} else {
		if d.accepted == nil {
			d.accepted = map[string]bool{}
		}
		d.accepted[id] = true
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "recorded"})
}

func (s *Server) handleRotate(w http.ResponseWriter, _ *http.Request, d *device) {
	credID := newUUID()
	token := newToken(credID)
	old := d.tokenHash
	d.prevTokenHash = &old
	d.tokenHash = sha256.Sum256([]byte(token))
	d.credID = credID
	d.rotations++
	writeJSON(w, http.StatusOK, protocol.RotateResponse{Credential: protocol.Credential{ID: credID, Token: token}})
}

func (s *Server) handleSelf(w http.ResponseWriter, _ *http.Request, d *device) {
	writeJSON(w, http.StatusOK, protocol.SelfResponse{
		DeviceID: d.id, MachineID: d.machineID, Status: "active", ServerTime: protocol.FormatTime(s.now()),
	})
}

// Summary is the test-only overview served at GET /_test/summary.
type Summary struct {
	Devices []DeviceSummary `json:"devices"`
}

// DeviceSummary is one device in a Summary.
type DeviceSummary struct {
	DeviceID          string `json:"device_id"`
	Hostname          string `json:"hostname"`
	Samples           int    `json:"samples"`
	SyntheticSamples  int    `json:"synthetic_samples"`
	HighestSeq        uint64 `json:"highest_seq"`
	Duplicates        int    `json:"duplicates"`
	HeartbeatRequests int    `json:"heartbeat_requests"`
	Contiguous        bool   `json:"contiguous"`
}

// Summarize builds the test-only overview.
func (s *Server) Summarize() Summary {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out Summary
	for _, d := range s.devices {
		contiguous := true
		var lowest uint64
		for seq := range d.samples {
			if lowest == 0 || seq < lowest {
				lowest = seq
			}
		}
		for seq := lowest; lowest != 0 && seq <= d.highest; seq++ {
			if _, ok := d.samples[seq]; !ok {
				contiguous = false
			}
		}
		out.Devices = append(out.Devices, DeviceSummary{
			DeviceID: d.id, Hostname: d.hostname, Samples: len(d.samples), SyntheticSamples: d.synthetic,
			HighestSeq: d.highest, Duplicates: d.duplicates, HeartbeatRequests: len(d.heartbeats), Contiguous: contiguous,
		})
	}
	return out
}

func (s *Server) handleSummary(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Summarize())
}
