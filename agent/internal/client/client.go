// Package client is the HTTP client for HappyMining's own device API
// (docs/agent-protocol.md). It never talks to Vast.ai.
//
// Everything is bounded: connection, TLS and overall timeouts, the request
// body (256 KiB) and the response body (1 MiB). TLS certificates are always
// verified (system roots plus an optional CA file, TLS 1.2 minimum); there is
// no option to skip verification. Plain HTTP is only possible to a loopback
// address and only when explicitly allowed.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/backoff"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/credential"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/version"
)

// MaxResponseBytes bounds every response body the client reads.
const MaxResponseBytes = 1024 * 1024

// DefaultTimeout bounds a whole request, including reading the response.
const DefaultTimeout = 60 * time.Second

// Sentinel errors.
var (
	// ErrResponseTooLarge means the server sent more than MaxResponseBytes.
	ErrResponseTooLarge = errors.New("response body larger than the 1 MiB limit")
	// ErrRequestTooLarge means the request would exceed the 256 KiB limit.
	ErrRequestTooLarge = errors.New("request body larger than the 256 KiB limit")
	// ErrMalformedResponse means a 2xx response was not the expected JSON.
	ErrMalformedResponse = errors.New("malformed response from the API")
)

// APIError is a non-2xx response.
type APIError struct {
	Status     int
	Code       string // empty when the body was not the protocol's error envelope
	Message    string
	RequestID  string
	RetryAfter time.Duration
	HasRetry   bool
}

func (e *APIError) Error() string {
	code := e.Code
	if code == "" {
		code = "no error envelope"
	}
	msg := fmt.Sprintf("API returned HTTP %d (%s)", e.Status, code)
	if e.Message != "" {
		msg += ": " + e.Message
	}
	if e.RequestID != "" {
		msg += " [request " + e.RequestID + "]"
	}
	return msg
}

// Options configures a Client.
type Options struct {
	BaseURL               string
	CAFile                string
	AllowInsecureLoopback bool
	Timeout               time.Duration
	// WrapTransport, if set, wraps the HTTP transport. The simulator uses it to
	// inject outages and lost responses in front of the real client code.
	WrapTransport func(http.RoundTripper) http.RoundTripper
}

// Client talks to one API base URL.
type Client struct {
	base string
	hc   *http.Client
}

// ValidateBaseURL enforces the transport policy on a base URL.
func ValidateBaseURL(raw string, allowInsecureLoopback bool) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("API URL is empty (set HM_API_URL)")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("API URL is not a valid URL")
	}
	if u.Host == "" || u.Hostname() == "" {
		return nil, errors.New("API URL has no host")
	}
	if u.User != nil {
		return nil, errors.New("API URL must not contain credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("API URL must not contain a query or fragment")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowInsecureLoopback {
			return nil, errors.New("plain HTTP is refused; use https (HTTP is only possible for loopback with HM_ALLOW_INSECURE_LOOPBACK=1)")
		}
		if !isLoopbackHost(u.Hostname()) {
			return nil, errors.New("plain HTTP is only allowed for 127.0.0.1, ::1 or localhost")
		}
	default:
		return nil, fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// New builds a Client.
func New(opts Options) (*Client, error) {
	u, err := ValidateBaseURL(opts.BaseURL, opts.AllowInsecureLoopback)
	if err != nil {
		return nil, err
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if opts.CAFile != "" {
		pem, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA file %s contains no certificate", opts.CAFile)
		}
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
		},
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  timeout,
		ExpectContinueTimeout:  time.Second,
		IdleConnTimeout:        90 * time.Second,
		MaxIdleConns:           2,
		MaxConnsPerHost:        2,
		MaxResponseHeaderBytes: 64 * 1024,
		ForceAttemptHTTP2:      true,
	}
	var rt http.RoundTripper = transport
	if opts.WrapTransport != nil {
		rt = opts.WrapTransport(rt)
	}
	return &Client{
		base: u.String(),
		hc: &http.Client{
			Transport: rt,
			Timeout:   timeout,
			// Never follow redirects: a bearer token must only ever go to
			// the configured base URL.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// BaseURL returns the normalised base URL.
func (c *Client) BaseURL() string { return c.base }

// CloseIdle closes idle connections.
func (c *Client) CloseIdle() { c.hc.CloseIdleConnections() }

func readLimited(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxResponseBytes+1))
	if err != nil {
		return data, err
	}
	if len(data) > MaxResponseBytes {
		return nil, ErrResponseTooLarge
	}
	return data, nil
}

func (c *Client) do(ctx context.Context, method, path, token string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		if len(raw) > protocol.MaxRequestBodyBytes {
			return ErrRequestTooLarge
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "happymining-agent/"+version.Version)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		if !credential.ValidToken(token) {
			return errors.New("refusing to send a credential that does not have the expected format")
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, readErr := readLimited(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return apiError(resp, data)
	}
	if readErr != nil {
		return fmt.Errorf("%s %s: read response: %w", method, path, readErr)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s %s: %w", method, path, ErrMalformedResponse)
	}
	return nil
}

func apiError(resp *http.Response, data []byte) *APIError {
	e := &APIError{Status: resp.StatusCode}
	var env protocol.ErrorEnvelope
	if json.Unmarshal(data, &env) == nil {
		e.Code = protocol.Truncate(env.Error.Code, 64)
		e.Message = protocol.Truncate(env.Error.Message, 300)
		e.RequestID = protocol.Truncate(env.Error.RequestID, 64)
	}
	if e.RequestID == "" {
		e.RequestID = protocol.Truncate(resp.Header.Get("X-Request-ID"), 64)
	}
	if d, ok := backoff.ParseRetryAfter(resp.Header.Get("Retry-After")); ok {
		e.RetryAfter, e.HasRetry = d, true
	}
	return e
}

// Enroll exchanges a pairing code for a device credential. It is never
// retried automatically.
func (c *Client) Enroll(ctx context.Context, req *protocol.EnrollRequest) (*protocol.EnrollResponse, error) {
	var out protocol.EnrollResponse
	if err := c.do(ctx, http.MethodPost, protocol.PathEnroll, "", req, &out); err != nil {
		return nil, err
	}
	if out.DeviceID == "" || out.MachineID == "" || out.Credential.ID == "" || !credential.ValidToken(out.Credential.Token) {
		return nil, fmt.Errorf("enrollment: %w", ErrMalformedResponse)
	}
	return &out, nil
}

// Heartbeat sends a batch of samples.
func (c *Client) Heartbeat(ctx context.Context, token string, req *protocol.HeartbeatRequest) (*protocol.HeartbeatResponse, error) {
	if len(req.Samples) < 1 || len(req.Samples) > protocol.MaxSamplesPerRequest {
		return nil, fmt.Errorf("heartbeat must carry 1 to %d samples", protocol.MaxSamplesPerRequest)
	}
	var out *protocol.HeartbeatResponse
	if err := c.do(ctx, http.MethodPost, protocol.PathHeartbeat, token, req, &out); err != nil {
		return nil, err
	}
	if out == nil { // the body was the JSON literal null
		return nil, fmt.Errorf("heartbeat: %w", ErrMalformedResponse)
	}
	return out, nil
}

// reOperationID matches the operation ids the agent is willing to put into a
// URL path (UUIDs).
var reOperationID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ValidOperationID reports whether id is a UUID.
func ValidOperationID(id string) bool { return reOperationID.MatchString(id) }

// AckOperation acknowledges an operation.
func (c *Client) AckOperation(ctx context.Context, token, id string, ack *protocol.AckRequest) error {
	if !ValidOperationID(id) {
		return errors.New("operation id is not a UUID")
	}
	return c.do(ctx, http.MethodPost, protocol.PathOperations+"/"+id+"/ack", token, ack, nil)
}

// ListOperations returns the pending operations.
func (c *Client) ListOperations(ctx context.Context, token string) ([]protocol.Operation, error) {
	var out protocol.OperationsResponse
	if err := c.do(ctx, http.MethodGet, protocol.PathOperations, token, nil, &out); err != nil {
		return nil, err
	}
	return out.Operations, nil
}

// RotateCredential asks for a new credential using the current one.
func (c *Client) RotateCredential(ctx context.Context, token string) (*protocol.Credential, error) {
	var out protocol.RotateResponse
	if err := c.do(ctx, http.MethodPost, protocol.PathRotate, token, struct{}{}, &out); err != nil {
		return nil, err
	}
	if out.Credential.ID == "" || !credential.ValidToken(out.Credential.Token) {
		return nil, fmt.Errorf("credential rotation: %w", ErrMalformedResponse)
	}
	return &out.Credential, nil
}

// Self checks connectivity and credential validity.
func (c *Client) Self(ctx context.Context, token string) (*protocol.SelfResponse, error) {
	var out protocol.SelfResponse
	if err := c.do(ctx, http.MethodGet, protocol.PathSelf, token, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Probe reports whether the API host answers HTTP at all (any status), with
// TLS verification. It sends no credential. Preflight uses it.
func (c *Client) Probe(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+protocol.PathSelf, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "happymining-agent/"+version.Version)
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, nil
}

// Action is what the agent does with a failed heartbeat.
type Action int

// Heartbeat failure handling, derived from the protocol's error table.
const (
	// ActionRetry: 5xx, network error, timeout, malformed or oversized
	// response, or a non-2xx response without the protocol's error envelope.
	ActionRetry Action = iota
	// ActionRetryAfter: 429, wait Retry-After then retry with jitter.
	ActionRetryAfter
	// ActionUnauthorized: 401 device_unauthorized. Stop sending.
	ActionUnauthorized
	// ActionDropPayload: 400/422 invalid_request. Do not resend this payload.
	ActionDropPayload
	// ActionSplit: 413. Split the batch and retry.
	ActionSplit
	// ActionHold: 403/404/409/410 on a heartbeat. Keep the samples, back off.
	ActionHold
)

// Classify maps an error from Heartbeat to an Action.
func Classify(err error) Action {
	var api *APIError
	if !errors.As(err, &api) {
		return ActionRetry
	}
	switch {
	case api.Status == http.StatusTooManyRequests:
		return ActionRetryAfter
	case api.Status == http.StatusRequestEntityTooLarge:
		return ActionSplit
	case api.Status >= 500:
		return ActionRetry
	case api.Code == "":
		// Not our API speaking (a proxy, a captive portal): never drop data
		// or declare the device revoked on such a response.
		return ActionRetry
	case api.Status == http.StatusUnauthorized && api.Code == protocol.CodeDeviceUnauthorized:
		return ActionUnauthorized
	case api.Status == http.StatusBadRequest || api.Status == http.StatusUnprocessableEntity:
		return ActionDropPayload
	case api.Status == http.StatusForbidden, api.Status == http.StatusNotFound,
		api.Status == http.StatusConflict, api.Status == http.StatusGone:
		return ActionHold
	}
	return ActionRetry
}

// IsFinalForAck reports whether an acknowledgement error is final (the
// acknowledgement must not be sent again).
func IsFinalForAck(err error) bool {
	var api *APIError
	if !errors.As(err, &api) {
		return false
	}
	if api.Code == "" {
		return false
	}
	switch api.Status {
	case http.StatusBadRequest, http.StatusUnprocessableEntity, http.StatusForbidden,
		http.StatusNotFound, http.StatusConflict, http.StatusGone:
		return true
	}
	return false
}
