package backup

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// S3 limits and defaults. The part limits are Amazon S3's: at most 10000
// parts, each at least 5 MiB except the last.
const (
	// DefaultS3PartSize is the size of one multipart part, and so the memory
	// an upload uses. With it an archive can be up to about 156 GiB.
	DefaultS3PartSize = 16 << 20
	// MinS3PartSize and MaxS3PartSize bound S3Config.PartSize.
	MinS3PartSize = 5 << 20
	MaxS3PartSize = 512 << 20

	maxS3Parts          = 10000
	maxS3ResponseBytes  = 8 << 20
	maxS3ListPages      = 1000
	defaultS3Timeout    = 60 * time.Second
	defaultS3PartTime   = 15 * time.Minute
	defaultS3IdleTime   = 2 * time.Minute
	defaultS3MaxRetries = 3

	sigV4Algorithm = "AWS4-HMAC-SHA256"
	sigV4TimeForm  = "20060102T150405Z"
	sigV4DateForm  = "20060102"
	s3Service      = "s3"
)

// S3Config describes an S3-compatible destination. The field rules are those
// of docs/appliance.md, section 4.5.
//
// An S3Config prints with its secret redacted, with every fmt verb.
type S3Config struct {
	// Endpoint is "https://host[:port]": no path, no query, no user info.
	// Addressing is path-style: https://host/bucket/key.
	Endpoint string
	// Region is the signing region, for example "eu-west-3".
	Region string
	Bucket string
	// Prefix is put in front of every archive name, followed by "/". Empty
	// means the root of the bucket.
	Prefix          string
	AccessKeyID     string
	SecretAccessKey string

	// PartSize is the size of one multipart part in bytes, between
	// MinS3PartSize and MaxS3PartSize. Zero means DefaultS3PartSize. One part
	// is held in memory; an archive may have at most 10000 parts.
	PartSize int64
	// RequestTimeout bounds every small request and the wait for the answer
	// to any request. Zero means 60 s.
	RequestTimeout time.Duration
	// PartTimeout bounds one attempt at sending one part. Zero means 15 min.
	PartTimeout time.Duration
	// IdleTimeout bounds how long a download may stay without receiving
	// anything. Zero means 2 min.
	IdleTimeout time.Duration
	// MaxRetries is how many times a request is repeated after a 500, 502,
	// 503 or 504 answer, or (for requests that can safely be repeated) after
	// a network error or a timeout. Zero means 3; a negative value means no
	// retry.
	MaxRetries int
	// AllowLoopbackHTTP accepts an "http://" endpoint whose host is a literal
	// loopback address (127.0.0.0/8 or ::1). It exists for tests. Anything
	// else must be HTTPS whatever this says.
	AllowLoopbackHTTP bool
}

// Format implements fmt.Formatter: the secret key is never printed.
func (c S3Config) Format(f fmt.State, _ rune) {
	fmt.Fprintf(f, "S3Config{Endpoint:%q Region:%q Bucket:%q Prefix:%q AccessKeyID:%q SecretAccessKey:(redacted)}",
		c.Endpoint, c.Region, c.Bucket, c.Prefix, c.AccessKeyID)
}

var (
	reS3Host      = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
	reS3Region    = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)
	reS3Bucket    = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	reS3Prefix    = regexp.MustCompile(`^[A-Za-z0-9._/-]{0,200}$`)
	reS3AccessKey = regexp.MustCompile(`^[A-Za-z0-9]{4,128}$`)
	reS3Code      = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// S3Error is an answer of the storage service that is not the expected one.
// It carries the HTTP status and the service's error code, never the body of
// the answer.
type S3Error struct {
	// Op is the operation: "PutObject", "UploadPart", ...
	Op     string
	Status int
	// Code is the service's error code ("NoSuchBucket", "AccessDenied",
	// ...), or "" when the answer had none.
	Code string
}

func (e *S3Error) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("backup: s3 %s: HTTP %d", e.Op, e.Status)
	}
	return fmt.Sprintf("backup: s3 %s: HTTP %d (%s)", e.Op, e.Status, e.Code)
}

// S3Destination keeps archives in an S3-compatible bucket, with AWS Signature
// Version 4 and path-style addressing.
//
// An archive that fits in one part is sent with one PutObject; a larger one is
// a multipart upload, read and sent part by part, each part hashed (SHA-256),
// the hash signed and checked by the service. If anything fails the multipart
// upload is aborted, so that no part is left behind and no object appears.
//
// Redirects are not followed. The secret key is used to sign and appears in no
// request, error or log.
//
// Verified against Amazon's documentation and against the in-package test
// server only; see the package tests. Not exercised against a real service.
type S3Destination struct {
	base      string // scheme://host[:port]
	host      string // the Host header
	region    string
	bucket    string
	prefix    string // "" or "a/b/" (with the trailing slash)
	accessKey string
	secret    string

	partSize       int64
	requestTimeout time.Duration
	partTimeout    time.Duration
	idleTimeout    time.Duration
	maxRetries     int

	client *http.Client
	now    func() time.Time
	sleep  func(ctx context.Context, d time.Duration) error
}

// Format implements fmt.Formatter: the secret key is never printed.
func (s *S3Destination) Format(f fmt.State, _ rune) {
	fmt.Fprintf(f, "S3Destination{%s/%s/%s}", s.base, s.bucket, s.prefix)
}

// NewS3Destination validates cfg and returns the destination. It makes no
// request.
func NewS3Destination(cfg S3Config) (*S3Destination, error) {
	bad := func(what string) (*S3Destination, error) {
		return nil, fmt.Errorf("%w: s3 %s", ErrInvalidConfig, what)
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return bad("endpoint must be https://host[:port]")
	}
	hostname := strings.ToLower(u.Hostname())
	ip := net.ParseIP(hostname)
	if ip == nil && !reS3Host.MatchString(hostname) {
		return bad("endpoint host")
	}
	if port := u.Port(); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return bad("endpoint port")
		}
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !cfg.AllowLoopbackHTTP || ip == nil || !ip.IsLoopback() {
			return bad("endpoint must use https")
		}
	default:
		return bad("endpoint must use https")
	}
	if !reS3Region.MatchString(cfg.Region) {
		return bad("region")
	}
	if !reS3Bucket.MatchString(cfg.Bucket) {
		return bad("bucket")
	}
	if !reS3Prefix.MatchString(cfg.Prefix) || strings.Contains(cfg.Prefix, "..") {
		return bad("prefix")
	}
	var segments []string
	for _, seg := range strings.Split(cfg.Prefix, "/") {
		switch seg {
		case "":
			// Leading, trailing and doubled slashes are dropped.
		case ".":
			return bad("prefix")
		default:
			segments = append(segments, seg)
		}
	}
	prefix := ""
	if len(segments) > 0 {
		prefix = strings.Join(segments, "/") + "/"
	}
	if !reS3AccessKey.MatchString(cfg.AccessKeyID) {
		return bad("access key id")
	}
	if cfg.SecretAccessKey == "" || len(cfg.SecretAccessKey) > 1024 ||
		strings.ContainsFunc(cfg.SecretAccessKey, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return bad("secret key")
	}
	partSize := cfg.PartSize
	if partSize == 0 {
		partSize = DefaultS3PartSize
	}
	if partSize < MinS3PartSize || partSize > MaxS3PartSize {
		return bad("part size")
	}
	orDefault := func(d, def time.Duration) time.Duration {
		if d <= 0 {
			return def
		}
		return d
	}
	s := &S3Destination{
		base:           u.Scheme + "://" + strings.ToLower(u.Host),
		host:           strings.ToLower(u.Host),
		region:         cfg.Region,
		bucket:         cfg.Bucket,
		prefix:         prefix,
		accessKey:      cfg.AccessKeyID,
		secret:         cfg.SecretAccessKey,
		partSize:       partSize,
		requestTimeout: orDefault(cfg.RequestTimeout, defaultS3Timeout),
		partTimeout:    orDefault(cfg.PartTimeout, defaultS3PartTime),
		idleTimeout:    orDefault(cfg.IdleTimeout, defaultS3IdleTime),
		maxRetries:     cfg.MaxRetries,
		now:            time.Now,
		sleep:          sleepContext,
	}
	switch {
	case s.maxRetries == 0:
		s.maxRetries = defaultS3MaxRetries
	case s.maxRetries < 0:
		s.maxRetries = 0
	}
	s.client = &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: s.requestTimeout,
			ExpectContinueTimeout: time.Second,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConns:          4,
			// Archives are sent and received as they are.
			DisableCompression: true,
		},
		// A redirect is an answer like any other: it is not followed, so a
		// signed request never goes to a host that was not configured.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return s, nil
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// --- AWS Signature Version 4 -------------------------------------------------
//
// Written from "Create a signed AWS API request" (IAM User Guide) and
// "Authenticating Requests: Using the Authorization Header" (Amazon S3 API
// Reference); the worked examples of the latter are tests of this code.

// uriEncode is AWS's UriEncode: every byte except the unreserved characters
// A-Z a-z 0-9 - . _ ~ becomes %XX with upper-case hexadecimal digits. "/" is
// kept in an object path and encoded everywhere else.
func uriEncode(s string, encodeSlash bool) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0x0f])
		}
	}
	return b.String()
}

// canonicalQuery encodes each name and value and sorts the pairs by encoded
// name (then value). A parameter without a value is "name=".
func canonicalQuery(params [][2]string) string {
	pairs := make([]string, 0, len(params))
	for _, p := range params {
		pairs = append(pairs, uriEncode(p[0], true)+"="+uriEncode(p[1], true))
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

// sigV4CanonicalRequest builds the canonical request and the list of signed
// headers. headers maps lower-case header names to values and must contain
// "host". canonicalURI is the path as it is sent, encoded once (Amazon S3
// does not encode twice and does not normalise the path).
func sigV4CanonicalRequest(method, canonicalURI, query string, headers map[string]string, payloadHash string) (request, signedHeaders string) {
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString(method)
	b.WriteByte('\n')
	b.WriteString(canonicalURI)
	b.WriteByte('\n')
	b.WriteString(query)
	b.WriteByte('\n')
	for _, name := range names {
		b.WriteString(name)
		b.WriteByte(':')
		// Trim, and turn runs of spaces into one space.
		b.WriteString(strings.Join(strings.Fields(headers[name]), " "))
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	signedHeaders = strings.Join(names, ";")
	b.WriteString(signedHeaders)
	b.WriteByte('\n')
	b.WriteString(payloadHash)
	return b.String(), signedHeaders
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// sigV4SigningKey derives the signing key of one day, region and service.
func sigV4SigningKey(secret, date, region, service string) []byte {
	k := hmacSHA256([]byte("AWS4"+secret), date)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	return hmacSHA256(k, "aws4_request")
}

// sigV4Authorization returns the Authorization header of a request.
func sigV4Authorization(method, canonicalURI, query string, headers map[string]string, payloadHash string,
	at time.Time, region, service, accessKey, secret string) string {
	at = at.UTC()
	date := at.Format(sigV4DateForm)
	scope := date + "/" + region + "/" + service + "/aws4_request"
	request, signedHeaders := sigV4CanonicalRequest(method, canonicalURI, query, headers, payloadHash)
	hashed := sha256.Sum256([]byte(request))
	stringToSign := sigV4Algorithm + "\n" + at.Format(sigV4TimeForm) + "\n" + scope + "\n" + hex.EncodeToString(hashed[:])
	signature := hex.EncodeToString(hmacSHA256(sigV4SigningKey(secret, date, region, service), stringToSign))
	return sigV4Algorithm + " Credential=" + accessKey + "/" + scope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + signature
}

// --- requests ----------------------------------------------------------------

// s3Request is one request to the service.
type s3Request struct {
	op     string
	method string
	// key is the object key; "" addresses the bucket.
	key   string
	query [][2]string
	// body is the whole payload; nil means none.
	body    []byte
	timeout time.Duration
	// repeatable says the request may be sent again after a network error or
	// a timeout, when it is not known whether the service acted on it.
	repeatable bool
}

type s3Response struct {
	status int
	header http.Header
	body   []byte
}

// send signs and sends rq once.
func (s *S3Destination) send(ctx context.Context, rq s3Request) (*http.Response, error) {
	path := "/" + s.bucket
	if rq.key != "" {
		path += "/" + rq.key
	}
	canonicalURI := uriEncode(path, false)
	query := canonicalQuery(rq.query)
	target := s.base + canonicalURI
	if query != "" {
		target += "?" + query
	}
	var body io.Reader
	if rq.body != nil {
		body = bytes.NewReader(rq.body)
	}
	req, err := http.NewRequestWithContext(ctx, rq.method, target, body)
	if err != nil {
		return nil, errors.New("request could not be built")
	}
	sum := sha256.Sum256(rq.body)
	payloadHash := hex.EncodeToString(sum[:])
	at := s.now().UTC()
	amzDate := at.Format(sigV4TimeForm)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	req.Header.Set("Authorization", sigV4Authorization(rq.method, canonicalURI, query, map[string]string{
		"host":                 s.host,
		"x-amz-content-sha256": payloadHash,
		"x-amz-date":           amzDate,
	}, payloadHash, at, s.region, s3Service, s.accessKey, s.secret))
	return s.client.Do(req)
}

// transportErr removes the URL that net/http puts in its errors.
func transportErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func retryableStatus(status int) bool {
	switch status {
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

func retryDelay(attempt int) time.Duration {
	d := 500 * time.Millisecond << min(attempt, 6)
	return min(d, 20*time.Second)
}

// s3ErrorOf builds the error of an unexpected answer.
func s3ErrorOf(op string, status int, body []byte) *S3Error {
	var e struct {
		XMLName xml.Name `xml:"Error"`
		Code    string   `xml:"Code"`
	}
	code := ""
	if xml.Unmarshal(body, &e) == nil && reS3Code.MatchString(e.Code) {
		code = e.Code
	}
	return &S3Error{Op: op, Status: status, Code: code}
}

// call sends rq, repeating it within the retry budget, and returns the answer
// with its body read. An answer with a status in ok is returned; any other
// answer is an *S3Error.
func (s *S3Destination) call(ctx context.Context, rq s3Request, ok ...int) (*s3Response, error) {
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		actx, cancel := context.WithTimeout(ctx, rq.timeout)
		resp, err := s.send(actx, rq)
		var res *s3Response
		if err == nil {
			var body []byte
			body, err = io.ReadAll(io.LimitReader(resp.Body, maxS3ResponseBytes))
			_ = resp.Body.Close()
			res = &s3Response{status: resp.StatusCode, header: resp.Header, body: body}
		}
		cancel()

		var failure error
		retry := false
		switch {
		case err != nil:
			if cerr := ctx.Err(); cerr != nil {
				return nil, cerr
			}
			failure = fmt.Errorf("backup: s3 %s: %w", rq.op, transportErr(err))
			retry = rq.repeatable
		case retryableStatus(res.status):
			failure = s3ErrorOf(rq.op, res.status, res.body)
			retry = true
		default:
			for _, status := range ok {
				if res.status == status {
					return res, nil
				}
			}
			return res, s3ErrorOf(rq.op, res.status, res.body)
		}
		if !retry || attempt >= s.maxRetries {
			return nil, failure
		}
		if err := s.sleep(ctx, retryDelay(attempt)); err != nil {
			return nil, err
		}
	}
}

func (s *S3Destination) objectKey(name string) string { return s.prefix + name }

// --- Destination ---------------------------------------------------------------

// Put implements Destination. It holds one part (PartSize bytes) in memory.
func (s *S3Destination) Put(ctx context.Context, name string, r io.Reader) error {
	if err := checkArchiveName(name); err != nil {
		return err
	}
	key := s.objectKey(name)
	pr := &partReader{r: ctxReader{ctx, r}, buf: make([]byte, s.partSize)}
	first, last, err := pr.next()
	if err != nil {
		return err
	}
	if last {
		// The whole archive fits in one part.
		_, err := s.call(ctx, s3Request{op: "PutObject", method: http.MethodPut, key: key, body: first,
			timeout: s.partTimeout, repeatable: true}, http.StatusOK)
		return err
	}

	uploadID, err := s.createMultipart(ctx, key)
	if err != nil {
		return err
	}
	parts, err := s.uploadParts(ctx, key, uploadID, pr, first)
	if err == nil {
		err = s.completeMultipart(ctx, key, uploadID, parts)
	}
	if err != nil {
		// Leave nothing behind: without this the service keeps the parts.
		// The caller's context may be the reason of the failure, so the
		// abort gets its own.
		if aerr := s.abortMultipart(context.WithoutCancel(ctx), key, uploadID); aerr != nil {
			return fmt.Errorf("%w (and the unfinished upload could not be aborted: %v)", err, aerr)
		}
		return err
	}
	return nil
}

// partReader cuts a stream into parts of len(buf) bytes. It reads one byte
// ahead, so that the last part is known to be the last when it is returned.
type partReader struct {
	r     io.Reader
	buf   []byte
	ahead byte
	have  bool // ahead holds the first byte of the next part
}

// next returns the next part, valid until the following call, and whether it
// is the last one. Only io.EOF itself ends the stream: any other error of the
// source, io.ErrUnexpectedEOF included, is a failure and is returned as it is.
func (p *partReader) next() (part []byte, last bool, err error) {
	n := 0
	if p.have {
		p.buf[0] = p.ahead
		p.have = false
		n = 1
	}
	for n < len(p.buf) {
		m, err := p.r.Read(p.buf[n:])
		n += m
		if err == io.EOF {
			return p.buf[:n], true, nil
		}
		if err != nil {
			return nil, false, err
		}
	}
	// The part is full. Is there anything after it?
	var one [1]byte
	for {
		m, err := p.r.Read(one[:])
		if m == 1 {
			p.ahead, p.have = one[0], true
			return p.buf, false, nil
		}
		if err == io.EOF {
			return p.buf, true, nil
		}
		if err != nil {
			return nil, false, err
		}
	}
}

func (s *S3Destination) createMultipart(ctx context.Context, key string) (string, error) {
	// Not repeatable after a network error: the service may have created an
	// upload whose id never arrived.
	res, err := s.call(ctx, s3Request{op: "CreateMultipartUpload", method: http.MethodPost, key: key,
		query: [][2]string{{"uploads", ""}}, timeout: s.requestTimeout}, http.StatusOK)
	if err != nil {
		return "", err
	}
	var out struct {
		XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
		UploadID string   `xml:"UploadId"`
	}
	if err := xml.Unmarshal(res.body, &out); err != nil || out.UploadID == "" || len(out.UploadID) > 2048 ||
		strings.ContainsFunc(out.UploadID, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", errors.New("backup: s3 CreateMultipartUpload: the answer has no usable upload id")
	}
	return out.UploadID, nil
}

type s3Part struct {
	number int
	etag   string
}

// uploadParts sends first, which Put already read, and then the rest of the
// stream, one part at a time.
func (s *S3Destination) uploadParts(ctx context.Context, key, uploadID string, pr *partReader, first []byte) ([]s3Part, error) {
	var parts []s3Part
	part, last := first, false
	for number := 1; ; number++ {
		if number > maxS3Parts {
			return nil, ErrTooManyParts
		}
		done, err := s.uploadPart(ctx, key, uploadID, number, part)
		if err != nil {
			return nil, err
		}
		parts = append(parts, done)
		if last {
			return parts, nil
		}
		if part, last, err = pr.next(); err != nil {
			return nil, err
		}
	}
}

func (s *S3Destination) uploadPart(ctx context.Context, key, uploadID string, number int, data []byte) (s3Part, error) {
	res, err := s.call(ctx, s3Request{op: "UploadPart", method: http.MethodPut, key: key,
		query:   [][2]string{{"partNumber", strconv.Itoa(number)}, {"uploadId", uploadID}},
		body:    data,
		timeout: s.partTimeout,
		// Sending a part again replaces the part of the same number.
		repeatable: true}, http.StatusOK)
	if err != nil {
		return s3Part{}, err
	}
	etag := res.header.Get("ETag")
	if etag == "" || len(etag) > 256 || strings.ContainsFunc(etag, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
		return s3Part{}, errors.New("backup: s3 UploadPart: the answer has no usable ETag")
	}
	return s3Part{number: number, etag: etag}, nil
}

func (s *S3Destination) completeMultipart(ctx context.Context, key, uploadID string, parts []s3Part) error {
	var body bytes.Buffer
	body.WriteString(`<CompleteMultipartUpload xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	for _, p := range parts {
		body.WriteString("<Part><PartNumber>")
		body.WriteString(strconv.Itoa(p.number))
		body.WriteString("</PartNumber><ETag>")
		if err := xml.EscapeText(&body, []byte(p.etag)); err != nil {
			return fmt.Errorf("backup: s3 CompleteMultipartUpload: %w", err)
		}
		body.WriteString("</ETag></Part>")
	}
	body.WriteString("</CompleteMultipartUpload>")
	rq := s3Request{op: "CompleteMultipartUpload", method: http.MethodPost, key: key,
		query: [][2]string{{"uploadId", uploadID}}, body: body.Bytes(), timeout: s.requestTimeout}
	// Amazon S3 can answer 200 and then report a failure in the body; its
	// documentation asks to read the body and to try again on an internal
	// error.
	for attempt := 0; ; attempt++ {
		res, err := s.call(ctx, rq, http.StatusOK)
		if err != nil {
			return err
		}
		var out struct {
			XMLName xml.Name
			Code    string `xml:"Code"`
		}
		if err := xml.Unmarshal(res.body, &out); err != nil {
			return errors.New("backup: s3 CompleteMultipartUpload: the answer cannot be read")
		}
		switch out.XMLName.Local {
		case "CompleteMultipartUploadResult":
			return nil
		case "Error":
			failure := s3ErrorOf(rq.op, res.status, res.body)
			if failure.Code != "InternalError" || attempt >= s.maxRetries {
				return failure
			}
			if err := s.sleep(ctx, retryDelay(attempt)); err != nil {
				return err
			}
		default:
			return errors.New("backup: s3 CompleteMultipartUpload: unexpected answer")
		}
	}
}

func (s *S3Destination) abortMultipart(ctx context.Context, key, uploadID string) error {
	// 404: the upload is already gone, which is what is wanted.
	_, err := s.call(ctx, s3Request{op: "AbortMultipartUpload", method: http.MethodDelete, key: key,
		query: [][2]string{{"uploadId", uploadID}}, timeout: s.requestTimeout, repeatable: true},
		http.StatusNoContent, http.StatusOK, http.StatusNotFound)
	return err
}

// Get implements Destination. The body is the archive as stored; it must be
// closed. A download that receives nothing for IdleTimeout fails.
func (s *S3Destination) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	if err := checkArchiveName(name); err != nil {
		return nil, err
	}
	rq := s3Request{op: "GetObject", method: http.MethodGet, key: s.objectKey(name)}
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// The request's context lives as long as the body is read; the wait
		// for the answer is bounded by the transport.
		rctx, cancel := context.WithCancel(ctx)
		resp, err := s.send(rctx, rq)
		if err == nil && resp.StatusCode == http.StatusOK {
			return &idleBody{rc: resp.Body, cancel: cancel, d: s.idleTimeout}, nil
		}
		var failure error
		if err != nil {
			cancel()
			if cerr := ctx.Err(); cerr != nil {
				return nil, cerr
			}
			failure = fmt.Errorf("backup: s3 %s: %w", rq.op, transportErr(err))
		} else {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, maxS3ResponseBytes))
			_ = resp.Body.Close()
			cancel()
			if resp.StatusCode == http.StatusNotFound {
				return nil, ErrNotFound
			}
			failure = s3ErrorOf(rq.op, resp.StatusCode, body)
			if !retryableStatus(resp.StatusCode) {
				return nil, failure
			}
		}
		if attempt >= s.maxRetries {
			return nil, failure
		}
		if err := s.sleep(ctx, retryDelay(attempt)); err != nil {
			return nil, err
		}
	}
}

// idleBody is a response body that fails when a Read waits longer than d.
type idleBody struct {
	rc     io.ReadCloser
	cancel context.CancelFunc
	d      time.Duration

	mu    sync.Mutex
	timer *time.Timer
	fired bool
}

func (b *idleBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	if b.timer == nil {
		b.timer = time.AfterFunc(b.d, func() {
			b.mu.Lock()
			b.fired = true
			b.mu.Unlock()
			b.cancel()
		})
	} else {
		b.timer.Reset(b.d)
	}
	b.mu.Unlock()

	n, err := b.rc.Read(p)

	b.mu.Lock()
	b.timer.Stop()
	fired := b.fired
	b.mu.Unlock()
	if err != nil && err != io.EOF {
		if fired {
			err = fmt.Errorf("backup: s3 GetObject: nothing received for %s", b.d)
		} else {
			err = fmt.Errorf("backup: s3 GetObject: %w", transportErr(err))
		}
	}
	return n, err
}

func (b *idleBody) Close() error {
	b.mu.Lock()
	if b.timer != nil {
		b.timer.Stop()
	}
	b.mu.Unlock()
	b.cancel()
	return b.rc.Close()
}

// List implements Destination: ListObjectsV2 under the prefix, page after
// page. Only objects directly under the prefix whose name is an archive name
// are returned.
func (s *S3Destination) List(ctx context.Context) ([]Entry, error) {
	var entries []Entry
	token := ""
	for page := 0; ; page++ {
		if page >= maxS3ListPages {
			return nil, fmt.Errorf("backup: s3 ListObjectsV2: more than %d pages", maxS3ListPages)
		}
		query := [][2]string{{"list-type", "2"}, {"delimiter", "/"}}
		if s.prefix != "" {
			query = append(query, [2]string{"prefix", s.prefix})
		}
		if token != "" {
			query = append(query, [2]string{"continuation-token", token})
		}
		res, err := s.call(ctx, s3Request{op: "ListObjectsV2", method: http.MethodGet, query: query,
			timeout: s.requestTimeout, repeatable: true}, http.StatusOK)
		if err != nil {
			return nil, err
		}
		var out struct {
			XMLName               xml.Name `xml:"ListBucketResult"`
			IsTruncated           bool     `xml:"IsTruncated"`
			NextContinuationToken string   `xml:"NextContinuationToken"`
			Contents              []struct {
				Key          string `xml:"Key"`
				LastModified string `xml:"LastModified"`
				Size         int64  `xml:"Size"`
			} `xml:"Contents"`
		}
		if err := xml.Unmarshal(res.body, &out); err != nil {
			return nil, errors.New("backup: s3 ListObjectsV2: the answer cannot be read")
		}
		for _, c := range out.Contents {
			name, found := strings.CutPrefix(c.Key, s.prefix)
			if !found || checkArchiveName(name) != nil {
				continue
			}
			if len(entries) >= maxListEntries {
				return nil, fmt.Errorf("backup: s3 ListObjectsV2: more than %d archives", maxListEntries)
			}
			// LastModified is informative; an unreadable one is left zero.
			modified, _ := time.Parse(time.RFC3339, c.LastModified)
			entries = append(entries, Entry{Name: name, Size: c.Size, ModTime: modified})
		}
		if !out.IsTruncated {
			break
		}
		if out.NextContinuationToken == "" || out.NextContinuationToken == token {
			return nil, errors.New("backup: s3 ListObjectsV2: truncated listing without a new continuation token")
		}
		token = out.NextContinuationToken
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

// Delete implements Destination.
func (s *S3Destination) Delete(ctx context.Context, name string) error {
	if err := checkArchiveName(name); err != nil {
		return err
	}
	_, err := s.call(ctx, s3Request{op: "DeleteObject", method: http.MethodDelete, key: s.objectKey(name),
		timeout: s.requestTimeout, repeatable: true}, http.StatusNoContent, http.StatusOK, http.StatusNotFound)
	return err
}
