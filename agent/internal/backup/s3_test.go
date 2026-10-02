package backup

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- Signature Version 4: Amazon's published examples --------------------------------

// The credentials and the request time of the examples in "Authenticating
// Requests: Using the Authorization Header (AWS Signature Version 4)", Amazon
// S3 API Reference (docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html).
const (
	awsExampleAccessKey = "AKIAIOSFODNN7EXAMPLE"
	awsExampleSecret    = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	awsExampleRegion    = "us-east-1"
	awsExampleHost      = "examplebucket.s3.amazonaws.com"
	emptyPayloadHash    = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

var awsExampleTime = time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)

type awsExample struct {
	name    string
	method  string
	path    string // not encoded
	query   [][2]string
	headers map[string]string
	payload string
	// From the documentation.
	canonicalRequest     string
	canonicalRequestHash string
	signature            string
}

func awsExamples() []awsExample {
	putHash := "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
	return []awsExample{
		{
			name: "GET Object", method: "GET", path: "/test.txt",
			headers: map[string]string{"host": awsExampleHost, "range": "bytes=0-9",
				"x-amz-content-sha256": emptyPayloadHash, "x-amz-date": "20130524T000000Z"},
			canonicalRequest: "GET\n/test.txt\n\nhost:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\n" +
				"x-amz-content-sha256:" + emptyPayloadHash + "\nx-amz-date:20130524T000000Z\n\n" +
				"host;range;x-amz-content-sha256;x-amz-date\n" + emptyPayloadHash,
			canonicalRequestHash: "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972",
			signature:            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
		},
		{
			name: "PUT Object", method: "PUT", path: "/test$file.text", payload: "Welcome to Amazon S3.",
			headers: map[string]string{"date": "Fri, 24 May 2013 00:00:00 GMT", "host": awsExampleHost,
				"x-amz-content-sha256": putHash, "x-amz-date": "20130524T000000Z", "x-amz-storage-class": "REDUCED_REDUNDANCY"},
			canonicalRequest: "PUT\n/test%24file.text\n\ndate:Fri, 24 May 2013 00:00:00 GMT\nhost:examplebucket.s3.amazonaws.com\n" +
				"x-amz-content-sha256:" + putHash + "\nx-amz-date:20130524T000000Z\nx-amz-storage-class:REDUCED_REDUNDANCY\n\n" +
				"date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class\n" + putHash,
			canonicalRequestHash: "9e0e90d9c76de8fa5b200d8c849cd5b8dc7a3be3951ddb7f6a76b4158342019d",
			signature:            "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd",
		},
		{
			name: "GET Bucket Lifecycle", method: "GET", path: "/", query: [][2]string{{"lifecycle", ""}},
			headers: map[string]string{"host": awsExampleHost, "x-amz-content-sha256": emptyPayloadHash, "x-amz-date": "20130524T000000Z"},
			canonicalRequest: "GET\n/\nlifecycle=\nhost:examplebucket.s3.amazonaws.com\n" +
				"x-amz-content-sha256:" + emptyPayloadHash + "\nx-amz-date:20130524T000000Z\n\n" +
				"host;x-amz-content-sha256;x-amz-date\n" + emptyPayloadHash,
			canonicalRequestHash: "9766c798316ff2757b517bc739a67f6213b4ab36dd5da2f94eaebf79c77395ca",
			signature:            "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
		},
		{
			name: "Get Bucket (List Objects)", method: "GET", path: "/",
			// Given out of order on purpose: the canonical form sorts them.
			query:   [][2]string{{"prefix", "J"}, {"max-keys", "2"}},
			headers: map[string]string{"host": awsExampleHost, "x-amz-content-sha256": emptyPayloadHash, "x-amz-date": "20130524T000000Z"},
			canonicalRequest: "GET\n/\nmax-keys=2&prefix=J\nhost:examplebucket.s3.amazonaws.com\n" +
				"x-amz-content-sha256:" + emptyPayloadHash + "\nx-amz-date:20130524T000000Z\n\n" +
				"host;x-amz-content-sha256;x-amz-date\n" + emptyPayloadHash,
			canonicalRequestHash: "df57d21db20da04d7fa30298dd4488ba3a2b47ca3a489c74750e0f1e7df1b9b7",
			signature:            "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
		},
	}
}

func TestSigV4MatchesAmazonsExamples(t *testing.T) {
	for _, ex := range awsExamples() {
		t.Run(ex.name, func(t *testing.T) {
			sum := sha256.Sum256([]byte(ex.payload))
			payloadHash := hex.EncodeToString(sum[:])
			if payloadHash != ex.headers["x-amz-content-sha256"] {
				t.Fatalf("payload hash %s", payloadHash)
			}
			uri, query := uriEncode(ex.path, false), canonicalQuery(ex.query)
			request, signed := sigV4CanonicalRequest(ex.method, uri, query, ex.headers, payloadHash)
			if request != ex.canonicalRequest {
				t.Fatalf("canonical request\n got %q\nwant %q", request, ex.canonicalRequest)
			}
			hashed := sha256.Sum256([]byte(request))
			if got := hex.EncodeToString(hashed[:]); got != ex.canonicalRequestHash {
				t.Fatalf("canonical request hash %s, want %s", got, ex.canonicalRequestHash)
			}
			auth := sigV4Authorization(ex.method, uri, query, ex.headers, payloadHash, awsExampleTime,
				awsExampleRegion, "s3", awsExampleAccessKey, awsExampleSecret)
			want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=" +
				signed + ", Signature=" + ex.signature
			if auth != want {
				t.Fatalf("Authorization\n got %s\nwant %s", auth, want)
			}
		})
	}
}

func TestSigV4SigningKeyDerivation(t *testing.T) {
	// Amazon's example of deriving a signing key (AWS General Reference,
	// "Examples of how to derive a signing key for Signature Version 4").
	got := sigV4SigningKey("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20120215", "us-east-1", "iam")
	if hex.EncodeToString(got) != "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d" {
		t.Fatalf("signing key %x", got)
	}
	// The S3 examples pin the same derivation for the "s3" service: with the
	// documented string to sign, the documented signature comes out.
	stringToSign := "AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n" +
		"7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"
	key := sigV4SigningKey(awsExampleSecret, "20130524", "us-east-1", "s3")
	if sig := hex.EncodeToString(hmacSHA256(key, stringToSign)); sig != "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41" {
		t.Fatalf("signature %s", sig)
	}
}

func TestSigV4Encoding(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "",
		"AZaz09-._~":             "AZaz09-._~",
		"a b":                    "a%20b",
		"a+b":                    "a%2Bb",
		"a=b&c":                  "a%3Db%26c",
		"test$file.text":         "test%24file.text",
		"é":                      "%C3%A9",
		"\x00\xff":               "%00%FF",
		"*'()!":                  "%2A%27%28%29%21",
		"1ueGcxLPRx1Tr/XYExHnh=": "1ueGcxLPRx1Tr%2FXYExHnh%3D",
	} {
		if got := uriEncode(in, true); got != want {
			t.Errorf("uriEncode(%q) = %q, want %q", in, got, want)
		}
	}
	if got := uriEncode("/bucket/photos/Jan/sample file.jpg", false); got != "/bucket/photos/Jan/sample%20file.jpg" {
		t.Errorf("path: %q", got)
	}
	// Amazon's example of a canonical query string: sorted by name, each
	// name and value encoded, "=" even without a value.
	got := canonicalQuery([][2]string{{"prefix", "somePrefix"}, {"marker", "someMarker"}, {"max-keys", "20"}})
	if got != "marker=someMarker&max-keys=20&prefix=somePrefix" {
		t.Errorf("canonical query %q", got)
	}
	if got := canonicalQuery([][2]string{{"uploads", ""}}); got != "uploads=" {
		t.Errorf("subresource: %q", got)
	}
	if got := canonicalQuery([][2]string{{"uploadId", "a/b+c=="}, {"partNumber", "3"}}); got != "partNumber=3&uploadId=a%2Fb%2Bc%3D%3D" {
		t.Errorf("multipart query: %q", got)
	}
	// Header values are trimmed and inner runs of spaces collapsed.
	request, _ := sigV4CanonicalRequest("GET", "/", "", map[string]string{"host": "h", "x-amz-meta": "  a   b  "}, emptyPayloadHash)
	if !strings.Contains(request, "\nx-amz-meta:a b\n") {
		t.Errorf("header trimming: %q", request)
	}
}

// --- an independent SigV4 verifier, for the test server ---------------------------
//
// Written from the specification ("Create a signed AWS API request", IAM User
// Guide; the S3 page above), without calling anything in s3.go.

func verifierEncode(s string, keepSlash bool) string {
	var out []string
	for _, b := range []byte(s) {
		isLetter := (b|0x20) >= 'a' && (b|0x20) <= 'z'
		isDigit := b >= '0' && b <= '9'
		if isLetter || isDigit || strings.IndexByte("-._~", b) >= 0 || (keepSlash && b == '/') {
			out = append(out, string(rune(b)))
		} else {
			out = append(out, fmt.Sprintf("%%%02X", b))
		}
	}
	return strings.Join(out, "")
}

func verifierHMAC(key []byte, msg string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = io.WriteString(h, msg)
	return h.Sum(nil)
}

// verifySigV4 recomputes the signature of a received request.
func verifySigV4(r *http.Request, body []byte, accessKey, secret, region string, now time.Time) error {
	auth := r.Header.Get("Authorization")
	algorithm, rest, ok := strings.Cut(auth, " ")
	if !ok || algorithm != "AWS4-HMAC-SHA256" {
		return fmt.Errorf("authorization algorithm %q", algorithm)
	}
	fields := map[string]string{}
	for _, part := range strings.Split(rest, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return fmt.Errorf("authorization field %q", part)
		}
		fields[k] = v
	}
	scope := strings.Split(fields["Credential"], "/")
	if len(scope) != 5 || scope[0] != accessKey || scope[2] != region || scope[3] != "s3" || scope[4] != "aws4_request" {
		return fmt.Errorf("credential %q", fields["Credential"])
	}
	amzDate := r.Header.Get("X-Amz-Date")
	at, err := time.Parse("20060102T150405Z", amzDate)
	if err != nil || at.Format("20060102") != scope[1] {
		return fmt.Errorf("x-amz-date %q does not match the scope date %q", amzDate, scope[1])
	}
	if skew := now.Sub(at); skew > 15*time.Minute || skew < -15*time.Minute {
		return fmt.Errorf("request time %s is too far from %s", amzDate, now.UTC().Format(time.RFC3339))
	}
	payloadHash := r.Header.Get("X-Amz-Content-Sha256")
	sum := sha256.Sum256(body)
	if payloadHash != hex.EncodeToString(sum[:]) {
		return fmt.Errorf("x-amz-content-sha256 %q is not the hash of the %d-byte body", payloadHash, len(body))
	}

	signed := strings.Split(fields["SignedHeaders"], ";")
	if !sort.StringsAreSorted(signed) {
		return fmt.Errorf("signed headers not sorted: %v", signed)
	}
	isSigned := map[string]bool{}
	for _, h := range signed {
		isSigned[h] = true
	}
	if !isSigned["host"] {
		return errors.New("host is not signed")
	}
	for name := range r.Header {
		lower := strings.ToLower(name)
		if (strings.HasPrefix(lower, "x-amz-") || lower == "content-type") && !isSigned[lower] {
			return fmt.Errorf("header %s is sent but not signed", lower)
		}
	}

	var canonical strings.Builder
	canonical.WriteString(r.Method + "\n")
	canonical.WriteString(verifierEncode(r.URL.Path, true) + "\n")
	values := r.URL.Query()
	var pairs []string
	for name, vs := range values {
		for _, v := range vs {
			pairs = append(pairs, verifierEncode(name, false)+"="+verifierEncode(v, false))
		}
	}
	sort.Strings(pairs)
	canonical.WriteString(strings.Join(pairs, "&") + "\n")
	for _, h := range signed {
		value := strings.Join(r.Header.Values(h), ",")
		if h == "host" {
			value = r.Host
		}
		canonical.WriteString(h + ":" + strings.Join(strings.Fields(value), " ") + "\n")
	}
	canonical.WriteString("\n" + strings.Join(signed, ";") + "\n" + payloadHash)

	hashed := sha256.Sum256([]byte(canonical.String()))
	stringToSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, strings.Join(scope[1:], "/"), hex.EncodeToString(hashed[:])}, "\n")
	key := verifierHMAC([]byte("AWS4"+secret), scope[1])
	for _, step := range scope[2:] {
		key = verifierHMAC(key, step)
	}
	want := hex.EncodeToString(verifierHMAC(key, stringToSign))
	if !hmac.Equal([]byte(want), []byte(fields["Signature"])) {
		return fmt.Errorf("signature mismatch for canonical request %q", canonical.String())
	}

	// What is on the wire must be what was signed: S3 does not normalise.
	wirePath, wireQuery, _ := strings.Cut(r.RequestURI, "?")
	if wirePath != verifierEncode(r.URL.Path, true) {
		return fmt.Errorf("the path on the wire %q is not the canonical path", wirePath)
	}
	if wireQuery != strings.Join(pairs, "&") {
		return fmt.Errorf("the query on the wire %q is not the canonical query %q", wireQuery, strings.Join(pairs, "&"))
	}
	return nil
}

// The verifier itself is checked against Amazon's examples, with the
// Authorization headers the documentation gives.
func TestVerifierAcceptsAmazonsExamples(t *testing.T) {
	for _, ex := range awsExamples() {
		target := verifierEncode(ex.path, true)
		if len(ex.query) > 0 {
			var pairs []string
			for _, p := range ex.query {
				pairs = append(pairs, verifierEncode(p[0], false)+"="+verifierEncode(p[1], false))
			}
			sort.Strings(pairs)
			target += "?" + strings.Join(pairs, "&")
		}
		r := httptest.NewRequest(ex.method, target, strings.NewReader(ex.payload))
		r.Host = awsExampleHost
		var names []string
		for name, value := range ex.headers {
			names = append(names, name)
			if name != "host" {
				r.Header.Set(name, value)
			}
		}
		sort.Strings(names)
		r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,"+
			"SignedHeaders="+strings.Join(names, ";")+",Signature="+ex.signature)
		if err := verifySigV4(r, []byte(ex.payload), awsExampleAccessKey, awsExampleSecret, awsExampleRegion, awsExampleTime); err != nil {
			t.Errorf("%s: the verifier refuses Amazon's own example: %v", ex.name, err)
		}
		// And it refuses the same request with anything changed.
		r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), ex.signature[:4], "0000", 1))
		if err := verifySigV4(r, []byte(ex.payload), awsExampleAccessKey, awsExampleSecret, awsExampleRegion, awsExampleTime); err == nil {
			t.Errorf("%s: an altered signature was accepted", ex.name)
		}
	}
	ex := awsExamples()[0]
	r := httptest.NewRequest("GET", "/test.txt", nil)
	r.Host = awsExampleHost
	for name, value := range ex.headers {
		r.Header.Set(name, value)
	}
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,"+
		"SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature="+ex.signature)
	for name, check := range map[string]func() error{
		"other secret": func() error {
			return verifySigV4(r, nil, awsExampleAccessKey, "another-secret", awsExampleRegion, awsExampleTime)
		},
		"other region": func() error {
			return verifySigV4(r, nil, awsExampleAccessKey, awsExampleSecret, "eu-west-3", awsExampleTime)
		},
		"other body": func() error {
			return verifySigV4(r, []byte("x"), awsExampleAccessKey, awsExampleSecret, awsExampleRegion, awsExampleTime)
		},
		"an hour later": func() error {
			return verifySigV4(r, nil, awsExampleAccessKey, awsExampleSecret, awsExampleRegion, awsExampleTime.Add(time.Hour))
		},
	} {
		if check() == nil {
			t.Errorf("the verifier accepted: %s", name)
		}
	}
}

// --- an S3-compatible server for the tests -------------------------------------------

const (
	fakeAccessKey = "AKIDTESTKEY0123456789"
	fakeSecret    = "s3cr3t/Key+With=Odd/Characters-0123456789abcdef"
	fakeRegion    = "eu-west-3"
	fakeBucket    = "hm-backups"
)

type fakeUpload struct {
	key   string
	parts map[int][]byte
}

type fakeS3 struct {
	t      *testing.T
	server *httptest.Server
	secret string // the secret the server knows

	mu       sync.Mutex
	objects  map[string][]byte
	uploads  map[string]*fakeUpload
	nextID   int
	pageSize int
	partSize int      // every part but the last must have this size
	ops      []string // operations received, in order
	// fail[op] is how many times op is answered with failStatus (default 500)
	// before it works; a negative count means always.
	fail       map[string]int
	failStatus map[string]int
	failCode   map[string]string
	// completeError[n] makes that many CompleteMultipartUpload calls answer
	// 200 with an <Error> body of the given code.
	completeErrors    int
	completeErrorCode string
	// hang[op] is how many times op gets no answer.
	hang          map[string]int
	stallGet      bool // send half of an object and then nothing
	redirectTo    string
	badSignatures int
	tolerateBad   bool
}

func newFakeS3(t *testing.T) *fakeS3 {
	f := &fakeS3{t: t, secret: fakeSecret, objects: map[string][]byte{}, uploads: map[string]*fakeUpload{},
		pageSize: 1000, fail: map[string]int{}, failStatus: map[string]int{}, failCode: map[string]string{}, hang: map[string]int{}}
	f.server = httptest.NewServer(f)
	t.Cleanup(func() {
		f.server.Close()
		if f.badSignatures != 0 && !f.tolerateBad {
			t.Errorf("%d requests had a bad signature", f.badSignatures)
		}
	})
	return f
}

func (f *fakeS3) count(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, op := range f.ops {
		if strings.HasPrefix(op, prefix) {
			n++
		}
	}
	return n
}

func (f *fakeS3) opsSeen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ops...)
}

// The tests read and prepare the server's state through these, under its lock.

func (f *fakeS3) object(key string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.objects[key]
}

func (f *fakeS3) has(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.objects[key]
	return ok
}

func (f *fakeS3) store(key string, data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = data
}

func (f *fakeS3) remove(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objects, key)
}

func (f *fakeS3) numObjects() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.objects)
}

func (f *fakeS3) numUploads() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.uploads)
}

func (f *fakeS3) resetOps() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ops = nil
}

func (f *fakeS3) bad() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.badSignatures
}

// set changes the server's behaviour.
func (f *fakeS3) set(change func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change()
}

func fakeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>this message is never shown</Message><RequestId>1</RequestId></Error>`, code)
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}
	if err := verifySigV4(r, body, fakeAccessKey, f.secret, fakeRegion, time.Now()); err != nil {
		f.mu.Lock()
		f.badSignatures++
		tolerate := f.tolerateBad
		f.mu.Unlock()
		if !tolerate {
			f.t.Errorf("%s %s: %v", r.Method, r.RequestURI, err)
		}
		fakeError(w, http.StatusForbidden, "SignatureDoesNotMatch")
		return
	}
	// Path-style addressing: /bucket[/key].
	rest, ok := strings.CutPrefix(r.URL.Path, "/"+fakeBucket)
	if !ok || (rest != "" && rest[0] != '/') {
		fakeError(w, http.StatusNotFound, "NoSuchBucket")
		return
	}
	key := strings.TrimPrefix(rest, "/")
	q := r.URL.Query()

	var op string
	switch {
	case key == "" && r.Method == http.MethodGet && q.Get("list-type") == "2":
		op = "ListObjectsV2"
	case r.Method == http.MethodPost && q.Has("uploads"):
		op = "CreateMultipartUpload"
	case r.Method == http.MethodPut && q.Has("partNumber") && q.Has("uploadId"):
		op = "UploadPart#" + q.Get("partNumber")
	case r.Method == http.MethodPost && q.Has("uploadId"):
		op = "CompleteMultipartUpload"
	case r.Method == http.MethodDelete && q.Has("uploadId"):
		op = "AbortMultipartUpload"
	case key != "" && r.Method == http.MethodPut:
		op = "PutObject"
	case key != "" && r.Method == http.MethodGet:
		op = "GetObject"
	case key != "" && r.Method == http.MethodDelete:
		op = "DeleteObject"
	default:
		fakeError(w, http.StatusBadRequest, "InvalidRequest")
		return
	}

	f.mu.Lock()
	f.ops = append(f.ops, op)
	if f.hang[op] != 0 {
		f.hang[op]--
		f.mu.Unlock()
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
		return
	}
	if n := f.fail[op]; n != 0 {
		if n > 0 {
			f.fail[op]--
		}
		status, code := f.failStatus[op], f.failCode[op]
		f.mu.Unlock()
		if status == 0 {
			status = http.StatusInternalServerError
		}
		if code == "" {
			code = "InternalError"
		}
		fakeError(w, status, code)
		return
	}
	if f.redirectTo != "" {
		target := f.redirectTo + r.RequestURI
		f.mu.Unlock()
		http.Redirect(w, r, target, http.StatusTemporaryRedirect)
		return
	}
	defer f.mu.Unlock()

	switch {
	case op == "ListObjectsV2":
		f.list(w, q)
	case op == "CreateMultipartUpload":
		f.nextID++
		// An id with characters that must be encoded in a query string.
		id := fmt.Sprintf("upload %d/+=&id", f.nextID)
		f.uploads[id] = &fakeUpload{key: key, parts: map[int][]byte{}}
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>%s</Bucket><Key>%s</Key><UploadId>%s</UploadId></InitiateMultipartUploadResult>`,
			fakeBucket, key, strings.ReplaceAll(id, "&", "&amp;"))
	case strings.HasPrefix(op, "UploadPart#"):
		up := f.uploads[q.Get("uploadId")]
		n, err := strconv.Atoi(q.Get("partNumber"))
		if up == nil || up.key != key {
			fakeError(w, http.StatusNotFound, "NoSuchUpload")
			return
		}
		if err != nil || n < 1 || n > 10000 {
			fakeError(w, http.StatusBadRequest, "InvalidArgument")
			return
		}
		if r.ContentLength != int64(len(body)) {
			fakeError(w, http.StatusBadRequest, "MissingContentLength")
			return
		}
		up.parts[n] = body
		w.Header().Set("ETag", fakeETag(body))
	case op == "CompleteMultipartUpload":
		f.complete(w, key, q.Get("uploadId"), body)
	case op == "AbortMultipartUpload":
		if _, ok := f.uploads[q.Get("uploadId")]; !ok {
			fakeError(w, http.StatusNotFound, "NoSuchUpload")
			return
		}
		delete(f.uploads, q.Get("uploadId"))
		w.WriteHeader(http.StatusNoContent)
	case op == "PutObject":
		if r.ContentLength != int64(len(body)) {
			fakeError(w, http.StatusBadRequest, "MissingContentLength")
			return
		}
		f.objects[key] = body
		w.Header().Set("ETag", fakeETag(body))
	case op == "GetObject":
		data, ok := f.objects[key]
		if !ok {
			fakeError(w, http.StatusNotFound, "NoSuchKey")
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		if f.stallGet {
			_, _ = w.Write(data[:len(data)/2])
			w.(http.Flusher).Flush()
			f.mu.Unlock()
			select {
			case <-r.Context().Done():
			case <-time.After(10 * time.Second):
			}
			f.mu.Lock()
			return
		}
		_, _ = w.Write(data)
	case op == "DeleteObject":
		delete(f.objects, key)
		w.WriteHeader(http.StatusNoContent)
	}
}

func fakeETag(data []byte) string {
	sum := md5.Sum(data)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

func (f *fakeS3) list(w http.ResponseWriter, q url.Values) {
	prefix, delimiter := q.Get("prefix"), q.Get("delimiter")
	var keys []string
	for key := range f.objects {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if delimiter != "" && strings.Contains(key[len(prefix):], delimiter) {
			continue // would be a CommonPrefixes element
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	start := 0
	if token := q.Get("continuation-token"); token != "" {
		raw, err := base64.StdEncoding.DecodeString(token)
		if err != nil {
			fakeError(w, http.StatusBadRequest, "InvalidArgument")
			return
		}
		start = sort.SearchStrings(keys, string(raw))
	}
	end := min(start+f.pageSize, len(keys))
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	fmt.Fprintf(&b, "<Name>%s</Name><Prefix>%s</Prefix><KeyCount>%d</KeyCount><MaxKeys>%d</MaxKeys><Delimiter>%s</Delimiter>",
		fakeBucket, prefix, end-start, f.pageSize, delimiter)
	fmt.Fprintf(&b, "<IsTruncated>%t</IsTruncated>", end < len(keys))
	for _, key := range keys[start:end] {
		fmt.Fprintf(&b, "<Contents><Key>%s</Key><LastModified>2026-10-02T03:04:05.000Z</LastModified><ETag>&quot;x&quot;</ETag><Size>%d</Size><StorageClass>STANDARD</StorageClass></Contents>",
			key, len(f.objects[key]))
	}
	if end < len(keys) {
		// Standard base64: tokens contain "+", "/" and "=".
		fmt.Fprintf(&b, "<NextContinuationToken>%s</NextContinuationToken>", base64.StdEncoding.EncodeToString([]byte(keys[end])))
	}
	b.WriteString("</ListBucketResult>")
	_, _ = io.WriteString(w, b.String())
}

func (f *fakeS3) complete(w http.ResponseWriter, key, id string, body []byte) {
	up := f.uploads[id]
	if up == nil || up.key != key {
		fakeError(w, http.StatusNotFound, "NoSuchUpload")
		return
	}
	if f.completeErrors > 0 {
		f.completeErrors--
		fakeError(w, http.StatusOK, f.completeErrorCode)
		return
	}
	var req struct {
		XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CompleteMultipartUpload"`
		Parts   []struct {
			PartNumber int    `xml:"PartNumber"`
			ETag       string `xml:"ETag"`
		} `xml:"Part"`
	}
	if err := xml.Unmarshal(body, &req); err != nil || len(req.Parts) == 0 {
		fakeError(w, http.StatusBadRequest, "MalformedXML")
		return
	}
	var object []byte
	for i, p := range req.Parts {
		data, ok := up.parts[p.PartNumber]
		switch {
		case p.PartNumber != i+1:
			fakeError(w, http.StatusBadRequest, "InvalidPartOrder")
			return
		case !ok || fakeETag(data) != p.ETag:
			fakeError(w, http.StatusBadRequest, "InvalidPart")
			return
		case i < len(req.Parts)-1 && len(data) != f.partSize:
			// Amazon S3 wants at least 5 MiB, other services want equal
			// parts; here: the configured size exactly.
			fakeError(w, http.StatusBadRequest, "EntityTooSmall")
			return
		case len(data) == 0:
			fakeError(w, http.StatusBadRequest, "EntityTooSmall")
			return
		}
		object = append(object, data...)
	}
	if len(req.Parts) != len(up.parts) {
		fakeError(w, http.StatusBadRequest, "InvalidPart")
		return
	}
	f.objects[key] = object
	delete(f.uploads, id)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Location>x</Location><Bucket>%s</Bucket><Key>%s</Key><ETag>&quot;final-1&quot;</ETag></CompleteMultipartUploadResult>`, fakeBucket, key)
}

// --- the destination under test ---------------------------------------------------------

const testPartSize = 1024

type testS3 struct {
	*S3Destination
	sleeps *[]time.Duration
}

func fakeConfig(f *fakeS3, prefix string) S3Config {
	return S3Config{Endpoint: f.server.URL, Region: fakeRegion, Bucket: fakeBucket, Prefix: prefix,
		AccessKeyID: fakeAccessKey, SecretAccessKey: fakeSecret, AllowLoopbackHTTP: true}
}

// newTestS3 returns a destination for the fake server, with small parts and no
// real waiting between retries.
func newTestS3(t *testing.T, f *fakeS3, prefix string) testS3 {
	t.Helper()
	d, err := NewS3Destination(fakeConfig(f, prefix))
	if err != nil {
		t.Fatal(err)
	}
	d.partSize = testPartSize
	f.partSize = testPartSize
	var mu sync.Mutex
	sleeps := &[]time.Duration{}
	d.sleep = func(_ context.Context, delay time.Duration) error {
		mu.Lock()
		defer mu.Unlock()
		*sleeps = append(*sleeps, delay)
		return nil
	}
	t.Cleanup(d.client.CloseIdleConnections)
	return testS3{d, sleeps}
}

func noSecret(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		return
	}
	for _, s := range []string{fakeSecret, fakeSecret[:12], "AWS4" + fakeSecret[:6]} {
		if strings.Contains(err.Error(), s) || strings.Contains(fmt.Sprintf("%+v %#v", err, err), s) {
			t.Errorf("%s: the error shows the secret key: %v", what, err)
		}
	}
	if strings.Contains(err.Error(), "never shown") {
		t.Errorf("%s: the error repeats the body of the answer: %v", what, err)
	}
}

func TestS3SmallArchiveIsOnePutObject(t *testing.T) {
	f := newFakeS3(t)
	d := newTestS3(t, f, "")
	ctx := context.Background()
	name := ArchiveName("m1", day(1))
	for _, size := range []int{0, 1, testPartSize - 1, testPartSize} {
		data := randomBytes(t, size)
		f.resetOps()
		if err := d.Put(ctx, name, bytes.NewReader(data)); err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if got := f.opsSeen(); fmt.Sprint(got) != "[PutObject]" {
			t.Fatalf("size %d: operations %v", size, got)
		}
		if !bytes.Equal(f.object(name), data) {
			t.Fatalf("size %d: stored object differs", size)
		}
	}

	rc, err := d.Get(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rc)
	if cerr := rc.Close(); err != nil || cerr != nil || !bytes.Equal(got, f.object(name)) {
		t.Fatalf("Get: %v / %v", err, cerr)
	}
	entries, err := d.List(ctx)
	if err != nil || len(entries) != 1 || entries[0].Name != name || entries[0].Size != testPartSize ||
		!entries[0].ModTime.Equal(time.Date(2026, 10, 2, 3, 4, 5, 0, time.UTC)) {
		t.Fatalf("List: %+v, %v", entries, err)
	}
	if err := d.Delete(ctx, name); err != nil {
		t.Fatal(err)
	}
	if f.numObjects() != 0 {
		t.Fatal("the object was not deleted")
	}
	if _, err := d.Get(ctx, name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete: %v", err)
	}
	if err := d.Delete(ctx, name); err != nil {
		t.Fatalf("deleting what is not there: %v", err)
	}
}

func TestS3LargeArchiveIsAMultipartUpload(t *testing.T) {
	f := newFakeS3(t)
	d := newTestS3(t, f, "site-a/machines")
	ctx := context.Background()
	name := ArchiveName("m1", day(1))
	for size, wantParts := range map[int]int{
		testPartSize + 1:     2,
		2 * testPartSize:     2, // no empty third part
		2*testPartSize + 1:   3,
		5*testPartSize + 100: 6,
	} {
		data := randomBytes(t, size)
		f.resetOps()
		// The source hands out odd-sized pieces, as a pipe would.
		if err := d.Put(ctx, name, &chunkyReader{data: data, step: 333}); err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		want := []string{"CreateMultipartUpload"}
		for n := 1; n <= wantParts; n++ {
			want = append(want, fmt.Sprintf("UploadPart#%d", n))
		}
		want = append(want, "CompleteMultipartUpload")
		if got := f.opsSeen(); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("size %d: operations %v, want %v", size, got, want)
		}
		if !bytes.Equal(f.object("site-a/machines/"+name), data) {
			t.Fatalf("size %d: the assembled object differs", size)
		}
		if f.numUploads() != 0 {
			t.Fatalf("size %d: an upload is left open", size)
		}
	}
	if len(*d.sleeps) != 0 {
		t.Fatalf("retries without a failure: %v", *d.sleeps)
	}
}

type chunkyReader struct {
	data []byte
	step int
}

func (c *chunkyReader) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p[:min(len(p), c.step)], c.data)
	c.data = c.data[n:]
	return n, nil
}

func TestS3RetriesAPartThatFailsOnce(t *testing.T) {
	f := newFakeS3(t)
	d := newTestS3(t, f, "")
	name := ArchiveName("m1", day(1))
	data := randomBytes(t, 3*testPartSize+7)
	f.fail["UploadPart#2"] = 1
	f.fail["CreateMultipartUpload"] = 1
	f.failStatus["CreateMultipartUpload"] = http.StatusServiceUnavailable
	f.failCode["CreateMultipartUpload"] = "SlowDown"
	f.completeErrors, f.completeErrorCode = 1, "InternalError"

	if err := d.Put(context.Background(), name, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.object(name), data) {
		t.Fatal("the object differs after a retried part")
	}
	want := "[CreateMultipartUpload CreateMultipartUpload UploadPart#1 UploadPart#2 UploadPart#2 UploadPart#3 UploadPart#4 CompleteMultipartUpload CompleteMultipartUpload]"
	if got := fmt.Sprint(f.opsSeen()); got != want {
		t.Fatalf("operations %s\nwant       %s", got, want)
	}
	if len(*d.sleeps) != 3 {
		t.Fatalf("waits between attempts: %v", *d.sleeps)
	}
}

func TestS3AbortsWhenAPartNeverGoesThrough(t *testing.T) {
	f := newFakeS3(t)
	d := newTestS3(t, f, "")
	name := ArchiveName("m1", day(1))
	f.fail["UploadPart#2"] = -1

	err := d.Put(context.Background(), name, bytes.NewReader(randomBytes(t, 4*testPartSize)))
	var se *S3Error
	if !errors.As(err, &se) || se.Op != "UploadPart" || se.Status != 500 || se.Code != "InternalError" {
		t.Fatalf("error %v", err)
	}
	noSecret(t, "failed part", err)
	// Bounded: the first attempt and MaxRetries more, then the upload is
	// aborted and nothing is left at the destination.
	if got := f.count("UploadPart#2"); got != 1+defaultS3MaxRetries {
		t.Fatalf("%d attempts at part 2", got)
	}
	if f.count("UploadPart#3") != 0 || f.count("CompleteMultipartUpload") != 0 {
		t.Fatalf("the upload went on after a lost part: %v", f.opsSeen())
	}
	if f.count("AbortMultipartUpload") != 1 {
		t.Fatalf("no abort: %v", f.opsSeen())
	}
	if f.numUploads() != 0 || f.numObjects() != 0 {
		t.Fatalf("left behind: %d uploads, %d objects", f.numUploads(), f.numObjects())
	}
	// The waits grow.
	if s := *d.sleeps; len(s) != defaultS3MaxRetries || s[0] >= s[1] || s[1] >= s[2] {
		t.Fatalf("waits %v", s)
	}
}

func TestS3AbortsOnEveryOtherFailure(t *testing.T) {
	name := ArchiveName("m1", day(1))
	t.Run("the source fails", func(t *testing.T) {
		f := newFakeS3(t)
		d := newTestS3(t, f, "")
		src := io.MultiReader(bytes.NewReader(randomBytes(t, 2*testPartSize+10)), failingReader{})
		if err := d.Put(context.Background(), name, src); !errors.Is(err, errInput) {
			t.Fatalf("error %v", err)
		}
		if f.count("AbortMultipartUpload") != 1 || f.count("CompleteMultipartUpload") != 0 || f.numUploads() != 0 || f.numObjects() != 0 {
			t.Fatalf("operations %v", f.opsSeen())
		}
	})
	t.Run("the source fails before anything is sent", func(t *testing.T) {
		f := newFakeS3(t)
		d := newTestS3(t, f, "")
		src := io.MultiReader(bytes.NewReader(randomBytes(t, 10)), failingReader{})
		if err := d.Put(context.Background(), name, src); !errors.Is(err, errInput) {
			t.Fatalf("error %v", err)
		}
		if len(f.opsSeen()) != 0 {
			t.Fatalf("a truncated archive was sent: %v", f.opsSeen())
		}
	})
	t.Run("an unexpected EOF of the source is a failure, not an end", func(t *testing.T) {
		f := newFakeS3(t)
		d := newTestS3(t, f, "")
		src := io.MultiReader(bytes.NewReader(randomBytes(t, 10)), readerFunc(func([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }))
		if err := d.Put(context.Background(), name, src); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("error %v", err)
		}
		if f.numObjects() != 0 || len(f.opsSeen()) != 0 {
			t.Fatalf("a cut archive was stored: %v", f.opsSeen())
		}
	})
	t.Run("the context is cancelled", func(t *testing.T) {
		f := newFakeS3(t)
		d := newTestS3(t, f, "")
		ctx, cancel := context.WithCancel(context.Background())
		sent := 0
		src := readerFunc(func(p []byte) (int, error) {
			if sent >= 2*testPartSize+50 {
				cancel() // after two parts are on their way
			}
			sent += len(p)
			return len(p), nil
		})
		if err := d.Put(ctx, name, src); !errors.Is(err, context.Canceled) {
			t.Fatalf("error %v", err)
		}
		// The abort is sent although the context is cancelled.
		if f.count("AbortMultipartUpload") != 1 || f.numUploads() != 0 || f.numObjects() != 0 {
			t.Fatalf("operations %v, %d uploads", f.opsSeen(), f.numUploads())
		}
	})
	t.Run("completion is refused", func(t *testing.T) {
		f := newFakeS3(t)
		d := newTestS3(t, f, "")
		f.completeErrors, f.completeErrorCode = 1, "InvalidPart"
		err := d.Put(context.Background(), name, bytes.NewReader(randomBytes(t, 2*testPartSize)))
		var se *S3Error
		if !errors.As(err, &se) || se.Op != "CompleteMultipartUpload" || se.Code != "InvalidPart" {
			t.Fatalf("error %v", err)
		}
		if f.count("CompleteMultipartUpload") != 1 || f.count("AbortMultipartUpload") != 1 || f.numUploads() != 0 || f.numObjects() != 0 {
			t.Fatalf("operations %v", f.opsSeen())
		}
	})
	t.Run("completion keeps failing inside a 200", func(t *testing.T) {
		f := newFakeS3(t)
		d := newTestS3(t, f, "")
		f.completeErrors, f.completeErrorCode = 100, "InternalError"
		err := d.Put(context.Background(), name, bytes.NewReader(randomBytes(t, 2*testPartSize)))
		var se *S3Error
		if !errors.As(err, &se) || se.Code != "InternalError" {
			t.Fatalf("error %v", err)
		}
		if f.count("CompleteMultipartUpload") != 1+defaultS3MaxRetries || f.count("AbortMultipartUpload") != 1 || f.numObjects() != 0 {
			t.Fatalf("operations %v", f.opsSeen())
		}
	})
	t.Run("the abort fails too", func(t *testing.T) {
		f := newFakeS3(t)
		d := newTestS3(t, f, "")
		f.fail["UploadPart#1"] = -1
		f.fail["AbortMultipartUpload"] = -1
		f.failStatus["AbortMultipartUpload"] = http.StatusForbidden
		f.failCode["AbortMultipartUpload"] = "AccessDenied"
		err := d.Put(context.Background(), name, bytes.NewReader(randomBytes(t, 2*testPartSize)))
		var se *S3Error
		if !errors.As(err, &se) || se.Op != "UploadPart" || !strings.Contains(err.Error(), "could not be aborted") {
			t.Fatalf("error %v", err)
		}
		noSecret(t, "abort failure", err)
	})
}

func TestS3DoesNotRetryWhatCannotSucceed(t *testing.T) {
	f := newFakeS3(t)
	d := newTestS3(t, f, "")
	name := ArchiveName("m1", day(1))
	for status, code := range map[int]string{403: "AccessDenied", 404: "NoSuchBucket", 400: "InvalidRequest", 301: "PermanentRedirect"} {
		f.resetOps()
		f.fail["PutObject"], f.failStatus["PutObject"], f.failCode["PutObject"] = 1, status, code
		err := d.Put(context.Background(), name, strings.NewReader("x"))
		var se *S3Error
		if !errors.As(err, &se) || se.Status != status || se.Code != code || se.Op != "PutObject" {
			t.Fatalf("%d: error %v", status, err)
		}
		if f.count("PutObject") != 1 {
			t.Fatalf("%d was retried: %v", status, f.opsSeen())
		}
		noSecret(t, code, err)
	}
	if len(*d.sleeps) != 0 {
		t.Fatalf("waited: %v", *d.sleeps)
	}
	// A code that is not a plain token is dropped, not repeated.
	f.fail["PutObject"], f.failStatus["PutObject"], f.failCode["PutObject"] = 1, 400, "<b>bad code</b> with spaces"
	err := d.Put(context.Background(), name, strings.NewReader("x"))
	var se *S3Error
	if !errors.As(err, &se) || se.Code != "" || strings.Contains(err.Error(), "bad code") {
		t.Fatalf("error %v", err)
	}
}

func TestS3WrongSecretIsRefusedAndNeverShown(t *testing.T) {
	f := newFakeS3(t)
	f.tolerateBad = true
	f.secret = "the-server-knows-another-secret"
	d := newTestS3(t, f, "")
	ctx := context.Background()
	name := ArchiveName("m1", day(1))

	var errs []error
	errs = append(errs, d.Put(ctx, name, strings.NewReader("x")))
	errs = append(errs, d.Put(ctx, name, bytes.NewReader(randomBytes(t, 3*testPartSize))))
	_, err := d.Get(ctx, name)
	errs = append(errs, err)
	_, err = d.List(ctx)
	errs = append(errs, err)
	errs = append(errs, d.Delete(ctx, name))
	for i, err := range errs {
		var se *S3Error
		if !errors.As(err, &se) || se.Status != 403 || se.Code != "SignatureDoesNotMatch" {
			t.Errorf("call %d: %v", i, err)
		}
		noSecret(t, "wrong secret", err)
	}
	if f.bad() != len(errs) {
		t.Fatalf("%d refused requests for %d calls: something was retried", f.bad(), len(errs))
	}

	// Nor in what a careless log line would print.
	cfg := fakeConfig(f, "p")
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		for _, v := range []any{cfg, &cfg, d.S3Destination, []S3Config{cfg}, struct{ C S3Config }{cfg}} {
			out := fmt.Sprintf(verb, v)
			if strings.Contains(out, fakeSecret) || strings.Contains(out, hex.EncodeToString([]byte(fakeSecret))) {
				t.Errorf("%s of %T prints the secret key: %s", verb, v, out)
			}
		}
	}
	if out := fmt.Sprintf("%+v", cfg); !strings.Contains(out, "redacted") || !strings.Contains(out, fakeBucket) {
		t.Errorf("config prints as %q", out)
	}
}

func TestS3ListFollowsPagesAndKeepsToItsPrefix(t *testing.T) {
	f := newFakeS3(t)
	f.pageSize = 3
	d := newTestS3(t, f, "backups/site-a")
	ctx := context.Background()
	var want []string
	for dd := 1; dd <= 8; dd++ {
		name := ArchiveName("m1", day(dd))
		want = append(want, name)
		f.store("backups/site-a/"+name, bytes.Repeat([]byte("x"), dd))
	}
	other := ArchiveName("m2", day(1))
	want = append(want, other)
	f.store("backups/site-a/"+other, []byte("x"))
	sort.Strings(want)
	// Things that are not this destination's archives.
	f.store("backups/site-a/notes.txt", []byte("x"))
	f.store("backups/site-a/"+ArchiveName("m1", day(1))+".part", []byte("x"))
	f.store("backups/site-a/sub/"+ArchiveName("m1", day(9)), []byte("x"))
	f.store("backups/site-ab/"+ArchiveName("m1", day(10)), []byte("x"))
	f.store("backups/"+ArchiveName("m1", day(11)), []byte("x"))
	f.store(ArchiveName("m1", day(12)), []byte("x"))

	entries, err := d.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("listed %v\nwant   %v", got, want)
	}
	if entries[0].Size != 1 || entries[7].Size != 8 {
		t.Fatalf("sizes %+v", entries)
	}
	// 11 keys directly under the prefix, three per page.
	if pages := f.count("ListObjectsV2"); pages != 4 {
		t.Fatalf("%d list requests", pages)
	}

	// Prune through the same listing: this machine's oldest, nothing else.
	deleted, err := Prune(ctx, d, "m1", 2)
	if err != nil || len(deleted) != 6 {
		t.Fatalf("prune: %v, %v", deleted, err)
	}
	if f.numObjects() != 15-6 {
		t.Fatalf("%d objects left", f.numObjects())
	}
	for _, key := range []string{"backups/site-a/notes.txt", "backups/site-a/" + other, "backups/site-ab/" + ArchiveName("m1", day(10)),
		"backups/site-a/sub/" + ArchiveName("m1", day(9)), ArchiveName("m1", day(12)),
		"backups/site-a/" + ArchiveName("m1", day(7)), "backups/site-a/" + ArchiveName("m1", day(8))} {
		if !f.has(key) {
			t.Errorf("%s was deleted", key)
		}
	}

	// A listing that says "truncated" without a way to go on is an error,
	// not an endless loop or a short list.
	f.pageSize = 1000
	loop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>same</NextContinuationToken></ListBucketResult>`)
	}))
	defer loop.Close()
	cfg := fakeConfig(f, "")
	cfg.Endpoint = loop.URL
	ld, err := NewS3Destination(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ld.List(ctx); err == nil || !strings.Contains(err.Error(), "continuation token") {
		t.Fatalf("looping listing: %v", err)
	}
}

func TestS3PrefixForms(t *testing.T) {
	f := newFakeS3(t)
	name := ArchiveName("m1", day(1))
	for prefix, wantKey := range map[string]string{
		"":             name,
		"a":            "a/" + name,
		"a/":           "a/" + name,
		"/a/b/":        "a/b/" + name,
		"a//b":         "a/b/" + name,
		"A.b_c-d/e":    "A.b_c-d/e/" + name,
		"/":            name,
		"deep/er/path": "deep/er/path/" + name,
	} {
		d := newTestS3(t, f, prefix)
		if err := d.Put(context.Background(), name, strings.NewReader(prefix)); err != nil {
			t.Fatalf("prefix %q: %v", prefix, err)
		}
		if got := f.object(wantKey); !f.has(wantKey) || string(got) != prefix {
			t.Errorf("prefix %q: no object at %q", prefix, wantKey)
		}
		entries, err := d.List(context.Background())
		if err != nil || len(entries) != 1 || entries[0].Name != name {
			t.Errorf("prefix %q: list %+v, %v", prefix, entries, err)
		}
		f.remove(wantKey)
	}
}

func TestS3TakesArchiveNamesOnly(t *testing.T) {
	f := newFakeS3(t)
	d := newTestS3(t, f, "p")
	ctx := context.Background()
	f.store("p/secret.txt", []byte("x"))
	for _, name := range []string{"", "secret.txt", "../other-prefix/" + ArchiveName("m1", day(1)), "a/b", ArchiveName("m1", day(1)) + "?acl", "%2e%2e"} {
		if err := d.Put(ctx, name, strings.NewReader("x")); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Put %q: %v", name, err)
		}
		if _, err := d.Get(ctx, name); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Get %q: %v", name, err)
		}
		if err := d.Delete(ctx, name); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Delete %q: %v", name, err)
		}
	}
	if len(f.opsSeen()) != 0 {
		t.Fatalf("requests were sent: %v", f.opsSeen())
	}
}

func TestS3DoesNotFollowRedirects(t *testing.T) {
	var elsewhere int
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere++ }))
	defer other.Close()
	f := newFakeS3(t)
	f.redirectTo = other.URL
	d := newTestS3(t, f, "")
	ctx := context.Background()
	name := ArchiveName("m1", day(1))

	err := d.Put(ctx, name, strings.NewReader("x"))
	var se *S3Error
	if !errors.As(err, &se) || se.Status != http.StatusTemporaryRedirect {
		t.Fatalf("Put: %v", err)
	}
	if _, err := d.Get(ctx, name); !errors.As(err, &se) || se.Status != http.StatusTemporaryRedirect {
		t.Fatalf("Get: %v", err)
	}
	if _, err := d.List(ctx); !errors.As(err, &se) {
		t.Fatalf("List: %v", err)
	}
	if err := d.Delete(ctx, name); !errors.As(err, &se) {
		t.Fatalf("Delete: %v", err)
	}
	if elsewhere != 0 {
		t.Fatalf("%d signed requests followed a redirect to another host", elsewhere)
	}
}

func TestS3TimeoutsAndRetries(t *testing.T) {
	name := ArchiveName("m1", day(1))
	newSlow := func(t *testing.T, f *fakeS3) testS3 {
		cfg := fakeConfig(f, "")
		cfg.RequestTimeout = 150 * time.Millisecond
		cfg.PartTimeout = 300 * time.Millisecond
		cfg.IdleTimeout = 200 * time.Millisecond
		cfg.MaxRetries = 2
		d, err := NewS3Destination(cfg)
		if err != nil {
			t.Fatal(err)
		}
		d.partSize, f.partSize = testPartSize, testPartSize
		d.sleep = func(context.Context, time.Duration) error { return nil }
		t.Cleanup(d.client.CloseIdleConnections)
		return testS3{d, nil}
	}

	t.Run("a part that gets no answer is sent again", func(t *testing.T) {
		f := newFakeS3(t)
		d := newSlow(t, f)
		f.hang["UploadPart#2"] = 1
		data := randomBytes(t, 2*testPartSize+5)
		start := time.Now()
		if err := d.Put(context.Background(), name, bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(f.object(name), data) || f.count("UploadPart#2") != 2 {
			t.Fatalf("operations %v", f.opsSeen())
		}
		if time.Since(start) > 5*time.Second {
			t.Fatalf("the timeout took %s", time.Since(start))
		}
	})
	t.Run("a part that never gets an answer fails within the budget", func(t *testing.T) {
		f := newFakeS3(t)
		d := newSlow(t, f)
		f.hang["UploadPart#1"] = -1
		start := time.Now()
		err := d.Put(context.Background(), name, bytes.NewReader(randomBytes(t, 2*testPartSize)))
		if err == nil || !strings.Contains(err.Error(), "UploadPart") {
			t.Fatalf("error %v", err)
		}
		noSecret(t, "timeout", err)
		if strings.Contains(err.Error(), "http://") || strings.Contains(err.Error(), "uploadId") {
			t.Fatalf("the error carries the request URL: %v", err)
		}
		if f.count("UploadPart#1") != 3 || f.count("AbortMultipartUpload") != 1 || f.numObjects() != 0 {
			t.Fatalf("operations %v", f.opsSeen())
		}
		if time.Since(start) > 5*time.Second {
			t.Fatalf("took %s", time.Since(start))
		}
	})
	t.Run("creating an upload is not repeated after a timeout", func(t *testing.T) {
		f := newFakeS3(t)
		d := newSlow(t, f)
		f.hang["CreateMultipartUpload"] = 1
		if err := d.Put(context.Background(), name, bytes.NewReader(randomBytes(t, 2*testPartSize))); err == nil {
			t.Fatal("expected an error")
		}
		if f.count("CreateMultipartUpload") != 1 {
			t.Fatalf("operations %v", f.opsSeen())
		}
	})
	t.Run("a download that stalls fails", func(t *testing.T) {
		f := newFakeS3(t)
		d := newSlow(t, f)
		f.store(name, randomBytes(t, 100_000))
		f.stallGet = true
		rc, err := d.Get(context.Background(), name)
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		start := time.Now()
		got, err := io.ReadAll(rc)
		if err == nil || !strings.Contains(err.Error(), "nothing received") {
			t.Fatalf("read %d bytes, error %v", len(got), err)
		}
		if len(got) != 50_000 || time.Since(start) > 5*time.Second {
			t.Fatalf("read %d bytes in %s", len(got), time.Since(start))
		}
	})
	t.Run("a get that fails once is asked again", func(t *testing.T) {
		f := newFakeS3(t)
		d := newSlow(t, f)
		f.store(name, []byte("content"))
		f.fail["GetObject"] = 1
		rc, err := d.Get(context.Background(), name)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(rc)
		_ = rc.Close()
		if string(got) != "content" || f.count("GetObject") != 2 {
			t.Fatalf("%q, %v", got, f.opsSeen())
		}
		f.fail["GetObject"] = -1
		if _, err := d.Get(context.Background(), name); err == nil || f.count("GetObject") != 2+3 {
			t.Fatalf("%v, %v", err, f.opsSeen())
		}
	})
	t.Run("nobody listens", func(t *testing.T) {
		f := newFakeS3(t)
		d := newSlow(t, f)
		f.server.Close()
		err := d.Put(context.Background(), name, strings.NewReader("x"))
		if err == nil || !strings.Contains(err.Error(), "PutObject") {
			t.Fatalf("error %v", err)
		}
		noSecret(t, "connection refused", err)
		if _, err := d.List(context.Background()); err == nil {
			t.Fatal("List succeeded without a server")
		}
	})
}

func TestS3ConfigValidation(t *testing.T) {
	good := S3Config{Endpoint: "https://s3.eu-west-3.amazonaws.com", Region: "eu-west-3", Bucket: "hm-backups",
		Prefix: "machines/a", AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "S3CR3T-value-0123"}
	if _, err := NewS3Destination(good); err != nil {
		t.Fatal(err)
	}
	d, _ := NewS3Destination(good)
	if d.partSize != 16<<20 || DefaultS3PartSize != 16<<20 {
		t.Fatalf("default part size %d", d.partSize)
	}
	if d.requestTimeout != 60*time.Second || d.partTimeout != 15*time.Minute || d.idleTimeout != 2*time.Minute || d.maxRetries != 3 {
		t.Fatalf("defaults: %v %v %v %d", d.requestTimeout, d.partTimeout, d.idleTimeout, d.maxRetries)
	}
	change := func(f func(c *S3Config)) S3Config {
		c := good
		f(&c)
		return c
	}
	for name, cfg := range map[string]S3Config{
		"http":                   change(func(c *S3Config) { c.Endpoint = "http://s3.example.com" }),
		"http although allowed":  change(func(c *S3Config) { c.Endpoint = "http://s3.example.com"; c.AllowLoopbackHTTP = true }),
		"http to a private host": change(func(c *S3Config) { c.Endpoint = "http://192.168.1.20:9000"; c.AllowLoopbackHTTP = true }),
		"http localhost name":    change(func(c *S3Config) { c.Endpoint = "http://localhost:9000"; c.AllowLoopbackHTTP = true }),
		"http loopback not allowed": change(func(c *S3Config) {
			c.Endpoint = "http://127.0.0.1:9000"
		}),
		"no scheme":        change(func(c *S3Config) { c.Endpoint = "s3.example.com" }),
		"other scheme":     change(func(c *S3Config) { c.Endpoint = "ftp://s3.example.com" }),
		"empty endpoint":   change(func(c *S3Config) { c.Endpoint = "" }),
		"path":             change(func(c *S3Config) { c.Endpoint = "https://s3.example.com/bucket" }),
		"query":            change(func(c *S3Config) { c.Endpoint = "https://s3.example.com?x=1" }),
		"empty query":      change(func(c *S3Config) { c.Endpoint = "https://s3.example.com?" }),
		"fragment":         change(func(c *S3Config) { c.Endpoint = "https://s3.example.com#f" }),
		"user info":        change(func(c *S3Config) { c.Endpoint = "https://user:pass@s3.example.com" }),
		"port zero":        change(func(c *S3Config) { c.Endpoint = "https://s3.example.com:0" }),
		"port too large":   change(func(c *S3Config) { c.Endpoint = "https://s3.example.com:70000" }),
		"host underscore":  change(func(c *S3Config) { c.Endpoint = "https://s3_x.example.com" }),
		"region upper":     change(func(c *S3Config) { c.Region = "EU-WEST-3" }),
		"region empty":     change(func(c *S3Config) { c.Region = "" }),
		"region slash":     change(func(c *S3Config) { c.Region = "eu/west" }),
		"bucket upper":     change(func(c *S3Config) { c.Bucket = "Bucket" }),
		"bucket short":     change(func(c *S3Config) { c.Bucket = "ab" }),
		"bucket slash":     change(func(c *S3Config) { c.Bucket = "a/b" }),
		"bucket dot dot":   change(func(c *S3Config) { c.Bucket = ".." }),
		"prefix dot dot":   change(func(c *S3Config) { c.Prefix = "a/../b" }),
		"prefix dots":      change(func(c *S3Config) { c.Prefix = "a..b" }),
		"prefix dot":       change(func(c *S3Config) { c.Prefix = "a/./b" }),
		"prefix space":     change(func(c *S3Config) { c.Prefix = "a b" }),
		"prefix query":     change(func(c *S3Config) { c.Prefix = "a?b" }),
		"prefix long":      change(func(c *S3Config) { c.Prefix = strings.Repeat("a", 201) }),
		"access key short": change(func(c *S3Config) { c.AccessKeyID = "abc" }),
		"access key slash": change(func(c *S3Config) { c.AccessKeyID = "abc/def" }),
		"no secret":        change(func(c *S3Config) { c.SecretAccessKey = "" }),
		"secret newline":   change(func(c *S3Config) { c.SecretAccessKey = "abc\ndef" }),
		"part too small":   change(func(c *S3Config) { c.PartSize = MinS3PartSize - 1 }),
		"part too large":   change(func(c *S3Config) { c.PartSize = MaxS3PartSize + 1 }),
		"part negative":    change(func(c *S3Config) { c.PartSize = -1 }),
	} {
		d, err := NewS3Destination(cfg)
		if !errors.Is(err, ErrInvalidConfig) || d != nil {
			t.Errorf("%s: %v", name, err)
		}
		noSecret(t, name, err)
		if err != nil && cfg.SecretAccessKey != "" && strings.Contains(err.Error(), cfg.SecretAccessKey) {
			t.Errorf("%s: the error shows the secret key", name)
		}
	}
	for name, cfg := range map[string]S3Config{
		"port":              change(func(c *S3Config) { c.Endpoint = "https://minio.lan:9000" }),
		"trailing slash":    change(func(c *S3Config) { c.Endpoint = "https://minio.lan:9000/" }),
		"address":           change(func(c *S3Config) { c.Endpoint = "https://192.168.1.20:9000" }),
		"upper case host":   change(func(c *S3Config) { c.Endpoint = "https://S3.Example.COM" }),
		"loopback http":     change(func(c *S3Config) { c.Endpoint = "http://127.0.0.1:9000"; c.AllowLoopbackHTTP = true }),
		"loopback http v6":  change(func(c *S3Config) { c.Endpoint = "http://[::1]:9000"; c.AllowLoopbackHTTP = true }),
		"no prefix":         change(func(c *S3Config) { c.Prefix = "" }),
		"part size 5 MiB":   change(func(c *S3Config) { c.PartSize = MinS3PartSize }),
		"part size 512 MiB": change(func(c *S3Config) { c.PartSize = MaxS3PartSize }),
		"no retry":          change(func(c *S3Config) { c.MaxRetries = -1 }),
	} {
		if _, err := NewS3Destination(cfg); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if d, _ := NewS3Destination(change(func(c *S3Config) { c.Endpoint = "https://S3.Example.COM" })); d.host != "s3.example.com" {
		t.Errorf("host %q", d.host)
	}
	if d, _ := NewS3Destination(change(func(c *S3Config) { c.MaxRetries = -1 })); d.maxRetries != 0 {
		t.Errorf("retries %d", d.maxRetries)
	}
}

// HTTPS, with the certificate checked.
func TestS3OverTLS(t *testing.T) {
	f := &fakeS3{t: t, secret: fakeSecret, objects: map[string][]byte{}, uploads: map[string]*fakeUpload{},
		pageSize: 1000, partSize: testPartSize, fail: map[string]int{}, failStatus: map[string]int{}, failCode: map[string]string{}, hang: map[string]int{}}
	f.server = httptest.NewUnstartedServer(f)
	f.server.Config.ErrorLog = log.New(io.Discard, "", 0) // the refused handshake below
	f.server.StartTLS()
	defer f.server.Close()
	cfg := fakeConfig(f, "tls")
	cfg.AllowLoopbackHTTP = false
	cfg.MaxRetries = -1
	name := ArchiveName("m1", day(1))

	// The test server's certificate is signed by nobody the system trusts.
	untrusting, err := NewS3Destination(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer untrusting.client.CloseIdleConnections()
	err = untrusting.Put(context.Background(), name, strings.NewReader("x"))
	if err == nil || len(f.opsSeen()) != 0 {
		t.Fatalf("an untrusted certificate was accepted: %v", err)
	}
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Fatalf("error %v", err)
	}
	noSecret(t, "certificate", err)

	// Trusting it: the same operations work over HTTPS.
	d, err := NewS3Destination(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer d.client.CloseIdleConnections()
	pool := x509.NewCertPool()
	pool.AddCert(f.server.Certificate())
	d.client.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool
	d.partSize = testPartSize
	data := randomBytes(t, 2*testPartSize+9)
	if err := d.Put(context.Background(), name, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	rc, err := d.Get(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	_ = rc.Close()
	if !bytes.Equal(got, data) || !bytes.Equal(f.object("tls/"+name), data) {
		t.Fatal("content differs over TLS")
	}
	if n := f.bad(); n != 0 {
		t.Fatalf("%d bad signatures", n)
	}
}
