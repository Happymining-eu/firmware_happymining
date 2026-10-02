package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/credential"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/release"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/version"
)

// DownloadStallTimeout is how long a package download may go without
// receiving a byte before it is abandoned.
const DownloadStallTimeout = 2 * time.Minute

// stallTimeout is DownloadStallTimeout; tests shorten it.
var stallTimeout = DownloadStallTimeout

// Errors of DownloadArtifact.
var (
	// ErrArtifactSize means the server sent more or fewer bytes than the
	// release says the package has.
	ErrArtifactSize = errors.New("the package does not have the size the release states")
	// ErrDownloadStalled means no byte arrived for DownloadStallTimeout.
	ErrDownloadStalled = errors.New("the package download stalled")
)

// GetUpdate returns the machine's update channel, policy and window and the
// release it may install now, if any (GET /api/v1/device/update).
func (c *Client) GetUpdate(ctx context.Context, token string) (*protocol.UpdateResponse, error) {
	var out *protocol.UpdateResponse
	if err := c.do(ctx, http.MethodGet, protocol.PathUpdate, token, nil, &out); err != nil {
		return nil, err
	}
	if out == nil {
		return nil, fmt.Errorf("update: %w", ErrMalformedResponse)
	}
	return out, nil
}

// DownloadArtifact writes the package of release ver to w. The path is built
// here from the version, which must be MAJOR.MINOR.PATCH; nothing the server
// sends is used as a URL. Exactly size bytes are accepted: a longer body is
// cut after size+1 bytes and refused, a shorter one is refused. The caller
// checks the content (SHA-256) and bounds the whole download with ctx.
func (c *Client) DownloadArtifact(ctx context.Context, token, ver string, size int64, w io.Writer) error {
	if _, err := release.ParseVersion(ver); err != nil {
		return fmt.Errorf("refusing to download a release whose version is not MAJOR.MINOR.PATCH: %w", err)
	}
	if size <= 0 || size > release.MaxArtifactBytes {
		return fmt.Errorf("refusing a package size of %d bytes (1 to %d)", size, int64(release.MaxArtifactBytes))
	}
	if !credential.ValidToken(token) {
		return errors.New("refusing to send a credential that does not have the expected format")
	}
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	path := protocol.UpdateArtifactPath(ver)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("User-Agent", "happymining-agent/"+version.Version)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.dl.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		data, _ := readLimited(io.LimitReader(resp.Body, 64*1024))
		return apiError(resp, data)
	}
	if resp.ContentLength >= 0 && resp.ContentLength != size {
		return fmt.Errorf("%w: the server announces %d bytes, the release %d", ErrArtifactSize, resp.ContentLength, size)
	}
	body := &stallReader{r: resp.Body, timeout: stallTimeout, stall: func() { cancel(ErrDownloadStalled) }}
	defer body.stop()
	n, err := io.Copy(w, io.LimitReader(body, size+1))
	if err != nil {
		if cause := context.Cause(ctx); errors.Is(cause, ErrDownloadStalled) {
			return fmt.Errorf("GET %s: %w after %d bytes", path, ErrDownloadStalled, n)
		}
		return fmt.Errorf("GET %s: read package: %w", path, err)
	}
	if n != size {
		return fmt.Errorf("%w: received %d bytes or more, the release states %d", ErrArtifactSize, n, size)
	}
	return nil
}

// stallReader calls stall when no Read returned data for timeout.
type stallReader struct {
	r       io.Reader
	timeout time.Duration
	stall   func()
	once    sync.Once
	timer   *time.Timer
}

func (s *stallReader) Read(p []byte) (int, error) {
	s.once.Do(func() { s.timer = time.AfterFunc(s.timeout, s.stall) })
	n, err := s.r.Read(p)
	if n > 0 {
		s.timer.Reset(s.timeout)
	}
	return n, err
}

func (s *stallReader) stop() {
	if s.timer != nil {
		s.timer.Stop()
	}
}
