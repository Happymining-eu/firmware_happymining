package agent

import (
	"errors"
	"net/http"
	"strings"
)

// dropAcks is a transport that lets the server process an acknowledgement
// but hides the response from the agent (a lost acknowledgement would look
// the same). Used to test that a lost ack never causes a second execution.
type ackDropper struct{ next http.RoundTripper }

func dropAcks(next http.RoundTripper) http.RoundTripper { return &ackDropper{next: next} }

func (d *ackDropper) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasSuffix(req.URL.Path, "/ack") {
		return nil, errors.New("simulated: acknowledgement lost before reaching the server")
	}
	return d.next.RoundTrip(req)
}
