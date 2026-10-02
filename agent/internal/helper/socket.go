package helper

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

// Socket protocol: the client connects to the root-owned unix socket
// (systemd socket activation, one helper process per connection), writes one
// JSON request terminated by a newline and reads one JSON response line. The helper checks the peer's uid with SO_PEERCRED.

// PeerUID returns the uid of the process at the other end of a unix socket.
func PeerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	return cred.Uid, nil
}

// ServeConn handles exactly one request on conn. allowedUIDs are the peers
// that may ask (root and the happymining user); everyone else is refused.
func ServeConn(ctx context.Context, conn net.Conn, peerUID uint32, allowedUIDs []uint32, d Deps) Response {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	reply := func(r Response) Response {
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		raw, _ := json.Marshal(r)
		_, _ = conn.Write(append(raw, '\n'))
		return r
	}
	allowed := false
	for _, uid := range allowedUIDs {
		if uid == peerUID {
			allowed = true
		}
	}
	if !allowed {
		d.audit("refused connection from uid %d", peerUID)
		return reply(Response{Code: CodeUnauthorized, Detail: "peer is not allowed to use the helper"})
	}
	line, err := bufio.NewReaderSize(conn, MaxRequestBytes+2).ReadSlice('\n')
	if err != nil {
		d.audit("refused request from uid %d: no complete request line", peerUID)
		return reply(Response{Code: CodeInvalid, Detail: "no complete request line within the size and time limit"})
	}
	req, err := DecodeRequest(bytes.NewReader(line))
	if err != nil {
		d.audit("refused request from uid %d: %v", peerUID, err)
		return reply(Response{Code: CodeInvalid, Detail: err.Error()})
	}
	d.audit("request from uid %d: action=%s", peerUID, req.Action)
	// The command itself may take longer than the read deadline.
	_ = conn.SetDeadline(time.Time{})
	return reply(Execute(ctx, req, d))
}

// Client is the agent's side of the helper socket.
type Client struct {
	SocketPath string
	Timeout    time.Duration
}

// ErrUnavailable means the helper socket could not be reached.
var ErrUnavailable = errors.New("privileged helper is not available")

// Do sends one request and returns the helper's response.
func (c *Client) Do(ctx context.Context, req Request) (Response, error) {
	if err := req.Validate(); err != nil {
		return Response{}, err
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 150 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return Response{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	// The helper may answer and close before it reads the request (for
	// example when it refuses the peer), which makes the write fail. Its
	// answer is still readable, so a write error is only reported if there is
	// no answer.
	_, writeErr := conn.Write(append(raw, '\n'))
	line, err := bufio.NewReaderSize(conn, 4096).ReadSlice('\n')
	if err != nil {
		if writeErr != nil {
			return Response{}, fmt.Errorf("write helper request: %w", writeErr)
		}
		return Response{}, fmt.Errorf("read helper response: %w", err)
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return Response{}, errors.New("helper sent an invalid response")
	}
	return resp, nil
}

// Invoke runs one action and turns a refusal into an error.
func (c *Client) Invoke(ctx context.Context, req Request) (string, error) {
	resp, err := c.Do(ctx, req)
	if err != nil {
		return "", err
	}
	if !resp.OK {
		return "", fmt.Errorf("helper refused (%s): %s", resp.Code, resp.Detail)
	}
	return resp.Detail, nil
}
