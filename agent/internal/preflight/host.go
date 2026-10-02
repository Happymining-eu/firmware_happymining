package preflight

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/client"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/collector"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/execx"
)

// HostEnv returns the Env for the running host. api may be nil (no API URL
// configured), in which case the API reachability check is skipped.
func HostEnv(api *client.Client, offline bool) Env {
	env := Env{
		Runner:     execx.OS{},
		Statfs:     collector.OSStatfs,
		Arch:       runtime.GOARCH,
		Offline:    offline,
		ProbeHTTPS: ProbeHTTPS,
	}
	if api != nil {
		env.ProbeAPI = func(ctx context.Context) (string, error) {
			status, err := api.Probe(ctx)
			if err != nil {
				return "", err
			}
			host := api.BaseURL()
			if u, perr := url.Parse(host); perr == nil {
				host = u.Host
			}
			return fmt.Sprintf("%s answered over a verified connection (HTTP %d without credentials)", host, status), nil
		}
	}
	return env
}

// ProbeHTTPS makes one HTTPS request with certificate verification and
// reports whether any HTTP response came back. It sends no credentials and
// follows no redirects.
func ProbeHTTPS(ctx context.Context, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("probe URL must be an https URL")
	}
	hc := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 8 * time.Second,
			DisableKeepAlives:     true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.Body.Close()
}
