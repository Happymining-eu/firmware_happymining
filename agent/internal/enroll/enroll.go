// Package enroll implements the pairing workflow shared by
// `happyminingctl pair` and the simulator: normalise the pairing code, make
// sure the install identity exists, call the enrollment endpoint once and
// store the credential atomically with mode 0600.
//
// The pairing code is never logged and never written to disk.
package enroll

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/client"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/credential"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/fsx"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/identity"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/pairing"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/protocol"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/version"
)

// ErrAlreadyPaired is returned when a credential already exists.
var ErrAlreadyPaired = errors.New("this machine is already paired; run `happyminingctl unpair` first if you really want to pair it again")

// ErrPairingFailed is the generic enrollment failure. The API does not say
// whether the code was wrong, expired, used or locked.
var ErrPairingFailed = errors.New("pairing failed: the code is wrong, expired, already used or locked. Ask your HappyMining administrator for a new code")

// Params are the inputs of Pair.
type Params struct {
	Client   *client.Client
	StateDir string
	Code     string // as typed; normalised here
	Hostname string
	OS       protocol.OSInfo
	// Owner, if set, becomes the owner of the files created in StateDir.
	Owner *fsx.Owner
	Now   func() time.Time
}

// Paired reports whether a credential file exists in stateDir.
func Paired(stateDir string) bool {
	_, err := os.Lstat(credential.Path(stateDir))
	return err == nil
}

// Pair enrolls the machine and stores the credential.
func Pair(ctx context.Context, p Params) (*credential.File, error) {
	if p.Now == nil {
		p.Now = time.Now
	}
	if Paired(p.StateDir) {
		return nil, ErrAlreadyPaired
	}
	code, err := pairing.Normalize(p.Code)
	if err != nil {
		return nil, err
	}
	idPath := identity.Path(p.StateDir)
	if _, err := identity.Init(idPath, false, p.Owner); err != nil {
		return nil, fmt.Errorf("install identity: %w", err)
	}
	fingerprint, err := identity.Fingerprint(idPath)
	if err != nil {
		return nil, fmt.Errorf("install identity: %w", err)
	}
	hostname := protocol.Truncate(strings.TrimSpace(p.Hostname), protocol.MaxStringLen)
	if hostname == "" {
		hostname = "unknown"
	}
	resp, err := p.Client.Enroll(ctx, &protocol.EnrollRequest{
		PairingCode:        code,
		Hostname:           hostname,
		MachineFingerprint: fingerprint,
		AgentVersion:       version.Version,
		OS:                 p.OS,
	})
	if err != nil {
		var api *client.APIError
		if errors.As(err, &api) && api.Status == 401 {
			return nil, ErrPairingFailed
		}
		return nil, fmt.Errorf("enrollment request failed: %w", err)
	}
	cred := &credential.File{
		DeviceID:     resp.DeviceID,
		MachineID:    resp.MachineID,
		CredentialID: resp.Credential.ID,
		Token:        resp.Credential.Token,
		ExpiresAt:    resp.Credential.ExpiresAt,
		APIURL:       p.Client.BaseURL(),
		PairedAt:     protocol.FormatTime(p.Now()),
	}
	if err := credential.Save(credential.Path(p.StateDir), cred, p.Owner); err != nil {
		return nil, fmt.Errorf("the API issued a credential but it could not be stored (the pairing code is now used; ask for a new one): %w", err)
	}
	return cred, nil
}
