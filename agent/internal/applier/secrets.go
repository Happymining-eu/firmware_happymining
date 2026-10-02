package applier

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/seal"
)

// maxLocalSecretsBytes bounds local-secrets.json: 32 secrets of at most
// 4096 bytes, sealed.
const maxLocalSecretsBytes = 512 * 1024

// loadLocalSecrets reads local-secrets.json (name -> sealed value), the
// secrets entered on the machine with `hm-helper secret-set`. A missing file
// is an empty set. It also returns the raw bytes, for the source key.
func (e *Env) loadLocalSecrets() (map[string]string, []byte, error) {
	data, err := readFile(e.Paths.localSecretsPath(), maxLocalSecretsBytes, &e.OwnerUID)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	out := map[string]string{}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, nil, fmt.Errorf("local-secrets.json is damaged")
	}
	for name, value := range out {
		if !seal.ValidName(name) || seal.CheckSealed(value) != nil {
			return nil, nil, fmt.Errorf("local-secrets.json is damaged")
		}
	}
	return out, data, nil
}

// sealKey loads the machine's sealing key, creating it on first use.
func (e *Env) sealKey() (*seal.PrivateKey, error) {
	if err := e.ensureStateDir(); err != nil {
		return nil, err
	}
	return seal.LoadOrCreateOwnedBy(e.Paths.sealKeyPath(), e.OwnerUID)
}

// opener opens the sealed values of one document.
type opener struct {
	key     *seal.PrivateKey
	sealed  map[string]string
	keyErr  error
	scrub   *scrubber
	present map[string]bool
}

func (e *Env) newOpener(sealed map[string]string) *opener {
	key, err := e.sealKey()
	o := &opener{key: key, keyErr: err, sealed: sealed, scrub: &scrubber{}, present: map[string]bool{}}
	for name := range sealed {
		o.present[name] = true
	}
	return o
}

// newScrubbingOpener is newOpener for work that runs commands: every secret
// of the document is opened once up front, only to remember its hash in the
// scrubber (the plaintext is wiped at once), so that the output of any
// command of this run is redacted for every one of them, not only for the
// secrets that command was given.
func (e *Env) newScrubbingOpener(sealed map[string]string) *opener {
	o := e.newOpener(sealed)
	for name := range sealed {
		if plain, err := o.open(name); err == nil {
			seal.Wipe(plain)
		}
	}
	return o
}

// errSecretMissing and errSecretUnreadable are the only two ways a secret
// fails; they name no value.
var (
	errSecretMissing    = errors.New("missing")
	errSecretUnreadable = errors.New("unreadable")
)

// open returns the plaintext of the secret name. The caller wipes it with
// seal.Wipe as soon as it has written it where it is needed. Every opened
// value is remembered by the scrubber (as a hash) so that command output
// that would contain it can be redacted.
func (o *opener) open(name string) ([]byte, error) {
	sealed, ok := o.sealed[name]
	if !ok || sealed == "" {
		return nil, errSecretMissing
	}
	if o.keyErr != nil || o.key == nil {
		return nil, errSecretUnreadable
	}
	plain, err := o.key.Open(name, sealed)
	if err != nil {
		return nil, errSecretUnreadable
	}
	o.scrub.add(plain)
	return plain, nil
}

// state returns the reported state of one secret without keeping anything.
func (o *opener) state(name string) string {
	plain, err := o.open(name)
	switch {
	case errors.Is(err, errSecretMissing):
		return appliance.SecretMissing
	case err != nil:
		return appliance.SecretUnreadable
	}
	seal.Wipe(plain)
	return appliance.SecretOK
}

// secretStates lists the secrets the document refers to: every required one,
// and an optional one only when a value is stored (an optional plugin secret
// that was never given is not a problem to report).
func (o *opener) secretStates(doc *appliance.Document, cat *appliance.Catalog) []appliance.SecretState {
	var out []appliance.SecretState
	seen := map[string]bool{}
	for _, ref := range appliance.SecretRefs(doc, cat) {
		seen[ref.Name] = true
		if !ref.Required && !o.present[ref.Name] {
			continue
		}
		out = append(out, appliance.SecretState{Name: ref.Name, State: o.state(ref.Name)})
	}
	// A cloud document may carry a secret of a plugin that is not in the
	// catalog's current list; it is still reported.
	var extra []string
	for name := range o.sealed {
		if !seen[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	for _, name := range extra {
		out = append(out, appliance.SecretState{Name: name, State: o.state(name)})
	}
	return out
}

// scrubber removes opened secret values from text that is about to become a
// detail. It keeps only the length and the SHA-256 of each value, never the
// value itself, and compares every window of that length.
type scrubber struct {
	entries []scrubEntry
}

type scrubEntry struct {
	n   int
	sum [32]byte
}

func (s *scrubber) add(plain []byte) {
	if s == nil || len(plain) == 0 {
		return
	}
	s.entries = append(s.entries, scrubEntry{n: len(plain), sum: sha256.Sum256(plain)})
}

const redacted = "[redacted]"

// scrub returns text with every occurrence of a remembered value replaced.
// Text is bounded by its callers (a few hundred bytes), so the window scan is
// cheap.
func (s *scrubber) scrub(text string) string {
	if s == nil || len(s.entries) == 0 {
		return text
	}
	b := []byte(text)
	for _, e := range s.entries {
		if e.n > len(b) {
			continue
		}
		var out []byte
		i := 0
		for i <= len(b)-e.n {
			if sha256.Sum256(b[i:i+e.n]) == e.sum {
				out = append(out, redacted...)
				i += e.n
				continue
			}
			out = append(out, b[i])
			i++
		}
		out = append(out, b[i:]...)
		b = out
	}
	return string(b)
}

// envValueProblem says why an opened secret cannot be given to a container
// through an env file, or "" when it can. A NUL cannot be in an environment
// variable and invalid UTF-8 would not survive Compose and the Docker API
// unchanged; everything else is written escaped (see encodeEnvValue).
func envValueProblem(plain []byte) string {
	if strings.IndexByte(string(plain), 0) >= 0 {
		return "contains a NUL byte"
	}
	if !utf8Valid(plain) {
		return "is not valid UTF-8"
	}
	return ""
}
