package appliance

import (
	"errors"
	"fmt"
	"io/fs"
)

// DefaultProfilePath is where the local profile lives on a machine.
const DefaultProfilePath = "/etc/happymining/appliance.json"

// Profile is the local profile file (section 6.4): how a machine is
// configured before it meets the cloud, and how its owner takes it out of
// remote control.
type Profile struct {
	Schema int `json:"schema"`
	// Control is ControlLocal when the machine follows this file and ignores
	// cloud documents, ControlCloud otherwise.
	Control string `json:"control"`
	// Document is what the machine runs under local control, or a start-up
	// profile used until the first cloud document arrives. It has no
	// revision and no secrets. It may be nil: a machine under local control
	// without a document has nothing configured, which is vast mode with no
	// plugin.
	Document *Document `json:"document,omitempty"`
}

// ParseProfile strictly decodes and validates the local profile against the
// catalog: one JSON object of at most MaxDocumentBytes with "schema" (1),
// "control" and an optional "document". The document follows every rule of
// ParseDocument, except that it has no "revision" and no "secrets" (either
// key is an error: the file holds no secrets), and that the secrets it
// refers to are checked by name only, since they are entered on the machine.
//
// An error means the file is there and cannot be used. A caller must not
// treat that like an absent file: the owner may have written it to take the
// machine out of remote control.
func ParseProfile(raw []byte, c *Catalog) (*Profile, error) {
	if c == nil {
		return nil, errors.New("no catalog")
	}
	tree, err := decodeStrict(raw, MaxDocumentBytes)
	if err != nil {
		return nil, fmt.Errorf("profile: %w", err)
	}
	ck := &checker{}
	o := ck.object("", tree)
	p := &Profile{}
	p.Schema = int(o.integer("schema", DocumentSchema, DocumentSchema))
	p.Control = o.oneOf("control", ControlCloud, ControlLocal)
	if v, ok := o.get("document"); ok {
		p.Document = parseDocument(ck, "document", v, c, true)
	}
	o.done()
	if ck.err != nil {
		return nil, fmt.Errorf("profile: %w", ck.err)
	}
	return p, nil
}

// LoadProfile reads and validates the profile file at path. The file must
// be a regular file (a symbolic link is refused) owned by ownerUID (0 in
// production), not writable by group or others, of at most MaxDocumentBytes.
// An absent file is not an error: it yields a profile with ControlCloud and
// no document.
func LoadProfile(path string, ownerUID uint32, c *Catalog) (*Profile, error) {
	raw, err := readRegular(path, &ownerUID, MaxDocumentBytes)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &Profile{Schema: DocumentSchema, Control: ControlCloud}, nil
		}
		return nil, err
	}
	p, err := ParseProfile(raw, c)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}
