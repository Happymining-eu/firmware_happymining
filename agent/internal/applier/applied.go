package applier

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
)

// maxAppliedBytes bounds applied.json: a document of at most 64 KiB plus the
// envelope.
const maxAppliedBytes = appliance.MaxDocumentBytes + 4096

// Applied is applied.json: the cloud document waiting for, or last given
// to, apply-stored. Its sealed secrets are kept as they are (a backup saves
// this file).
type Applied struct {
	Origin   string          `json:"origin"`
	Revision int64           `json:"revision"`
	SHA256   string          `json:"sha256"`
	Received string          `json:"received_at"`
	Document json.RawMessage `json:"document"`
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// loadApplied reads applied.json. A missing file yields nil and no error.
func (e *Env) loadApplied() (*Applied, error) {
	data, err := readFile(e.Paths.appliedPath(), maxAppliedBytes, &e.OwnerUID)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var a Applied
	if err := json.Unmarshal(data, &a); err != nil || a.Origin != OriginCloud || len(a.Document) == 0 {
		return nil, fmt.Errorf("applied.json is damaged")
	}
	if sha256Hex(a.Document) != a.SHA256 {
		return nil, fmt.Errorf("applied.json does not match its checksum")
	}
	return &a, nil
}

func (e *Env) saveApplied(a *Applied) error {
	if err := e.ensureStateDir(); err != nil {
		return err
	}
	data, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return writeFile(e.Paths.StateDir, appliedFile, append(data, '\n'), 0o600)
}

// compactJSON returns the compact form of raw (the document as received,
// without insignificant white space). It does not reorder keys.
func compactJSON(raw []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// effective is the document the machine should run now, wherever it comes
// from, with what is needed to apply it.
type effective struct {
	Origin string
	Doc    *appliance.Document
	// Revision is the cloud revision (0 for a local or absent document).
	Revision int64
	// Control is what the heartbeat reports.
	Control string
	// Secrets are the sealed values: the cloud document's own, or the ones
	// entered on the machine under local control.
	Secrets map[string]string
	// SourceKey changes whenever the document or its local secrets change.
	SourceKey string
	// Problem explains a document that cannot be used: the local profile is
	// unusable, or the stored cloud document no longer validates.
	Problem string
	// Catalog is the installed catalog the document was checked against.
	Catalog *appliance.Catalog
}

// emptyVast is the document of a machine with nothing configured.
func emptyVast() *appliance.Document {
	return &appliance.Document{Schema: appliance.DocumentSchema, Mode: appliance.ModeVast,
		Plugins: []appliance.PluginConfig{}, NAS: []appliance.NAS{}, Schedules: []appliance.Schedule{}}
}

// loadCatalog loads the installed catalog with the ownership checks of a
// privileged reader.
func (e *Env) loadCatalog() (*appliance.Catalog, error) {
	return appliance.LoadCatalogOwnedBy(e.Paths.CatalogDir, e.OwnerUID)
}

// resolve decides which document is in force:
//
//  1. a local profile that cannot be used: nothing may be applied (it may
//     have been written to take the machine out of remote control), control
//     is reported as local;
//  2. control: local: the profile's document (none: vast with nothing);
//  3. a stored cloud document;
//  4. a start-up profile (control: cloud with a document);
//  5. nothing: vast with nothing.
func (e *Env) resolve() (*effective, error) {
	cat, err := e.loadCatalog()
	if err != nil {
		return nil, fmt.Errorf("the installed plugin catalog cannot be used: %v", err)
	}
	eff := &effective{Catalog: cat, Control: appliance.ControlCloud}
	prof, err := appliance.LoadProfile(e.Paths.ProfilePath, e.OwnerUID, cat)
	if err != nil {
		eff.Control = appliance.ControlLocal
		eff.Origin = OriginLocal
		eff.Problem = "the local profile cannot be used; nothing is applied until it is fixed or removed: " +
			clipText(err.Error(), 300)
		return eff, nil
	}
	localDoc := func() error {
		eff.Origin = OriginLocal
		eff.Doc = prof.Document
		if eff.Doc == nil {
			eff.Doc = emptyVast()
		}
		secrets, raw, err := e.loadLocalSecrets()
		if err != nil {
			return err
		}
		eff.Secrets = secrets
		canon, err := json.Marshal(eff.Doc)
		if err != nil {
			return err
		}
		eff.SourceKey = OriginLocal + ":" + sha256Hex(canon) + ":" + sha256Hex(raw)
		return nil
	}
	if prof.Control == appliance.ControlLocal {
		eff.Control = appliance.ControlLocal
		return eff, localDoc()
	}
	applied, err := e.loadApplied()
	if err != nil {
		return nil, err
	}
	if applied != nil {
		eff.Origin = OriginCloud
		eff.Revision = applied.Revision
		eff.SourceKey = OriginCloud + ":" + applied.SHA256
		doc, err := appliance.ParseDocument(applied.Document, cat)
		if err != nil {
			eff.Problem = "the stored document no longer validates against the installed catalog: " +
				clipText(err.Error(), 300)
			return eff, nil
		}
		eff.Doc = doc
		eff.Secrets = doc.Secrets
		return eff, nil
	}
	if prof.Document != nil {
		return eff, localDoc()
	}
	eff.Origin = OriginNone
	eff.Doc = emptyVast()
	eff.SourceKey = OriginNone
	return eff, nil
}

// reportedRevision is applied_revision for the heartbeat: the last finished
// cloud revision while a cloud document is in force, else 0 (the machine does
// not run any cloud revision).
func reportedRevision(st *State, origin string) int64 {
	if origin == OriginCloud {
		return st.CloudRevision
	}
	return 0
}

// bootID reads the kernel's boot id ("" when it cannot be read).
func (e *Env) bootID() string {
	data, err := readFile(e.Paths.BootID, 128, nil)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// revisionOf extracts "revision" from a document that may not validate, so
// that a rejected document can be reported against its revision.
func revisionOf(raw []byte) int64 {
	var probe struct {
		Revision json.Number `json:"revision"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&probe); err != nil {
		return 0
	}
	n, err := probe.Revision.Int64()
	if err != nil || n < 1 {
		return 0
	}
	return n
}
