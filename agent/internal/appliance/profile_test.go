package appliance

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

// profileDocument is the full fixture without "revision" and "secrets": what
// a profile's document looks like.
func profileDocument(t *testing.T) map[string]any {
	t.Helper()
	doc := fullDocument(t)
	delete(doc, "revision")
	delete(doc, "secrets")
	return doc
}

func TestParseProfile(t *testing.T) {
	c := fixtureCatalog(t)

	p, err := ParseProfile(encode(t, map[string]any{"schema": 1, "control": "local", "document": profileDocument(t)}), c)
	if err != nil {
		t.Fatalf("a local profile with a document: %v", err)
	}
	if p.Schema != 1 || p.Control != ControlLocal || p.Document == nil {
		t.Fatalf("profile = %+v", p)
	}
	doc := p.Document
	if doc.Revision != 0 || doc.Secrets != nil || doc.Mode != ModePrivateAI || len(doc.Plugins) != 4 || len(doc.NAS) != 2 ||
		doc.Vectorizer == nil || doc.Backup == nil || len(doc.Schedules) != 2 || doc.Update == nil {
		t.Fatalf("profile document = %+v", doc)
	}
	// The secrets it refers to are named, and entered on the machine.
	if got, want := SecretNames(doc), []string{SecretAnswerAPIKey, "nas.docs.password"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("SecretNames = %v, want %v", got, want)
	}
	refs := SecretRefs(doc, c)
	if len(refs) != 3 || refs[2].Name != "plugin.assistant.api_key" || refs[2].Required || refs[2].Env != "ASSISTANT_API_KEY" {
		t.Fatalf("SecretRefs = %+v", refs)
	}
	// The same document is not a cloud document: it has no revision.
	if _, err := ParseDocument(encode(t, profileDocument(t)), c); err == nil {
		t.Fatal("a document without a revision was accepted as a cloud document")
	}

	// A start-up profile under cloud control, and profiles without a document.
	p, err = ParseProfile(encode(t, map[string]any{"schema": 1, "control": "cloud", "document": profileDocument(t)}), c)
	if err != nil || p.Control != ControlCloud || p.Document == nil {
		t.Fatalf("a start-up profile: %+v, %v", p, err)
	}
	for _, control := range []string{ControlCloud, ControlLocal} {
		p, err = ParseProfile([]byte(`{"schema": 1, "control": "`+control+`"}`), c)
		if err != nil || p.Control != control || p.Document != nil {
			t.Fatalf("control %s without a document: %+v, %v", control, p, err)
		}
	}
	p, err = ParseProfile([]byte(`{"schema":1,"control":"local","document":{"schema":1,"mode":"vast"}}`), c)
	if err != nil || p.Document.Mode != ModeVast || len(p.Document.Plugins) != 0 {
		t.Fatalf("a minimal local document: %+v, %v", p, err)
	}

	with := func(change func(doc map[string]any)) []byte {
		doc := profileDocument(t)
		change(doc)
		return encode(t, map[string]any{"schema": 1, "control": "local", "document": doc})
	}
	bad := map[string]struct {
		raw  []byte
		want string
	}{
		"schema missing":            {[]byte(`{"control":"local"}`), "schema: is required"},
		"schema 2":                  {[]byte(`{"schema":2,"control":"local"}`), "schema: must be 1"},
		"control missing":           {[]byte(`{"schema":1}`), "control: is required"},
		"control unknown":           {[]byte(`{"schema":1,"control":"remote"}`), "control: must be one of"},
		"control a boolean":         {[]byte(`{"schema":1,"control":true}`), "control: must be a string"},
		"unknown key":               {[]byte(`{"schema":1,"control":"local","owner":"me"}`), `unknown key "owner"`},
		"secrets at the top":        {[]byte(`{"schema":1,"control":"local","secrets":{}}`), `unknown key "secrets"`},
		"duplicate key":             {[]byte(`{"schema":1,"control":"cloud","control":"local"}`), `duplicate key "control"`},
		"document null":             {[]byte(`{"schema":1,"control":"local","document":null}`), "document: must be an object"},
		"document a list":           {[]byte(`{"schema":1,"control":"local","document":[]}`), "document: must be an object"},
		"not an object":             {[]byte(`[]`), "must be an object"},
		"not JSON":                  {[]byte(`control: local`), "not valid JSON"},
		"too large":                 {[]byte(`{"schema":1,"control":"local"}` + strings.Repeat(" ", MaxDocumentBytes)), "larger than 65536 bytes"},
		"document with a revision":  {with(func(d map[string]any) { d["revision"] = 3 }), `document: unknown key "revision"`},
		"document with secrets":     {with(func(d map[string]any) { d["secrets"] = map[string]any{"nas.docs.password": sealedSamples(t)[0]} }), `document: unknown key "secrets"`},
		"document with no secrets":  {with(func(d map[string]any) { d["secrets"] = map[string]any{} }), `document: unknown key "secrets"`},
		"document without schema":   {with(func(d map[string]any) { delete(d, "schema") }), "document.schema: is required"},
		"document without mode":     {with(func(d map[string]any) { delete(d, "mode") }), "document.mode: is required"},
		"document unknown key":      {with(func(d map[string]any) { d["extra"] = 1 }), `document: unknown key "extra"`},
		"wrong NAS secret name":     {with(func(d map[string]any) { obj(t, list(t, d["nas"])[0])["secret"] = "nas.other.password" }), "document.nas[0].secret: must be exactly"},
		"user name without secret":  {with(func(d map[string]any) { delete(obj(t, list(t, d["nas"])[0]), "secret") }), "document.nas[0].secret: is required"},
		"wrong answer secret name":  {with(func(d map[string]any) { obj(t, obj(t, d["vectorizer"])["answer"])["secret"] = "ai.key" }), "document.vectorizer.answer.secret: must be exactly"},
		"cloud answer without name": {with(func(d map[string]any) { delete(obj(t, obj(t, d["vectorizer"])["answer"]), "secret") }), "document.vectorizer.answer.secret: is required"},
		"bad host":                  {with(func(d map[string]any) { obj(t, list(t, d["nas"])[0])["host"] = "-o" }), "document.nas[0].host"},
		"unknown plugin":            {with(func(d map[string]any) { obj(t, list(t, d["plugins"])[0])["id"] = "notthere" }), "document.plugins[0].id"},
		"requirement disabled":      {with(func(d map[string]any) { obj(t, list(t, d["plugins"])[1])["enabled"] = false }), "document.plugins[2]: requires plugin qdrant to be enabled"},
		"mount options":             {with(func(d map[string]any) { obj(t, list(t, d["nas"])[1])["options"] = "suid" }), `document.nas[1]: unknown key "options"`},
	}
	for why, b := range bad {
		_, err := ParseProfile(b.raw, c)
		if err == nil {
			t.Errorf("%s: accepted, must be refused", why)
			continue
		}
		if !strings.Contains(err.Error(), b.want) {
			t.Errorf("%s: refused for another reason:\n  got  %v\n  want something about %q", why, err, b.want)
		}
	}
	if _, err := ParseProfile([]byte(`{"schema":1,"control":"local"}`), nil); err == nil {
		t.Error("a nil catalog must be refused")
	}
}

// Every valid fixture, stripped of revision and secrets, is a valid profile
// document; every invalid fixture stays invalid unless its fault was in the
// revision or in the secrets object itself.
func TestFixturesAsProfileDocuments(t *testing.T) {
	c := fixtureCatalog(t)
	strip := func(f fixture) []byte {
		doc := tree(t, f.raw)
		delete(doc, "revision")
		delete(doc, "secrets")
		return encode(t, map[string]any{"schema": 1, "control": "local", "document": doc})
	}
	for _, f := range loadFixtures(t, fixtureValidDir) {
		if _, err := ParseProfile(strip(f), c); err != nil {
			t.Errorf("valid/%s as a profile document: %v", f.file, err)
		}
	}
	accepted := 0
	for _, f := range loadFixtures(t, fixtureInvalidDir) {
		aboutSecretsOrRevision := strings.HasPrefix(f.file, "revision-") || strings.HasPrefix(f.file, "secret")
		_, err := ParseProfile(strip(f), c)
		if err == nil {
			accepted++
			if !aboutSecretsOrRevision {
				t.Errorf("invalid/%s (%s) is accepted as a profile document", f.file, f.why)
			}
		}
	}
	if accepted == 0 {
		t.Error("no invalid fixture became valid without revision and secrets: the test proves nothing about them")
	}
}

func TestLoadProfile(t *testing.T) {
	c := fixtureCatalog(t)
	write := func(t *testing.T, content string, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "appliance.json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	local := `{"schema":1,"control":"local","document":{"schema":1,"mode":"vast"}}`

	p, err := LoadProfile(filepath.Join(t.TempDir(), "appliance.json"), myUID(), c)
	if err != nil || p.Control != ControlCloud || p.Document != nil || p.Schema != 1 {
		t.Fatalf("an absent profile: %+v, %v", p, err)
	}
	for _, mode := range []os.FileMode{0o644, 0o600, 0o444, 0o640} {
		p, err = LoadProfile(write(t, local, mode), myUID(), c)
		if err != nil || p.Control != ControlLocal || p.Document == nil {
			t.Fatalf("mode %04o: %+v, %v", mode, p, err)
		}
	}
	for _, mode := range []os.FileMode{0o664, 0o646, 0o666, 0o622} {
		if _, err := LoadProfile(write(t, local, mode), myUID(), c); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
			t.Errorf("mode %04o: %v", mode, err)
		}
	}
	if _, err := LoadProfile(write(t, local, 0o644), myUID()+1, c); err == nil || !strings.Contains(err.Error(), "is not owned by uid") {
		t.Errorf("a profile owned by someone else: %v", err)
	}

	// An unusable profile is an error, never "absent".
	if _, err := LoadProfile(write(t, `{"schema":1,"control":"locl"}`, 0o644), myUID(), c); err == nil {
		t.Error("a profile with a typo must be an error")
	}
	if _, err := LoadProfile(write(t, local+strings.Repeat(" ", MaxDocumentBytes), 0o644), myUID(), c); err == nil {
		t.Error("a profile above 64 KiB must be refused")
	}
	real := write(t, local, 0o644)
	link := filepath.Join(t.TempDir(), "appliance.json")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProfile(link, myUID(), c); err == nil {
		t.Error("a symbolic link must be refused")
	}
	dangling := filepath.Join(t.TempDir(), "appliance.json")
	if err := os.Symlink(filepath.Join(t.TempDir(), "nowhere"), dangling); err != nil {
		t.Fatal(err)
	}
	if p, err := LoadProfile(dangling, myUID(), c); err == nil {
		t.Errorf("a dangling symbolic link is read as %+v, must be an error", p)
	}
	dir := filepath.Join(t.TempDir(), "appliance.json")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProfile(dir, myUID(), c); err == nil {
		t.Error("a directory must be refused")
	}
	fifo := filepath.Join(t.TempDir(), "appliance.json")
	if err := syscall.Mkfifo(fifo, 0o644); err == nil {
		done := make(chan error, 1)
		go func() {
			_, err := LoadProfile(fifo, myUID(), c)
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Error("a FIFO must be refused")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("LoadProfile hangs on a FIFO")
		}
	}
}
