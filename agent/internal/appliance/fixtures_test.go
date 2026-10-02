package appliance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
)

// The fixtures shared with the control plane's validator
// (docs/appliance.md, section 4).
const (
	fixtureCatalogDir = "../../../appliance/testdata/catalog"
	fixtureValidDir   = "../../../appliance/testdata/documents/valid"
	fixtureInvalidDir = "../../../appliance/testdata/documents/invalid"
	shippedCatalogDir = "../../../appliance/catalog"
	contractPath      = "../../../docs/appliance.md"
	sealVectorsPath   = "../../../appliance/testdata/seal-vectors.json"
)

func fixtureCatalog(t *testing.T) *Catalog {
	t.Helper()
	c, err := LoadCatalog(fixtureCatalogDir)
	if err != nil {
		t.Fatalf("the fixture catalog does not load: %v", err)
	}
	return c
}

type fixture struct {
	file string
	why  string
	raw  []byte // the "document", serialised again
}

var (
	fixtureMu    sync.Mutex
	fixtureCache = map[string][]fixture{}
)

// loadFixtures reads a fixture directory once per test run.
func loadFixtures(t *testing.T, dir string) []fixture {
	t.Helper()
	fixtureMu.Lock()
	defer fixtureMu.Unlock()
	if cached, ok := fixtureCache[dir]; ok {
		return cached
	}
	fixtureCache[dir] = readFixtures(t, dir)
	return fixtureCache[dir]
}

func readFixtures(t *testing.T, dir string) []fixture {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	var out []fixture
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var f struct {
			Why      string          `json:"why"`
			Document json.RawMessage `json:"document"`
		}
		dec := json.NewDecoder(strings.NewReader(string(data)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&f); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if f.Why == "" || len(f.Document) == 0 {
			t.Fatalf("%s: a fixture is {\"why\": …, \"document\": …}", path)
		}
		out = append(out, fixture{file: filepath.Base(path), why: f.Why, raw: reserialise(t, f.Document)})
	}
	return out
}

// reserialise writes a JSON value again, compactly, keeping every number as
// it was written (1.5 stays 1.5, 12 stays 12).
func reserialise(t *testing.T, raw json.RawMessage) []byte {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The acceptance test of the contract: every valid fixture is accepted and
// every invalid fixture is refused, against the fixture catalog.
func TestFixtureDocuments(t *testing.T) {
	c := fixtureCatalog(t)
	valid := loadFixtures(t, fixtureValidDir)
	invalid := loadFixtures(t, fixtureInvalidDir)
	if len(valid) < 10 || len(invalid) < 100 {
		t.Fatalf("found %d valid and %d invalid fixtures: the fixture directories are not where the test looks", len(valid), len(invalid))
	}
	for _, f := range valid {
		if _, err := ParseDocument(f.raw, c); err != nil {
			t.Errorf("valid/%s (%s) is refused: %v", f.file, f.why, err)
		}
	}
	for _, f := range invalid {
		if _, err := ParseDocument(f.raw, c); err == nil {
			t.Errorf("invalid/%s (%s) is accepted", f.file, f.why)
		}
	}
}

// Each invalid fixture differs from a valid document in one respect. The
// error must be about that, not about something the parser stumbled on
// first: the word that names the faulty key or rule has to be in it.
func TestFixtureErrorsNameTheFault(t *testing.T) {
	c := fixtureCatalog(t)
	want := map[string]string{
		"backup-enabled-missing.json":            "backup.enabled: is required",
		"backup-keep-huge.json":                  "backup.keep",
		"backup-keep-zero.json":                  "backup.keep",
		"backup-kind-unknown.json":               "backup.destination.kind",
		"backup-nas-read-only.json":              "access write",
		"backup-nas-unknown.json":                "backup.destination.nas_id",
		"backup-s3-bucket-upper.json":            "backup.destination.bucket",
		"backup-s3-endpoint-path.json":           "backup.destination.endpoint",
		"backup-s3-http.json":                    "backup.destination.endpoint",
		"backup-s3-key-id-bad.json":              "backup.destination.access_key_id",
		"backup-s3-prefix-dotdot.json":           "backup.destination.prefix",
		"backup-s3-region-bad.json":              "backup.destination.region",
		"backup-s3-secret-missing.json":          "backup.destination.secret: is required",
		"backup-s3-with-nas-id.json":             `unknown key "nas_id"`,
		"backup-subpath-dotdot.json":             "backup.destination.subpath",
		"backup-unknown-key.json":                `unknown key "passphrase"`,
		"mode-missing.json":                      "mode: is required",
		"mode-unknown.json":                      "mode: must be one of",
		"nas-access-missing.json":                "nas[0].access: is required",
		"nas-access-unknown.json":                "nas[0].access",
		"nas-bad-id.json":                        "nas[0].id",
		"nas-domain-bad.json":                    "nas[0].domain",
		"nas-duplicate-id.json":                  "nas[2].id: is used twice",
		"nas-guest-with-secret.json":             "nas[0].secret: guest access",
		"nas-host-empty.json":                    "nas[0].host",
		"nas-host-option.json":                   "nas[0].host",
		"nas-host-slash.json":                    "nas[0].host",
		"nas-host-space.json":                    "nas[0].host",
		"nas-kind-unknown.json":                  "nas[1].kind",
		"nas-nfs-export-dotdot.json":             "nas[1].export: must not contain a .. segment",
		"nas-nfs-export-option.json":             "nas[1].export",
		"nas-nfs-export-relative.json":           "nas[1].export",
		"nas-nfs-with-secret.json":               "nas[1].secret: an nfs entry has no secret",
		"nas-nfs-with-username.json":             "nas[1].username: an nfs entry has no username",
		"nas-secret-wrong-name.json":             "nas[0].secret: must be exactly",
		"nas-smb-missing-share.json":             "nas[0].share: is required",
		"nas-smb-share-slash.json":               "nas[0].share",
		"nas-smb-share-trailing-space.json":      "nas[0].share: must not end with a space",
		"nas-smb-with-export.json":               "nas[0].export: an smb entry has no export",
		"nas-subpath-backslash.json":             "nas[0].subpath",
		"nas-subpath-comma.json":                 "nas[0].subpath",
		"nas-subpath-dotdot.json":                "nas[0].subpath",
		"nas-subpath-empty-segment.json":         "nas[0].subpath",
		"nas-subpath-leading-slash.json":         "nas[0].subpath",
		"nas-subpath-trailing-slash.json":        "nas[0].subpath",
		"nas-too-many.json":                      "nas: has more than 8",
		"nas-unknown-key.json":                   `nas[0]: unknown key "options"`,
		"nas-username-comma.json":                "nas[0].username: must not contain",
		"nas-username-control.json":              "nas[0].username: contains a control character",
		"nas-username-space.json":                "nas[0].username: must not contain",
		"nas-username-without-secret.json":       "nas[0].secret: is required",
		"plugin-bad-id.json":                     "plugins[0].id",
		"plugin-bool-as-string.json":             "plugins[3].settings.telemetry: must be true or false",
		"plugin-duplicate.json":                  "plugins[4].id: is listed twice",
		"plugin-enabled-missing.json":            "plugins[0].enabled: is required",
		"plugin-enabled-string.json":             "plugins[0].enabled: must be true or false",
		"plugin-enum-invalid.json":               "plugins[3].settings.bind: must be one of",
		"plugin-int-as-bool.json":                "plugins[3].settings.workers: must be an integer",
		"plugin-int-as-string.json":              "plugins[3].settings.workers: must be an integer",
		"plugin-int-too-big.json":                "plugins[3].settings.workers: must be 1 to 8",
		"plugin-int-too-small.json":              "plugins[3].settings.workers: must be 1 to 8",
		"plugin-list-as-string.json":             "plugins[0].settings.models: must be a list of strings",
		"plugin-list-item-not-string.json":       "plugins[0].settings.models: item 0 must be a string",
		"plugin-list-item-pattern.json":          "plugins[0].settings.models: item 0",
		"plugin-list-item-space.json":            "plugins[0].settings.models: item 0",
		"plugin-list-too-long.json":              "plugins[0].settings.models: has more than 4 items",
		"plugin-requires-disabled.json":          "plugins[2]: requires plugin qdrant to be enabled",
		"plugin-string-newline.json":             "plugins[3].settings.model",
		"plugin-string-pattern.json":             "plugins[3].settings.model",
		"plugin-unknown-id.json":                 "plugins[0].id: is not a plugin of this machine's catalog",
		"plugin-unknown-key.json":                `plugins[0]: unknown key "image"`,
		"plugin-unknown-setting.json":            `plugins[0].settings: unknown setting "command"`,
		"plugins-not-a-list.json":                "plugins: must be a list",
		"revision-bool.json":                     "revision: must be an integer",
		"revision-float.json":                    "revision: must be an integer",
		"revision-missing.json":                  "revision: is required",
		"revision-negative.json":                 "revision: must be",
		"revision-string.json":                   "revision: must be an integer",
		"revision-zero.json":                     "revision: must be",
		"sched-cron-expression.json":             "schedules[0].every",
		"sched-daily-missing-hour.json":          "schedules[0].hour: is required",
		"sched-daily-with-weekday.json":          "schedules[0].weekday: only a weekly schedule has a weekday",
		"sched-duplicate-id.json":                "schedules[2].id: is used twice",
		"sched-enabled-missing.json":             "schedules[0].enabled: is required",
		"sched-every-unknown.json":               "schedules[0].every",
		"sched-hour-24.json":                     "schedules[0].hour: must be 0 to 23",
		"sched-hourly-with-hour.json":            "schedules[0].hour: an hourly schedule has no hour",
		"sched-job-unknown.json":                 "schedules[0].job",
		"sched-minute-60.json":                   "schedules[0].minute: must be 0 to 59",
		"sched-minute-missing.json":              "schedules[0].minute: is required",
		"sched-mode-change.json":                 "schedules[0].job",
		"sched-plugin-on-other-job.json":         "schedules[0].plugin: only plugin_restart takes a plugin",
		"sched-restart-unknown-plugin.json":      "schedules[0].plugin: is not a plugin of this document",
		"sched-restart-without-plugin.json":      "schedules[0].plugin: is required",
		"sched-too-many.json":                    "schedules: has more than 16",
		"sched-weekday-7.json":                   "schedules[1].weekday: must be 0 to 6",
		"sched-weekly-missing-weekday.json":      "schedules[1].weekday: is required",
		"schema-2.json":                          "schema: must be 1",
		"schema-missing.json":                    "schema: is required",
		"secret-not-a-string.json":               `secrets["nas.docs.password"]: is not a sealed value`,
		"secret-not-sealed.json":                 `secrets["nas.docs.password"]: is not a sealed value`,
		"secret-plugin-not-configured.json":      `secrets["plugin.assistant.api_key"]: nothing in the document refers to this secret`,
		"secret-plugin-unknown-key.json":         `secrets["plugin.assistant.other"]: nothing in the document refers to this secret`,
		"secret-truncated.json":                  `secrets["nas.docs.password"]: is not a sealed value`,
		"secret-unreferenced.json":               `secrets["nas.gone.password"]: nothing in the document refers to this secret`,
		"secret-wrong-prefix.json":               `secrets["nas.docs.password"]: is not a sealed value`,
		"secrets-not-an-object.json":             "secrets: must be an object",
		"top-unknown-key.json":                   `top level: unknown key "extra"`,
		"update-channel-unknown.json":            "update.channel",
		"update-policy-unknown.json":             "update.policy",
		"update-unknown-key.json":                `update: unknown key "url"`,
		"update-window-equal.json":               "update.window: start_hour and end_hour must differ",
		"update-window-hour-24.json":             "update.window.end_hour: must be 0 to 23",
		"vec-answer-local-with-secret.json":      "vectorizer.answer.secret: only a cloud provider takes a secret",
		"vec-answer-local-with-url.json":         "vectorizer.answer.base_url: only a cloud provider takes a base_url",
		"vec-answer-missing.json":                "vectorizer.answer: is required",
		"vec-answer-model-bad.json":              "vectorizer.answer.model",
		"vec-answer-model-missing.json":          "vectorizer.answer.model: is required",
		"vec-answer-none-with-model.json":        "vectorizer.answer.model: provider none takes no model",
		"vec-answer-openai-no-url.json":          "vectorizer.answer.base_url: is required",
		"vec-answer-provider-unknown.json":       "vectorizer.answer.provider",
		"vec-answer-secret-missing.json":         "vectorizer.answer.secret: is required",
		"vec-answer-secret-wrong-name.json":      "vectorizer.answer.secret: must be exactly ai.answer.api_key",
		"vec-answer-url-fragment.json":           "vectorizer.answer.base_url",
		"vec-answer-url-http.json":               "vectorizer.answer.base_url",
		"vec-answer-url-no-host.json":            "vectorizer.answer.base_url",
		"vec-answer-url-query.json":              "vectorizer.answer.base_url",
		"vec-answer-url-userinfo.json":           "vectorizer.answer.base_url",
		"vec-exclude-dotdot.json":                "vectorizer.exclude[0]",
		"vec-extension-dot.json":                 "vectorizer.extensions[0]",
		"vec-extension-upper.json":               "vectorizer.extensions[0]",
		"vec-extensions-empty.json":              "vectorizer.extensions: needs at least 1",
		"vec-max-file-huge.json":                 "vectorizer.max_file_mib: must be 1 to 2048",
		"vec-max-file-zero.json":                 "vectorizer.max_file_mib: must be 1 to 2048",
		"vec-model-space.json":                   "vectorizer.embedding_model",
		"vec-ocr-string.json":                    "vectorizer.ocr: must be true or false",
		"vec-source-unknown.json":                "vectorizer.sources[0]: is not the id of a NAS entry",
		"vec-source-write.json":                  "vectorizer.sources[0]: a source must be a NAS entry with access read",
		"vec-sources-duplicate.json":             "vectorizer.sources[1]: is listed twice",
		"vec-sources-empty.json":                 "vectorizer.sources: needs at least 1",
		"vec-unknown-key.json":                   `vectorizer: unknown key "command"`,
		"vectorizer-plugin-without-section.json": "plugins[2]: the vectorizer plugin needs the vectorizer object",
		// This fixture's document is a plugin entry, not a document (reported
		// to the lead): it is refused for its missing "schema".
		"plugin-requires-absent.json": "schema: is required",
	}
	seen := map[string]bool{}
	for _, f := range loadFixtures(t, fixtureInvalidDir) {
		seen[f.file] = true
		_, err := ParseDocument(f.raw, c)
		if err == nil {
			continue // reported by TestFixtureDocuments
		}
		expected, ok := want[f.file]
		if !ok {
			t.Errorf("invalid/%s (%s) has no expected error in this test; it is refused with: %v", f.file, f.why, err)
			continue
		}
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("invalid/%s (%s): refused for another reason:\n  got  %v\n  want something about %q", f.file, f.why, err, expected)
		}
	}
	for file := range want {
		if !seen[file] {
			t.Errorf("invalid/%s is expected by this test and is gone", file)
		}
	}
}

// What the parser returns is itself a document: encoding it and parsing it
// again gives the same thing, defaults written out.
func TestFixtureDocumentsRoundTrip(t *testing.T) {
	c := fixtureCatalog(t)
	for _, f := range loadFixtures(t, fixtureValidDir) {
		doc, err := ParseDocument(f.raw, c)
		if err != nil {
			continue // reported by TestFixtureDocuments
		}
		encoded, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("valid/%s: %v", f.file, err)
		}
		again, err := ParseDocument(encoded, c)
		if err != nil {
			t.Errorf("valid/%s: the encoded document is refused: %v\n%s", f.file, err, encoded)
			continue
		}
		if !reflect.DeepEqual(doc, again) {
			t.Errorf("valid/%s: the document changed in a round trip:\n%+v\n%+v", f.file, doc, again)
		}
	}
}
