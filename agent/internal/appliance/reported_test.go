package appliance

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// The JSON encoding of Reported is exactly the example of section 6.1: every
// key of the contract is a field, and there is no other field.
func TestReportedMatchesTheContractExample(t *testing.T) {
	example := contractExample(t, "### 6.1 Heartbeat request")
	var r Reported
	dec := json.NewDecoder(strings.NewReader(example))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("the contract's example does not decode into Reported: %v", err)
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var want, got any
	if err := json.Unmarshal([]byte(example), &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Reported does not encode to the contract's example.\n got: %s\nwant: %s", encoded, example)
	}
	// Spot checks, so that a field mapped to the wrong key is noticed.
	if r.Control != ControlCloud || r.AppliedRevision != 12 || r.ApplyStatus != ApplyApplied || r.Mode != ModePrivateAI ||
		!r.Capabilities.Docker || r.Catalog[0] != (CatalogEntry{"ollama", "1"}) || r.Plugins[0].Ports[0] != 11434 ||
		r.NAS[0].State != NASMounted || r.Secrets[0] != (SecretState{"nas.docs.password", SecretOK}) ||
		r.Vectorizer.FilesIndexed != 1820 || r.Vectorizer.Chunks != 40211 || !r.Backup.KeyPresent || r.Backup.KeyID != "9f2c1a7b" ||
		r.Backup.LastSizeBytes != 123456 || r.Update.CurrentVersion != "0.2.0" || r.Schedules[0].ID != "nightly-sync" {
		t.Fatalf("decoded example = %+v", r)
	}
}

func TestZeroReportEncodesWithoutNulls(t *testing.T) {
	var r Reported
	r.Sanitize()
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "null") {
		t.Fatalf("a sanitized report holds null: %s", encoded)
	}
	want := `{"schema":1,"control":"unknown","applied_revision":0,"apply_status":"unknown","apply_detail":"","mode":"unknown",` +
		`"seal_public_key":"","capabilities":{"plugins":false,"nas":false,"backup":false,"update":false,"docker":false},` +
		`"catalog":[],"plugins":[],"nas":[],"secrets":[],` +
		`"vectorizer":{"state":"error","last_run_at":"","last_ok_at":"","files_indexed":0,"files_failed":0,"files_skipped":0,"chunks":0,"detail":""},` +
		`"backup":{"state":"error","key_present":false,"key_id":"","last_ok_at":"","last_size_bytes":0,"detail":""},` +
		`"update":{"current_version":"","state":"error","target_version":"","detail":""},"schedules":[]}`
	if string(encoded) != want {
		t.Fatalf("zero report:\n got %s\nwant %s", encoded, want)
	}
}

func validReport() Reported {
	return Reported{
		Schema: 1, Control: ControlLocal, AppliedRevision: 7, ApplyStatus: ApplyPartial, ApplyDetail: "one plugin failed",
		Mode:          ModeVectorize,
		SealPublicKey: "hmk1.BHqMZ5y0R-ZqUgMyQnIG7COJHRBudGlPYXahXnAanVs0zizDQPwx0RPbBK5G3lOWd579QDu7xuOJaLJ7qLrnZt0",
		Capabilities:  Capabilities{Plugins: true, NAS: true, Backup: true, Update: true, Docker: true},
		Catalog:       []CatalogEntry{{"ollama", "1"}, {"qdrant", "2"}},
		Plugins: []PluginState{
			{ID: "ollama", State: PluginRunning, Detail: "", Version: "1", Ports: []int{11434}},
			{ID: "qdrant", State: PluginBlocked, Detail: "a foreign container is running", Version: "2", Ports: []int{}},
		},
		NAS:     []NASState{{ID: "docs", State: NASMounted}, {ID: "bk", State: NASError, Detail: "mount failed"}},
		Secrets: []SecretState{{"nas.docs.password", SecretOK}, {"ai.answer.api_key", SecretUnreadable}, {"backup.s3.secret_key", SecretMissing}},
		Vectorizer: VectorizerState{State: VectorizerIdle, LastRunAt: "2026-10-02T02:30:00Z", LastOKAt: "2026-10-02T02:41:10Z",
			FilesIndexed: 1820, FilesFailed: 3, FilesSkipped: 12, Chunks: 40211},
		Backup:    BackupState{State: BackupOK, KeyPresent: true, KeyID: "9f2c1a7b", LastOKAt: "2026-10-01T03:00:00Z", LastSizeBytes: 123456},
		Update:    UpdateState{CurrentVersion: "0.2.0", State: UpdateIdle},
		Schedules: []ScheduleState{{ID: "nightly-sync", LastRunAt: "2026-10-02T02:30:00Z", LastStatus: RunOK, NextRunAt: "2026-10-03T02:30:00Z"}},
	}
}

func TestSanitizeKeepsAValidReport(t *testing.T) {
	r, want := validReport(), validReport()
	r.Sanitize()
	if !reflect.DeepEqual(r, want) {
		got, _ := json.Marshal(r)
		expected, _ := json.Marshal(want)
		t.Fatalf("Sanitize changed a valid report:\n got %s\nwant %s", got, expected)
	}
	// Every state the contract lists is kept.
	for _, state := range []string{PluginRunning, PluginStarting, PluginStopped, PluginBlocked, PluginError, PluginNotInCatalog} {
		r := Reported{Plugins: []PluginState{{ID: "p", State: state}}}
		if r.Sanitize(); r.Plugins[0].State != state {
			t.Errorf("plugin state %s became %s", state, r.Plugins[0].State)
		}
	}
	for _, state := range []string{NASMounted, NASUnmounted, NASError} {
		r := Reported{NAS: []NASState{{ID: "n", State: state}}}
		if r.Sanitize(); r.NAS[0].State != state {
			t.Errorf("nas state %s became %s", state, r.NAS[0].State)
		}
	}
	for _, state := range []string{SecretOK, SecretUnreadable, SecretMissing} {
		r := Reported{Secrets: []SecretState{{Name: "x", State: state}}}
		if r.Sanitize(); r.Secrets[0].State != state {
			t.Errorf("secret state %s became %s", state, r.Secrets[0].State)
		}
	}
	for _, state := range []string{VectorizerDisabled, VectorizerIdle, VectorizerRunning, VectorizerError} {
		r := Reported{Vectorizer: VectorizerState{State: state}}
		if r.Sanitize(); r.Vectorizer.State != state {
			t.Errorf("vectorizer state %s became %s", state, r.Vectorizer.State)
		}
	}
	for _, state := range []string{BackupDisabled, BackupNoKey, BackupNever, BackupRunning, BackupOK, BackupError} {
		r := Reported{Backup: BackupState{State: state}}
		if r.Sanitize(); r.Backup.State != state {
			t.Errorf("backup state %s became %s", state, r.Backup.State)
		}
	}
	for _, state := range []string{UpdateIdle, UpdateDownloading, UpdateInstalling, UpdateInstalled, UpdateRolledBack, UpdateError} {
		r := Reported{Update: UpdateState{State: state}}
		if r.Sanitize(); r.Update.State != state {
			t.Errorf("update state %s became %s", state, r.Update.State)
		}
	}
	for _, status := range []string{RunOK, RunFailed, RunSkipped, RunNever} {
		r := Reported{Schedules: []ScheduleState{{ID: "s", LastStatus: status}}}
		if r.Sanitize(); r.Schedules[0].LastStatus != status {
			t.Errorf("last_status %s became %s", status, r.Schedules[0].LastStatus)
		}
	}
	for _, status := range []string{ApplyApplied, ApplyPartial, ApplyRejected, ApplyDisabled, ApplyPending} {
		r := Reported{ApplyStatus: status}
		if r.Sanitize(); r.ApplyStatus != status {
			t.Errorf("apply_status %s became %s", status, r.ApplyStatus)
		}
	}
	for _, mode := range []string{ModeVast, ModePrivateAI, ModeVectorize} {
		r := Reported{Mode: mode, Control: ControlCloud}
		if r.Sanitize(); r.Mode != mode || r.Control != ControlCloud {
			t.Errorf("mode %s became %s", mode, r.Mode)
		}
	}
}

func TestSanitizeEnforcesTheBounds(t *testing.T) {
	long := strings.Repeat("é", 1000)
	var r Reported
	r.Schema = 7
	r.Control = "remote"
	r.AppliedRevision = -5
	r.ApplyStatus = "done"
	r.ApplyDetail = long
	r.Mode = "mining"
	r.SealPublicKey = "hmk1.not-a-key"
	for i := 0; i < 40; i++ {
		id := fmt.Sprintf("p%02d", i)
		r.Catalog = append(r.Catalog, CatalogEntry{ID: id, Version: long})
		ports := []int{0, -1, 65536, 80}
		for port := 1000; port < 1040; port++ {
			ports = append(ports, port)
		}
		r.Plugins = append(r.Plugins, PluginState{ID: id, State: "exploded", Detail: long, Version: long, Ports: ports})
		r.NAS = append(r.NAS, NASState{ID: id, State: "weird", Detail: long})
		r.Secrets = append(r.Secrets, SecretState{Name: "nas." + id + ".password", State: "leaked"})
		r.Schedules = append(r.Schedules, ScheduleState{ID: id, LastRunAt: "yesterday", LastStatus: "great", NextRunAt: "2026-10-03T04:30:00+02:00"})
	}
	// Entries whose id or name is not well formed are dropped.
	r.Catalog = append([]CatalogEntry{{ID: "Bad Id", Version: "1"}, {ID: "", Version: "1"}}, r.Catalog...)
	r.Plugins = append([]PluginState{{ID: "../etc", State: PluginRunning}}, r.Plugins...)
	r.NAS = append([]NASState{{ID: "a b", State: NASMounted}}, r.NAS...)
	r.Secrets = append([]SecretState{{Name: "Not A Name", State: SecretOK}, {Name: strings.Repeat("a", 64), State: SecretOK}}, r.Secrets...)
	r.Schedules = append([]ScheduleState{{ID: "x\ny", LastStatus: RunOK}}, r.Schedules...)
	r.Vectorizer = VectorizerState{State: "busy", LastRunAt: "02:30", LastOKAt: "2026-13-45T00:00:00Z",
		FilesIndexed: -1, FilesFailed: -2, FilesSkipped: -3, Chunks: -4, Detail: long}
	r.Backup = BackupState{State: "fine", KeyPresent: true, KeyID: "9F2C1A7B-and-more", LastOKAt: "never", LastSizeBytes: -9, Detail: long}
	r.Update = UpdateState{CurrentVersion: long, State: "rebooting", TargetVersion: long, Detail: long}

	r.Sanitize()

	if r.Schema != 1 || r.Control != StateUnknown || r.AppliedRevision != 0 || r.ApplyStatus != StateUnknown || r.Mode != StateUnknown {
		t.Errorf("top level = %+v", r)
	}
	if r.SealPublicKey != "" {
		t.Errorf("a malformed sealing key is reported: %q", r.SealPublicKey)
	}
	if n := utf8.RuneCountInString(r.ApplyDetail); n != MaxReportedDetail {
		t.Errorf("apply_detail has %d characters", n)
	}
	if len(r.Catalog) != MaxReportedList || len(r.Plugins) != MaxReportedList || len(r.NAS) != MaxReportedList ||
		len(r.Secrets) != MaxReportedList || len(r.Schedules) != MaxReportedList {
		t.Errorf("list lengths: %d %d %d %d %d", len(r.Catalog), len(r.Plugins), len(r.NAS), len(r.Secrets), len(r.Schedules))
	}
	if r.Catalog[0].ID != "p00" || r.Plugins[0].ID != "p00" || r.NAS[0].ID != "p00" || r.Secrets[0].Name != "nas.p00.password" || r.Schedules[0].ID != "p00" {
		t.Errorf("malformed entries were kept: %v %v %v %v %v", r.Catalog[0], r.Plugins[0], r.NAS[0], r.Secrets[0], r.Schedules[0])
	}
	if n := utf8.RuneCountInString(r.Catalog[0].Version); n != MaxReportedString {
		t.Errorf("catalog version has %d characters", n)
	}
	p := r.Plugins[0]
	if p.State != PluginError || utf8.RuneCountInString(p.Detail) != MaxReportedDetail || utf8.RuneCountInString(p.Version) != MaxReportedString {
		t.Errorf("plugin = %+v", p)
	}
	if len(p.Ports) != MaxReportedList || p.Ports[0] != 80 || p.Ports[1] != 1000 {
		t.Errorf("ports = %v", p.Ports)
	}
	if r.NAS[0].State != NASError || utf8.RuneCountInString(r.NAS[0].Detail) != MaxReportedDetail {
		t.Errorf("nas = %+v", r.NAS[0])
	}
	if r.Secrets[0].State != StateUnknown {
		t.Errorf("secret = %+v", r.Secrets[0])
	}
	s := r.Schedules[0]
	if s.LastRunAt != "" || s.LastStatus != StateUnknown || s.NextRunAt != "2026-10-03T02:30:00Z" {
		t.Errorf("schedule = %+v", s)
	}
	v := r.Vectorizer
	if v.State != VectorizerError || v.LastRunAt != "" || v.LastOKAt != "" || v.FilesIndexed != 0 || v.FilesFailed != 0 ||
		v.FilesSkipped != 0 || v.Chunks != 0 || utf8.RuneCountInString(v.Detail) != MaxReportedDetail {
		t.Errorf("vectorizer = %+v", v)
	}
	b := r.Backup
	if b.State != BackupError || b.KeyID != "" || b.LastOKAt != "" || b.LastSizeBytes != 0 || !b.KeyPresent ||
		utf8.RuneCountInString(b.Detail) != MaxReportedDetail {
		t.Errorf("backup = %+v", b)
	}
	u := r.Update
	if u.State != UpdateError || utf8.RuneCountInString(u.CurrentVersion) != MaxReportedString ||
		utf8.RuneCountInString(u.TargetVersion) != MaxReportedString || utf8.RuneCountInString(u.Detail) != MaxReportedDetail {
		t.Errorf("update = %+v", u)
	}
	// Whatever went in, the result is within the bounds: check all of it.
	checkBounds(t, r)
	// Sanitizing twice changes nothing more.
	again := r
	again.Sanitize()
	if !reflect.DeepEqual(again, r) {
		t.Error("Sanitize is not idempotent")
	}
}

// checkBounds walks the encoded report and applies the bounds of 6.1 to
// every list and string in it.
func checkBounds(t *testing.T, r Reported) {
	t.Helper()
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var v any
	if err := json.Unmarshal(encoded, &v); err != nil {
		t.Fatal(err)
	}
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for key, value := range x {
				walk(path+"."+key, value)
			}
		case []any:
			if len(x) > MaxReportedList {
				t.Errorf("%s has %d entries", path, len(x))
			}
			for _, value := range x {
				walk(path+"[]", value)
			}
		case string:
			limit := MaxReportedString
			if strings.HasSuffix(path, "detail") {
				limit = MaxReportedDetail
			}
			if n := utf8.RuneCountInString(x); n > limit {
				t.Errorf("%s has %d characters", path, n)
			}
			if hasControl(x) || !utf8.ValidString(x) {
				t.Errorf("%s holds a control character or invalid UTF-8", path)
			}
		case nil:
			t.Errorf("%s is null", path)
		}
	}
	walk("", v)
}

func TestSanitizeCleansText(t *testing.T) {
	r := Reported{
		ApplyDetail: "line one\nline two\ttabbed\x00\x1b[31m\x7f end",
		Update:      UpdateState{CurrentVersion: "0.2.0\n", Detail: "bad \xff\xfe bytes"},
		Plugins:     []PluginState{{ID: "p", State: PluginError, Detail: "exit\r\n1", Version: "1\x00"}},
	}
	r.Sanitize()
	if r.ApplyDetail != "line one line two tabbed  [31m  end" {
		t.Errorf("apply_detail = %q", r.ApplyDetail)
	}
	if r.Update.CurrentVersion != "0.2.0 " || r.Update.Detail != "bad � bytes" {
		t.Errorf("update = %q, %q", r.Update.CurrentVersion, r.Update.Detail)
	}
	if r.Plugins[0].Detail != "exit  1" || r.Plugins[0].Version != "1 " {
		t.Errorf("plugin = %+v", r.Plugins[0])
	}
	checkBounds(t, r)
}

func TestFormatTime(t *testing.T) {
	if FormatTime(time.Time{}) != "" {
		t.Error("the zero time must be empty")
	}
	paris := time.FixedZone("CEST", 2*3600)
	if got := FormatTime(time.Date(2026, 10, 2, 4, 30, 0, 123, paris)); got != "2026-10-02T02:30:00Z" {
		t.Errorf("FormatTime = %q", got)
	}
	// What FormatTime writes survives Sanitize unchanged.
	r := Reported{Vectorizer: VectorizerState{LastRunAt: FormatTime(time.Date(2026, 10, 2, 4, 30, 0, 0, paris))}}
	r.Sanitize()
	if r.Vectorizer.LastRunAt != "2026-10-02T02:30:00Z" {
		t.Errorf("last_run_at = %q", r.Vectorizer.LastRunAt)
	}
	// The placeholder the contract's example uses is not a time.
	r = Reported{Backup: BackupState{LastOKAt: "…"}}
	r.Sanitize()
	if r.Backup.LastOKAt != "" {
		t.Errorf("last_ok_at = %q", r.Backup.LastOKAt)
	}
}

func TestCatalogSummaryFitsTheReport(t *testing.T) {
	c := fixtureCatalog(t)
	r := Reported{Catalog: c.Summary()}
	r.Sanitize()
	if !reflect.DeepEqual(r.Catalog, c.Summary()) {
		t.Errorf("the catalog summary does not survive Sanitize: %v", r.Catalog)
	}
}
