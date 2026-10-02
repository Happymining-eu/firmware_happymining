package appliance

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/schedule"
)

// The document the contract prints as its example must be accepted.
func TestContractDocumentExampleIsAccepted(t *testing.T) {
	example := contractExample(t, "## 4. The desired-state document")
	samples := sealedSamples(t)
	if !strings.Contains(example, `"hmseal1.…"`) {
		t.Fatal("the contract's example no longer abbreviates its sealed values as hmseal1.…")
	}
	example = strings.ReplaceAll(example, `"hmseal1.…"`, `"`+samples[0]+`"`)
	doc, err := ParseDocument([]byte(example), fixtureCatalog(t))
	if err != nil {
		t.Fatalf("the contract's example is refused: %v", err)
	}
	if doc.Revision != 12 || doc.Mode != ModePrivateAI || len(doc.Plugins) != 3 || len(doc.NAS) != 2 || len(doc.Schedules) != 2 ||
		doc.Vectorizer == nil || doc.Backup == nil || doc.Update == nil || len(doc.Secrets) != 2 {
		t.Fatalf("parsed example = %+v", doc)
	}
}

func TestParsedDocumentContent(t *testing.T) {
	c := fixtureCatalog(t)
	doc := mustAccept(t, c, "full", fullDocument(t))
	if doc == nil {
		t.FailNow()
	}
	hour2, hour3, day6 := 2, 3, 6
	samples := sealedSamples(t)
	want := &Document{
		Schema: 1, Revision: 12, Mode: ModePrivateAI,
		Plugins: []PluginConfig{
			{ID: "ollama", Enabled: true, Settings: map[string]any{"models": []string{"hermes3:8b", "bge-m3"}}},
			{ID: "qdrant", Enabled: true, Settings: map[string]any{}},
			{ID: "vectorizer", Enabled: true, Settings: map[string]any{}},
			{ID: "assistant", Enabled: true, Settings: map[string]any{
				"bind": "localhost", "workers": int64(4), "telemetry": false, "model": "hermes3:8b"}},
		},
		NAS: []NAS{
			{ID: "docs", Kind: NASKindSMB, Host: "nas.lan", Share: "documents", Username: "indexer",
				Secret: "nas.docs.password", Access: AccessRead},
			{ID: "bk", Kind: NASKindNFS, Host: "192.168.1.20", Export: "/volume1/backup", Access: AccessWrite},
		},
		Vectorizer: &Vectorizer{
			Sources:        []string{"docs"},
			Extensions:     []string{"pdf", "docx", "pptx", "xlsx", "html", "md", "txt"},
			Exclude:        []string{"#recycle", "private/hr"},
			MaxFileMiB:     64,
			EmbeddingModel: "bge-m3",
			Answer: Answer{Provider: AnswerOpenAICompatible, Model: "gpt-4.1-mini",
				BaseURL: "https://api.openai.com/v1", Secret: SecretAnswerAPIKey},
		},
		Backup: &Backup{Enabled: true, Destination: BackupDestination{Kind: DestinationNAS, NASID: "bk", Subpath: "happymining"}, Keep: 7},
		Schedules: []Schedule{
			{ID: "nightly-sync", Job: JobVectorizeSync, Every: schedule.Daily, Hour: &hour2, Minute: 30, Enabled: true},
			{ID: "weekly-backup", Job: JobBackupRun, Every: schedule.Weekly, Weekday: &day6, Hour: &hour3, Minute: 0, Enabled: true},
		},
		Update:  &Update{Channel: ChannelStable, Policy: PolicyAuto, Window: &Window{StartHour: 2, EndHour: 5}},
		Secrets: map[string]string{"nas.docs.password": samples[0], SecretAnswerAPIKey: samples[1]},
	}
	if !reflect.DeepEqual(doc, want) {
		got, _ := json.MarshalIndent(doc, "", " ")
		expected, _ := json.MarshalIndent(want, "", " ")
		t.Fatalf("parsed document differs.\n got: %s\nwant: %s", got, expected)
	}
	if spec := doc.Schedules[1].Spec(); spec.Every != schedule.Weekly || *spec.Weekday != 6 || *spec.Hour != 3 || spec.Minute != 0 || spec.Validate() != nil {
		t.Fatalf("Spec = %+v", spec)
	}
	if NASSecretName("docs") != "nas.docs.password" {
		t.Fatal("NASSecretName")
	}
}

func TestDefaultsAreApplied(t *testing.T) {
	c := fixtureCatalog(t)
	doc, err := ParseDocument([]byte(`{"schema":1,"revision":1,"mode":"vast"}`), c)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Plugins == nil || doc.NAS == nil || doc.Schedules == nil || doc.Secrets == nil ||
		len(doc.Plugins)+len(doc.NAS)+len(doc.Schedules)+len(doc.Secrets) != 0 ||
		doc.Vectorizer != nil || doc.Backup != nil || doc.Update != nil {
		t.Fatalf("minimal document = %+v", doc)
	}
	encoded, _ := json.Marshal(doc)
	if string(encoded) != `{"schema":1,"revision":1,"mode":"vast","plugins":[],"nas":[],"schedules":[]}` {
		t.Fatalf("encoded minimal document = %s", encoded)
	}

	// A plugin without "settings", and settings left out, take the defaults.
	doc, err = ParseDocument([]byte(`{"schema":1,"revision":1,"mode":"private_ai","plugins":[
		{"id":"ollama","enabled":true},
		{"id":"assistant","enabled":true,"settings":{"workers":8}}]}`), c)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(doc.Plugins[0].Settings, map[string]any{"models": []string{}}) {
		t.Fatalf("ollama settings = %#v", doc.Plugins[0].Settings)
	}
	wantAssistant := map[string]any{"bind": "lan", "workers": int64(8), "telemetry": false, "model": "hermes3:8b"}
	if !reflect.DeepEqual(doc.Plugins[1].Settings, wantAssistant) {
		t.Fatalf("assistant settings = %#v", doc.Plugins[1].Settings)
	}

	// SMB: subpath and domain default to ""; NFS: subpath is optional.
	doc, err = ParseDocument([]byte(`{"schema":1,"revision":1,"mode":"vast","nas":[
		{"id":"a","kind":"smb","host":"h","share":"s","username":"","access":"read"},
		{"id":"b","kind":"nfs","host":"h","export":"/e","subpath":"x/y","access":"write"}]}`), c)
	if err != nil {
		t.Fatal(err)
	}
	if doc.NAS[0].Subpath != "" || doc.NAS[0].Domain != "" || doc.NAS[0].Secret != "" || doc.NAS[1].Subpath != "x/y" {
		t.Fatalf("NAS = %+v", doc.NAS)
	}
	encoded, _ = json.Marshal(doc.NAS)
	wantJSON := `[{"id":"a","kind":"smb","host":"h","share":"s","subpath":"","username":"","domain":"","access":"read"},` +
		`{"id":"b","kind":"nfs","host":"h","export":"/e","subpath":"x/y","access":"write"}]`
	if string(encoded) != wantJSON {
		t.Fatalf("encoded NAS = %s", encoded)
	}
}

func TestAnswerProviders(t *testing.T) {
	c := fixtureCatalog(t)
	with := func(answer map[string]any, secret bool) map[string]any {
		doc := fullDocument(t)
		obj(t, doc["vectorizer"])["answer"] = answer
		if !secret {
			delete(obj(t, doc["secrets"]), SecretAnswerAPIKey)
		}
		return doc
	}
	doc := mustAccept(t, c, "anthropic without base_url",
		with(map[string]any{"provider": "anthropic", "model": "claude-sonnet-4-5", "secret": SecretAnswerAPIKey}, true))
	if doc != nil && doc.Vectorizer.Answer.BaseURL != DefaultAnthropicBaseURL {
		t.Errorf("anthropic default base_url = %q", doc.Vectorizer.Answer.BaseURL)
	}
	doc = mustAccept(t, c, "anthropic with base_url",
		with(map[string]any{"provider": "anthropic", "model": "m", "base_url": "https://proxy.example.com/anthropic", "secret": SecretAnswerAPIKey}, true))
	if doc != nil && doc.Vectorizer.Answer.BaseURL != "https://proxy.example.com/anthropic" {
		t.Errorf("anthropic base_url = %q", doc.Vectorizer.Answer.BaseURL)
	}
	doc = mustAccept(t, c, "none", with(map[string]any{"provider": "none"}, false))
	if doc != nil && doc.Vectorizer.Answer != (Answer{Provider: AnswerNone}) {
		t.Errorf("none = %+v", doc.Vectorizer.Answer)
	}
	doc = mustAccept(t, c, "local", with(map[string]any{"provider": "local", "model": "hermes3:8b"}, false))
	if doc != nil && doc.Vectorizer.Answer != (Answer{Provider: AnswerLocal, Model: "hermes3:8b"}) {
		t.Errorf("local = %+v", doc.Vectorizer.Answer)
	}

	mustRefuse(t, c, "anthropic without its key", with(map[string]any{"provider": "anthropic", "model": "m"}, false), "vectorizer.answer.secret: is required")
	mustRefuse(t, c, "anthropic with a bad base_url", with(map[string]any{"provider": "anthropic", "model": "m", "base_url": "http://x", "secret": SecretAnswerAPIKey}, true), "vectorizer.answer.base_url")
	mustRefuse(t, c, "none with a secret", with(map[string]any{"provider": "none", "secret": SecretAnswerAPIKey}, true), "vectorizer.answer.secret")
	mustRefuse(t, c, "none with a base_url", with(map[string]any{"provider": "none", "base_url": "https://x.example"}, false), "vectorizer.answer.base_url")
	mustRefuse(t, c, "the key without a reference", with(map[string]any{"provider": "none"}, true), "nothing in the document refers to this secret")
	mustRefuse(t, c, "model of 101 characters", with(map[string]any{"provider": "local", "model": strings.Repeat("m", 101)}, false), "vectorizer.answer.model")
	mustRefuse(t, c, "model empty", with(map[string]any{"provider": "local", "model": ""}, false), "vectorizer.answer.model")
	mustRefuse(t, c, "unknown answer key", with(map[string]any{"provider": "none", "temperature": 1}, false), `vectorizer.answer: unknown key "temperature"`)
}

func TestBaseURLAndEndpointRules(t *testing.T) {
	long := "https://api.example.com/" + strings.Repeat("a", 200-len("https://api.example.com/"))
	goodURLs := []string{
		"https://api.openai.com/v1",
		"https://api.openai.com",
		"https://api.openai.com/",
		"https://api.example.com:8443/v1/",
		"https://10.0.0.5:443",
		"https://gateway.ai.example.com/v1/acc-1/gw_2/openai",
		"https://a/~user/x.y",
		"https://h:1",
		"https://h:65535/x",
		long,
	}
	badURLs := map[string]string{
		"empty":                "",
		"http":                 "http://api.example.com/v1",
		"upper-case scheme":    "HTTPS://api.example.com/v1",
		"no scheme":            "api.example.com/v1",
		"scheme only":          "https://",
		"no host":              "https:///v1",
		"user info":            "https://user:pw@api.example.com/v1",
		"user only":            "https://user@api.example.com",
		"at sign in the path":  "https://api.example.com/a@b",
		"query":                "https://api.example.com/v1?x=1",
		"empty query":          "https://api.example.com/v1?",
		"fragment":             "https://api.example.com/v1#x",
		"port 0":               "https://api.example.com:0/v1",
		"port 65536":           "https://api.example.com:65536/v1",
		"port 99999":           "https://api.example.com:99999",
		"empty port":           "https://api.example.com:/v1",
		"port not a number":    "https://api.example.com:https/v1",
		"IPv6 literal":         "https://[::1]/v1",
		"space":                "https://api.example.com/v 1",
		"percent escape":       "https://api.example.com/a%2Fb",
		"backslash":            `https://api.example.com\@evil.example/v1`,
		"quote":                `https://api.example.com/"`,
		"dollar":               "https://api.example.com/$HOME",
		"host starts with dot": "https://.example.com/v1",
		"host starts with -":   "https://-o.example.com/v1",
		"host ends with dash":  "https://example-/v1",
		"non-ASCII host":       "https://exämple.com/v1",
		"201 characters":       long + "a",
		"file scheme":          "file:///etc/passwd",
		"trailing white space": "https://api.example.com/v1 ",
	}
	for _, url := range goodURLs {
		if !validHTTPSURL(url, true) {
			t.Errorf("base_url %q is refused", url)
		}
	}
	for why, url := range badURLs {
		if validHTTPSURL(url, true) {
			t.Errorf("base_url, %s: %q is accepted", why, url)
		}
		if validHTTPSURL(url, false) {
			t.Errorf("endpoint, %s: %q is accepted", why, url)
		}
	}
	for _, endpoint := range []string{"https://s3.eu-central-1.amazonaws.com", "https://minio.lan:9000", "https://10.0.0.9"} {
		if !validHTTPSURL(endpoint, false) {
			t.Errorf("endpoint %q is refused", endpoint)
		}
	}
	for why, endpoint := range map[string]string{
		"path":           "https://s3.example.com/x",
		"trailing slash": "https://s3.example.com/",
		"bucket path":    "https://s3.example.com/bucket/key",
	} {
		if validHTTPSURL(endpoint, false) {
			t.Errorf("endpoint, %s: %q is accepted", why, endpoint)
		}
	}

	// Through the document, for both fields.
	c := fixtureCatalog(t)
	doc := fullDocument(t)
	obj(t, obj(t, doc["vectorizer"])["answer"])["base_url"] = "https://api.example.com:0/v1"
	mustRefuse(t, c, "base_url with port 0", doc, "vectorizer.answer.base_url")
}

func s3Document(t *testing.T, change func(dest map[string]any)) map[string]any {
	t.Helper()
	doc := fullDocument(t)
	dest := map[string]any{"kind": "s3", "endpoint": "https://s3.example.com", "region": "eu-central-1",
		"bucket": "acme-hm-backups", "prefix": "site1/", "access_key_id": "AKIAEXAMPLEKEY000001", "secret": SecretBackupS3Key}
	if change != nil {
		change(dest)
	}
	obj(t, doc["backup"])["destination"] = dest
	obj(t, doc["secrets"])[SecretBackupS3Key] = sealedSamples(t)[2]
	return doc
}

func TestBackupDestinations(t *testing.T) {
	c := fixtureCatalog(t)
	doc := mustAccept(t, c, "s3", s3Document(t, nil))
	if doc != nil {
		want := BackupDestination{Kind: DestinationS3, Endpoint: "https://s3.example.com", Region: "eu-central-1",
			Bucket: "acme-hm-backups", Prefix: "site1/", AccessKeyID: "AKIAEXAMPLEKEY000001", Secret: SecretBackupS3Key}
		if doc.Backup.Destination != want {
			t.Errorf("destination = %+v", doc.Backup.Destination)
		}
		encoded, _ := json.Marshal(doc.Backup.Destination)
		if string(encoded) != `{"kind":"s3","endpoint":"https://s3.example.com","region":"eu-central-1","bucket":"acme-hm-backups","prefix":"site1/","access_key_id":"AKIAEXAMPLEKEY000001","secret":"backup.s3.secret_key"}` {
			t.Errorf("encoded destination = %s", encoded)
		}
	}
	mustAccept(t, c, "s3 with a port", s3Document(t, func(d map[string]any) { d["endpoint"] = "https://minio.lan:9000" }))
	mustAccept(t, c, "s3 with an empty prefix", s3Document(t, func(d map[string]any) { d["prefix"] = "" }))
	mustAccept(t, c, "s3 without prefix", s3Document(t, func(d map[string]any) { delete(d, "prefix") }))
	mustAccept(t, c, "bucket of 3 characters", s3Document(t, func(d map[string]any) { d["bucket"] = "abc" }))

	bad := map[string]struct {
		change func(d map[string]any)
		want   string
	}{
		"endpoint with a slash":   {func(d map[string]any) { d["endpoint"] = "https://s3.example.com/" }, "backup.destination.endpoint"},
		"endpoint missing":        {func(d map[string]any) { delete(d, "endpoint") }, "backup.destination.endpoint: is required"},
		"region missing":          {func(d map[string]any) { delete(d, "region") }, "backup.destination.region: is required"},
		"region upper case":       {func(d map[string]any) { d["region"] = "EU" }, "backup.destination.region"},
		"region empty":            {func(d map[string]any) { d["region"] = "" }, "backup.destination.region"},
		"bucket of 2 characters":  {func(d map[string]any) { d["bucket"] = "ab" }, "backup.destination.bucket"},
		"bucket ending in a dash": {func(d map[string]any) { d["bucket"] = "abc-" }, "backup.destination.bucket"},
		"bucket of 64 characters": {func(d map[string]any) { d["bucket"] = strings.Repeat("a", 64) }, "backup.destination.bucket"},
		"bucket with a slash":     {func(d map[string]any) { d["bucket"] = "a/b" }, "backup.destination.bucket"},
		"prefix with ..":          {func(d map[string]any) { d["prefix"] = "a/../b" }, "backup.destination.prefix"},
		"prefix with .. inside":   {func(d map[string]any) { d["prefix"] = "a..b" }, "backup.destination.prefix"},
		"prefix with a space":     {func(d map[string]any) { d["prefix"] = "a b" }, "backup.destination.prefix"},
		"prefix of 201":           {func(d map[string]any) { d["prefix"] = strings.Repeat("a", 201) }, "backup.destination.prefix"},
		"key id of 3":             {func(d map[string]any) { d["access_key_id"] = "abc" }, "backup.destination.access_key_id"},
		"key id missing":          {func(d map[string]any) { delete(d, "access_key_id") }, "backup.destination.access_key_id: is required"},
		"secret another name":     {func(d map[string]any) { d["secret"] = "backup.s3.key" }, "backup.destination.secret: must be exactly backup.s3.secret_key"},
		"secret in clear":         {func(d map[string]any) { d["secret_access_key"] = "hunter2" }, `backup.destination: unknown key "secret_access_key"`},
		"subpath on s3":           {func(d map[string]any) { d["subpath"] = "x" }, `backup.destination: unknown key "subpath"`},
	}
	for why, b := range bad {
		mustRefuse(t, c, why, s3Document(t, b.change), b.want)
	}

	// The sealed S3 key must be there, and must go when S3 goes.
	missing := s3Document(t, nil)
	delete(obj(t, missing["secrets"]), SecretBackupS3Key)
	mustRefuse(t, c, "s3 without its sealed key", missing, "secrets: backup.s3.secret_key is referred to and missing")
	leftover := fullDocument(t)
	obj(t, leftover["secrets"])[SecretBackupS3Key] = sealedSamples(t)[2]
	mustRefuse(t, c, "a sealed S3 key without S3", leftover, "nothing in the document refers to this secret")

	// NAS destination: subpath is optional and holds no S3 key.
	nasDoc := fullDocument(t)
	delete(obj(t, obj(t, nasDoc["backup"])["destination"]), "subpath")
	if doc := mustAccept(t, c, "nas destination without subpath", nasDoc); doc != nil && doc.Backup.Destination.Subpath != "" {
		t.Errorf("subpath = %q", doc.Backup.Destination.Subpath)
	}
	nasDoc = fullDocument(t)
	obj(t, obj(t, nasDoc["backup"])["destination"])["bucket"] = "abc"
	mustRefuse(t, c, "nas destination with a bucket", nasDoc, `backup.destination: unknown key "bucket"`)
	nasDoc = fullDocument(t)
	delete(obj(t, obj(t, nasDoc["backup"])["destination"]), "nas_id")
	mustRefuse(t, c, "nas destination without nas_id", nasDoc, "backup.destination.nas_id: is required")
}

func TestStrictDecoding(t *testing.T) {
	c := fixtureCatalog(t)
	minimal := `{"schema":1,"revision":1,"mode":"vast"}`
	if _, err := ParseDocument([]byte(minimal), c); err != nil {
		t.Fatal(err)
	}
	padding := strings.Repeat(" ", MaxDocumentBytes-len(minimal))
	if _, err := ParseDocument([]byte(minimal+padding), c); err != nil {
		t.Fatalf("a document of exactly %d bytes is refused: %v", MaxDocumentBytes, err)
	}
	bad := map[string]struct{ raw, want string }{
		"one byte too large":      {minimal + padding + " ", "larger than 65536 bytes"},
		"empty":                   {"", "not valid JSON"},
		"null":                    {"null", "must be an object"},
		"a list":                  {"[" + minimal + "]", "must be an object"},
		"a string":                {`"vast"`, "must be an object"},
		"trailing data":           {minimal + minimal, "not valid JSON"},
		"trailing garbage":        {minimal + " x", "not valid JSON"},
		"truncated":               {minimal[:len(minimal)-1], "not valid JSON"},
		"single quotes":           {`{'schema':1,'revision':1,'mode':'vast'}`, "not valid JSON"},
		"trailing comma":          {`{"schema":1,"revision":1,"mode":"vast",}`, "not valid JSON"},
		"comment":                 {minimal + " // ok", "not valid JSON"},
		"NaN":                     {`{"schema":1,"revision":NaN,"mode":"vast"}`, "not valid JSON"},
		"byte order mark":         {"\xef\xbb\xbf" + minimal, "not valid JSON"},
		"invalid UTF-8":           {`{"schema":1,"revision":1,"mode":"va` + "\xff" + `st"}`, "not UTF-8"},
		"unpaired high surrogate": {`{"schema":1,"revision":1,"mode":"vast","nas":[{"id":"\ud83d"}]}`, "unpaired surrogate"},
		"unpaired low surrogate":  {`{"schema":1,"revision":1,"mode":"vast","nas":[{"id":"\ude00"}]}`, "unpaired surrogate"},
		"reversed surrogates":     {`{"schema":1,"revision":1,"mode":"vast","nas":[{"id":"\ude00\ud83d"}]}`, "unpaired surrogate"},
		"duplicate top-level key": {`{"schema":1,"revision":1,"mode":"private_ai","mode":"vast"}`, `duplicate key "mode"`},
		"duplicate nested key":    {`{"schema":1,"revision":1,"mode":"vast","update":{"channel":"none","channel":"beta","policy":"manual"}}`, `duplicate key "channel"`},
		"duplicate in a list":     {`{"schema":1,"revision":1,"mode":"vast","plugins":[{"id":"qdrant","enabled":false,"enabled":true}]}`, `duplicate key "enabled"`},
		"nested too deeply":       {`{"schema":1,"revision":1,"mode":"vast","plugins":` + strings.Repeat("[", 20) + strings.Repeat("]", 20) + `}`, "nested too deeply"},
		"schema as 1.0":           {`{"schema":1.0,"revision":1,"mode":"vast"}`, "schema: must be an integer"},
		"schema as true":          {`{"schema":true,"revision":1,"mode":"vast"}`, "schema: must be an integer"},
		"revision as 1e1":         {`{"schema":1,"revision":1e1,"mode":"vast"}`, "revision: must be an integer"},
		"revision as 2.0":         {`{"schema":1,"revision":2.0,"mode":"vast"}`, "revision: must be an integer"},
		"revision beyond int64":   {`{"schema":1,"revision":99999999999999999999,"mode":"vast"}`, "revision: must be an integer"},
		"revision null":           {`{"schema":1,"revision":null,"mode":"vast"}`, "revision: must be an integer"},
		"mode null":               {`{"schema":1,"revision":1,"mode":null}`, "mode: must be a string"},
		"mode a number":           {`{"schema":1,"revision":1,"mode":1}`, "mode: must be a string"},
		"mode upper case":         {`{"schema":1,"revision":1,"mode":"VAST"}`, "mode: must be one of"},
		"plugins null":            {`{"schema":1,"revision":1,"mode":"vast","plugins":null}`, "plugins: must be a list"},
		"nas null":                {`{"schema":1,"revision":1,"mode":"vast","nas":null}`, "nas: must be a list"},
		"schedules null":          {`{"schema":1,"revision":1,"mode":"vast","schedules":null}`, "schedules: must be a list"},
		"secrets null":            {`{"schema":1,"revision":1,"mode":"vast","secrets":null}`, "secrets: must be an object"},
		"vectorizer null":         {`{"schema":1,"revision":1,"mode":"vast","vectorizer":null}`, "vectorizer: must be an object"},
		"backup null":             {`{"schema":1,"revision":1,"mode":"vast","backup":null}`, "backup: must be an object"},
		"update null":             {`{"schema":1,"revision":1,"mode":"vast","update":null}`, "update: must be an object"},
		"update a list":           {`{"schema":1,"revision":1,"mode":"vast","update":[]}`, "update: must be an object"},
		"plugin entry a string":   {`{"schema":1,"revision":1,"mode":"vast","plugins":["ollama"]}`, "plugins[0]: must be an object"},
		"settings a list":         {`{"schema":1,"revision":1,"mode":"vast","plugins":[{"id":"qdrant","enabled":true,"settings":[]}]}`, "plugins[0].settings: must be an object"},
		"settings null":           {`{"schema":1,"revision":1,"mode":"vast","plugins":[{"id":"qdrant","enabled":true,"settings":null}]}`, "plugins[0].settings: must be an object"},
		"key in another case":     {`{"schema":1,"revision":1,"mode":"vast","Mode":"private_ai"}`, `unknown key "Mode"`},
	}
	for why, b := range bad {
		mustRefuse(t, c, why, b.raw, b.want)
	}

	// A properly paired surrogate escape is an ordinary character.
	paired := `{"schema":1,"revision":1,"mode":"vast","nas":[{"id":"a","kind":"smb","host":"h","share":"s","subpath":"😀","username":"","access":"read"}]}`
	doc, err := ParseDocument([]byte(paired), c)
	if err != nil || doc.NAS[0].Subpath != "😀" {
		t.Fatalf("a paired surrogate escape: %v", err)
	}
	// A hostile key cannot flood the error.
	huge := `{"schema":1,"revision":1,"mode":"vast","` + strings.Repeat("k", 5000) + `":1}`
	if _, err := ParseDocument([]byte(huge), c); err == nil || len(err.Error()) > 200 {
		t.Fatalf("an error of %d bytes for a long unknown key", len(err.Error()))
	}
	if _, err := ParseDocument([]byte(minimal), nil); err == nil {
		t.Fatal("a nil catalog must be refused")
	}
}

// Every string of a document is checked for control characters: put one in
// each string of the full fixture in turn.
func TestControlCharacterInAnyStringIsRefused(t *testing.T) {
	c := fixtureCatalog(t)
	base := encode(t, fullDocument(t))
	var paths [][]any
	var walk func(v any, path []any)
	walk = func(v any, path []any) {
		switch x := v.(type) {
		case map[string]any:
			for key, value := range x {
				walk(value, append(append([]any(nil), path...), key))
			}
		case []any:
			for i, value := range x {
				walk(value, append(append([]any(nil), path...), i))
			}
		case string:
			paths = append(paths, path)
		}
	}
	walk(tree(t, base), nil)
	if len(paths) < 40 {
		t.Fatalf("found only %d strings in the full document", len(paths))
	}
	for _, path := range paths {
		for _, control := range []string{"\x00", "\x01", "\n", "\t", "\x1f", "\x7f"} {
			doc := tree(t, base)
			var parent any = doc
			for _, step := range path[:len(path)-1] {
				switch p := parent.(type) {
				case map[string]any:
					parent = p[step.(string)]
				case []any:
					parent = p[step.(int)]
				}
			}
			switch p := parent.(type) {
			case map[string]any:
				p[path[len(path)-1].(string)] = p[path[len(path)-1].(string)].(string) + control
			case []any:
				p[path[len(path)-1].(int)] = p[path[len(path)-1].(int)].(string) + control
			}
			if _, err := ParseDocument(encode(t, doc), c); err == nil {
				t.Errorf("a control character %q appended at %v is accepted", control, path)
			}
		}
	}
}

func TestErrorsNeverQuoteValues(t *testing.T) {
	c := fixtureCatalog(t)
	doc := fullDocument(t)
	obj(t, doc["secrets"])["nas.docs.password"] = "hunter2-in-clear-text"
	_, err := ParseDocument(encode(t, doc), c)
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("a secret in clear text: %v", err)
	}
	doc = fullDocument(t)
	obj(t, list(t, doc["nas"])[0])["username"] = "very,secret=user"
	_, err = ParseDocument(encode(t, doc), c)
	if err == nil || strings.Contains(err.Error(), "very") {
		t.Fatalf("a bad user name: %v", err)
	}
	doc = fullDocument(t)
	obj(t, obj(t, list(t, doc["plugins"])[3])["settings"])["model"] = "Private-Value"
	_, err = ParseDocument(encode(t, doc), c)
	if err == nil || strings.Contains(err.Error(), "Private") {
		t.Fatalf("a bad setting: %v", err)
	}
}

func TestPluginRules(t *testing.T) {
	c := fixtureCatalog(t)
	plugins := func(entries ...map[string]any) map[string]any {
		doc := map[string]any{"schema": 1, "revision": 1, "mode": "private_ai"}
		var l []any
		for _, e := range entries {
			l = append(l, e)
		}
		doc["plugins"] = l
		return doc
	}
	entry := func(id string, enabled bool, settings map[string]any) map[string]any {
		e := map[string]any{"id": id, "enabled": enabled}
		if settings != nil {
			e["settings"] = settings
		}
		return e
	}

	// What the fixture "plugin-requires-absent" means to test.
	mustRefuse(t, c, "a requirement absent from the list", plugins(entry("assistant", true, nil)), "plugins[0]: requires plugin ollama to be enabled")
	mustRefuse(t, c, "a requirement disabled", plugins(entry("ollama", false, nil), entry("assistant", true, nil)), "plugins[1]: requires plugin ollama to be enabled")
	mustRefuse(t, c, "one of two requirements absent", plugins(entry("qdrant", true, nil), entry("vectorizer", true, nil)), "plugins[1]: requires plugin ollama to be enabled")
	mustAccept(t, c, "a requirement listed after its dependent", plugins(entry("assistant", true, nil), entry("ollama", true, nil)))
	mustAccept(t, c, "a disabled plugin without its requirement", plugins(entry("assistant", false, nil)))

	// The pattern alone refuses a value made of harmless characters.
	mustRefuse(t, c, "string against the pattern", plugins(entry("ollama", true, nil), entry("assistant", true, map[string]any{"model": "UPPER"})),
		"plugins[1].settings.model: does not match the pattern")
	mustRefuse(t, c, "list item against the pattern", plugins(entry("ollama", true, map[string]any{"models": []any{"ok", "Not-Ok"}})),
		"plugins[0].settings.models: item 1 does not match the pattern")
	mustRefuse(t, c, "empty list item", plugins(entry("ollama", true, map[string]any{"models": []any{""}})),
		"plugins[0].settings.models: item 0 is empty")
	mustRefuse(t, c, "string too long", plugins(entry("ollama", true, nil), entry("assistant", true, map[string]any{"model": strings.Repeat("a", 101)})),
		"plugins[1].settings.model: is longer than 100 characters")
	mustRefuse(t, c, "integer as a fraction", plugins(entry("ollama", true, nil), entry("assistant", true, map[string]any{"workers": 2.5})),
		"plugins[1].settings.workers: must be an integer")
	mustRefuse(t, c, "integer written 2.0", `{"schema":1,"revision":1,"mode":"private_ai","plugins":[{"id":"ollama","enabled":true},{"id":"assistant","enabled":true,"settings":{"workers":2.0}}]}`,
		"plugins[1].settings.workers: must be an integer")
	mustRefuse(t, c, "enum as a number", plugins(entry("ollama", true, nil), entry("assistant", true, map[string]any{"bind": 1})),
		"plugins[1].settings.bind: must be a string")
	mustRefuse(t, c, "setting null", plugins(entry("ollama", true, nil), entry("assistant", true, map[string]any{"telemetry": nil})),
		"plugins[1].settings.telemetry: must be true or false")
	mustRefuse(t, c, "setting of a plugin without settings", plugins(entry("qdrant", true, map[string]any{"anything": 1})),
		`plugins[0].settings: unknown setting "anything"`)
	mustRefuse(t, c, "id missing", plugins(map[string]any{"enabled": true}), "plugins[0].id: is required")
	mustRefuse(t, c, "id a number", plugins(map[string]any{"id": 1, "enabled": true}), "plugins[0].id: must be a string")

	var many []map[string]any
	for i := 0; i <= MaxPlugins; i++ {
		many = append(many, entry("qdrant", true, nil))
	}
	mustRefuse(t, c, "33 plugin entries", plugins(many...), "plugins: has more than 32 entries")

	// The vectorizer plugin and the vectorizer object.
	withoutPlugin := fullDocument(t)
	withoutPlugin["plugins"] = list(t, withoutPlugin["plugins"])[:2]
	mustAccept(t, c, "the vectorizer object without the plugin", withoutPlugin)
	disabled := fullDocument(t)
	obj(t, list(t, disabled["plugins"])[2])["enabled"] = false
	delete(disabled, "vectorizer")
	delete(obj(t, disabled["secrets"]), SecretAnswerAPIKey)
	mustAccept(t, c, "the vectorizer plugin disabled, without the object", disabled)
}

func TestPluginSecrets(t *testing.T) {
	needy := basePlugin("needy")
	needy["secrets"] = []any{
		map[string]any{"key": "token", "env": "NEEDY_TOKEN", "label": "Token", "required": true},
		map[string]any{"key": "extra", "env": "NEEDY_EXTRA", "label": "Extra", "required": false},
	}
	c := loadTemp(t, needy, basePlugin("plain"))
	sealed := sealedSamples(t)[0]
	doc := func(enabled bool, secrets map[string]any) map[string]any {
		d := map[string]any{"schema": 1, "revision": 1, "mode": "private_ai",
			"plugins": []any{map[string]any{"id": "needy", "enabled": enabled}}}
		if secrets != nil {
			d["secrets"] = secrets
		}
		return d
	}
	mustRefuse(t, c, "enabled without its required secret", doc(true, nil), "secrets: plugin.needy.token is referred to and missing")
	mustRefuse(t, c, "enabled with only the optional secret", doc(true, map[string]any{"plugin.needy.extra": sealed}),
		"secrets: plugin.needy.token is referred to and missing")
	mustAccept(t, c, "enabled with the required secret", doc(true, map[string]any{"plugin.needy.token": sealed}))
	mustAccept(t, c, "enabled with both", doc(true, map[string]any{"plugin.needy.token": sealed, "plugin.needy.extra": sealed}))
	mustAccept(t, c, "disabled without secrets", doc(false, nil))
	mustAccept(t, c, "disabled, keeping its secrets", doc(false, map[string]any{"plugin.needy.token": sealed}))
	mustRefuse(t, c, "a key the catalog does not declare", doc(true, map[string]any{"plugin.needy.token": sealed, "plugin.needy.other": sealed}),
		`secrets["plugin.needy.other"]: nothing in the document refers to this secret`)
	mustRefuse(t, c, "a secret of a plugin that is not listed", doc(true, map[string]any{"plugin.needy.token": sealed, "plugin.plain.token": sealed}),
		`secrets["plugin.plain.token"]: nothing in the document refers to this secret`)
	mustRefuse(t, c, "a secret that is not sealed", doc(true, map[string]any{"plugin.needy.token": "hunter2"}),
		`secrets["plugin.needy.token"]: is not a sealed value`)
	mustRefuse(t, c, "a secret that is null", doc(true, map[string]any{"plugin.needy.token": nil}),
		`secrets["plugin.needy.token"]: is not a sealed value`)
	mustRefuse(t, c, "a name that is no secret name", doc(false, map[string]any{"Not A Name": sealed}),
		`secrets["Not A Name"]: nothing in the document refers to this secret`)

	parsed := mustAccept(t, c, "refs", doc(true, map[string]any{"plugin.needy.token": sealed}))
	if parsed == nil {
		t.FailNow()
	}
	wantRefs := []SecretRef{
		{Name: "plugin.needy.extra", Required: false, Plugin: "needy", Env: "NEEDY_EXTRA"},
		{Name: "plugin.needy.token", Required: true, Plugin: "needy", Env: "NEEDY_TOKEN"},
	}
	if got := SecretRefs(parsed, c); !reflect.DeepEqual(got, wantRefs) {
		t.Errorf("SecretRefs = %+v", got)
	}
	if got := SecretNames(parsed); !reflect.DeepEqual(got, []string{"plugin.needy.token"}) {
		t.Errorf("SecretNames = %v", got)
	}
	// Disabled: the required secret is not required to apply the document.
	parsed = mustAccept(t, c, "refs of a disabled plugin", doc(false, nil))
	if got := SecretRefs(parsed, c); len(got) != 2 || got[0].Required || got[1].Required {
		t.Errorf("SecretRefs of a disabled plugin = %+v", got)
	}
}

func TestSecretNamesAndRefs(t *testing.T) {
	c := fixtureCatalog(t)
	doc := mustAccept(t, c, "s3", s3Document(t, nil))
	if doc == nil {
		t.FailNow()
	}
	wantNames := []string{SecretAnswerAPIKey, SecretBackupS3Key, "nas.docs.password"}
	if got := SecretNames(doc); !reflect.DeepEqual(got, wantNames) {
		t.Errorf("SecretNames = %v, want %v", got, wantNames)
	}
	wantRefs := []SecretRef{
		{Name: SecretAnswerAPIKey, Required: true},
		{Name: SecretBackupS3Key, Required: true},
		{Name: "nas.docs.password", Required: true},
		{Name: "plugin.assistant.api_key", Required: false, Plugin: "assistant", Env: "ASSISTANT_API_KEY"},
	}
	if got := SecretRefs(doc, c); !reflect.DeepEqual(got, wantRefs) {
		t.Errorf("SecretRefs = %+v", got)
	}
	if SecretNames(nil) != nil || SecretRefs(nil, c) != nil {
		t.Error("a nil document has no secrets")
	}
	if got := SecretRefs(doc, nil); len(got) != 3 {
		t.Errorf("SecretRefs without a catalog = %+v", got)
	}
	minimal, _ := ParseDocument([]byte(`{"schema":1,"revision":1,"mode":"vast"}`), c)
	if got := SecretNames(minimal); len(got) != 0 {
		t.Errorf("SecretNames of a minimal document = %v", got)
	}

	// At most 32 secrets.
	var plugins []map[string]any
	doc33 := map[string]any{"schema": 1, "revision": 1, "mode": "private_ai"}
	var entries []any
	secrets := map[string]any{}
	for i := 0; i < 3; i++ {
		p := basePlugin(fmt.Sprintf("p%d", i))
		var declared []any
		for j := 0; j < 11; j++ {
			declared = append(declared, map[string]any{"key": fmt.Sprintf("k%d", j), "env": fmt.Sprintf("P%d_K%d", i, j)})
			secrets[fmt.Sprintf("plugin.p%d.k%d", i, j)] = sealedSamples(t)[0]
		}
		p["secrets"] = declared
		plugins = append(plugins, p)
		entries = append(entries, map[string]any{"id": p["id"], "enabled": true})
	}
	doc33["plugins"], doc33["secrets"] = entries, secrets
	big := loadTemp(t, plugins...)
	mustRefuse(t, big, "33 secrets", doc33, "secrets: has more than 32 secrets")
	delete(secrets, "plugin.p0.k0")
	mustAccept(t, big, "32 secrets", doc33)
}

func TestNASRules(t *testing.T) {
	c := fixtureCatalog(t)
	smb := func(change func(n map[string]any)) map[string]any {
		n := map[string]any{"id": "a", "kind": "smb", "host": "nas.lan", "share": "docs", "username": "", "access": "read"}
		if change != nil {
			change(n)
		}
		return map[string]any{"schema": 1, "revision": 1, "mode": "vast", "nas": []any{n}}
	}
	nfs := func(change func(n map[string]any)) map[string]any {
		n := map[string]any{"id": "a", "kind": "nfs", "host": "nas.lan", "export": "/volume1/x", "access": "write"}
		if change != nil {
			change(n)
		}
		return map[string]any{"schema": 1, "revision": 1, "mode": "vast", "nas": []any{n}}
	}
	good := map[string]map[string]any{
		"guest":                    smb(nil),
		"share with $ and spaces":  smb(func(n map[string]any) { n["share"] = "Public Share$" }),
		"share of 80 characters":   smb(func(n map[string]any) { n["share"] = strings.Repeat("a", 80) }),
		"subpath with spaces":      smb(func(n map[string]any) { n["subpath"] = "Année 2026/Été/a b" }),
		"subpath of 512":           smb(func(n map[string]any) { n["subpath"] = strings.Repeat("a", 512) }),
		"subpath with dots inside": smb(func(n map[string]any) { n["subpath"] = "a..b/.hidden/c." }),
		"domain":                   smb(func(n map[string]any) { n["domain"] = "CORP.example_1-x" }),
		"host of one character":    smb(func(n map[string]any) { n["host"] = "n" }),
		"host of 253 characters":   smb(func(n map[string]any) { n["host"] = strings.Repeat("a", 253) }),
		"id of 31 characters":      smb(func(n map[string]any) { n["id"] = "a" + strings.Repeat("-", 29) + "z" }),
		"nfs":                      nfs(nil),
		"nfs root export":          nfs(func(n map[string]any) { n["export"] = "/" }),
		"nfs export with dots":     nfs(func(n map[string]any) { n["export"] = "/a..b/c.d/.e" }),
		"nfs export of 255":        nfs(func(n map[string]any) { n["export"] = "/" + strings.Repeat("a", 254) }),
		"nfs with subpath":         nfs(func(n map[string]any) { n["subpath"] = "happymining" }),
	}
	for why, doc := range good {
		mustAccept(t, c, why, doc)
	}
	bad := map[string]struct {
		doc  map[string]any
		want string
	}{
		"share of 81 characters":     {smb(func(n map[string]any) { n["share"] = strings.Repeat("a", 81) }), "nas[0].share"},
		"share starting with a dot":  {smb(func(n map[string]any) { n["share"] = ".hidden" }), "nas[0].share"},
		"share with a backslash":     {smb(func(n map[string]any) { n["share"] = `a\b` }), "nas[0].share"},
		"share with a comma":         {smb(func(n map[string]any) { n["share"] = "a,rw" }), "nas[0].share"},
		"share empty":                {smb(func(n map[string]any) { n["share"] = "" }), "nas[0].share"},
		"username missing":           {smb(func(n map[string]any) { delete(n, "username") }), "nas[0].username: is required"},
		"username null":              {smb(func(n map[string]any) { n["username"] = nil }), "nas[0].username: must be a string"},
		"username with =":            {smb(func(n map[string]any) { n["username"] = "a=b"; n["secret"] = "nas.a.password" }), "nas[0].username: must not contain"},
		"username with a backslash":  {smb(func(n map[string]any) { n["username"] = `CORP\user`; n["secret"] = "nas.a.password" }), "nas[0].username: must not contain"},
		"username with a slash":      {smb(func(n map[string]any) { n["username"] = "corp/user"; n["secret"] = "nas.a.password" }), "nas[0].username: must not contain"},
		"username with a colon":      {smb(func(n map[string]any) { n["username"] = "user:pw"; n["secret"] = "nas.a.password" }), "nas[0].username: must not contain"},
		"username with a no-break":   {smb(func(n map[string]any) { n["username"] = "a b"; n["secret"] = "nas.a.password" }), "nas[0].username: must not contain"},
		"username of 65 characters":  {smb(func(n map[string]any) { n["username"] = strings.Repeat("u", 65); n["secret"] = "nas.a.password" }), "nas[0].username: is longer than 64"},
		"domain of 65 characters":    {smb(func(n map[string]any) { n["domain"] = strings.Repeat("d", 65) }), "nas[0].domain"},
		"domain with a space":        {smb(func(n map[string]any) { n["domain"] = "a b" }), "nas[0].domain"},
		"domain null":                {smb(func(n map[string]any) { n["domain"] = nil }), "nas[0].domain: must be a string"},
		"subpath of 513":             {smb(func(n map[string]any) { n["subpath"] = strings.Repeat("a", 513) }), "nas[0].subpath: is longer than 512"},
		"subpath a single dot":       {smb(func(n map[string]any) { n["subpath"] = "." }), "nas[0].subpath"},
		"subpath dot segment":        {smb(func(n map[string]any) { n["subpath"] = "a/./b" }), "nas[0].subpath"},
		"subpath ending in ..":       {smb(func(n map[string]any) { n["subpath"] = "a/.." }), "nas[0].subpath"},
		"subpath a number":           {smb(func(n map[string]any) { n["subpath"] = 1 }), "nas[0].subpath: must be a string"},
		"host of 254 characters":     {smb(func(n map[string]any) { n["host"] = strings.Repeat("a", 254) }), "nas[0].host"},
		"host ending with a dot":     {smb(func(n map[string]any) { n["host"] = "nas.lan." }), "nas[0].host"},
		"host with a colon":          {smb(func(n map[string]any) { n["host"] = "nas.lan:445" }), "nas[0].host"},
		"host with a comma":          {smb(func(n map[string]any) { n["host"] = "nas,rw" }), "nas[0].host"},
		"host IPv6":                  {smb(func(n map[string]any) { n["host"] = "fe80::1" }), "nas[0].host"},
		"host with an underscore":    {smb(func(n map[string]any) { n["host"] = "my_nas" }), "nas[0].host"},
		"id of 32 characters":        {smb(func(n map[string]any) { n["id"] = strings.Repeat("a", 32) }), "nas[0].id"},
		"id starting with a digit":   {smb(func(n map[string]any) { n["id"] = "1a" }), "nas[0].id"},
		"id with an underscore":      {smb(func(n map[string]any) { n["id"] = "a_b" }), "nas[0].id"},
		"id missing":                 {smb(func(n map[string]any) { delete(n, "id") }), "nas[0].id: is required"},
		"kind missing":               {smb(func(n map[string]any) { delete(n, "kind") }), "nas[0].kind: is required"},
		"access upper case":          {smb(func(n map[string]any) { n["access"] = "READ" }), "nas[0].access"},
		"smb secret for a guest":     {smb(func(n map[string]any) { n["secret"] = "nas.a.password" }), "nas[0].secret: guest access"},
		"nfs export with a space":    {nfs(func(n map[string]any) { n["export"] = "/a b" }), "nas[0].export"},
		"nfs export of 256":          {nfs(func(n map[string]any) { n["export"] = "/" + strings.Repeat("a", 255) }), "nas[0].export"},
		"nfs export ending in ..":    {nfs(func(n map[string]any) { n["export"] = "/a/.." }), "nas[0].export: must not contain a .. segment"},
		"nfs export with a colon":    {nfs(func(n map[string]any) { n["export"] = "/a:b" }), "nas[0].export"},
		"nfs export missing":         {nfs(func(n map[string]any) { delete(n, "export") }), "nas[0].export: is required"},
		"nfs with a share":           {nfs(func(n map[string]any) { n["share"] = "x" }), "nas[0].share: an nfs entry has no share"},
		"nfs with a domain":          {nfs(func(n map[string]any) { n["domain"] = "" }), "nas[0].domain: an nfs entry has no domain"},
		"nfs with an empty username": {nfs(func(n map[string]any) { n["username"] = "" }), "nas[0].username: an nfs entry has no username"},
		"nfs with mount options":     {nfs(func(n map[string]any) { n["options"] = "rw,suid,dev,exec" }), `nas[0]: unknown key "options"`},
		"entry not an object":        {map[string]any{"schema": 1, "revision": 1, "mode": "vast", "nas": []any{"docs"}}, "nas[0]: must be an object"},
	}
	for why, b := range bad {
		mustRefuse(t, c, why, b.doc, b.want)
	}

	// A user name needs its sealed password, and gets it by its exact name.
	withUser := smb(func(n map[string]any) { n["username"] = "indexer"; n["secret"] = "nas.a.password" })
	mustRefuse(t, c, "the password is not in secrets", withUser, "secrets: nas.a.password is referred to and missing")
	withUser["secrets"] = map[string]any{"nas.a.password": sealedSamples(t)[0]}
	mustAccept(t, c, "a user name with its sealed password", withUser)
}

func TestVectorizerRules(t *testing.T) {
	c := fixtureCatalog(t)
	with := func(change func(v map[string]any)) map[string]any {
		doc := fullDocument(t)
		change(obj(t, doc["vectorizer"]))
		return doc
	}
	manyStrings := func(n int, format string) []any {
		var out []any
		for i := 0; i < n; i++ {
			out = append(out, fmt.Sprintf(format, i))
		}
		return out
	}
	good := map[string]map[string]any{
		"40 extensions":           with(func(v map[string]any) { v["extensions"] = manyStrings(40, "e%d") }),
		"an extension twice":      with(func(v map[string]any) { v["extensions"] = []any{"pdf", "pdf"} }),
		"8-character extension":   with(func(v map[string]any) { v["extensions"] = []any{"abcdefg8"} }),
		"no exclude":              with(func(v map[string]any) { v["exclude"] = []any{} }),
		"32 excludes":             with(func(v map[string]any) { v["exclude"] = manyStrings(32, "dir %d") }),
		"exclude of 200":          with(func(v map[string]any) { v["exclude"] = []any{strings.Repeat("a", 200)} }),
		"max_file_mib 1":          with(func(v map[string]any) { v["max_file_mib"] = 1 }),
		"max_file_mib 2048":       with(func(v map[string]any) { v["max_file_mib"] = 2048 }),
		"embedding model tagged":  with(func(v map[string]any) { v["embedding_model"] = "library/nomic-embed-text:v1.5" }),
		"ocr on":                  with(func(v map[string]any) { v["ocr"] = true }),
		"answer model with slash": with(func(v map[string]any) { obj(t, v["answer"])["model"] = "org/Model_1.5:free" }),
	}
	for why, doc := range good {
		mustAccept(t, c, why, doc)
	}
	bad := map[string]struct {
		doc  map[string]any
		want string
	}{
		"sources missing":           {with(func(v map[string]any) { delete(v, "sources") }), "vectorizer.sources: is required"},
		"sources a string":          {with(func(v map[string]any) { v["sources"] = "docs" }), "vectorizer.sources: must be a list"},
		"source a number":           {with(func(v map[string]any) { v["sources"] = []any{1} }), "vectorizer.sources[0]: must be a string"},
		"extensions missing":        {with(func(v map[string]any) { delete(v, "extensions") }), "vectorizer.extensions: is required"},
		"41 extensions":             {with(func(v map[string]any) { v["extensions"] = manyStrings(41, "e%d") }), "vectorizer.extensions: has more than 40"},
		"9-character extension":     {with(func(v map[string]any) { v["extensions"] = []any{"abcdefghi"} }), "vectorizer.extensions[0]"},
		"extension empty":           {with(func(v map[string]any) { v["extensions"] = []any{""} }), "vectorizer.extensions[0]"},
		"extension with a star":     {with(func(v map[string]any) { v["extensions"] = []any{"*"} }), "vectorizer.extensions[0]"},
		"exclude missing":           {with(func(v map[string]any) { delete(v, "exclude") }), "vectorizer.exclude: is required"},
		"33 excludes":               {with(func(v map[string]any) { v["exclude"] = manyStrings(33, "d%d") }), "vectorizer.exclude: has more than 32"},
		"exclude of 201":            {with(func(v map[string]any) { v["exclude"] = []any{strings.Repeat("a", 201)} }), "vectorizer.exclude[0]: is longer than 200"},
		"exclude empty":             {with(func(v map[string]any) { v["exclude"] = []any{""} }), "vectorizer.exclude[0]: must not be empty"},
		"exclude absolute":          {with(func(v map[string]any) { v["exclude"] = []any{"ok", "/etc"} }), "vectorizer.exclude[1]"},
		"exclude with a dot":        {with(func(v map[string]any) { v["exclude"] = []any{"a/./b"} }), "vectorizer.exclude[0]"},
		"max_file_mib missing":      {with(func(v map[string]any) { delete(v, "max_file_mib") }), "vectorizer.max_file_mib: is required"},
		"max_file_mib a string":     {with(func(v map[string]any) { v["max_file_mib"] = "64" }), "vectorizer.max_file_mib: must be an integer"},
		"max_file_mib a fraction":   {with(func(v map[string]any) { v["max_file_mib"] = 1.5 }), "vectorizer.max_file_mib: must be an integer"},
		"embedding_model missing":   {with(func(v map[string]any) { delete(v, "embedding_model") }), "vectorizer.embedding_model: is required"},
		"embedding_model upper":     {with(func(v map[string]any) { v["embedding_model"] = "BGE-M3" }), "vectorizer.embedding_model"},
		"embedding_model with a ;":  {with(func(v map[string]any) { v["embedding_model"] = "bge;reboot" }), "vectorizer.embedding_model"},
		"embedding_model two tags":  {with(func(v map[string]any) { v["embedding_model"] = "a:b:c" }), "vectorizer.embedding_model"},
		"embedding_model too long":  {with(func(v map[string]any) { v["embedding_model"] = strings.Repeat("a", 82) }), "vectorizer.embedding_model"},
		"ocr missing":               {with(func(v map[string]any) { delete(v, "ocr") }), "vectorizer.ocr: is required"},
		"ocr a number":              {with(func(v map[string]any) { v["ocr"] = 1 }), "vectorizer.ocr: must be true or false"},
		"answer a string":           {with(func(v map[string]any) { v["answer"] = "none" }), "vectorizer.answer: must be an object"},
		"answer without a provider": {with(func(v map[string]any) { delete(obj(t, v["answer"]), "provider") }), "vectorizer.answer.provider: is required"},
		"9 sources":                 {with(func(v map[string]any) { v["sources"] = manyStrings(9, "docs") }), "vectorizer.sources: has more than 8"},
	}
	for why, b := range bad {
		mustRefuse(t, c, why, b.doc, b.want)
	}
}

func TestScheduleAndUpdateRules(t *testing.T) {
	c := fixtureCatalog(t)
	sched := func(entries ...map[string]any) map[string]any {
		doc := fullDocument(t)
		var l []any
		for _, e := range entries {
			l = append(l, e)
		}
		doc["schedules"] = l
		return doc
	}
	daily := func(change func(s map[string]any)) map[string]any {
		s := map[string]any{"id": "s", "job": "backup_run", "every": "daily", "hour": 2, "minute": 30, "enabled": true}
		if change != nil {
			change(s)
		}
		return s
	}
	mustAccept(t, c, "midnight", sched(daily(func(s map[string]any) { s["hour"] = 0; s["minute"] = 0 })))
	mustAccept(t, c, "23:59", sched(daily(func(s map[string]any) { s["hour"] = 23; s["minute"] = 59 })))
	mustAccept(t, c, "a job whose feature is not configured", func() map[string]any {
		doc := map[string]any{"schema": 1, "revision": 1, "mode": "vast",
			"schedules": []any{map[string]any{"id": "s", "job": "vectorize_sync", "every": "hourly", "minute": 5, "enabled": true}}}
		return doc
	}())
	mustAccept(t, c, "restart of a disabled plugin", func() map[string]any {
		doc := sched(daily(func(s map[string]any) { s["job"] = "plugin_restart"; s["plugin"] = "assistant" }))
		obj(t, list(t, doc["plugins"])[3])["enabled"] = false
		return doc
	}())
	bad := map[string]struct {
		doc  map[string]any
		want string
	}{
		"hour negative":           {sched(daily(func(s map[string]any) { s["hour"] = -1 })), "schedules[0].hour: must be 0 to 23"},
		"minute negative":         {sched(daily(func(s map[string]any) { s["minute"] = -1 })), "schedules[0].minute: must be 0 to 59"},
		"minute a string":         {sched(daily(func(s map[string]any) { s["minute"] = "30" })), "schedules[0].minute: must be an integer"},
		"hour a fraction":         {sched(daily(func(s map[string]any) { s["hour"] = 2.5 })), "schedules[0].hour: must be an integer"},
		"hour null":               {sched(daily(func(s map[string]any) { s["hour"] = nil })), "schedules[0].hour: must be an integer"},
		"hourly with a weekday":   {sched(daily(func(s map[string]any) { s["every"] = "hourly"; delete(s, "hour"); s["weekday"] = 1 })), "schedules[0].weekday: only a weekly schedule has a weekday"},
		"weekly without an hour":  {sched(daily(func(s map[string]any) { s["every"] = "weekly"; delete(s, "hour"); s["weekday"] = 1 })), "schedules[0].hour: is required"},
		"weekday negative":        {sched(daily(func(s map[string]any) { s["every"] = "weekly"; s["weekday"] = -1 })), "schedules[0].weekday: must be 0 to 6"},
		"every missing":           {sched(daily(func(s map[string]any) { delete(s, "every") })), "schedules[0].every: is required"},
		"job missing":             {sched(daily(func(s map[string]any) { delete(s, "job") })), "schedules[0].job: is required"},
		"job install_update":      {sched(daily(func(s map[string]any) { s["job"] = "install_update" })), "schedules[0].job: must be one of"},
		"id missing":              {sched(daily(func(s map[string]any) { delete(s, "id") })), "schedules[0].id: is required"},
		"id upper case":           {sched(daily(func(s map[string]any) { s["id"] = "Nightly" })), "schedules[0].id"},
		"enabled a number":        {sched(daily(func(s map[string]any) { s["enabled"] = 1 })), "schedules[0].enabled: must be true or false"},
		"a command":               {sched(daily(func(s map[string]any) { s["command"] = "reboot" })), `schedules[0]: unknown key "command"`},
		"a mode":                  {sched(daily(func(s map[string]any) { s["mode"] = "vast" })), `schedules[0]: unknown key "mode"`},
		"restart of a bad id":     {sched(daily(func(s map[string]any) { s["job"] = "plugin_restart"; s["plugin"] = "../x" })), "schedules[0].plugin: is not a plugin of this document"},
		"restart plugin a number": {sched(daily(func(s map[string]any) { s["job"] = "plugin_restart"; s["plugin"] = 1 })), "schedules[0].plugin: must be a string"},
		"entry not an object":     {sched(), "schedules"},
	}
	delete(bad, "entry not an object")
	for why, b := range bad {
		mustRefuse(t, c, why, b.doc, b.want)
	}
	notObject := fullDocument(t)
	notObject["schedules"] = []any{"nightly"}
	mustRefuse(t, c, "entry not an object", notObject, "schedules[0]: must be an object")

	update := func(u map[string]any) map[string]any {
		return map[string]any{"schema": 1, "revision": 1, "mode": "vast", "update": u}
	}
	doc := mustAccept(t, c, "manual without a window", update(map[string]any{"channel": "beta", "policy": "manual"}))
	if doc != nil && (doc.Update.Window != nil || doc.Update.Channel != ChannelBeta) {
		t.Errorf("update = %+v", doc.Update)
	}
	mustAccept(t, c, "channel none", update(map[string]any{"channel": "none", "policy": "manual"}))
	mustAccept(t, c, "window 23 to 0", update(map[string]any{"channel": "stable", "policy": "auto", "window": map[string]any{"start_hour": 23, "end_hour": 0}}))
	mustRefuse(t, c, "auto without a window", update(map[string]any{"channel": "stable", "policy": "auto"}), "update.window: is required")
	mustRefuse(t, c, "channel missing", update(map[string]any{"policy": "manual"}), "update.channel: is required")
	mustRefuse(t, c, "policy missing", update(map[string]any{"channel": "stable"}), "update.policy: is required")
	mustRefuse(t, c, "window without end", update(map[string]any{"channel": "stable", "policy": "auto", "window": map[string]any{"start_hour": 2}}), "update.window.end_hour: is required")
	mustRefuse(t, c, "window start negative", update(map[string]any{"channel": "stable", "policy": "auto", "window": map[string]any{"start_hour": -1, "end_hour": 3}}), "update.window.start_hour: must be 0 to 23")
	mustRefuse(t, c, "window with minutes", update(map[string]any{"channel": "stable", "policy": "auto", "window": map[string]any{"start_hour": 2, "end_hour": 3, "start_minute": 30}}), `update.window: unknown key "start_minute"`)
	mustRefuse(t, c, "manual with an equal window", update(map[string]any{"channel": "stable", "policy": "manual", "window": map[string]any{"start_hour": 4, "end_hour": 4}}), "update.window: start_hour and end_hour must differ")
	mustRefuse(t, c, "a version to install", update(map[string]any{"channel": "stable", "policy": "manual", "version": "9.9.9"}), `update: unknown key "version"`)
}

func TestWindowContains(t *testing.T) {
	night := Window{StartHour: 2, EndHour: 5}
	for hour, want := range map[int]bool{0: false, 1: false, 2: true, 3: true, 4: true, 5: false, 6: false, 23: false} {
		if night.Contains(hour) != want {
			t.Errorf("02–05 contains %d = %v", hour, !want)
		}
	}
	across := Window{StartHour: 22, EndHour: 4}
	for hour, want := range map[int]bool{21: false, 22: true, 23: true, 0: true, 3: true, 4: false, 12: false} {
		if across.Contains(hour) != want {
			t.Errorf("22–04 contains %d = %v", hour, !want)
		}
	}
}
