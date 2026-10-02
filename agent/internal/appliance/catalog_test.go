package appliance

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestFixtureCatalog(t *testing.T) {
	c := fixtureCatalog(t)
	if got, want := c.IDs(), []string{"assistant", "ollama", "qdrant", "vectorizer"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("IDs = %v, want %v", got, want)
	}
	want := []CatalogEntry{{"assistant", "3"}, {"ollama", "1"}, {"qdrant", "1"}, {"vectorizer", "1"}}
	if got := c.Summary(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Summary = %v, want %v", got, want)
	}
	if !filepath.IsAbs(c.Dir()) {
		t.Fatalf("Dir = %q, want an absolute path", c.Dir())
	}
	if _, ok := c.Plugin("notthere"); ok {
		t.Fatal("a plugin that is not in the catalog was found")
	}
	// IDs returns a copy.
	c.IDs()[0] = "changed"
	if c.IDs()[0] != "assistant" {
		t.Fatal("IDs exposes the catalog's own slice")
	}

	ollama, ok := c.Plugin("ollama")
	if !ok {
		t.Fatal("ollama is missing")
	}
	if !ollama.GPU || ollama.Version != "1" || ollama.Name != "Ollama (fixture)" || ollama.License != "MIT" {
		t.Fatalf("ollama = %+v", ollama)
	}
	if !ollama.RunsIn(ModePrivateAI) || !ollama.RunsIn(ModeVectorize) || ollama.RunsIn(ModeVast) || ollama.RunsIn("") {
		t.Fatalf("ollama modes = %v", ollama.Modes)
	}
	if !reflect.DeepEqual(ollama.Ports, []Port{{Name: "api", Port: 11434, Protocol: "http", UI: false}}) {
		t.Fatalf("ollama ports = %+v", ollama.Ports)
	}
	models := ollama.Settings["models"]
	if models == nil || models.Type != SettingStringList || models.Env != "HM_SET_MODELS" || models.MaxItems != 4 ||
		!reflect.DeepEqual(models.Default, []string{}) || models.Name != "models" {
		t.Fatalf("ollama models setting = %+v", models)
	}
	if !reflect.DeepEqual(ollama.Volumes, []Volume{{Name: "models", Backup: VolumeBackupModels}}) {
		t.Fatalf("ollama volumes = %+v", ollama.Volumes)
	}
	wantPost := []PostStart{{Service: "ollama", Exec: []string{"ollama", "pull", "{item}"}, ForEach: "models", TimeoutS: 3600}}
	if !reflect.DeepEqual(ollama.PostStart, wantPost) {
		t.Fatalf("ollama post_start = %+v", ollama.PostStart)
	}
	if !ollama.ImagesVerified() || ollama.Build != nil {
		t.Fatalf("ollama images = %+v", ollama.Images)
	}
	if ollama.ComposePath() != filepath.Join(c.Dir(), "ollama", "compose.yaml") || ollama.Dir() != filepath.Join(c.Dir(), "ollama") {
		t.Fatalf("ollama paths: %s, %s", ollama.ComposePath(), ollama.Dir())
	}

	assistant, _ := c.Plugin("assistant")
	if assistant.GPU || assistant.RunsIn(ModeVectorize) || !assistant.RunsIn(ModePrivateAI) {
		t.Fatalf("assistant = %+v", assistant)
	}
	if !reflect.DeepEqual(assistant.Requires, []string{"ollama"}) {
		t.Fatalf("assistant requires %v", assistant.Requires)
	}
	if !reflect.DeepEqual(assistant.SettingNames(), []string{"bind", "model", "telemetry", "workers"}) {
		t.Fatalf("assistant settings: %v", assistant.SettingNames())
	}
	if s := assistant.Settings["workers"]; s.Type != SettingInt || s.Min != 1 || s.Max != 8 || s.Default != int64(2) {
		t.Fatalf("workers = %+v", s)
	}
	if s := assistant.Settings["bind"]; s.Type != SettingEnum || !reflect.DeepEqual(s.Values, []string{"lan", "localhost"}) || s.Default != "lan" {
		t.Fatalf("bind = %+v", s)
	}
	if s := assistant.Settings["telemetry"]; s.Type != SettingBool || s.Default != false {
		t.Fatalf("telemetry = %+v", s)
	}
	if s := assistant.Settings["model"]; s.Type != SettingString || s.MaxLen != 100 || s.Default != "hermes3:8b" {
		t.Fatalf("model = %+v", s)
	}
	wantSecrets := []PluginSecret{{Key: "api_key", Env: "ASSISTANT_API_KEY", Label: "Cloud API key", Required: false}}
	if !reflect.DeepEqual(assistant.Secrets, wantSecrets) || assistant.SecretName("api_key") != "plugin.assistant.api_key" {
		t.Fatalf("assistant secrets = %+v", assistant.Secrets)
	}

	vectorizer, _ := c.Plugin("vectorizer")
	if vectorizer.ImagesVerified() {
		t.Fatal("the vectorizer fixture has an unverified image")
	}
	if vectorizer.Images[0].Digest != "" || vectorizer.Images[0].Verified {
		t.Fatalf("vectorizer image = %+v", vectorizer.Images[0])
	}
	if vectorizer.Build == nil || *vectorizer.Build != (Build{Context: "vectorizer", Image: "happymining/vectorizer:1"}) {
		t.Fatalf("vectorizer build = %+v", vectorizer.Build)
	}
}

// The plugin.json the contract prints as its example must load.
func TestContractPluginExampleLoads(t *testing.T) {
	example := contractExample(t, "## 7. Plugin catalog")
	example = strings.ReplaceAll(example, `"sha256:…"`, `"sha256:`+strings.Repeat("0", 64)+`"`)
	p, err := parsePlugin([]byte(example), "ollama")
	if err != nil {
		t.Fatalf("the contract's example is refused: %v", err)
	}
	if p.ID != "ollama" || !p.GPU || len(p.Secrets) != 1 || p.Secrets[0].Env != "EXAMPLE_API_KEY" || len(p.Volumes) != 2 ||
		len(p.PostStart) != 1 || p.Settings["models"].MaxItems != 8 {
		t.Fatalf("parsed example = %+v", p)
	}
}

// The catalog shipped in the repository must load. It is written by others;
// while it is empty there is nothing to check.
func TestShippedCatalogLoads(t *testing.T) {
	entries, err := os.ReadDir(shippedCatalogDir)
	if err != nil || len(entries) == 0 {
		t.Skip("appliance/catalog is empty")
	}
	c, err := LoadCatalog(shippedCatalogDir)
	if err != nil {
		t.Fatalf("appliance/catalog does not load: %v", err)
	}
	if len(c.IDs()) == 0 {
		t.Skip("appliance/catalog holds no plugin yet")
	}
	for _, id := range c.IDs() {
		p, _ := c.Plugin(id)
		if _, err := p.Env(nil); err != nil {
			t.Errorf("%s: the defaults do not make an environment: %v", id, err)
		}
		if _, err := p.PostStartCommands(nil); err != nil {
			t.Errorf("%s: post_start with the defaults: %v", id, err)
		}
	}
}

// set returns a copy of the base plugin with one top-level key replaced, or
// removed when value is nil.
func set(id, key string, value any) map[string]any {
	p := basePlugin(id)
	if value == nil {
		delete(p, key)
	} else {
		p[key] = value
	}
	return p
}

func TestPluginFileRules(t *testing.T) {
	sha := "sha256:" + strings.Repeat("a", 64)
	image := func(fields map[string]any) []any {
		img := map[string]any{"ref": "docker.io/example/x:1.0.0", "digest": sha, "verified": true}
		for key, value := range fields {
			img[key] = value
		}
		return []any{img}
	}
	withSettings := func(settings map[string]any) map[string]any {
		if settings == nil {
			settings = map[string]any{}
		}
		return set("x", "settings", settings)
	}
	withPost := func(settings map[string]any, post map[string]any) map[string]any {
		p := withSettings(settings)
		p["post_start"] = []any{post}
		return p
	}
	okList := map[string]any{"models": listSetting("HM_SET_MODELS", "^[a-z0-9]+$", 4)}

	bad := map[string]struct {
		plugin map[string]any
		want   string
	}{
		"schema 2":                   {set("x", "schema", 2), "schema: must be 1"},
		"schema missing":             {set("x", "schema", nil), "schema: is required"},
		"schema as a string":         {set("x", "schema", "1"), "schema: must be an integer"},
		"id differs from directory":  {set("x", "id", "y"), "id: must equal the directory name"},
		"id missing":                 {set("x", "id", nil), "id: is required"},
		"version missing":            {set("x", "version", nil), "version: is required"},
		"version empty":              {set("x", "version", ""), "version: must be 1 to 128 characters"},
		"version a number":           {set("x", "version", 1), "version: must be a string"},
		"version too long":           {set("x", "version", strings.Repeat("1", 129)), "version: must be 1 to 128 characters"},
		"version with a newline":     {set("x", "version", "1\n2"), "version: contains a control character"},
		"name missing":               {set("x", "name", nil), "name: is required"},
		"gpu missing":                {set("x", "gpu", nil), "gpu: is required"},
		"gpu as a string":            {set("x", "gpu", "true"), "gpu: must be true or false"},
		"modes missing":              {set("x", "modes", nil), "modes: is required"},
		"modes with vast":            {set("x", "modes", []any{"private_ai", "vast"}), "modes[1]: no plugin runs in vast mode"},
		"modes only vast":            {set("x", "modes", []any{"vast"}), "modes[0]: no plugin runs in vast mode"},
		"modes unknown":              {set("x", "modes", []any{"mining"}), "modes[0]: must be private_ai or vectorize"},
		"modes twice":                {set("x", "modes", []any{"private_ai", "private_ai"}), "modes[1]: is listed twice"},
		"modes not a list":           {set("x", "modes", "private_ai"), "modes: must be a list"},
		"requires itself":            {set("x", "requires", []any{"x"}), "requires[0]: a plugin cannot require itself"},
		"requires twice":             {set("x", "requires", []any{"y", "y"}), "requires[1]: is listed twice"},
		"requires a bad id":          {set("x", "requires", []any{"Y"}), "requires[0]: is not a plugin id"},
		"port 0":                     {set("x", "ports", []any{map[string]any{"name": "a", "port": 0, "protocol": "http", "ui": false}}), "ports[0].port: must be 1 to 65535"},
		"port 65536":                 {set("x", "ports", []any{map[string]any{"name": "a", "port": 65536, "protocol": "http", "ui": false}}), "ports[0].port: must be 1 to 65535"},
		"port as a string":           {set("x", "ports", []any{map[string]any{"name": "a", "port": "80", "protocol": "http", "ui": false}}), "ports[0].port: must be an integer"},
		"port without ui":            {set("x", "ports", []any{map[string]any{"name": "a", "port": 80, "protocol": "http"}}), "ports[0].ui: is required"},
		"port with an unknown key":   {set("x", "ports", []any{map[string]any{"name": "a", "port": 80, "protocol": "http", "ui": true, "host": "0.0.0.0"}}), `ports[0]: unknown key "host"`},
		"port twice":                 {set("x", "ports", []any{map[string]any{"name": "a", "port": 80, "protocol": "http", "ui": true}, map[string]any{"name": "b", "port": 80, "protocol": "http", "ui": true}}), "ports[1]: the port is used twice"},
		"port name twice":            {set("x", "ports", []any{map[string]any{"name": "a", "port": 80, "protocol": "http", "ui": true}, map[string]any{"name": "a", "port": 81, "protocol": "http", "ui": true}}), "ports[1]: the name is used twice"},
		"unknown top-level key":      {set("x", "command", "rm -rf /"), `top level: unknown key "command"`},
		"privileged":                 {set("x", "privileged", true), `top level: unknown key "privileged"`},
		"images missing":             {set("x", "images", nil), "images: is required"},
		"images empty":               {set("x", "images", []any{}), "images: needs at least 1"},
		"image without a tag":        {set("x", "images", image(map[string]any{"ref": "docker.io/example/x"})), "images[0].ref"},
		"image with only a port":     {set("x", "images", image(map[string]any{"ref": "localhost:5000/x"})), "images[0].ref"},
		"image with a digest in ref": {set("x", "images", image(map[string]any{"ref": "docker.io/example/x:1@" + sha})), "images[0].ref"},
		"image with a space":         {set("x", "images", image(map[string]any{"ref": "docker.io/example/x:1 --privileged"})), "images[0].ref"},
		"image upper case":           {set("x", "images", image(map[string]any{"ref": "Docker.io/example/x:1"})), "images[0].ref"},
		"digest malformed":           {set("x", "images", image(map[string]any{"digest": "sha256:abc"})), "images[0].digest"},
		"digest md5":                 {set("x", "images", image(map[string]any{"digest": "md5:" + strings.Repeat("a", 64)})), "images[0].digest"},
		"digest a number":            {set("x", "images", image(map[string]any{"digest": 1})), "images[0].digest: must be a string"},
		"verified without digest":    {set("x", "images", []any{map[string]any{"ref": "docker.io/example/x:1", "digest": nil, "verified": true}}), "images[0]: an image without a digest cannot be verified"},
		"verified missing":           {set("x", "images", []any{map[string]any{"ref": "docker.io/example/x:1", "digest": sha}}), "images[0].verified: is required"},
		"image twice":                {set("x", "images", append(image(nil), image(nil)...)), "images[1]: the image is listed twice"},
		"image unknown key":          {set("x", "images", image(map[string]any{"pull": "always"})), `images[0]: unknown key "pull"`},
		"volume backup unknown":      {set("x", "volumes", []any{map[string]any{"name": "data", "backup": "sometimes"}}), "volumes[0].backup: must be one of"},
		"volume name with a slash":   {set("x", "volumes", []any{map[string]any{"name": "/etc", "backup": "never"}}), "volumes[0].name"},
		"volume name traversal":      {set("x", "volumes", []any{map[string]any{"name": "..", "backup": "never"}}), "volumes[0].name"},
		"volume twice":               {set("x", "volumes", []any{map[string]any{"name": "data", "backup": "never"}, map[string]any{"name": "data", "backup": "always"}}), "volumes[1]: the name is used twice"},
		"volume without backup":      {set("x", "volumes", []any{map[string]any{"name": "data"}}), "volumes[0].backup: is required"},
		"build context traversal":    {set("x", "build", map[string]any{"context": "../etc", "image": "happymining/x:1"}), "build.context"},
		"build context absolute":     {set("x", "build", map[string]any{"context": "/etc", "image": "happymining/x:1"}), "build.context"},
		"build context nested":       {set("x", "build", map[string]any{"context": "a/b", "image": "happymining/x:1"}), "build.context"},
		"build image without a tag":  {set("x", "build", map[string]any{"context": "x", "image": "happymining/x"}), "build.image"},
		"build without image":        {set("x", "build", map[string]any{"context": "x"}), "build.image: is required"},
		"build unknown key":          {set("x", "build", map[string]any{"context": "x", "image": "happymining/x:1", "args": []any{}}), `build: unknown key "args"`},
		"build not an object":        {set("x", "build", "x"), "build: must be an object"},
		"settings not an object":     {set("x", "settings", []any{}), "settings: must be an object"},
		"setting name upper case":    {withSettings(map[string]any{"Models": boolSetting("HM_SET_A", false)}), `settings: "Models" is not a setting name`},
		"setting name with a dash":   {withSettings(map[string]any{"a-b": boolSetting("HM_SET_A", false)}), `is not a setting name`},
		"setting type unknown":       {withSettings(map[string]any{"a": map[string]any{"type": "path", "label": "A", "env": "HM_SET_A", "default": "/"}}), "settings.a.type: must be one of"},
		"setting without type":       {withSettings(map[string]any{"a": map[string]any{"label": "A", "env": "HM_SET_A", "default": false}}), "settings.a.type: is required"},
		"setting without label":      {withSettings(map[string]any{"a": map[string]any{"type": "bool", "env": "HM_SET_A", "default": false}}), "settings.a.label: is required"},
		"setting without default":    {withSettings(map[string]any{"a": map[string]any{"type": "bool", "label": "A", "env": "HM_SET_A"}}), "settings.a.default: is required"},
		"setting without env":        {withSettings(map[string]any{"a": map[string]any{"type": "bool", "label": "A", "default": false}}), "settings.a.env: is required"},
		"env without the prefix":     {withSettings(map[string]any{"a": boolSetting("MODELS", false)}), "settings.a.env: must be HM_SET_"},
		"env PATH":                   {withSettings(map[string]any{"a": boolSetting("PATH", false)}), "settings.a.env: must be HM_SET_"},
		"env lower case":             {withSettings(map[string]any{"a": boolSetting("HM_SET_models", false)}), "settings.a.env: must be HM_SET_"},
		"env only the prefix":        {withSettings(map[string]any{"a": boolSetting("HM_SET_", false)}), "settings.a.env: must be HM_SET_"},
		"env too long":               {withSettings(map[string]any{"a": boolSetting("HM_SET_"+strings.Repeat("A", 41), false)}), "settings.a.env: must be HM_SET_"},
		"env with an equals sign":    {withSettings(map[string]any{"a": boolSetting("HM_SET_A=1", false)}), "settings.a.env: must be HM_SET_"},
		"env twice":                  {withSettings(map[string]any{"a": boolSetting("HM_SET_A", false), "b": boolSetting("HM_SET_A", true)}), "settings.b: the variable HM_SET_A is used twice"},
		"bool default a string":      {withSettings(map[string]any{"a": boolSetting("HM_SET_A", false), "b": map[string]any{"type": "bool", "label": "B", "env": "HM_SET_B", "default": "false"}}), "settings.b.default: must be true or false"},
		"bool with min":              {withSettings(map[string]any{"a": map[string]any{"type": "bool", "label": "A", "env": "HM_SET_A", "default": false, "min": 0}}), `settings.a: unknown key "min"`},
		"int without min":            {withSettings(map[string]any{"a": map[string]any{"type": "int", "label": "A", "env": "HM_SET_A", "max": 3, "default": 1}}), "settings.a.min: is required"},
		"int without max":            {withSettings(map[string]any{"a": map[string]any{"type": "int", "label": "A", "env": "HM_SET_A", "min": 3, "default": 3}}), "settings.a.max: is required"},
		"int min above max":          {withSettings(map[string]any{"a": intSetting("HM_SET_A", 5, 1, 3)}), "settings.a: min is greater than max"},
		"int default out of range":   {withSettings(map[string]any{"a": intSetting("HM_SET_A", 1, 8, 9)}), "settings.a.default: must be 1 to 8"},
		"int default a string":       {withSettings(map[string]any{"a": map[string]any{"type": "int", "label": "A", "env": "HM_SET_A", "min": 1, "max": 8, "default": "2"}}), "settings.a.default: must be an integer"},
		"int default a fraction":     {withSettings(map[string]any{"a": map[string]any{"type": "int", "label": "A", "env": "HM_SET_A", "min": 1, "max": 8, "default": 2.5}}), "settings.a.default: must be an integer"},
		"int with a pattern":         {withSettings(map[string]any{"a": map[string]any{"type": "int", "label": "A", "env": "HM_SET_A", "min": 1, "max": 8, "default": 2, "pattern": "^1$"}}), `settings.a: unknown key "pattern"`},
		"enum without values":        {withSettings(map[string]any{"a": map[string]any{"type": "enum", "label": "A", "env": "HM_SET_A", "default": "x"}}), "settings.a.values: is required"},
		"enum with no value":         {withSettings(map[string]any{"a": enumSetting("HM_SET_A", "x")}), "settings.a.values: needs at least 1"},
		"enum default not a value":   {withSettings(map[string]any{"a": enumSetting("HM_SET_A", "z", "x", "y")}), "settings.a.default: must be one of"},
		"enum value twice":           {withSettings(map[string]any{"a": enumSetting("HM_SET_A", "x", "x", "x")}), "settings.a.values[1]: is listed twice"},
		"enum value with a dollar":   {withSettings(map[string]any{"a": enumSetting("HM_SET_A", "x", "x", "$HOME")}), "settings.a.values[1]: contains a character that is not allowed"},
		"enum value with a quote":    {withSettings(map[string]any{"a": enumSetting("HM_SET_A", "x", "x", `a"b`)}), "settings.a.values[1]: contains a character that is not allowed"},
		"enum value with a newline":  {withSettings(map[string]any{"a": enumSetting("HM_SET_A", "x", "x", "a\nb")}), "settings.a.values[1]: contains a control character"},
		"enum value empty":           {withSettings(map[string]any{"a": enumSetting("HM_SET_A", "x", "x", "")}), "settings.a.values[1]: must be 1 to 200 bytes"},
		"enum value a number":        {withSettings(map[string]any{"a": enumSetting("HM_SET_A", "x", "x", 1)}), "settings.a.values[1]: must be a string"},
		"string without pattern":     {withSettings(map[string]any{"a": map[string]any{"type": "string", "label": "A", "env": "HM_SET_A", "max_len": 10, "default": ""}}), "settings.a.pattern: is required"},
		"string without max_len":     {withSettings(map[string]any{"a": map[string]any{"type": "string", "label": "A", "env": "HM_SET_A", "pattern": "^a*$", "default": ""}}), "settings.a.max_len: is required"},
		"string max_len 201":         {withSettings(map[string]any{"a": stringSetting("HM_SET_A", "^a*$", 201, "")}), "settings.a.max_len: must be 1 to 200"},
		"string max_len 0":           {withSettings(map[string]any{"a": stringSetting("HM_SET_A", "^a*$", 0, "")}), "settings.a.max_len: must be 1 to 200"},
		"string default too long":    {withSettings(map[string]any{"a": stringSetting("HM_SET_A", "^a*$", 3, "aaaa")}), "settings.a.default: is longer than 3 characters"},
		"string default mismatch":    {withSettings(map[string]any{"a": stringSetting("HM_SET_A", "^a+$", 3, "")}), "settings.a.default: does not match the pattern"},
		"string with max_items":      {withSettings(map[string]any{"a": map[string]any{"type": "string", "label": "A", "env": "HM_SET_A", "pattern": "^a*$", "max_len": 3, "max_items": 2, "default": ""}}), `settings.a: unknown key "max_items"`},
		"list without max_items":     {withSettings(map[string]any{"a": map[string]any{"type": "string_list", "label": "A", "env": "HM_SET_A", "pattern": "^a+$", "default": []any{}}}), "settings.a.max_items: is required"},
		"list max_items 33":          {withSettings(map[string]any{"a": listSetting("HM_SET_A", "^a+$", 33)}), "settings.a.max_items: must be 1 to 32"},
		"list default too long":      {withSettings(map[string]any{"a": listSetting("HM_SET_A", "^a+$", 1, "a", "aa")}), "settings.a.default: has more than 1 items"},
		"list default mismatch":      {withSettings(map[string]any{"a": listSetting("HM_SET_A", "^a+$", 2, "b")}), "settings.a.default: item 0 does not match the pattern"},
		"list default a string":      {withSettings(map[string]any{"a": map[string]any{"type": "string_list", "label": "A", "env": "HM_SET_A", "pattern": "^a+$", "max_items": 2, "default": "a"}}), "settings.a.default: must be a list of strings"},
		"pattern unanchored":         {withSettings(map[string]any{"a": stringSetting("HM_SET_A", "[a-z]+", 10, "a")}), "settings.a.pattern: must be anchored"},
		"pattern matching a dollar":  {withSettings(map[string]any{"a": stringSetting("HM_SET_A", `^[a-z$]+$`, 10, "a")}), "settings.a.pattern: can match"},
		"list pattern with a space":  {withSettings(map[string]any{"a": listSetting("HM_SET_A", `^[a-z ]+$`, 2)}), "settings.a.pattern: can match a space"},
		"pattern invalid":            {withSettings(map[string]any{"a": stringSetting("HM_SET_A", `^[a-z+$`, 10, "a")}), "settings.a.pattern: is not a valid regular expression"},
		"secret key upper case":      {set("x", "secrets", []any{map[string]any{"key": "API", "env": "X_API_KEY"}}), "secrets[0].key"},
		"secret key with a dot":      {set("x", "secrets", []any{map[string]any{"key": "a.b", "env": "X_API_KEY"}}), "secrets[0].key"},
		"secret env lower case":      {set("x", "secrets", []any{map[string]any{"key": "api_key", "env": "x_api_key"}}), "secrets[0].env"},
		"secret env one letter":      {set("x", "secrets", []any{map[string]any{"key": "api_key", "env": "X"}}), "secrets[0].env"},
		"secret env a setting's":     {set("x", "secrets", []any{map[string]any{"key": "api_key", "env": "HM_SET_MODELS"}}), "secrets[0]: the variable HM_SET_MODELS is reserved"},
		"secret env HM_BIND":         {set("x", "secrets", []any{map[string]any{"key": "api_key", "env": "HM_BIND"}}), "secrets[0]: the variable HM_BIND is reserved"},
		"secret env HM_PLUGIN_DATA":  {set("x", "secrets", []any{map[string]any{"key": "api_key", "env": "HM_PLUGIN_DATA"}}), "secrets[0]: the variable HM_PLUGIN_DATA is reserved"},
		"secret env twice":           {set("x", "secrets", []any{map[string]any{"key": "a", "env": "X_KEY"}, map[string]any{"key": "b", "env": "X_KEY"}}), "secrets[1]: the variable X_KEY is used twice"},
		"secret key twice":           {set("x", "secrets", []any{map[string]any{"key": "a", "env": "X_KEY"}, map[string]any{"key": "a", "env": "Y_KEY"}}), "secrets[1]: the key is used twice"},
		"secret without env":         {set("x", "secrets", []any{map[string]any{"key": "a"}}), "secrets[0].env: is required"},
		"secret required a string":   {set("x", "secrets", []any{map[string]any{"key": "a", "env": "X_KEY", "required": "yes"}}), "secrets[0].required: must be true or false"},
		"secret unknown key":         {set("x", "secrets", []any{map[string]any{"key": "a", "env": "X_KEY", "value": "hunter2"}}), `secrets[0]: unknown key "value"`},
		"post_start without exec":    {withPost(nil, map[string]any{"service": "x", "timeout_s": 10}), "post_start[0].exec: is required"},
		"post_start empty exec":      {withPost(nil, map[string]any{"service": "x", "exec": []any{}, "timeout_s": 10}), "post_start[0].exec: needs at least 1"},
		"post_start exec a string":   {withPost(nil, map[string]any{"service": "x", "exec": "sh -c 'rm -rf /'", "timeout_s": 10}), "post_start[0].exec: must be a list"},
		"post_start arg a number":    {withPost(nil, map[string]any{"service": "x", "exec": []any{"sleep", 1}, "timeout_s": 10}), "post_start[0].exec[1]: must be a string"},
		"post_start arg empty":       {withPost(nil, map[string]any{"service": "x", "exec": []any{"echo", ""}, "timeout_s": 10}), "post_start[0].exec[1]: must be 1 to 200 bytes"},
		"post_start arg newline":     {withPost(nil, map[string]any{"service": "x", "exec": []any{"echo", "a\nb"}, "timeout_s": 10}), "post_start[0].exec[1]: contains a control character"},
		"post_start without timeout": {withPost(nil, map[string]any{"service": "x", "exec": []any{"true"}}), "post_start[0].timeout_s: is required"},
		"post_start timeout 0":       {withPost(nil, map[string]any{"service": "x", "exec": []any{"true"}, "timeout_s": 0}), "post_start[0].timeout_s: must be 1 to 86400"},
		"post_start timeout huge":    {withPost(nil, map[string]any{"service": "x", "exec": []any{"true"}, "timeout_s": 86401}), "post_start[0].timeout_s: must be 1 to 86400"},
		"post_start bad service":     {withPost(nil, map[string]any{"service": "x; reboot", "exec": []any{"true"}, "timeout_s": 10}), "post_start[0].service"},
		"post_start without service": {withPost(nil, map[string]any{"exec": []any{"true"}, "timeout_s": 10}), "post_start[0].service: is required"},
		"post_start unknown key":     {withPost(nil, map[string]any{"service": "x", "exec": []any{"true"}, "timeout_s": 10, "shell": true}), `post_start[0]: unknown key "shell"`},
		"for_each unknown setting":   {withPost(okList, map[string]any{"service": "x", "exec": []any{"pull", "{item}"}, "for_each": "nope", "timeout_s": 10}), "post_start[0].for_each: must name a string_list setting"},
		"for_each not a list":        {withPost(map[string]any{"a": boolSetting("HM_SET_A", false)}, map[string]any{"service": "x", "exec": []any{"pull", "{item}"}, "for_each": "a", "timeout_s": 10}), "post_start[0].for_each: must name a string_list setting"},
		"for_each empty":             {withPost(okList, map[string]any{"service": "x", "exec": []any{"pull", "{item}"}, "for_each": "", "timeout_s": 10}), "post_start[0].for_each: must name a string_list setting"},
		"item without for_each":      {withPost(okList, map[string]any{"service": "x", "exec": []any{"pull", "{item}"}, "timeout_s": 10}), "post_start[0]: {item} is used without for_each"},
		"item as the command":        {withPost(okList, map[string]any{"service": "x", "exec": []any{"{item}"}, "for_each": "models", "timeout_s": 10}), "post_start[0]: the command itself cannot be {item}"},
	}
	for why, c := range bad {
		_, err := parsePlugin(encode(t, c.plugin), "x")
		if err == nil {
			t.Errorf("%s: accepted, must be refused", why)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: refused for another reason:\n  got  %v\n  want something about %q", why, err, c.want)
		}
	}

	// The base plugin and the optional keys left out are fine.
	if _, err := parsePlugin(encode(t, basePlugin("x")), "x"); err != nil {
		t.Fatalf("the base plugin is refused: %v", err)
	}
	minimal := map[string]any{"schema": 1, "id": "x", "version": "1", "name": "X", "gpu": false, "modes": []any{},
		"images": []any{map[string]any{"ref": "docker.io/example/x:1", "verified": false}}}
	p, err := parsePlugin(encode(t, minimal), "x")
	if err != nil {
		t.Fatalf("a plugin with only the required keys is refused: %v", err)
	}
	if p.RunsIn(ModePrivateAI) || p.ImagesVerified() || len(p.Settings) != 0 || p.Build != nil {
		t.Fatalf("minimal plugin = %+v", p)
	}
	// A good for_each.
	good := withPost(okList, map[string]any{"service": "x", "exec": []any{"pull", "--model={item}"}, "for_each": "models", "timeout_s": 10})
	if _, err := parsePlugin(encode(t, good), "x"); err != nil {
		t.Fatalf("a post_start with for_each is refused: %v", err)
	}
}

func TestPluginFileIsReadStrictly(t *testing.T) {
	base := string(encode(t, basePlugin("x")))
	for why, raw := range map[string]string{
		"duplicate key":        strings.Replace(base, `"gpu":false`, `"gpu":false,"gpu":true`, 1),
		"duplicate nested key": strings.Replace(base, `"name":"api"`, `"name":"api","name":"web"`, 1),
		"trailing data":        base + "{}",
		"not an object":        "[" + base + "]",
		"empty":                "",
		"a comment":            "// plugin\n" + base,
		"a byte order mark":    "\xef\xbb\xbf" + base,
		"invalid UTF-8":        strings.Replace(base, "A test plugin.", "A test\xff plugin.", 1),
		"unpaired surrogate":   strings.Replace(base, "A test plugin.", `A test \ud83d plugin.`, 1),
		"too large":            strings.Replace(base, "A test plugin.", strings.Repeat("a", maxPluginFileBytes), 1),
	} {
		if _, err := parsePlugin([]byte(raw), "x"); err == nil {
			t.Errorf("%s: accepted, must be refused", why)
		}
	}
	if !strings.Contains(base, `"gpu":false`) || !strings.Contains(base, `"name":"api"`) || !strings.Contains(base, "A test plugin.") {
		t.Fatal("the base plugin changed: the replacements above no longer apply")
	}
}

func TestSecretNameMustFitTheSealFormat(t *testing.T) {
	// "plugin." + id + "." + key is at most 63 characters.
	id := "p" + strings.Repeat("a", 30)   // 31
	key := "k" + strings.Repeat("b", 23)  // 24: 7 + 31 + 1 + 24 = 63
	long := "k" + strings.Repeat("b", 24) // 64 in all
	ok := set(id, "secrets", []any{map[string]any{"key": key, "env": "X_KEY"}})
	if _, err := parsePlugin(encode(t, ok), id); err != nil {
		t.Fatalf("a 63-character secret name is refused: %v", err)
	}
	tooLong := set(id, "secrets", []any{map[string]any{"key": long, "env": "X_KEY"}})
	if _, err := parsePlugin(encode(t, tooLong), id); err == nil || !strings.Contains(err.Error(), "too long for a secret name") {
		t.Fatalf("a 64-character secret name: %v", err)
	}
}

func TestSettingPatternSafety(t *testing.T) {
	type c struct {
		pattern string
		list    bool
	}
	good := []c{
		{`^[a-z0-9][a-z0-9._/-]{0,80}(:[A-Za-z0-9._-]{1,40})?$`, true},
		{`^[a-z0-9][a-z0-9._/-]{0,80}(:[A-Za-z0-9._-]{1,40})?$`, false},
		{`^$`, false},
		{`^[A-Za-z0-9 ]*$`, false}, // a space is fine in a single string
		{`^(lan|localhost)$`, false},
		{`^(?:a|b)+$`, true},
		{`^[a-z]+(,[a-z]+)*$`, true},
		{`^\d{1,5}$`, true},
		{`^\w+$`, true},
		{`^[[:alnum:]]+$`, true},
		{`^[a-zà-ÿ]+$`, true},
		{`\A[a-z]+\z`, true},
		{`(?i)^[a-z]+$`, true},
		{`^https://[a-z0-9.-]+(:[0-9]{1,5})?(/[a-z0-9._/-]*)?$`, false},
		{`^[#%&()*+,./:;<=>?@^_{|}~!-]+$`, true}, // odd but none of the forbidden characters
	}
	for _, g := range good {
		if _, err := compilePattern(g.pattern, g.list); err != nil {
			t.Errorf("%q (list=%v) is refused: %v", g.pattern, g.list, err)
		}
	}
	bad := map[string]c{
		"empty":                        {``, false},
		"not anchored":                 {`[a-z]+`, false},
		"only the start anchored":      {`^[a-z]+`, false},
		"only the end anchored":        {`[a-z]+$`, false},
		"alternation escapes anchors":  {`^a|b$`, false},
		"alternation of anchored":      {`^a$|^b.*$`, false},
		"anchor inside a group":        {`(^[a-z]+$)`, false},
		"optional end anchor":          {`^[a-z]+$?`, false},
		"multi-line mode":              {`(?m)^[a-z]+$`, false},
		"multi-line inside":            {`^[a-z]+(?m:$)x*$`, false},
		"dot":                          {`^.*$`, false},
		"dot with s flag":              {`(?s)^.*$`, false},
		"dot bounded":                  {`^a.b$`, false},
		"negated class":                {`^[^,]+$`, false},
		"negated class of letters":     {`^[^a-z]*$`, false},
		"non-space class":              {`^\S+$`, false},
		"non-word class":               {`^\W*$`, false},
		"non-digit class":              {`^\D*$`, false},
		"double quote":                 {`^[a-z"]+$`, false},
		"single quote":                 {`^[a-z']+$`, false},
		"dollar in a class":            {`^[a-z$]+$`, false},
		"dollar literal":               {`^\$[a-z]+$`, false},
		"backquote":                    {"^[a-z`]+$", false},
		"backslash":                    {`^[a-z\\]+$`, false},
		"backslash literal":            {`^a\\b$`, false},
		"newline in a class":           {`^[a-z\n]+$`, false},
		"newline literal":              {"^a\nb$", false},
		"tab":                          {`^[a-z\t]+$`, false},
		"white space class":            {`^[a-z\s]+$`, false},
		"NUL":                          {`^[a-z\x00]+$`, false},
		"DEL":                          {`^[a-z\x7f]+$`, false},
		"range over the quotes":        {`^[!-/]+$`, false},
		"range over the backslash":     {`^[A-z]+$`, false},
		"range over everything":        {`^[\x00-\x{10FFFF}]*$`, false},
		"printable ASCII":              {`^[ -~]+$`, false},
		"posix punct":                  {`^[[:punct:]]+$`, false},
		"posix print":                  {`^[[:print:]]+$`, false},
		"unicode punctuation":          {`^\pP+$`, false},
		"quote in an alternative":      {`^(a|b|")$`, false},
		"quote in a nested group":      {`^(a(b(c'?)?)?)$`, false},
		"dollar in an optional group":  {`^a(\$b)?$`, false},
		"invalid expression":           {`^[a-z+$`, false},
		"lookahead (not RE2)":          {`^(?=a)[a-z]+$`, false},
		"backreference (not RE2)":      {`^(a)\1$`, false},
		"too long":                     {`^` + strings.Repeat("a", maxPatternLen) + `$`, false},
		"space in a list":              {`^[a-z ]+$`, true},
		"space literal in a list":      {`^a b$`, true},
		"space in a list alternative":  {`^(a|b| )$`, true},
		"range over space in a list":   {`^[ -#%&]+$`, true},
		"posix space class in a list":  {`^[[:blank:]a]+$`, true},
		"quote in a list":              {`^[a-z"]+$`, true},
		"dot in a list":                {`^.+$`, true},
		"negated class in a list":      {`^[^ ]+$`, true},
		"case-insensitive with dollar": {`(?i)^[a-z$]+$`, true},
	}
	for why, b := range bad {
		if re, err := compilePattern(b.pattern, b.list); err == nil {
			t.Errorf("%s: %q (list=%v) is accepted (compiled to %v)", why, b.pattern, b.list, re)
		}
	}

	// Whatever compilePattern accepts cannot match a forbidden character:
	// probe each accepted pattern with every forbidden character alone and
	// between letters and digits.
	forbidden := []string{"\x00", "\x01", "\t", "\n", "\r", "\x1b", "\x1f", "\x7f", `"`, `'`, `$`, "`", `\`}
	for _, g := range good {
		re, err := compilePattern(g.pattern, g.list)
		if err != nil {
			continue
		}
		probes := forbidden
		if g.list {
			probes = append(append([]string(nil), forbidden...), " ")
		}
		for _, f := range probes {
			for _, probe := range []string{f, "a" + f, f + "a", "a" + f + "a", "1" + f + "1", "a:" + f, f + f, "lan" + f, "a,a" + f} {
				if re.MatchString(probe) {
					t.Errorf("%q matches %q", g.pattern, probe)
				}
			}
		}
	}
}

func TestCatalogRequires(t *testing.T) {
	requires := func(id string, reqs ...any) map[string]any { return set(id, "requires", append([]any{}, reqs...)) }
	uniquePorts := func(plugins ...map[string]any) []map[string]any { return plugins }

	c := loadTemp(t, uniquePorts(requires("a", "b", "c"), requires("b", "c"), requires("c"))...)
	if got := c.IDs(); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("IDs = %v", got)
	}

	bad := map[string]struct {
		plugins []map[string]any
		want    string
	}{
		"unknown requirement": {uniquePorts(requires("a", "ghost")), "plugin a requires ghost, which is not in the catalog"},
		"cycle of two":        {uniquePorts(requires("a", "b"), requires("b", "a")), "the requirements form a cycle: a requires b requires a"},
		"cycle of three":      {uniquePorts(requires("a", "b"), requires("b", "c"), requires("c", "a")), "the requirements form a cycle: a requires b requires c requires a"},
		"cycle behind a root": {uniquePorts(requires("a", "b"), requires("b", "c"), requires("c", "b")), "the requirements form a cycle: a requires b requires c requires b"},
	}
	for why, b := range bad {
		_, err := LoadCatalog(writeCatalog(t, b.plugins...))
		if err == nil {
			t.Errorf("%s: the catalog loads", why)
			continue
		}
		if !strings.Contains(err.Error(), b.want) {
			t.Errorf("%s: %v, want something about %q", why, err, b.want)
		}
	}
}

func TestCatalogDirectoryRules(t *testing.T) {
	good := encode(t, basePlugin("a"))

	t.Run("files next to the plugins are ignored", func(t *testing.T) {
		dir := writeCatalog(t, basePlugin("a"))
		if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "a", "notes.txt"), []byte("hello"), 0o644); err != nil {
			t.Fatal(err)
		}
		c, err := LoadCatalog(dir)
		if err != nil || !reflect.DeepEqual(c.IDs(), []string{"a"}) {
			t.Fatalf("%v, %v", c, err)
		}
	})

	t.Run("an empty catalog loads", func(t *testing.T) {
		c, err := LoadCatalog(writeCatalog(t))
		if err != nil || len(c.IDs()) != 0 || len(c.Summary()) != 0 {
			t.Fatalf("%v, %v", c, err)
		}
	})

	refused := func(t *testing.T, dir, want string) {
		t.Helper()
		_, err := LoadCatalog(dir)
		if err == nil {
			t.Fatalf("the catalog loads, want an error about %q", want)
		}
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("%v, want something about %q", err, want)
		}
	}

	t.Run("missing directory", func(t *testing.T) {
		refused(t, filepath.Join(t.TempDir(), "missing"), "no such file")
	})
	t.Run("a file in place of the catalog", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "catalog")
		if err := os.WriteFile(path, good, 0o644); err != nil {
			t.Fatal(err)
		}
		refused(t, path, "is not a directory")
	})
	t.Run("a symbolic link in place of the catalog", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(writeCatalog(t, basePlugin("a")), link); err != nil {
			t.Fatal(err)
		}
		refused(t, link, "is not a directory")
	})
	t.Run("a directory that is not an id", func(t *testing.T) {
		dir := writeCatalog(t, basePlugin("a"))
		if err := os.Mkdir(filepath.Join(dir, "Not_An_Id"), 0o755); err != nil {
			t.Fatal(err)
		}
		refused(t, dir, "the directory name is not a plugin id")
	})
	t.Run("a directory without plugin.json", func(t *testing.T) {
		dir := writeCatalog(t, basePlugin("a"))
		if err := os.Mkdir(filepath.Join(dir, "b"), 0o755); err != nil {
			t.Fatal(err)
		}
		refused(t, dir, "plugin.json")
	})
	t.Run("compose.yaml missing", func(t *testing.T) {
		dir := writeCatalog(t, basePlugin("a"))
		if err := os.Remove(filepath.Join(dir, "a", ComposeFile)); err != nil {
			t.Fatal(err)
		}
		refused(t, dir, "compose.yaml")
	})
	t.Run("compose.yaml is a directory", func(t *testing.T) {
		dir := writeCatalog(t, basePlugin("a"))
		path := filepath.Join(dir, "a", ComposeFile)
		_ = os.Remove(path)
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
		refused(t, dir, "compose.yaml is not a regular file")
	})
	t.Run("compose.yaml is a symbolic link", func(t *testing.T) {
		dir := writeCatalog(t, basePlugin("a"))
		path := filepath.Join(dir, "a", ComposeFile)
		elsewhere := filepath.Join(t.TempDir(), "evil.yaml")
		if err := os.WriteFile(elsewhere, []byte("services: {}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(path)
		if err := os.Symlink(elsewhere, path); err != nil {
			t.Fatal(err)
		}
		refused(t, dir, "a symbolic link is not accepted")
	})
	t.Run("compose.yaml is a FIFO", func(t *testing.T) {
		dir := writeCatalog(t, basePlugin("a"))
		path := filepath.Join(dir, "a", ComposeFile)
		_ = os.Remove(path)
		if err := syscall.Mkfifo(path, 0o644); err != nil {
			t.Skipf("mkfifo: %v", err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := LoadCatalog(dir)
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("a FIFO in place of compose.yaml must be refused")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("LoadCatalog hangs on a FIFO")
		}
	})
	t.Run("plugin.json is a symbolic link", func(t *testing.T) {
		dir := writeCatalog(t, basePlugin("a"))
		path := filepath.Join(dir, "a", PluginFile)
		elsewhere := filepath.Join(t.TempDir(), "plugin.json")
		if err := os.WriteFile(elsewhere, good, 0o644); err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(path)
		if err := os.Symlink(elsewhere, path); err != nil {
			t.Fatal(err)
		}
		refused(t, dir, "a symbolic link is not accepted")
	})
	t.Run("a plugin directory is a symbolic link", func(t *testing.T) {
		real := writeCatalog(t, basePlugin("a"))
		dir := writeCatalog(t)
		if err := os.Symlink(filepath.Join(real, "a"), filepath.Join(dir, "a")); err != nil {
			t.Fatal(err)
		}
		refused(t, dir, "is a symbolic link")
	})
	t.Run("id differs from the directory", func(t *testing.T) {
		dir := writeCatalog(t)
		writePlugin(t, dir, "b", good)
		refused(t, dir, "id: must equal the directory name")
	})
	t.Run("one broken plugin refuses the catalog", func(t *testing.T) {
		dir := writeCatalog(t, basePlugin("a"))
		writePlugin(t, dir, "b", []byte(`{"schema": 1`))
		refused(t, dir, "not valid JSON")
	})
	t.Run("too many plugins", func(t *testing.T) {
		var plugins []map[string]any
		for i := 0; i <= MaxCatalogPlugins; i++ {
			plugins = append(plugins, basePlugin(fmt.Sprintf("p%02d", i)))
		}
		refused(t, writeCatalog(t, plugins...), "more than 32 plugins")
		if _, err := LoadCatalog(writeCatalog(t, plugins[:MaxCatalogPlugins]...)); err != nil {
			t.Fatalf("%d plugins must load: %v", MaxCatalogPlugins, err)
		}
	})
}

func TestLoadCatalogOwnedBy(t *testing.T) {
	dir := writeCatalog(t, basePlugin("a"), basePlugin("b"))
	c, err := LoadCatalogOwnedBy(dir, myUID())
	if err != nil || len(c.IDs()) != 2 {
		t.Fatalf("a catalog owned by the caller: %v", err)
	}
	if _, err := LoadCatalogOwnedBy(dir, myUID()+1); err == nil || !strings.Contains(err.Error(), "is not owned by uid") {
		t.Fatalf("a catalog owned by someone else: %v", err)
	}
	for _, target := range []string{"", "a", "b/plugin.json", "a/compose.yaml"} {
		for _, bits := range []os.FileMode{0o020, 0o002} {
			dir := writeCatalog(t, basePlugin("a"), basePlugin("b"))
			path := filepath.Join(dir, target)
			fi, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, fi.Mode().Perm()|bits); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadCatalogOwnedBy(dir, myUID()); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
				t.Errorf("%q with mode bits %04o added: %v", target, bits, err)
			}
			// The plain loader does not look at ownership or modes.
			if _, err := LoadCatalog(dir); err != nil {
				t.Errorf("LoadCatalog with %q writable: %v", target, err)
			}
		}
	}
}
