package appliance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func myUID() uint32 { return uint32(os.Getuid()) }

// contractExample returns the first ```json block after the given heading
// of docs/appliance.md, so that the tests follow the contract's own examples.
func contractExample(t *testing.T, heading string) string {
	t.Helper()
	data, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	at := strings.Index(text, "\n"+heading)
	if at < 0 {
		t.Fatalf("the contract has no heading %q", heading)
	}
	text = text[at:]
	start := strings.Index(text, "```json\n")
	if start < 0 {
		t.Fatalf("no JSON example after %q", heading)
	}
	text = text[start+len("```json\n"):]
	end := strings.Index(text, "```")
	if end < 0 {
		t.Fatalf("unterminated JSON example after %q", heading)
	}
	return text[:end]
}

// sealedSamples returns well-formed sealed values (the shared test vectors).
func sealedSamples(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(sealVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Vectors []struct {
			Sealed string `json:"sealed"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &v); err != nil || len(v.Vectors) == 0 {
		t.Fatalf("seal vectors: %v", err)
	}
	var out []string
	for _, vec := range v.Vectors {
		out = append(out, vec.Sealed)
	}
	return out
}

// tree decodes JSON into maps and lists, keeping numbers as written.
func tree(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func encode(t *testing.T, v any) []byte {
	t.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// fullDocument returns the "every section in use" fixture as a tree that a
// test may change before encoding it again.
func fullDocument(t *testing.T) map[string]any {
	t.Helper()
	for _, f := range loadFixtures(t, fixtureValidDir) {
		if f.file == "full.json" {
			return tree(t, f.raw)
		}
	}
	t.Fatal("valid/full.json is gone")
	return nil
}

// obj and list reach into a tree; they fail the test when the shape is not
// what the test expects.
func obj(t *testing.T, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("not an object: %T", v)
	}
	return m
}

func list(t *testing.T, v any) []any {
	t.Helper()
	l, ok := v.([]any)
	if !ok {
		t.Fatalf("not a list: %T", v)
	}
	return l
}

// mustRefuse checks that the document is refused with an error that
// mentions want.
func mustRefuse(t *testing.T, c *Catalog, why string, doc any, want string) {
	t.Helper()
	var raw []byte
	switch d := doc.(type) {
	case []byte:
		raw = d
	case string:
		raw = []byte(d)
	default:
		raw = encode(t, doc)
	}
	_, err := ParseDocument(raw, c)
	if err == nil {
		t.Errorf("%s: accepted, must be refused", why)
		return
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("%s: refused for another reason:\n  got  %v\n  want something about %q", why, err, want)
	}
}

func mustAccept(t *testing.T, c *Catalog, why string, doc any) *Document {
	t.Helper()
	parsed, err := ParseDocument(encode(t, doc), c)
	if err != nil {
		t.Errorf("%s: refused: %v", why, err)
		return nil
	}
	return parsed
}

// basePlugin returns a minimal valid plugin.json as a tree.
func basePlugin(id string) map[string]any {
	return map[string]any{
		"schema":   1,
		"id":       id,
		"version":  "1",
		"name":     "Test " + id,
		"summary":  "A test plugin.",
		"homepage": "https://example.invalid/" + id,
		"license":  "MIT",
		"gpu":      false,
		"modes":    []any{"private_ai", "vectorize"},
		"requires": []any{},
		"ports":    []any{map[string]any{"name": "api", "port": 8080, "protocol": "http", "ui": false}},
		"settings": map[string]any{},
		"secrets":  []any{},
		"images": []any{map[string]any{
			"ref": "docker.io/example/" + id + ":1.0.0", "digest": "sha256:" + strings.Repeat("a", 64), "verified": true,
		}},
		"volumes":    []any{map[string]any{"name": "data", "backup": "always"}},
		"post_start": []any{},
	}
}

// writeCatalog writes a catalog of the given plugin trees into a fresh
// directory and returns it.
func writeCatalog(t *testing.T, plugins ...map[string]any) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "catalog")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, plugin := range plugins {
		id, _ := plugin["id"].(string)
		writePlugin(t, dir, id, encode(t, plugin))
	}
	return dir
}

// writePlugin writes one catalog entry: plugin.json and a compose.yaml.
func writePlugin(t *testing.T, dir, name string, pluginJSON []byte) {
	t.Helper()
	pdir := filepath.Join(dir, name)
	if err := os.Mkdir(pdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pdir, PluginFile), pluginJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pdir, ComposeFile), []byte("services: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// loadTemp writes and loads a temporary catalog.
func loadTemp(t *testing.T, plugins ...map[string]any) *Catalog {
	t.Helper()
	c, err := LoadCatalog(writeCatalog(t, plugins...))
	if err != nil {
		t.Fatalf("the temporary catalog does not load: %v", err)
	}
	return c
}

// stringSetting, listSetting, intSetting, boolSetting and enumSetting build
// catalog settings for tests.
func stringSetting(env, pattern string, maxLen int, def string) map[string]any {
	return map[string]any{"type": "string", "label": "A string", "env": env, "pattern": pattern, "max_len": maxLen, "default": def}
}

func listSetting(env, pattern string, maxItems int, def ...any) map[string]any {
	if def == nil {
		def = []any{}
	}
	return map[string]any{"type": "string_list", "label": "A list", "env": env, "pattern": pattern, "max_items": maxItems, "default": def}
}

func intSetting(env string, min, max, def int) map[string]any {
	return map[string]any{"type": "int", "label": "A number", "env": env, "min": min, "max": max, "default": def}
}

func boolSetting(env string, def bool) map[string]any {
	return map[string]any{"type": "bool", "label": "A switch", "env": env, "default": def}
}

func enumSetting(env string, def string, values ...any) map[string]any {
	return map[string]any{"type": "enum", "label": "A choice", "env": env, "values": append([]any{}, values...), "default": def}
}

// mustCompile compiles a pattern without the safety checks of the catalog,
// for tests that build a Setting by hand.
func mustCompile(t *testing.T, pattern string) *regexp.Regexp {
	t.Helper()
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatal(err)
	}
	return re
}
