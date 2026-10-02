package appliance

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// envPlugin is a plugin with one setting of every type.
func envPlugin(t *testing.T) *Plugin {
	t.Helper()
	p := basePlugin("x")
	p["settings"] = map[string]any{
		"models":    listSetting("HM_SET_MODELS", `^[a-z0-9][a-z0-9._/-]{0,80}(:[A-Za-z0-9._-]{1,40})?$`, 4, "bge-m3"),
		"bind":      enumSetting("HM_SET_BIND", "lan", "lan", "localhost"),
		"workers":   intSetting("HM_SET_WORKERS", -2, 8, 2),
		"telemetry": boolSetting("HM_SET_TELEMETRY", false),
		"title":     stringSetting("HM_SET_TITLE", `^[A-Za-z0-9 .-]*$`, 20, "My server"),
	}
	p["post_start"] = []any{
		map[string]any{"service": "x", "exec": []any{"x", "pull", "{item}"}, "for_each": "models", "timeout_s": 3600},
		map[string]any{"service": "x-worker", "exec": []any{"x", "migrate"}, "timeout_s": 30},
		map[string]any{"service": "x", "exec": []any{"x", "warm", "--model={item}", "--tag={item}"}, "for_each": "models", "timeout_s": 60},
	}
	c := loadTemp(t, p)
	plugin, _ := c.Plugin("x")
	return plugin
}

func TestEnv(t *testing.T) {
	p := envPlugin(t)
	cases := map[string]struct {
		settings map[string]any
		want     []EnvVar
	}{
		"defaults": {nil, []EnvVar{
			{"HM_SET_BIND", "lan"}, {"HM_SET_MODELS", "bge-m3"}, {"HM_SET_TELEMETRY", "false"},
			{"HM_SET_TITLE", "My server"}, {"HM_SET_WORKERS", "2"},
		}},
		"empty map": {map[string]any{}, []EnvVar{
			{"HM_SET_BIND", "lan"}, {"HM_SET_MODELS", "bge-m3"}, {"HM_SET_TELEMETRY", "false"},
			{"HM_SET_TITLE", "My server"}, {"HM_SET_WORKERS", "2"},
		}},
		"typed values": {map[string]any{
			"models": []string{"hermes3:8b", "bge-m3", "library/x:1.5"}, "bind": "localhost", "workers": int64(-2),
			"telemetry": true, "title": "",
		}, []EnvVar{
			{"HM_SET_BIND", "localhost"}, {"HM_SET_MODELS", "hermes3:8b bge-m3 library/x:1.5"}, {"HM_SET_TELEMETRY", "true"},
			{"HM_SET_TITLE", ""}, {"HM_SET_WORKERS", "-2"},
		}},
		"values as JSON gives them": {map[string]any{
			"models": []any{"a", "b"}, "workers": json.Number("8"),
		}, []EnvVar{
			{"HM_SET_BIND", "lan"}, {"HM_SET_MODELS", "a b"}, {"HM_SET_TELEMETRY", "false"},
			{"HM_SET_TITLE", "My server"}, {"HM_SET_WORKERS", "8"},
		}},
		"an empty list and a plain int": {map[string]any{"models": []string{}, "workers": 3}, []EnvVar{
			{"HM_SET_BIND", "lan"}, {"HM_SET_MODELS", ""}, {"HM_SET_TELEMETRY", "false"},
			{"HM_SET_TITLE", "My server"}, {"HM_SET_WORKERS", "3"},
		}},
	}
	for why, c := range cases {
		got, err := p.Env(c.settings)
		if err != nil {
			t.Errorf("%s: %v", why, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got %v\nwant %v", why, got, c.want)
		}
	}
	// The order does not depend on map iteration.
	first, _ := p.Env(nil)
	for i := 0; i < 50; i++ {
		if again, _ := p.Env(nil); !reflect.DeepEqual(first, again) {
			t.Fatal("Env is not deterministic")
		}
	}

	bad := map[string]struct {
		settings map[string]any
		want     string
	}{
		"unknown setting":           {map[string]any{"command": "x"}, `unknown setting "command"`},
		"bool as a string":          {map[string]any{"telemetry": "true"}, "setting telemetry must be true or false"},
		"bool as a number":          {map[string]any{"telemetry": 1}, "setting telemetry must be true or false"},
		"int as a string":           {map[string]any{"workers": "2"}, "setting workers must be an integer"},
		"int as a float":            {map[string]any{"workers": 2.0}, "setting workers must be an integer"},
		"int as a bool":             {map[string]any{"workers": true}, "setting workers must be an integer"},
		"int as a fraction literal": {map[string]any{"workers": json.Number("2.0")}, "setting workers must be an integer"},
		"int above max":             {map[string]any{"workers": 9}, "setting workers must be -2 to 8"},
		"int below min":             {map[string]any{"workers": int64(-3)}, "setting workers must be -2 to 8"},
		"enum outside":              {map[string]any{"bind": "public"}, "setting bind must be one of"},
		"enum as a list":            {map[string]any{"bind": []string{"lan"}}, "setting bind must be a string"},
		"string too long":           {map[string]any{"title": strings.Repeat("a", 21)}, "setting title is longer than 20 characters"},
		"string against pattern":    {map[string]any{"title": "a_b"}, "setting title does not match the pattern"},
		"string as a number":        {map[string]any{"title": 1}, "setting title must be a string"},
		"string nil":                {map[string]any{"title": nil}, "setting title must be a string"},
		"list as a string":          {map[string]any{"models": "a b"}, "setting models must be a list of strings"},
		"list too long":             {map[string]any{"models": []string{"a", "b", "c", "d", "e"}}, "setting models has more than 4 items"},
		"list item against pattern": {map[string]any{"models": []string{"ok", "Not"}}, "setting models item 1 does not match the pattern"},
		"list item not a string":    {map[string]any{"models": []any{"ok", 1}}, "setting models item 1 must be a string"},
		"list item empty":           {map[string]any{"models": []string{""}}, "setting models item 0 is empty"},
		"list item with a space":    {map[string]any{"models": []string{"a b"}}, "setting models item 0 contains a character that is not allowed"},
	}
	for why, c := range bad {
		got, err := p.Env(c.settings)
		if err == nil {
			t.Errorf("%s: accepted: %v", why, got)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want something about %q", why, err, c.want)
		}
	}
}

// Whatever a pattern allows, Env never produces a value with a character
// that would need quoting. The settings here are built by hand with patterns
// that compilePattern would refuse, to test the checks behind it.
func TestEnvNeverProducesAnUnsafeValue(t *testing.T) {
	anything := mustCompile(t, `(?s)^.*$`)
	p := &Plugin{ID: "x", Settings: map[string]*Setting{
		"text": {Name: "text", Type: SettingString, Env: "HM_SET_TEXT", Default: "", MaxLen: 200, Pattern: `(?s)^.*$`, re: anything},
		"list": {Name: "list", Type: SettingStringList, Env: "HM_SET_LIST", Default: []string{}, MaxItems: 8, Pattern: `(?s)^.*$`, re: anything},
		"enum": {Name: "enum", Type: SettingEnum, Env: "HM_SET_ENUM", Default: "ok", Values: []string{"ok", "$(reboot)", "a\nb"}},
	}}
	if _, err := p.Env(nil); err != nil {
		t.Fatalf("the defaults: %v", err)
	}
	forbidden := []string{"\n", "\r", "\x00", "\t", "\x1b", "\x7f", `"`, `'`, `$`, "`", `\`}
	for _, f := range forbidden {
		for _, value := range []string{f, "a" + f + "b", "$(reboot)" + f, f + f} {
			if got, err := p.Env(map[string]any{"text": value}); err == nil {
				t.Errorf("string %q gives %v", value, got)
			}
			if got, err := p.Env(map[string]any{"list": []string{"ok", value}}); err == nil {
				t.Errorf("list item %q gives %v", value, got)
			}
		}
	}
	for _, value := range []string{"$(reboot)", "a\nb"} {
		if got, err := p.Env(map[string]any{"enum": value}); err == nil {
			t.Errorf("enum value %q gives %v", value, got)
		}
	}
	if got, err := p.Env(map[string]any{"text": "a\xffb"}); err == nil {
		t.Errorf("invalid UTF-8 gives %v", got)
	}
	if got, err := p.Env(map[string]any{"list": []string{"a b"}}); err == nil {
		t.Errorf("a list item with a space gives %v", got)
	}
	// Harmless values still pass, so the refusals above mean something.
	got, err := p.Env(map[string]any{"text": "a b=c #d", "list": []string{"x", "y"}})
	if err != nil {
		t.Fatal(err)
	}
	want := []EnvVar{{"HM_SET_ENUM", "ok"}, {"HM_SET_LIST", "x y"}, {"HM_SET_TEXT", "a b=c #d"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestPostStartCommands(t *testing.T) {
	p := envPlugin(t)
	got, err := p.PostStartCommands(map[string]any{"models": []string{"hermes3:8b", "bge-m3"}})
	if err != nil {
		t.Fatal(err)
	}
	want := []Command{
		{Service: "x", Argv: []string{"x", "pull", "hermes3:8b"}, Timeout: time.Hour},
		{Service: "x", Argv: []string{"x", "pull", "bge-m3"}, Timeout: time.Hour},
		{Service: "x-worker", Argv: []string{"x", "migrate"}, Timeout: 30 * time.Second},
		{Service: "x", Argv: []string{"x", "warm", "--model=hermes3:8b", "--tag=hermes3:8b"}, Timeout: time.Minute},
		{Service: "x", Argv: []string{"x", "warm", "--model=bge-m3", "--tag=bge-m3"}, Timeout: time.Minute},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("commands:\n got %+v\nwant %+v", got, want)
	}
	// The default list is used when the setting is not given, and an empty
	// list gives no command for its entries.
	got, err = p.PostStartCommands(nil)
	if err != nil || len(got) != 3 || got[0].Argv[2] != "bge-m3" {
		t.Fatalf("with defaults: %+v, %v", got, err)
	}
	got, err = p.PostStartCommands(map[string]any{"models": []string{}})
	if err != nil || len(got) != 1 || got[0].Service != "x-worker" {
		t.Fatalf("with an empty list: %+v, %v", got, err)
	}
	// The catalog's argv is not shared with the caller.
	got[0].Argv[0] = "changed"
	if p.PostStart[1].Exec[0] != "x" {
		t.Fatal("PostStartCommands exposes the catalog's own slice")
	}
	if _, err := p.PostStartCommands(map[string]any{"models": []string{"a; reboot"}}); err == nil {
		t.Fatal("invalid settings must be refused")
	}
	if _, err := p.PostStartCommands(map[string]any{"nope": 1}); err == nil {
		t.Fatal("unknown settings must be refused")
	}

	// An item that looks like an option never reaches a command line.
	dashes := &Plugin{ID: "y", Settings: map[string]*Setting{
		"items": {Name: "items", Type: SettingStringList, Env: "HM_SET_ITEMS", Default: []string{}, MaxItems: 4,
			Pattern: `^[a-z-]+$`, re: mustCompile(t, `^[a-z-]+$`)},
	}, PostStart: []PostStart{{Service: "y", Exec: []string{"tool", "{item}"}, ForEach: "items", TimeoutS: 5}}}
	if got, err := dashes.PostStartCommands(map[string]any{"items": []string{"ok", "--privileged"}}); err == nil {
		t.Fatalf("an item starting with a dash gives %+v", got)
	}
	if _, err := dashes.PostStartCommands(map[string]any{"items": []string{"ok", "also-ok"}}); err != nil {
		t.Fatal(err)
	}
}

func TestSettingCheckReturnsCanonicalTypes(t *testing.T) {
	p := envPlugin(t)
	cases := []struct {
		setting string
		in      any
		want    any
	}{
		{"telemetry", true, true},
		{"workers", 3, int64(3)},
		{"workers", int64(3), int64(3)},
		{"workers", json.Number("3"), int64(3)},
		{"workers", json.Number("-0"), int64(0)},
		{"bind", "lan", "lan"},
		{"title", "A b", "A b"},
		{"models", []any{"a"}, []string{"a"}},
		{"models", []string{"a"}, []string{"a"}},
		{"models", []any{}, []string{}},
	}
	for _, c := range cases {
		got, err := p.Settings[c.setting].Check(c.in)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: Check(%#v) = %#v, %v; want %#v", c.setting, c.in, got, err, c.want)
		}
	}
	for _, in := range []any{json.Number("3.0"), json.Number("1e0"), json.Number("03"), json.Number("+3"), json.Number(""),
		json.Number("99999999999999999999"), 3.0, float32(3), uint(3), "3", nil} {
		if got, err := p.Settings["workers"].Check(in); err == nil {
			t.Errorf("workers: Check(%#v) = %#v, want an error", in, got)
		}
	}
	if _, err := (&Setting{Type: "path"}).Check("x"); err == nil {
		t.Error("a setting of an unknown type must refuse every value")
	}
}

func TestEnvSafe(t *testing.T) {
	for _, ok := range []string{"", "a", "hermes3:8b", "a b", "x=y #z", "é😀", "a/b.c-d_e:f,g;h(i)[j]{k}<l>|m&n*o?p!q~r%s^t+u@v"} {
		if !envSafe(ok, false) {
			t.Errorf("%q must be safe", ok)
		}
	}
	for _, bad := range []string{"\n", "a\nb", "\r", "\x00", "\t", "\x1f", "\x7f", `"`, `'`, `$`, "`", `\`, "a$b", "$(x)", "a\xffb"} {
		if envSafe(bad, false) {
			t.Errorf("%q must not be safe", bad)
		}
		if envSafe(bad, true) {
			t.Errorf("%q must not be safe in a list", bad)
		}
	}
	if envSafe("a b", true) || !envSafe("a-b", true) {
		t.Error("a list item must not contain a space")
	}
}
