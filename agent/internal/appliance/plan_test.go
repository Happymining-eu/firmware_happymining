package appliance

import (
	"fmt"
	"reflect"
	"testing"
)

func planOf(t *testing.T, c *Catalog, mode string, plugins ...PluginConfig) []PluginStep {
	t.Helper()
	return Plan(&Document{Schema: 1, Revision: 1, Mode: mode, Plugins: plugins}, c)
}

func TestPlanForTheFixtureDocument(t *testing.T) {
	c := fixtureCatalog(t)
	parse := func(mode string) *Document {
		doc := fullDocument(t)
		doc["mode"] = mode
		parsed := mustAccept(t, c, mode, doc)
		if parsed == nil {
			t.FailNow()
		}
		return parsed
	}
	cases := []struct {
		mode string
		want []PluginStep
		gpu  []string
	}{
		{ModePrivateAI, []PluginStep{
			{ID: "ollama", Run: true, GPU: true},
			{ID: "qdrant", Run: true},
			{ID: "vectorizer", Run: true},
			{ID: "assistant", Run: true},
		}, []string{"ollama"}},
		// assistant does not list vectorize in its modes.
		{ModeVectorize, []PluginStep{
			{ID: "ollama", Run: true, GPU: true},
			{ID: "qdrant", Run: true},
			{ID: "vectorizer", Run: true},
			{ID: "assistant", Reason: ReasonMode},
		}, []string{"ollama"}},
		// In vast mode nothing runs, whatever is enabled.
		{ModeVast, []PluginStep{
			{ID: "ollama", Reason: ReasonMode, GPU: true},
			{ID: "qdrant", Reason: ReasonMode},
			{ID: "vectorizer", Reason: ReasonMode},
			{ID: "assistant", Reason: ReasonMode},
		}, nil},
	}
	for _, c2 := range cases {
		steps := Plan(parse(c2.mode), c)
		if !reflect.DeepEqual(steps, c2.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", c2.mode, steps, c2.want)
		}
		if got := GPUPlugins(steps); !reflect.DeepEqual(got, c2.gpu) {
			t.Errorf("%s: GPU plugins = %v, want %v", c2.mode, got, c2.gpu)
		}
	}
}

func TestPlanDependencyOrder(t *testing.T) {
	c := fixtureCatalog(t)
	ids := func(steps []PluginStep) []string {
		var out []string
		for _, s := range steps {
			out = append(out, s.ID)
		}
		return out
	}
	on := func(id string) PluginConfig { return PluginConfig{ID: id, Enabled: true} }
	off := func(id string) PluginConfig { return PluginConfig{ID: id} }

	// Requirements first, whatever the document's order; the catalog's
	// order of requirements (qdrant, then ollama) decides between them.
	steps := planOf(t, c, ModePrivateAI, on("assistant"), on("vectorizer"), on("qdrant"), on("ollama"))
	if got, want := ids(steps), []string{"ollama", "assistant", "qdrant", "vectorizer"}; !reflect.DeepEqual(got, want) {
		t.Errorf("order = %v, want %v", got, want)
	}
	for _, s := range steps {
		if !s.Run {
			t.Errorf("%s does not run: %s", s.ID, s.Reason)
		}
	}
	// Independent plugins keep the document's order.
	steps = planOf(t, c, ModePrivateAI, on("qdrant"), on("ollama"))
	if got, want := ids(steps), []string{"qdrant", "ollama"}; !reflect.DeepEqual(got, want) {
		t.Errorf("order = %v, want %v", got, want)
	}
	// Every requirement comes before its dependent, in every permutation.
	all := []PluginConfig{on("assistant"), on("vectorizer"), on("qdrant"), on("ollama")}
	permute(all, func(order []PluginConfig) {
		position := map[string]int{}
		for i, s := range planOf(t, c, ModePrivateAI, order...) {
			position[s.ID] = i
		}
		for _, id := range c.IDs() {
			entry, _ := c.Plugin(id)
			for _, req := range entry.Requires {
				if position[req] > position[id] {
					t.Errorf("document order %v: %s is planned before its requirement %s", order, id, req)
				}
			}
		}
		if len(position) != 4 {
			t.Errorf("document order %v: %d steps", order, len(position))
		}
	})

	// Disabled plugins are listed, in order, and do not run.
	steps = planOf(t, c, ModePrivateAI, off("assistant"), on("ollama"), off("qdrant"))
	want := []PluginStep{
		{ID: "ollama", Run: true, GPU: true},
		{ID: "assistant", Reason: ReasonDisabled},
		{ID: "qdrant", Reason: ReasonDisabled},
	}
	if !reflect.DeepEqual(steps, want) {
		t.Errorf("got %+v\nwant %+v", steps, want)
	}
	// "disabled" wins over "mode".
	steps = planOf(t, c, ModeVast, off("ollama"), on("qdrant"))
	want = []PluginStep{{ID: "ollama", Reason: ReasonDisabled, GPU: true}, {ID: "qdrant", Reason: ReasonMode}}
	if !reflect.DeepEqual(steps, want) {
		t.Errorf("got %+v\nwant %+v", steps, want)
	}
	if got := GPUPlugins(steps); got != nil {
		t.Errorf("GPU plugins in vast mode = %v", got)
	}

	// Documents ParseDocument would refuse do not make Plan start anything
	// it should not.
	steps = planOf(t, c, ModePrivateAI, on("assistant"))
	if want := []PluginStep{{ID: "assistant", Reason: ReasonRequirement}}; !reflect.DeepEqual(steps, want) {
		t.Errorf("a requirement that is absent: %+v", steps)
	}
	steps = planOf(t, c, ModePrivateAI, on("assistant"), off("ollama"))
	want = []PluginStep{{ID: "ollama", Reason: ReasonDisabled, GPU: true}, {ID: "assistant", Reason: ReasonRequirement}}
	if !reflect.DeepEqual(steps, want) {
		t.Errorf("a requirement that is disabled: %+v", steps)
	}
	steps = planOf(t, c, ModePrivateAI, on("ghost"), on("qdrant"), on("qdrant"))
	want = []PluginStep{{ID: "ghost", Reason: ReasonNotInCatalog}, {ID: "qdrant", Run: true}}
	if !reflect.DeepEqual(steps, want) {
		t.Errorf("an unknown and a repeated plugin: %+v", steps)
	}
	steps = planOf(t, c, "mining", on("qdrant"))
	if want := []PluginStep{{ID: "qdrant", Reason: ReasonMode}}; !reflect.DeepEqual(steps, want) {
		t.Errorf("an unknown mode: %+v", steps)
	}
	if Plan(nil, c) != nil || Plan(&Document{}, nil) != nil {
		t.Error("Plan without a document or a catalog must be empty")
	}
	if steps := planOf(t, c, ModePrivateAI); len(steps) != 0 {
		t.Errorf("a document without plugins: %+v", steps)
	}
}

// permute calls visit with every ordering of items.
func permute(items []PluginConfig, visit func([]PluginConfig)) {
	var rec func(k int)
	rec = func(k int) {
		if k == len(items) {
			visit(append([]PluginConfig(nil), items...))
			return
		}
		for i := k; i < len(items); i++ {
			items[k], items[i] = items[i], items[k]
			rec(k + 1)
			items[k], items[i] = items[i], items[k]
		}
	}
	rec(0)
}

// A plugin whose requirement does not run in the document's mode does not
// run either: it would start without what it needs.
func TestPlanRequirementThatDoesNotRunInThisMode(t *testing.T) {
	ui := set("ui", "modes", []any{"private_ai"})
	indexer := set("indexer", "modes", []any{"private_ai", "vectorize"})
	indexer["requires"] = []any{"ui"}
	top := set("top", "modes", []any{"private_ai", "vectorize"})
	top["requires"] = []any{"indexer"}
	top["gpu"] = true
	c := loadTemp(t, ui, indexer, top)
	raw := `{"schema":1,"revision":1,"mode":"%s","plugins":[{"id":"top","enabled":true},{"id":"indexer","enabled":true},{"id":"ui","enabled":true}]}`

	doc, err := ParseDocument([]byte(fmt.Sprintf(raw, ModeVectorize)), c)
	if err != nil {
		t.Fatal(err)
	}
	steps := Plan(doc, c)
	want := []PluginStep{
		{ID: "ui", Reason: ReasonMode},
		{ID: "indexer", Reason: ReasonRequirement},
		{ID: "top", Reason: ReasonRequirement, GPU: true},
	}
	if !reflect.DeepEqual(steps, want) {
		t.Errorf("vectorize:\n got %+v\nwant %+v", steps, want)
	}
	if got := GPUPlugins(steps); got != nil {
		t.Errorf("GPU plugins = %v", got)
	}

	doc, err = ParseDocument([]byte(fmt.Sprintf(raw, ModePrivateAI)), c)
	if err != nil {
		t.Fatal(err)
	}
	steps = Plan(doc, c)
	want = []PluginStep{{ID: "ui", Run: true}, {ID: "indexer", Run: true}, {ID: "top", Run: true, GPU: true}}
	if !reflect.DeepEqual(steps, want) {
		t.Errorf("private_ai:\n got %+v\nwant %+v", steps, want)
	}
	if got := GPUPlugins(steps); !reflect.DeepEqual(got, []string{"top"}) {
		t.Errorf("GPU plugins = %v", got)
	}
}

// No plugin runs in vast mode, even if a catalog entry claimed the mode.
// LoadCatalog refuses such an entry; this is the check behind it.
func TestNothingRunsInVastModeWhateverTheCatalogSays(t *testing.T) {
	rogue := &Plugin{ID: "rogue", Modes: []string{ModeVast, ModePrivateAI}, GPU: true}
	if rogue.RunsIn(ModeVast) {
		t.Fatal("RunsIn(vast) is true")
	}
	if !rogue.RunsIn(ModePrivateAI) {
		t.Fatal("RunsIn(private_ai) is false")
	}
	c := &Catalog{plugins: map[string]*Plugin{"rogue": rogue}, ids: []string{"rogue"}}
	steps := planOf(t, c, ModeVast, PluginConfig{ID: "rogue", Enabled: true})
	if want := []PluginStep{{ID: "rogue", Reason: ReasonMode, GPU: true}}; !reflect.DeepEqual(steps, want) {
		t.Fatalf("plan in vast mode = %+v", steps)
	}
	if got := GPUPlugins(steps); got != nil {
		t.Fatalf("GPU plugins in vast mode = %v", got)
	}
}
