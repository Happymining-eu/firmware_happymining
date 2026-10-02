package appliance

// Reasons a plugin of the document does not run (PluginStep.Reason).
const (
	// ReasonDisabled: the document says enabled: false.
	ReasonDisabled = "disabled"
	// ReasonMode: the mode is vast, or the catalog entry does not list the
	// document's mode.
	ReasonMode = "mode"
	// ReasonRequirement: a plugin it requires does not run. A validated
	// document only gets here when a requirement does not run in this mode.
	ReasonRequirement = "requirement"
	// ReasonNotInCatalog: the plugin is not in the catalog. ParseDocument
	// refuses such a document; this is for a document that outlived its
	// catalog.
	ReasonNotInCatalog = "not_in_catalog"
)

// PluginStep says what to do with one plugin of the document.
type PluginStep struct {
	ID string
	// Run: the plugin should be running. False: it should be stopped.
	Run bool
	// Reason is empty when Run is true and one of the Reason constants
	// otherwise.
	Reason string
	// GPU: the catalog entry says the plugin uses the GPUs. Before starting
	// such a plugin the helper applies the foreign-container guard of
	// section 2.
	GPU bool
}

// Plan lists every plugin of the document in dependency order, requirements
// first, and says for each whether it should run in the document's mode:
// start in this order, stop in the reverse order. Among plugins that do not
// depend on each other the document's order is kept.
//
// In vast mode nothing runs. In the other modes an enabled plugin runs when
// its catalog entry lists the mode and everything it requires runs.
//
// Plan decides what the document asks for. Whether the helper may act on it
// (its switches, the image pins, the foreign-container guard) is not decided
// here.
func Plan(doc *Document, c *Catalog) []PluginStep {
	if doc == nil || c == nil {
		return nil
	}
	configs := map[string]PluginConfig{}
	for _, cfg := range doc.Plugins {
		if _, dup := configs[cfg.ID]; !dup {
			configs[cfg.ID] = cfg
		}
	}
	var order []string
	visited := map[string]bool{}
	var visit func(id string)
	visit = func(id string) {
		if visited[id] {
			return
		}
		visited[id] = true
		if entry, ok := c.Plugin(id); ok {
			for _, req := range entry.Requires {
				if _, listed := configs[req]; listed {
					visit(req)
				}
			}
		}
		order = append(order, id)
	}
	for _, cfg := range doc.Plugins {
		visit(cfg.ID)
	}

	runs := map[string]bool{}
	steps := make([]PluginStep, 0, len(order))
	for _, id := range order {
		step := PluginStep{ID: id}
		entry, ok := c.Plugin(id)
		switch {
		case !ok:
			step.Reason = ReasonNotInCatalog
		case !configs[id].Enabled:
			step.Reason = ReasonDisabled
		case !entry.RunsIn(doc.Mode):
			step.Reason = ReasonMode
		default:
			for _, req := range entry.Requires {
				if !runs[req] {
					step.Reason = ReasonRequirement
				}
			}
		}
		if ok {
			step.GPU = entry.GPU
		}
		step.Run = step.Reason == ""
		runs[id] = step.Run
		steps = append(steps, step)
	}
	return steps
}

// GPUPlugins returns the ids of the steps that run and use the GPUs, in plan
// order: the plugins the foreign-container guard applies to.
func GPUPlugins(steps []PluginStep) []string {
	var ids []string
	for _, step := range steps {
		if step.Run && step.GPU {
			ids = append(ids, step.ID)
		}
	}
	return ids
}
