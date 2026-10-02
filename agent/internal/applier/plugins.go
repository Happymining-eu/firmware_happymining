package applier

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/appliance"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/seal"
)

// Values the vectorizer's configuration needs (appliance/vectorizer,
// hm_vectorizer/config.py): the NAS root as the container sees it (its
// Compose file mounts the host's /srv/happymining/nas there), and the
// addresses of the ollama and qdrant services on the hm-appliance network.
const (
	containerNASRoot     = "/srv/happymining/nas"
	vectorizerOllamaURL  = "http://ollama:11434"
	vectorizerQdrantURL  = "http://qdrant:6333"
	vectorizerCollection = "happymining_docs"
	vectorizerAPIKeyEnv  = "HM_ANSWER_API_KEY"
)

// Bind addresses (HM_BIND).
const (
	bindLAN       = "0.0.0.0"
	bindLocalhost = "127.0.0.1"
)

// post_start retries: a service is often not ready to take a command right
// after `up -d`.
var postStartWaits = []time.Duration{10 * time.Second, 30 * time.Second}

const defaultPostStartTimeout = 10 * time.Minute

// pluginOutcome is the result of the plugin step.
type pluginOutcome struct {
	Failed   []string
	Blocked  []string
	Disabled bool
}

func catalogPorts(entry *appliance.Plugin) []int {
	ports := []int{}
	if entry == nil {
		return ports
	}
	for _, p := range entry.Ports {
		ports = append(ports, p.Port)
	}
	return ports
}

// recordPlugin stores the outcome of the apply for one plugin.
func (e *Env) recordPlugin(id string, entry *appliance.Plugin, desired bool, state, detail string, started *bool) {
	detail = clipText(detail, 400)
	_, _ = e.updateState(func(st *State) {
		r := st.plugin(id)
		r.Desired, r.ApplyState, r.ApplyDetail = desired, state, detail
		if entry != nil {
			r.Version = entry.Version
		}
		r.Ports = catalogPorts(entry)
		r.GuardBlocked = false
		if started != nil {
			r.Started = *started
		}
		if state != appliance.PluginStarting && state != appliance.PluginRunning {
			r.Observed, r.ObservedDetail = "", ""
		}
	})
}

func boolPtr(b bool) *bool { return &b }

// down takes a plugin's Compose project down (never with -v).
func (e *Env) down(ctx context.Context, id string) cmdResult {
	return e.docker(ctx, timeoutComposeDown, argvComposeDown(id)...)
}

// applyPlugins brings the plugins to what the document asks for.
func (e *Env) applyPlugins(ctx context.Context, eff *effective, op *opener) pluginOutcome {
	var out pluginOutcome
	doc, cat := eff.Doc, eff.Catalog
	steps := appliance.Plan(doc, cat)
	st, err := e.loadState()
	if err != nil {
		out.Failed = append(out.Failed, "plugins: "+err.Error())
		return out
	}
	if !e.Switches.AllowPlugins {
		// Starting a plugin needs the switch; stopping one that HappyMining
		// started earlier, while the switch was on, does not. A plugin the
		// document no longer runs (vast mode above all) must not keep running
		// because the switch went off at the same time; and the state must
		// not say "stopped" while it runs. Only HappyMining's own Compose
		// projects (hm-<id>) are touched. A plugin the document still runs is
		// left as it is: with the switch off HappyMining neither starts nor
		// stops it.
		started := map[string]bool{}
		for _, rec := range st.Plugins {
			if rec.Started && ValidID(rec.ID) {
				started[rec.ID] = true
			}
		}
		stop := func(id string) (string, string) {
			if !e.hasDocker() {
				return appliance.PluginError, "started earlier and not stopped: Docker is not available"
			}
			if res := e.down(ctx, id); !res.ok {
				out.Failed = append(out.Failed, "plugin "+id+" could not be stopped")
				return appliance.PluginError, "could not be stopped: " + res.describe(op.scrub)
			}
			return appliance.PluginStopped, ""
		}
		inDoc := map[string]bool{}
		for i := len(steps) - 1; i >= 0; i-- {
			step := steps[i]
			inDoc[step.ID] = true
			entry, _ := cat.Plugin(step.ID)
			state, detail := appliance.PluginStopped, ""
			var startedNow *bool
			switch {
			case step.Run && started[step.ID]:
				state, detail = appliance.PluginBlocked, "plugins are not managed while ALLOW_PLUGINS is off in helper.conf; "+
					"the plugin started earlier is left as it is"
				out.Disabled = true
			case step.Run:
				state, detail = appliance.PluginBlocked, "starting plugins is disabled in helper.conf (ALLOW_PLUGINS)"
				out.Disabled = true
			case started[step.ID]:
				state, detail = stop(step.ID)
				if state == appliance.PluginStopped {
					startedNow = boolPtr(false)
				}
			}
			e.recordPlugin(step.ID, entry, step.Run, state, detail, startedNow)
		}
		for _, rec := range st.Plugins {
			if inDoc[rec.ID] || !started[rec.ID] {
				continue
			}
			id := rec.ID
			if state, _ := stop(id); state == appliance.PluginStopped {
				_, _ = e.updateState(func(s *State) { s.dropPlugin(id) })
			}
		}
		return out
	}
	if !e.hasDocker() {
		for _, step := range steps {
			entry, _ := cat.Plugin(step.ID)
			if step.Run {
				e.recordPlugin(step.ID, entry, true, appliance.PluginError, "Docker is not installed on this machine", nil)
				out.Failed = append(out.Failed, "plugin "+step.ID+": Docker is not installed")
			} else {
				e.recordPlugin(step.ID, entry, false, appliance.PluginStopped, "", nil)
			}
		}
		return out
	}

	// 1. Stop what must not run: plugins that left the document first, then
	// the document's plugins that do not run, in reverse plan order.
	inDoc := map[string]bool{}
	for _, step := range steps {
		inDoc[step.ID] = true
	}
	for _, rec := range st.Plugins {
		if inDoc[rec.ID] || !ValidID(rec.ID) {
			continue
		}
		id := rec.ID
		if res := e.down(ctx, id); !res.ok {
			out.Failed = append(out.Failed, "removed plugin "+id+" could not be stopped: "+res.describe(op.scrub))
			continue
		}
		_, _ = e.updateState(func(s *State) { s.dropPlugin(id) })
	}
	for i := len(steps) - 1; i >= 0; i-- {
		step := steps[i]
		if step.Run {
			continue
		}
		entry, _ := cat.Plugin(step.ID)
		state, detail := appliance.PluginStopped, ""
		switch step.Reason {
		case appliance.ReasonMode:
			state, detail = appliance.PluginBlocked, "does not run in mode "+doc.Mode
			if doc.Mode == appliance.ModeVast {
				detail = "no plugin runs in vast mode"
			}
		case appliance.ReasonRequirement:
			state, detail = appliance.PluginBlocked, "a plugin it requires does not run in this mode"
		case appliance.ReasonNotInCatalog:
			state, detail = appliance.PluginNotInCatalog, "not in the installed catalog"
		}
		if res := e.down(ctx, step.ID); !res.ok {
			state, detail = appliance.PluginError, "could not be stopped: "+res.describe(op.scrub)
			out.Failed = append(out.Failed, "plugin "+step.ID+" could not be stopped")
			e.recordPlugin(step.ID, entry, false, state, detail, nil)
			continue
		}
		e.recordPlugin(step.ID, entry, false, state, detail, boolPtr(false))
	}
	if doc.Mode == appliance.ModeVast {
		return out
	}

	// 2. The shared network.
	var anyRun bool
	for _, step := range steps {
		anyRun = anyRun || step.Run
	}
	if !anyRun {
		return out
	}
	if netErr := e.ensureNetwork(ctx); netErr != "" {
		_, _ = e.updateState(func(s *State) { s.NetworkDetail = netErr })
		for _, step := range steps {
			if step.Run {
				entry, _ := cat.Plugin(step.ID)
				e.recordPlugin(step.ID, entry, true, appliance.PluginError, "the plugin network "+NetworkName+" is not available: "+netErr, nil)
				out.Failed = append(out.Failed, "plugin "+step.ID+": no plugin network")
			}
		}
		return out
	}
	_, _ = e.updateState(func(s *State) { s.NetworkDetail = "" })

	// 3. Start what must run, requirements first.
	foreign, foreignErr, foreignChecked := 0, error(nil), false
	running := map[string]bool{}
	configs := map[string]appliance.PluginConfig{}
	for _, c := range doc.Plugins {
		configs[c.ID] = c
	}
	for _, step := range steps {
		if !step.Run {
			continue
		}
		entry, ok := cat.Plugin(step.ID)
		if !ok {
			continue
		}
		block := func(detail string, guard bool) {
			if res := e.down(ctx, step.ID); !res.ok {
				detail += "; it could not be stopped: " + res.describe(op.scrub)
			}
			e.recordPlugin(step.ID, entry, true, appliance.PluginBlocked, detail, boolPtr(false))
			if guard {
				id := step.ID
				_, _ = e.updateState(func(s *State) { s.plugin(id).GuardBlocked = true })
			}
			out.Blocked = append(out.Blocked, step.ID)
		}
		missing := ""
		for _, req := range entry.Requires {
			if !running[req] {
				missing = req
				break
			}
		}
		if missing != "" {
			e.recordPlugin(step.ID, entry, true, appliance.PluginError, "the plugin it requires, "+missing+", did not start", nil)
			out.Failed = append(out.Failed, "plugin "+step.ID+": requirement "+missing+" did not start")
			continue
		}
		if !entry.ImagesVerified() && !e.Switches.AllowUnpinnedImages {
			block("an image of this plugin is not pinned to a verified digest, and helper.conf does not allow unpinned images (ALLOW_UNPINNED_IMAGES)", false)
			continue
		}
		if step.GPU && !e.Switches.AllowForeignContainers {
			if !foreignChecked {
				foreign, foreignErr = e.foreignContainers(ctx)
				foreignChecked = true
			}
			if foreignErr != nil {
				block("uses the GPUs, and whether containers HappyMining did not start are running cannot be told, so it is not started", true)
				continue
			}
			if foreign > 0 {
				// A guard, not a proof of safety: see foreignContainers.
				block(fmt.Sprintf("uses the GPUs while %d container(s) HappyMining did not start are running (ALLOW_FOREIGN_CONTAINERS is off); this guard is not a proof that no rental is affected", foreign), true)
				continue
			}
		}
		state, detail, upOK := e.startPlugin(ctx, eff, entry, configs[step.ID], op)
		if state == appliance.PluginError {
			out.Failed = append(out.Failed, "plugin "+step.ID+": "+detail)
		}
		if upOK {
			running[step.ID] = true
			e.recordPlugin(step.ID, entry, true, state, detail, boolPtr(true))
		} else {
			e.recordPlugin(step.ID, entry, true, state, detail, nil)
		}
	}
	return out
}

const postStartPrefix = "started, but post-start command "

// ensureNetwork makes sure the shared plugin network exists. It returns ""
// or what went wrong.
func (e *Env) ensureNetwork(ctx context.Context) string {
	if res := e.docker(ctx, timeoutDockerQuick, argvNetworkInspect()...); res.ok {
		return ""
	}
	if res := e.docker(ctx, timeoutDockerQuick, argvNetworkCreate()...); !res.ok {
		return res.describe(nil)
	}
	return ""
}

// startPlugin writes the env file (and the vectorizer's configuration),
// builds the image when it is built on the machine and missing, runs
// `compose up -d` and the post_start commands. It returns the plugin state,
// a detail, and whether `up -d` succeeded.
func (e *Env) startPlugin(ctx context.Context, eff *effective, entry *appliance.Plugin, cfg appliance.PluginConfig, op *opener) (string, string, bool) {
	id := entry.ID
	if err := ensureDirs(0o700, e.OwnerUID, e.Paths.PluginDataRoot, e.Paths.pluginData(id)); err != nil {
		return appliance.PluginError, "the plugin data directory cannot be used: " + err.Error(), false
	}
	restart := false
	if id == vectorizerPlugin {
		changed, err := e.writeVectorizerConfig(eff.Doc)
		if err != nil {
			return appliance.PluginError, "the vectorizer configuration cannot be written: " + err.Error(), false
		}
		restart = changed
	}
	if detail := e.writeEnvFile(eff, entry, cfg, op); detail != "" {
		return appliance.PluginError, detail, false
	}
	if entry.Build != nil {
		if res := e.docker(ctx, timeoutDockerQuick, argvImageInspect(entry.Build.Image)...); !res.ok {
			context := filepath.Join(e.Paths.BuildRoot, entry.Build.Context)
			if err := checkRealDir(context); err != nil {
				return appliance.PluginError, "the build context of the image is missing", false
			}
			if res := e.docker(ctx, timeoutBuild, argvBuild(entry.Build.Image, context)...); !res.ok {
				return appliance.PluginError, "the image could not be built: " + res.describe(op.scrub), false
			}
		}
	}
	res := e.docker(ctx, timeoutComposeUp, argvComposeUp(id, e.Paths.envFile(id), entry.ComposePath())...)
	if !res.ok {
		return appliance.PluginError, "docker compose up failed: " + res.describe(op.scrub), false
	}
	if restart {
		// `up -d` does not recreate a running container whose bind-mounted
		// configuration changed; the vectorizer reads it only at start.
		if res := e.docker(ctx, timeoutComposeUp, argvComposeRestart(id)...); !res.ok {
			return appliance.PluginError, "the vectorizer could not be restarted with its new configuration: " +
				res.describe(op.scrub), true
		}
	}
	cmds, err := entry.PostStartCommands(cfg.Settings)
	if err != nil {
		return appliance.PluginError, postStartPrefix + "list is not valid: " + err.Error(), true
	}
	for i, c := range cmds {
		timeout := c.Timeout
		if timeout <= 0 {
			timeout = defaultPostStartTimeout
		}
		var last cmdResult
		for attempt := 0; ; attempt++ {
			last = e.docker(ctx, timeout, argvComposeExec(id, c.Service, c.Argv)...)
			if last.ok || attempt >= len(postStartWaits) || ctx.Err() != nil {
				break
			}
			e.sleep(postStartWaits[attempt])
		}
		if !last.ok {
			return appliance.PluginError, fmt.Sprintf("%s%d of %d (service %s) failed: %s", postStartPrefix, i+1, len(cmds),
				c.Service, last.describe(op.scrub)), true
		}
	}
	return appliance.PluginStarting, "", true
}

// bindAddress is HM_BIND for a plugin: 0.0.0.0 when its "bind" setting is
// "lan" or it has none, 127.0.0.1 for "localhost" (and, to fail closed, for
// any other value).
func bindAddress(entry *appliance.Plugin, cfg appliance.PluginConfig) string {
	if _, has := entry.Settings["bind"]; !has {
		return bindLAN
	}
	v, _ := cfg.Settings["bind"].(string)
	if v == "" {
		if s := entry.Settings["bind"]; s != nil {
			v, _ = s.Default.(string)
		}
	}
	if v == "lan" {
		return bindLAN
	}
	return bindLocalhost
}

// writeEnvFile writes plugins/<id>.env: the settings (Plugin.Env), HM_BIND,
// HM_PLUGIN_DATA and the opened secrets. Each plaintext is wiped as soon as
// it is in the buffer, and the buffer once the file is written. It returns
// "" or the problem.
func (e *Env) writeEnvFile(eff *effective, entry *appliance.Plugin, cfg appliance.PluginConfig, op *opener) string {
	f := newEnvFile()
	defer f.wipe()
	vars, err := entry.Env(cfg.Settings)
	if err != nil {
		return "the settings cannot be passed: " + err.Error()
	}
	for _, v := range vars {
		if err := f.add(v.Name, v.Value); err != nil {
			return err.Error()
		}
	}
	if err := f.add("HM_BIND", bindAddress(entry, cfg)); err != nil {
		return err.Error()
	}
	if err := f.add("HM_PLUGIN_DATA", e.Paths.pluginData(entry.ID)); err != nil {
		return err.Error()
	}
	addSecret := func(name, env string, required bool) string {
		plain, err := op.open(name)
		if err == errSecretMissing && !required {
			return ""
		}
		if err != nil {
			// An optional secret that exists but does not open is an error
			// too: starting without it could start the plugin without the
			// protection it was meant to have.
			return "secret " + name + " is " + err.Error()
		}
		aerr := f.addSecret(env, plain)
		seal.Wipe(plain)
		if aerr != nil {
			return "secret " + name + " cannot be passed to the container: " + aerr.Error()
		}
		return ""
	}
	for _, s := range entry.Secrets {
		if p := addSecret(entry.SecretName(s.Key), s.Env, s.Required); p != "" {
			return p
		}
	}
	if entry.ID == vectorizerPlugin && eff.Doc.Vectorizer != nil && eff.Doc.Vectorizer.Answer.Secret != "" {
		if p := addSecret(eff.Doc.Vectorizer.Answer.Secret, vectorizerAPIKeyEnv, true); p != "" {
			return p
		}
	}
	if err := e.ensureStateDir(); err != nil {
		return "the env file cannot be written"
	}
	if err := writeFile(e.Paths.pluginsEnvDir(), entry.ID+".env", f.buf, 0o600); err != nil {
		return "the env file cannot be written"
	}
	return ""
}

// vectorizerFile is vectorizer.json: the document's vectorizer object plus
// the runtime keys hm_vectorizer/config.py requires.
type vectorizerFile struct {
	Sources        []string          `json:"sources"`
	Extensions     []string          `json:"extensions"`
	Exclude        []string          `json:"exclude"`
	MaxFileMiB     int               `json:"max_file_mib"`
	EmbeddingModel string            `json:"embedding_model"`
	OCR            bool              `json:"ocr"`
	Answer         appliance.Answer  `json:"answer"`
	SourcePaths    map[string]string `json:"source_paths"`
	OllamaURL      string            `json:"ollama_url"`
	QdrantURL      string            `json:"qdrant_url"`
	Collection     string            `json:"collection"`
}

// Modes of the vectorizer's configuration: the directory and files belong to
// root and to the group the container runs as, which may read them and
// nothing more. The container never runs as root.
const (
	vectorizerConfigDirMode  = 0o750
	vectorizerConfigFileMode = 0o640
)

// ensureVectorizerConfigDir creates the plugin's data directory (root only)
// and its config directory (readable by the container's group).
func (e *Env) ensureVectorizerConfigDir() (string, error) {
	dir := e.Paths.vectorizerConfigDir()
	if err := ensureDirs(0o700, e.OwnerUID, e.Paths.PluginDataRoot, e.Paths.pluginData(vectorizerPlugin)); err != nil {
		return "", err
	}
	if err := ensureGroupDir(dir, vectorizerConfigDirMode, e.OwnerUID, e.vectorizerGID()); err != nil {
		return "", err
	}
	return dir, nil
}

// writeVectorizerConfig writes config/vectorizer.json (no secret) and
// creates config/token when it is missing or not a valid token. It reports
// whether vectorizer.json changed: the vectorizer reads it only when it
// starts, so a running container must then be restarted.
func (e *Env) writeVectorizerConfig(doc *appliance.Document) (bool, error) {
	if doc.Vectorizer == nil {
		return false, fmt.Errorf("the document has no vectorizer section")
	}
	dir, err := e.ensureVectorizerConfigDir()
	if err != nil {
		return false, err
	}
	v := doc.Vectorizer
	f := vectorizerFile{
		Sources: v.Sources, Extensions: v.Extensions, Exclude: v.Exclude, MaxFileMiB: v.MaxFileMiB,
		EmbeddingModel: v.EmbeddingModel, OCR: v.OCR, Answer: v.Answer,
		SourcePaths: map[string]string{}, OllamaURL: vectorizerOllamaURL, QdrantURL: vectorizerQdrantURL,
		Collection: vectorizerCollection,
	}
	if f.Exclude == nil {
		f.Exclude = []string{}
	}
	for _, id := range v.Sources {
		if !ValidID(id) {
			return false, fmt.Errorf("source %s is not a valid id", id)
		}
		// The NAS entry's subpath is part of what is mounted, so a source is
		// its mount point.
		f.SourcePaths[id] = containerNASRoot + "/" + id
	}
	data, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		return false, err
	}
	data = append(data, '\n')
	previous, readErr := readFile(filepath.Join(dir, vectorizerJSON), maxVectorizerConfigBytes, &e.OwnerUID)
	// Restart only a container that may have read an older configuration:
	// when there was none, the container has not started with one.
	changed := readErr == nil && !bytes.Equal(previous, data)
	if err := writeGroupFile(dir, vectorizerJSON, data, vectorizerConfigFileMode, e.OwnerUID, e.vectorizerGID()); err != nil {
		return false, err
	}
	_, err = e.ensureVectorizerToken()
	return changed, err
}

// hasModeAndGroup reports whether path is a regular file with exactly mode
// and group gid.
func hasModeAndGroup(path string, mode os.FileMode, gid int) bool {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != mode {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Gid) == gid
}

// maxVectorizerConfigBytes bounds the configuration read back for comparison
// (the vectorizer itself refuses more than 64 KiB).
const maxVectorizerConfigBytes = 64 * 1024

// validToken is the vectorizer's token rule: one line of 16 to 512
// printable ASCII characters without spaces.
func validToken(t string) bool {
	if len(t) < 16 || len(t) > 512 {
		return false
	}
	for i := 0; i < len(t); i++ {
		if t[i] < 0x21 || t[i] > 0x7e {
			return false
		}
	}
	return true
}

// ensureVectorizerToken returns the token, creating it when missing.
func (e *Env) ensureVectorizerToken() (string, error) {
	dir, err := e.ensureVectorizerConfigDir()
	if err != nil {
		return "", err
	}
	if data, err := readFile(filepath.Join(dir, vectorizerToken), 1024, &e.OwnerUID); err == nil {
		t := string(trimLineEnd(data))
		if validToken(t) {
			// A token written root-only (by an earlier version) is given to
			// the container's group, read-only.
			if !hasModeAndGroup(filepath.Join(dir, vectorizerToken), vectorizerConfigFileMode, e.vectorizerGID()) {
				if err := writeGroupFile(dir, vectorizerToken, []byte(t+"\n"), vectorizerConfigFileMode, e.OwnerUID, e.vectorizerGID()); err != nil {
					return "", err
				}
			}
			return t, nil
		}
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	if err := writeGroupFile(dir, vectorizerToken, []byte(token+"\n"), vectorizerConfigFileMode, e.OwnerUID, e.vectorizerGID()); err != nil {
		return "", err
	}
	e.audit("vectorizer token created")
	return token, nil
}

func trimLineEnd(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
	}
	if n := len(b); n > 0 && b[n-1] == '\r' {
		b = b[:n-1]
	}
	return b
}
