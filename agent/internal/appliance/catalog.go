package appliance

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/seal"
)

// File names of a catalog entry.
const (
	PluginFile  = "plugin.json"
	ComposeFile = "compose.yaml"
)

// Bounds of the catalog. The contract does not give them; they keep a root
// process from reading without limit and match what a heartbeat can report.
const (
	// MaxCatalogPlugins is the largest catalog: a heartbeat lists at most
	// MaxReportedList entries.
	MaxCatalogPlugins = MaxReportedList

	maxPluginFileBytes = 256 * 1024
	maxSettings        = 32
	maxEnumValues      = 64
	maxStringLen       = 200
	maxListItems       = 32
	maxPluginSecrets   = 16
	maxPorts           = 16
	maxImages          = 16
	maxVolumes         = 16
	maxPostStart       = 16
	maxExecArgs        = 32
	maxTimeoutS        = 24 * 3600
)

var (
	reID          = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
	reSettingName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)
	reSettingEnv  = regexp.MustCompile(`^HM_SET_[A-Z0-9_]{1,40}$`)
	reSecretKey   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)
	reSecretEnv   = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,60}$`)
	reProtocol    = regexp.MustCompile(`^[a-z][a-z0-9]{0,15}$`)
	reImageRef    = regexp.MustCompile(`^[a-z0-9]([a-z0-9._/:-]{0,200}[a-z0-9])?:[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
	reDigest      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	reSimpleName  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,30}$`)
)

// reservedEnv are the variables the helper sets itself for every Compose
// file; a plugin secret must not take their names.
var reservedEnv = []string{"HM_BIND", "HM_PLUGIN_DATA"}

// Catalog is the set of plugins installed with the firmware.
type Catalog struct {
	dir     string
	plugins map[string]*Plugin
	ids     []string // sorted
}

// Plugin is one catalog entry: the content of its plugin.json (section 7).
type Plugin struct {
	// ID equals the name of the entry's directory.
	ID string
	// Version changes whenever the entry changes.
	Version string
	// Name, Summary, Homepage and License are text for people.
	Name     string
	Summary  string
	Homepage string
	License  string
	// GPU says the plugin uses the GPUs. The helper does not start such a
	// plugin while a container HappyMining did not start is running, unless
	// ALLOW_FOREIGN_CONTAINERS is set.
	GPU bool
	// Modes are the modes in which the plugin runs. Never ModeVast.
	Modes []string
	// Requires are the plugins that must be enabled with this one.
	Requires []string
	// Ports are the only ports the Compose file may publish.
	Ports []Port
	// Settings are the typed settings by name.
	Settings map[string]*Setting
	// Secrets are the secrets the plugin takes.
	Secrets []PluginSecret
	// Images are the images the Compose file uses.
	Images []Image
	// Volumes are the plugin's named volumes.
	Volumes []Volume
	// Build is set for a plugin whose image is built on the machine.
	Build *Build
	// PostStart are the commands to run after the plugin started; see
	// PostStartCommands.
	PostStart []PostStart

	dir string
}

// Port is a port a plugin publishes.
type Port struct {
	Name     string
	Port     int
	Protocol string
	// UI says the port serves a page for people.
	UI bool
}

// PluginSecret is a secret a plugin takes. In a document its name is
// "plugin.<plugin id>.<Key>"; the helper passes the opened value to the
// Compose file as the environment variable Env.
type PluginSecret struct {
	Key   string
	Env   string
	Label string
	// Required: the plugin cannot be enabled without it.
	Required bool
}

// Image is an image the Compose file of a plugin uses.
type Image struct {
	// Ref is the image with its tag.
	Ref string
	// Digest is "sha256:…", or empty when it is not known.
	Digest string
	// Verified: the digest was read from the registry for that tag and the
	// Compose file pins it.
	Verified bool
}

// Volume is a named volume of a plugin.
type Volume struct {
	Name string
	// Backup is VolumeBackupAlways, VolumeBackupModels or VolumeBackupNever.
	Backup string
}

// Build describes an image built on the machine.
type Build struct {
	// Context is a directory shipped with the package, relative to
	// /usr/share/happymining. It is a single path element.
	Context string
	// Image is the name the built image gets, with its tag.
	Image string
}

// PostStart is one post_start entry as written in the catalog.
type PostStart struct {
	Service string
	// Exec is the argv array; "{item}" stands for an item of ForEach.
	Exec []string
	// ForEach names a string_list setting, or is empty.
	ForEach  string
	TimeoutS int
}

// CatalogEntry is how a catalog entry is listed in the heartbeat.
type CatalogEntry struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// LoadCatalog reads the catalog in dir: one directory per plugin, named
// after its id, holding plugin.json and compose.yaml. plugin.json is read
// strictly (an unknown or duplicate key is an error) and checked against
// every rule of section 7 that concerns it; compose.yaml must be there as a
// regular file and is not parsed (the repository's tests check its rules).
// Any error refuses the whole catalog.
//
// Files directly in dir are ignored. A symbolic link, anywhere a directory
// or one of the two files is expected, is an error.
//
// LoadCatalog does not look at who owns the files. A process that acts on
// the catalog as root uses LoadCatalogOwnedBy.
func LoadCatalog(dir string) (*Catalog, error) { return loadCatalog(dir, nil) }

// LoadCatalogOwnedBy is LoadCatalog for a privileged caller: dir, every
// plugin directory, plugin.json and compose.yaml must also be owned by
// ownerUID and not writable by group or others. Production code passes 0.
// The directories above dir are not examined.
func LoadCatalogOwnedBy(dir string, ownerUID uint32) (*Catalog, error) {
	return loadCatalog(dir, &ownerUID)
}

func loadCatalog(dir string, ownerUID *uint32) (*Catalog, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := checkDir(abs, ownerUID); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(abs)
	if err != nil {
		return nil, err
	}
	c := &Catalog{dir: abs, plugins: map[string]*Plugin{}}
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(abs, name)
		if entry.Type()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s is a symbolic link", path)
		}
		if !entry.IsDir() {
			continue
		}
		if !reID.MatchString(name) {
			return nil, fmt.Errorf("%s: the directory name is not a plugin id", path)
		}
		if len(c.plugins) >= MaxCatalogPlugins {
			return nil, fmt.Errorf("%s holds more than %d plugins", abs, MaxCatalogPlugins)
		}
		if err := checkDir(path, ownerUID); err != nil {
			return nil, err
		}
		raw, err := readRegular(filepath.Join(path, PluginFile), ownerUID, maxPluginFileBytes)
		if err != nil {
			return nil, err
		}
		if _, err := readRegular(filepath.Join(path, ComposeFile), ownerUID, 0); err != nil {
			return nil, err
		}
		plugin, err := parsePlugin(raw, name)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(path, PluginFile), err)
		}
		plugin.dir = path
		c.plugins[name] = plugin
		c.ids = append(c.ids, name)
	}
	sort.Strings(c.ids)
	if err := c.checkRequires(); err != nil {
		return nil, fmt.Errorf("%s: %w", abs, err)
	}
	return c, nil
}

// checkDir checks that path is a directory, not a symbolic link, and, when
// ownerUID is given, that it is owned by it and not writable by group or
// others.
func checkDir(path string, ownerUID *uint32) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory (a symbolic link is not accepted)", path)
	}
	return checkOwner(path, fi, ownerUID)
}

func checkOwner(path string, fi fs.FileInfo, ownerUID *uint32) error {
	if ownerUID == nil {
		return nil
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != *ownerUID {
		return fmt.Errorf("%s is not owned by uid %d", path, *ownerUID)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or others", path)
	}
	return nil
}

// readRegular opens path without following a symbolic link, checks the
// opened file (so the file that is checked is the file that is read) and
// returns at most maxBytes of it; a larger file is an error. With maxBytes 0
// nothing is read.
func readRegular(path string, ownerUID *uint32, maxBytes int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		return nil, fmt.Errorf("%s cannot be opened (a symbolic link is not accepted): %w", path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if err := checkOwner(path, fi, ownerUID); err != nil {
		return nil, err
	}
	if maxBytes == 0 {
		return nil, nil
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxBytes)
	}
	return data, nil
}

// Plugin returns the entry with the given id.
func (c *Catalog) Plugin(id string) (*Plugin, bool) {
	p, ok := c.plugins[id]
	return p, ok
}

// IDs returns the ids of all entries, sorted.
func (c *Catalog) IDs() []string { return append([]string(nil), c.ids...) }

// Dir returns the absolute path of the catalog directory.
func (c *Catalog) Dir() string { return c.dir }

// Summary returns id and version of every entry, sorted by id, as the
// heartbeat reports the catalog.
func (c *Catalog) Summary() []CatalogEntry {
	out := make([]CatalogEntry, 0, len(c.ids))
	for _, id := range c.ids {
		out = append(out, CatalogEntry{ID: id, Version: c.plugins[id].Version})
	}
	return out
}

// checkRequires checks that every requirement exists and that the
// requirements form no cycle.
func (c *Catalog) checkRequires() error {
	for _, id := range c.ids {
		for _, req := range c.plugins[id].Requires {
			if _, ok := c.plugins[req]; !ok {
				return fmt.Errorf("plugin %s requires %s, which is not in the catalog", id, req)
			}
		}
	}
	const (
		unvisited = iota
		visiting
		done
	)
	state := map[string]int{}
	var stack []string
	var visit func(id string) error
	visit = func(id string) error {
		switch state[id] {
		case done:
			return nil
		case visiting:
			return fmt.Errorf("the requirements form a cycle: %s", strings.Join(append(stack, id), " requires "))
		}
		state[id] = visiting
		stack = append(stack, id)
		for _, req := range c.plugins[id].Requires {
			if err := visit(req); err != nil {
				return err
			}
		}
		stack = stack[:len(stack)-1]
		state[id] = done
		return nil
	}
	for _, id := range c.ids {
		if err := visit(id); err != nil {
			return err
		}
	}
	return nil
}

// ComposePath returns the absolute path of the entry's Compose file.
func (p *Plugin) ComposePath() string { return filepath.Join(p.dir, ComposeFile) }

// Dir returns the absolute path of the entry's directory.
func (p *Plugin) Dir() string { return p.dir }

// RunsIn reports whether the plugin runs in mode. No plugin runs in ModeVast.
func (p *Plugin) RunsIn(mode string) bool {
	if mode == ModeVast {
		return false
	}
	for _, m := range p.Modes {
		if m == mode {
			return true
		}
	}
	return false
}

// ImagesVerified reports whether every image of the plugin is pinned to a
// digest read from its registry. The helper starts a plugin for which this
// is false only with ALLOW_UNPINNED_IMAGES.
func (p *Plugin) ImagesVerified() bool {
	for _, image := range p.Images {
		if !image.Verified {
			return false
		}
	}
	return true
}

// SecretName returns the document's name for the plugin secret with the
// given key: "plugin.<id>.<key>".
func (p *Plugin) SecretName(key string) string { return "plugin." + p.ID + "." + key }

// SettingNames returns the names of the plugin's settings, sorted.
func (p *Plugin) SettingNames() []string {
	names := make([]string, 0, len(p.Settings))
	for name := range p.Settings {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// parsePlugin reads one plugin.json. dirName is the directory it came from.
func parsePlugin(raw []byte, dirName string) (*Plugin, error) {
	tree, err := decodeStrict(raw, maxPluginFileBytes)
	if err != nil {
		return nil, err
	}
	c := &checker{}
	o := c.object("", tree)
	p := &Plugin{Settings: map[string]*Setting{}}

	o.integer("schema", DocumentSchema, DocumentSchema)
	p.ID = o.match("id", reID, "must be a plugin id: a lower-case letter, then up to 30 lower-case letters, digits or dashes")
	if c.err == nil && p.ID != dirName {
		c.failf("id", "must equal the directory name")
	}
	p.Version = o.text("version", 1, MaxReportedString)
	p.Name = o.text("name", 1, MaxReportedString)
	p.Summary = o.optText("summary", MaxReportedDetail)
	p.Homepage = o.optText("homepage", maxStringLen)
	p.License = o.optText("license", MaxReportedString)
	p.GPU = o.boolean("gpu")

	for i, v := range o.list("modes", 0, 2) {
		path := index("modes", i)
		mode := c.str(path, v)
		switch {
		case mode == ModeVast:
			c.failf(path, "no plugin runs in vast mode")
		case mode != ModePrivateAI && mode != ModeVectorize:
			c.failf(path, "must be %s or %s", ModePrivateAI, ModeVectorize)
		case containsString(p.Modes, mode):
			c.failf(path, "is listed twice")
		}
		p.Modes = append(p.Modes, mode)
	}

	for i, v := range o.optList("requires", MaxCatalogPlugins) {
		path := index("requires", i)
		req := c.str(path, v)
		switch {
		case !reID.MatchString(req):
			c.failf(path, "is not a plugin id")
		case req == p.ID:
			c.failf(path, "a plugin cannot require itself")
		case containsString(p.Requires, req):
			c.failf(path, "is listed twice")
		}
		p.Requires = append(p.Requires, req)
	}

	for i, v := range o.optList("ports", maxPorts) {
		path := index("ports", i)
		po := c.object(path, v)
		port := Port{
			Name:     po.match("name", reID, "must be a lower-case letter, then up to 30 lower-case letters, digits or dashes"),
			Port:     int(po.integer("port", 1, 65535)),
			Protocol: po.match("protocol", reProtocol, "must be a lower-case protocol name"),
			UI:       po.boolean("ui"),
		}
		po.done()
		for _, other := range p.Ports {
			if other.Name == port.Name {
				c.failf(path, "the name is used twice")
			}
			if other.Port == port.Port {
				c.failf(path, "the port is used twice")
			}
		}
		p.Ports = append(p.Ports, port)
	}

	envs := map[string]bool{}
	if so := o.optSub("settings"); so != nil {
		names := so.sortedKeys()
		if len(names) > maxSettings {
			c.failf("settings", "has more than %d settings", maxSettings)
		}
		for _, name := range names {
			if !reSettingName.MatchString(name) {
				c.failf("settings", "%s is not a setting name", quoteKey(name))
				break
			}
			setting := parseSetting(c, join("settings", name), name, so.m[name])
			if c.err == nil && envs[setting.Env] {
				c.failf(join("settings", name), "the variable %s is used twice", setting.Env)
			}
			envs[setting.Env] = true
			p.Settings[name] = setting
		}
	}

	for i, v := range o.optList("secrets", maxPluginSecrets) {
		path := index("secrets", i)
		so := c.object(path, v)
		secret := PluginSecret{
			Key:      so.match("key", reSecretKey, "must be a lower-case letter, then up to 30 lower-case letters, digits or underscores"),
			Env:      so.match("env", reSecretEnv, "must be an upper-case variable name of 2 to 61 characters"),
			Label:    so.optText("label", MaxReportedString),
			Required: so.optBoolean("required", false),
		}
		so.done()
		if c.err != nil {
			break
		}
		switch {
		case strings.HasPrefix(secret.Env, "HM_SET_") || containsString(reservedEnv, secret.Env):
			c.failf(path, "the variable %s is reserved for settings and for the helper", secret.Env)
		case envs[secret.Env]:
			c.failf(path, "the variable %s is used twice", secret.Env)
		case !seal.ValidName(p.SecretName(secret.Key)):
			c.failf(path, "plugin id and key together are too long for a secret name")
		}
		for _, other := range p.Secrets {
			if other.Key == secret.Key {
				c.failf(path, "the key is used twice")
			}
		}
		envs[secret.Env] = true
		p.Secrets = append(p.Secrets, secret)
	}

	for i, v := range o.list("images", 1, maxImages) {
		path := index("images", i)
		img := c.object(path, v)
		image := Image{
			Ref:      img.match("ref", reImageRef, "must be an image reference with a tag and without a digest"),
			Verified: img.boolean("verified"),
		}
		if digest, ok := img.get("digest"); ok && digest != nil {
			image.Digest = c.str(join(path, "digest"), digest)
			if c.err == nil && !reDigest.MatchString(image.Digest) {
				c.failf(join(path, "digest"), "must be sha256: followed by 64 hexadecimal characters, or null")
			}
		}
		img.done()
		if c.err == nil && image.Verified && image.Digest == "" {
			c.failf(path, "an image without a digest cannot be verified")
		}
		for _, other := range p.Images {
			if other.Ref == image.Ref {
				c.failf(path, "the image is listed twice")
			}
		}
		p.Images = append(p.Images, image)
	}

	for i, v := range o.optList("volumes", maxVolumes) {
		path := index("volumes", i)
		vo := c.object(path, v)
		volume := Volume{
			Name:   vo.match("name", reSimpleName, "must be a lower-case letter, then up to 30 lower-case letters, digits, dashes or underscores"),
			Backup: vo.oneOf("backup", VolumeBackupAlways, VolumeBackupModels, VolumeBackupNever),
		}
		vo.done()
		for _, other := range p.Volumes {
			if other.Name == volume.Name {
				c.failf(path, "the name is used twice")
			}
		}
		p.Volumes = append(p.Volumes, volume)
	}

	if bo := o.optSub("build"); bo != nil {
		p.Build = &Build{
			Context: bo.match("context", reSimpleName, "must be one directory name: a lower-case letter, then up to 30 lower-case letters, digits, dashes or underscores"),
			Image:   bo.match("image", reImageRef, "must be an image name with a tag"),
		}
		bo.done()
	}

	for i, v := range o.optList("post_start", maxPostStart) {
		path := index("post_start", i)
		so := c.object(path, v)
		step := PostStart{
			Service:  so.match("service", reSimpleName, "must be a service name: a lower-case letter, then up to 30 lower-case letters, digits, dashes or underscores"),
			ForEach:  so.optStr("for_each", ""),
			TimeoutS: int(so.integer("timeout_s", 1, maxTimeoutS)),
		}
		usesItem := false
		for j, arg := range so.list("exec", 1, maxExecArgs) {
			text := c.str(index(join(path, "exec"), j), arg)
			if text == "" || len(text) > maxStringLen {
				c.failf(index(join(path, "exec"), j), "must be 1 to %d bytes", maxStringLen)
			}
			usesItem = usesItem || strings.Contains(text, itemPlaceholder)
			step.Exec = append(step.Exec, text)
		}
		so.done()
		if c.err != nil {
			break
		}
		switch {
		case so.has("for_each") && (p.Settings[step.ForEach] == nil || p.Settings[step.ForEach].Type != SettingStringList):
			c.failf(join(path, "for_each"), "must name a string_list setting of this plugin")
		case usesItem && step.ForEach == "":
			c.failf(path, "%s is used without for_each", itemPlaceholder)
		case strings.Contains(step.Exec[0], itemPlaceholder):
			c.failf(path, "the command itself cannot be %s", itemPlaceholder)
		}
		p.PostStart = append(p.PostStart, step)
	}

	o.done()
	if c.err != nil {
		return nil, c.err
	}
	return p, nil
}

// parseSetting reads one entry of "settings".
func parseSetting(c *checker, path, name string, v any) *Setting {
	so := c.object(path, v)
	s := &Setting{Name: name}
	s.Type = so.oneOf("type", SettingBool, SettingInt, SettingEnum, SettingString, SettingStringList)
	s.Label = so.text("label", 1, MaxReportedString)
	s.Env = so.match("env", reSettingEnv, "must be HM_SET_ followed by 1 to 40 upper-case letters, digits or underscores")
	def, _ := so.need("default")
	switch s.Type {
	case SettingInt:
		const limit = 1 << 53 // integers every JSON reader agrees on
		s.Min = so.integer("min", -limit, limit)
		s.Max = so.integer("max", -limit, limit)
		if c.err == nil && s.Min > s.Max {
			c.failf(path, "min is greater than max")
		}
	case SettingEnum:
		for i, item := range so.list("values", 1, maxEnumValues) {
			itemPath := index(join(path, "values"), i)
			value := c.str(itemPath, item)
			switch {
			case value == "" || len(value) > maxStringLen:
				c.failf(itemPath, "must be 1 to %d bytes", maxStringLen)
			case !envSafe(value, false):
				c.failf(itemPath, "contains a character that is not allowed in a setting")
			case containsString(s.Values, value):
				c.failf(itemPath, "is listed twice")
			}
			s.Values = append(s.Values, value)
		}
	case SettingString, SettingStringList:
		s.Pattern = so.str("pattern")
		if s.Type == SettingString {
			s.MaxLen = int(so.integer("max_len", 1, maxStringLen))
		} else {
			s.MaxItems = int(so.integer("max_items", 1, maxListItems))
		}
		if c.err == nil {
			re, err := compilePattern(s.Pattern, s.Type == SettingStringList)
			if err != nil {
				c.failf(join(path, "pattern"), "%s", err.Error())
			}
			s.re = re
		}
	}
	so.done()
	if c.err != nil {
		return s
	}
	checked, err := s.Check(def)
	if err != nil {
		c.failf(join(path, "default"), "%s", err.Error())
	}
	s.Default = checked
	return s
}

func containsString(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}
