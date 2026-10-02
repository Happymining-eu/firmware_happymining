package appliance

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Happymining-eu/firmware_happymining/agent/internal/schedule"
	"github.com/Happymining-eu/firmware_happymining/agent/internal/seal"
)

// Document is a validated desired-state document (section 4). Its JSON
// encoding is again a valid document, with every default written out.
type Document struct {
	Schema int `json:"schema"`
	// Revision is at least 1 in a cloud document and 0 in a profile document.
	Revision   int64          `json:"revision,omitempty"`
	Mode       string         `json:"mode"`
	Plugins    []PluginConfig `json:"plugins"`
	NAS        []NAS          `json:"nas"`
	Vectorizer *Vectorizer    `json:"vectorizer,omitempty"`
	Backup     *Backup        `json:"backup,omitempty"`
	Schedules  []Schedule     `json:"schedules"`
	Update     *Update        `json:"update,omitempty"`
	// Secrets maps secret names to sealed values. A profile document has none.
	Secrets map[string]string `json:"secrets,omitempty"`
}

// PluginConfig is one entry of the document's plugin list.
type PluginConfig struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
	// Settings holds every setting of the catalog entry, defaults included,
	// as bool, int64, string or []string.
	Settings map[string]any `json:"settings"`
}

// NAS is one network share (section 4.3). Share, Username, Domain and Secret
// belong to NASKindSMB; Export belongs to NASKindNFS.
type NAS struct {
	ID       string
	Kind     string
	Host     string
	Share    string
	Export   string
	Subpath  string
	Username string
	Domain   string
	// Secret is the name of the sealed password, or empty for guest access.
	Secret string
	Access string
}

// MarshalJSON writes the entry with the keys of its kind only.
func (n NAS) MarshalJSON() ([]byte, error) {
	if n.Kind == NASKindNFS {
		return json.Marshal(struct {
			ID      string `json:"id"`
			Kind    string `json:"kind"`
			Host    string `json:"host"`
			Export  string `json:"export"`
			Subpath string `json:"subpath"`
			Access  string `json:"access"`
		}{n.ID, n.Kind, n.Host, n.Export, n.Subpath, n.Access})
	}
	return json.Marshal(struct {
		ID       string `json:"id"`
		Kind     string `json:"kind"`
		Host     string `json:"host"`
		Share    string `json:"share"`
		Subpath  string `json:"subpath"`
		Username string `json:"username"`
		Domain   string `json:"domain"`
		Secret   string `json:"secret,omitempty"`
		Access   string `json:"access"`
	}{n.ID, n.Kind, n.Host, n.Share, n.Subpath, n.Username, n.Domain, n.Secret, n.Access})
}

// Vectorizer is the document's vectorizer object (section 4.4).
type Vectorizer struct {
	Sources        []string `json:"sources"`
	Extensions     []string `json:"extensions"`
	Exclude        []string `json:"exclude"`
	MaxFileMiB     int      `json:"max_file_mib"`
	EmbeddingModel string   `json:"embedding_model"`
	OCR            bool     `json:"ocr"`
	Answer         Answer   `json:"answer"`
}

// Answer says what produces answers from the index.
type Answer struct {
	Provider string `json:"provider"`
	Model    string `json:"model,omitempty"`
	// BaseURL is set for the cloud providers; an anthropic answer without
	// one gets DefaultAnthropicBaseURL.
	BaseURL string `json:"base_url,omitempty"`
	// Secret is the name of the sealed API key for the cloud providers.
	Secret string `json:"secret,omitempty"`
}

// Backup is the document's backup object (section 4.5).
type Backup struct {
	Enabled       bool              `json:"enabled"`
	Destination   BackupDestination `json:"destination"`
	IncludeModels bool              `json:"include_models"`
	Keep          int               `json:"keep"`
}

// BackupDestination is where archives go. NASID and Subpath belong to
// DestinationNAS; the other fields to DestinationS3.
type BackupDestination struct {
	Kind        string
	NASID       string
	Subpath     string
	Endpoint    string
	Region      string
	Bucket      string
	Prefix      string
	AccessKeyID string
	// Secret is the name of the sealed S3 secret key.
	Secret string
}

// MarshalJSON writes the destination with the keys of its kind only.
func (d BackupDestination) MarshalJSON() ([]byte, error) {
	if d.Kind == DestinationS3 {
		return json.Marshal(struct {
			Kind        string `json:"kind"`
			Endpoint    string `json:"endpoint"`
			Region      string `json:"region"`
			Bucket      string `json:"bucket"`
			Prefix      string `json:"prefix"`
			AccessKeyID string `json:"access_key_id"`
			Secret      string `json:"secret"`
		}{d.Kind, d.Endpoint, d.Region, d.Bucket, d.Prefix, d.AccessKeyID, d.Secret})
	}
	return json.Marshal(struct {
		Kind    string `json:"kind"`
		NASID   string `json:"nas_id"`
		Subpath string `json:"subpath"`
	}{d.Kind, d.NASID, d.Subpath})
}

// Schedule is one entry of the document's schedule list (section 4.6).
type Schedule struct {
	ID  string `json:"id"`
	Job string `json:"job"`
	// Plugin is set for JobPluginRestart only.
	Plugin  string `json:"plugin,omitempty"`
	Every   string `json:"every"`
	Minute  int    `json:"minute"`
	Hour    *int   `json:"hour,omitempty"`
	Weekday *int   `json:"weekday,omitempty"`
	Enabled bool   `json:"enabled"`
}

// Spec returns the timing of the schedule for the schedule package.
func (s Schedule) Spec() schedule.Spec {
	return schedule.Spec{Every: s.Every, Minute: s.Minute, Hour: s.Hour, Weekday: s.Weekday}
}

// Update is the document's update object (section 4.7).
type Update struct {
	Channel string  `json:"channel"`
	Policy  string  `json:"policy"`
	Window  *Window `json:"window,omitempty"`
}

// Window is the daily time span in which an automatic update may install.
type Window struct {
	StartHour int `json:"start_hour"`
	EndHour   int `json:"end_hour"`
}

// Contains reports whether the local hour (0–23) lies in the window, which
// starts at StartHour:00, ends before EndHour:00 and may cross midnight.
func (w Window) Contains(hour int) bool {
	if w.StartHour < w.EndHour {
		return hour >= w.StartHour && hour < w.EndHour
	}
	return hour >= w.StartHour || hour < w.EndHour
}

var (
	reHost        = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	reShare       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._$-]{0,79}$`)
	reExport      = regexp.MustCompile(`^/[A-Za-z0-9._/-]{0,254}$`)
	reDomain      = regexp.MustCompile(`^[A-Za-z0-9._-]{0,64}$`)
	reExtension   = regexp.MustCompile(`^[a-z0-9]{1,8}$`)
	reModelRef    = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,80}(:[A-Za-z0-9._-]{1,40})?$`)
	reAnswerModel = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,100}$`)
	reRegion      = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)
	reBucket      = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	rePrefix      = regexp.MustCompile(`^[A-Za-z0-9._/-]{0,200}$`)
	reAccessKeyID = regexp.MustCompile(`^[A-Za-z0-9]{4,128}$`)
	// https://host[:port][/path]. The path is limited to unreserved URL
	// characters: no "?", "#", "@", "%" or white space can appear anywhere.
	reHTTPSURL = regexp.MustCompile(`^https://[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(:([0-9]{1,5}))?(/[A-Za-z0-9._~/-]*)?$`)
)

const (
	maxSubpathLen  = 512
	maxExcludeLen  = 200
	maxUsernameLen = 64
	maxBaseURLLen  = 200
	maxSources     = 8
	maxExtensions  = 40
	maxExcludes    = 32
)

// NASSecretName returns the name of the sealed password of the NAS entry
// with the given id: "nas.<id>.password".
func NASSecretName(id string) string { return "nas." + id + ".password" }

// ParseDocument strictly decodes and completely validates a cloud document
// against the catalog. raw is one JSON object of at most MaxDocumentBytes.
// Unknown keys anywhere, duplicate keys, a wrong type (an integer is a JSON
// integer: "12", 12.5 and true are not), a control character in any string,
// a broken cross reference, a secret that nothing refers to or that is not
// shaped like a sealed value: each refuses the whole document. The error
// names the place and the rule and never quotes a value of the document.
func ParseDocument(raw []byte, c *Catalog) (*Document, error) {
	if c == nil {
		return nil, errors.New("no catalog")
	}
	tree, err := decodeStrict(raw, MaxDocumentBytes)
	if err != nil {
		return nil, fmt.Errorf("document: %w", err)
	}
	ck := &checker{}
	doc := parseDocument(ck, "", tree, c, false)
	if ck.err != nil {
		return nil, fmt.Errorf("document: %w", ck.err)
	}
	return doc, nil
}

// parseDocument validates a document tree. In a profile document "revision"
// and "secrets" are unknown keys, and the secrets the document refers to are
// not looked for.
func parseDocument(ck *checker, path string, tree any, c *Catalog, profile bool) *Document {
	o := ck.object(path, tree)
	doc := &Document{
		Plugins:   []PluginConfig{},
		NAS:       []NAS{},
		Schedules: []Schedule{},
	}
	doc.Schema = int(o.integer("schema", DocumentSchema, DocumentSchema))
	if !profile {
		doc.Revision = o.integer("revision", 1, math.MaxInt64)
	}
	doc.Mode = o.oneOf("mode", ModeVast, ModePrivateAI, ModeVectorize)

	// refs collects the secret names the document refers to: true for a
	// secret that must be there, false for one that may.
	refs := map[string]bool{}

	for i, v := range o.optList("plugins", MaxPlugins) {
		doc.Plugins = append(doc.Plugins, parsePluginConfig(ck, index(o.at("plugins"), i), v, c, doc.Plugins, refs))
	}
	for i, v := range o.optList("nas", MaxNAS) {
		doc.NAS = append(doc.NAS, parseNAS(ck, index(o.at("nas"), i), v, doc.NAS, refs))
	}
	if vo := o.optSub("vectorizer"); vo != nil {
		doc.Vectorizer = parseVectorizer(vo, doc.NAS, refs)
	}
	if bo := o.optSub("backup"); bo != nil {
		doc.Backup = parseBackup(bo, doc.NAS, refs)
	}
	for i, v := range o.optList("schedules", MaxSchedules) {
		doc.Schedules = append(doc.Schedules, parseSchedule(ck, index(o.at("schedules"), i), v, doc))
	}
	if uo := o.optSub("update"); uo != nil {
		doc.Update = parseUpdate(uo)
	}

	// Cross references between plugins.
	for i, plugin := range doc.Plugins {
		if !plugin.Enabled || ck.err != nil {
			continue
		}
		entry, _ := c.Plugin(plugin.ID)
		for _, req := range entry.Requires {
			if !pluginEnabled(doc.Plugins, req) {
				ck.failf(index(o.at("plugins"), i), "requires plugin %s to be enabled", req)
			}
		}
		if plugin.ID == PluginVectorizer && doc.Vectorizer == nil {
			ck.failf(index(o.at("plugins"), i), "the vectorizer plugin needs the vectorizer object")
		}
	}

	if !profile {
		doc.Secrets = map[string]string{}
		if so := o.optSub("secrets"); so != nil {
			names := so.sortedKeys()
			if len(names) > MaxSecrets {
				ck.failf(so.path, "has more than %d secrets", MaxSecrets)
			}
			for _, name := range names {
				// The name is quoted and bounded: it comes from the input.
				at := so.path + "[" + quoteKey(name) + "]"
				if _, known := refs[name]; !known {
					ck.failf(at, "nothing in the document refers to this secret")
					break
				}
				sealed, ok := so.m[name].(string)
				if !ok || seal.CheckSealed(sealed) != nil {
					ck.failf(at, "is not a sealed value")
					break
				}
				doc.Secrets[name] = sealed
			}
		}
		if ck.err == nil {
			for _, name := range sortedNames(refs) {
				if _, present := doc.Secrets[name]; refs[name] && !present {
					ck.failf(o.at("secrets"), "%s is referred to and missing", name)
					break
				}
			}
		}
	}
	o.done()
	return doc
}

func pluginEnabled(plugins []PluginConfig, id string) bool {
	for _, p := range plugins {
		if p.ID == id {
			return p.Enabled
		}
	}
	return false
}

func sortedNames(set map[string]bool) []string {
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func parsePluginConfig(ck *checker, path string, v any, c *Catalog, seen []PluginConfig, refs map[string]bool) PluginConfig {
	o := ck.object(path, v)
	cfg := PluginConfig{Settings: map[string]any{}}
	cfg.ID = o.match("id", reID, "is not a plugin id")
	cfg.Enabled = o.boolean("enabled")
	settings := o.optSub("settings")
	o.done()
	if ck.err != nil {
		return cfg
	}
	entry, ok := c.Plugin(cfg.ID)
	if !ok {
		ck.failf(o.at("id"), "is not a plugin of this machine's catalog")
		return cfg
	}
	for _, other := range seen {
		if other.ID == cfg.ID {
			ck.failf(o.at("id"), "is listed twice")
			return cfg
		}
	}
	if settings != nil {
		for _, name := range settings.sortedKeys() {
			setting, known := entry.Settings[name]
			if !known {
				ck.failf(settings.path, "unknown setting %s", quoteKey(name))
				return cfg
			}
			checked, err := setting.Check(settings.m[name])
			if err != nil {
				ck.failf(join(settings.path, name), "%s", err.Error())
				return cfg
			}
			cfg.Settings[name] = checked
		}
	}
	for name, setting := range entry.Settings {
		if _, given := cfg.Settings[name]; !given {
			cfg.Settings[name] = setting.Default
		}
	}
	for _, secret := range entry.Secrets {
		refs[entry.SecretName(secret.Key)] = secret.Required && cfg.Enabled
	}
	return cfg
}

func parseNAS(ck *checker, path string, v any, seen []NAS, refs map[string]bool) NAS {
	o := ck.object(path, v)
	n := NAS{}
	n.ID = o.match("id", reID, "must be a lower-case letter, then up to 30 lower-case letters, digits or dashes")
	n.Kind = o.oneOf("kind", NASKindSMB, NASKindNFS)
	n.Host = o.match("host", reHost, "must be a host name or an IPv4 address")
	n.Access = o.oneOf("access", AccessRead, AccessWrite)
	n.Subpath = o.optStr("subpath", "")
	checkRelPath(ck, o.at("subpath"), n.Subpath, maxSubpathLen, true)
	// The subpath becomes part of the mount source (//host/share/subpath),
	// and mount.cifs hands what follows the share to the kernel as
	// prefixpath=<subpath> without escaping it: a comma there would add mount
	// options. A backslash is a path separator for SMB and could hide a ..
	// segment. Neither is allowed.
	if strings.ContainsAny(n.Subpath, ",\\") {
		ck.failf(o.at("subpath"), "must not contain a comma or a backslash")
	}
	switch n.Kind {
	case NASKindSMB:
		n.Share = o.match("share", reShare, "must be a share name of letters, digits, space, dot, underscore, dollar or dash, starting with a letter or a digit")
		if strings.HasSuffix(n.Share, " ") {
			ck.failf(o.at("share"), "must not end with a space")
		}
		n.Username = o.str("username")
		checkUsername(ck, o.at("username"), n.Username)
		n.Domain = o.optStr("domain", "")
		if !reDomain.MatchString(n.Domain) {
			ck.failf(o.at("domain"), "must be at most 64 letters, digits, dots, underscores or dashes")
		}
		if n.Username == "" {
			o.forbid("secret", "guest access (an empty username) has no password")
		} else {
			n.Secret = o.str("secret")
			if ck.err == nil && n.Secret != NASSecretName(n.ID) {
				ck.failf(o.at("secret"), "must be exactly nas.<id>.password")
			}
			refs[NASSecretName(n.ID)] = true
		}
		o.forbid("export", "an smb entry has no export")
	case NASKindNFS:
		n.Export = o.match("export", reExport, "must be an absolute path of letters, digits, dot, underscore, slash or dash")
		if hasSegment(n.Export, "..") {
			ck.failf(o.at("export"), "must not contain a .. segment")
		}
		for _, key := range []string{"share", "username", "domain", "secret"} {
			o.forbid(key, "an nfs entry has no "+key)
		}
	}
	o.done()
	for _, other := range seen {
		if other.ID == n.ID {
			ck.failf(o.at("id"), "is used twice")
		}
	}
	return n
}

// checkUsername applies the SMB user name rule: at most 64 characters, none
// of , = \ / : and no white space. The characters refused are the ones that
// could add a mount option or split the credentials file.
func checkUsername(ck *checker, path, name string) {
	if utf8.RuneCountInString(name) > maxUsernameLen {
		ck.failf(path, "is longer than %d characters", maxUsernameLen)
		return
	}
	for _, r := range name {
		if strings.ContainsRune(`,=\/:`, r) || unicode.IsSpace(r) {
			ck.failf(path, `must not contain , = \ / : or white space`)
			return
		}
	}
}

// checkRelPath applies the rule of "subpath": a relative path of at most
// max characters whose segments, separated by "/", are never empty, "." or
// "..". The empty path is the root and is accepted only with allowEmpty.
func checkRelPath(ck *checker, path, value string, max int, allowEmpty bool) {
	if value == "" {
		if !allowEmpty {
			ck.failf(path, "must not be empty")
		}
		return
	}
	if utf8.RuneCountInString(value) > max {
		ck.failf(path, "is longer than %d characters", max)
		return
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			ck.failf(path, "must be a relative path without empty, . or .. segments and without a leading or trailing /")
			return
		}
	}
}

func hasSegment(path, segment string) bool {
	for _, s := range strings.Split(path, "/") {
		if s == segment {
			return true
		}
	}
	return false
}

func findNAS(entries []NAS, id string) (NAS, bool) {
	for _, n := range entries {
		if n.ID == id {
			return n, true
		}
	}
	return NAS{}, false
}

func parseVectorizer(o *object, nas []NAS, refs map[string]bool) *Vectorizer {
	ck := o.c
	v := &Vectorizer{Sources: []string{}, Extensions: []string{}, Exclude: []string{}}
	for i, item := range o.list("sources", 1, maxSources) {
		at := index(o.at("sources"), i)
		id := ck.str(at, item)
		entry, ok := findNAS(nas, id)
		switch {
		case ck.err != nil:
		case !ok:
			ck.failf(at, "is not the id of a NAS entry")
		case entry.Access != AccessRead:
			ck.failf(at, "a source must be a NAS entry with access read")
		case containsString(v.Sources, id):
			ck.failf(at, "is listed twice")
		}
		v.Sources = append(v.Sources, id)
	}
	for i, item := range o.list("extensions", 1, maxExtensions) {
		at := index(o.at("extensions"), i)
		ext := ck.str(at, item)
		if ck.err == nil && !reExtension.MatchString(ext) {
			ck.failf(at, "must be 1 to 8 lower-case letters or digits, without a dot")
		}
		v.Extensions = append(v.Extensions, ext)
	}
	for i, item := range o.list("exclude", 0, maxExcludes) {
		at := index(o.at("exclude"), i)
		excluded := ck.str(at, item)
		if ck.err == nil {
			checkRelPath(ck, at, excluded, maxExcludeLen, false)
		}
		v.Exclude = append(v.Exclude, excluded)
	}
	v.MaxFileMiB = int(o.integer("max_file_mib", 1, 2048))
	v.EmbeddingModel = o.match("embedding_model", reModelRef, "must be a model reference such as bge-m3 or name:tag")
	v.OCR = o.boolean("ocr")

	a := o.sub("answer")
	v.Answer.Provider = a.oneOf("provider", AnswerNone, AnswerLocal, AnswerOpenAICompatible, AnswerAnthropic)
	provider := v.Answer.Provider
	cloud := provider == AnswerOpenAICompatible || provider == AnswerAnthropic
	if provider == AnswerNone {
		a.forbid("model", "provider none takes no model")
	} else {
		v.Answer.Model = a.match("model", reAnswerModel, "must be 1 to 100 letters, digits, dots, underscores, colons, slashes or dashes")
	}
	switch {
	case provider == AnswerOpenAICompatible || (provider == AnswerAnthropic && a.has("base_url")):
		v.Answer.BaseURL = a.str("base_url")
		if ck.err == nil && !validHTTPSURL(v.Answer.BaseURL, true) {
			ck.failf(a.at("base_url"), "must be https://host[:port][/path], at most %d characters, without user info, query or fragment", maxBaseURLLen)
		}
	case provider == AnswerAnthropic:
		v.Answer.BaseURL = DefaultAnthropicBaseURL
	default:
		a.forbid("base_url", "only a cloud provider takes a base_url")
	}
	if cloud {
		v.Answer.Secret = a.str("secret")
		if ck.err == nil && v.Answer.Secret != SecretAnswerAPIKey {
			ck.failf(a.at("secret"), "must be exactly %s", SecretAnswerAPIKey)
		}
		refs[SecretAnswerAPIKey] = true
	} else {
		a.forbid("secret", "only a cloud provider takes a secret")
	}
	a.done()
	o.done()
	return v
}

// validHTTPSURL applies the rule of base_url (withPath, at most 200
// characters) and of the S3 endpoint (no path): https, a host name or IPv4
// address, an optional port, and for base_url an optional path of unreserved
// characters. User info, query and fragment cannot be written in what the
// expression accepts, and it accepts ASCII only.
func validHTTPSURL(value string, withPath bool) bool {
	if withPath && len(value) > maxBaseURLLen {
		return false
	}
	m := reHTTPSURL.FindStringSubmatch(value)
	if m == nil {
		return false
	}
	if m[3] != "" {
		if port, err := strconv.Atoi(m[3]); err != nil || port < 1 || port > 65535 {
			return false
		}
	}
	return withPath || m[4] == ""
}

func parseBackup(o *object, nas []NAS, refs map[string]bool) *Backup {
	ck := o.c
	b := &Backup{}
	b.Enabled = o.boolean("enabled")
	d := o.sub("destination")
	b.Destination.Kind = d.oneOf("kind", DestinationNAS, DestinationS3)
	switch b.Destination.Kind {
	case DestinationNAS:
		b.Destination.NASID = d.str("nas_id")
		entry, ok := findNAS(nas, b.Destination.NASID)
		switch {
		case ck.err != nil:
		case !ok:
			ck.failf(d.at("nas_id"), "is not the id of a NAS entry")
		case entry.Access != AccessWrite:
			ck.failf(d.at("nas_id"), "a backup destination must be a NAS entry with access write")
		}
		b.Destination.Subpath = d.optStr("subpath", "")
		checkRelPath(ck, d.at("subpath"), b.Destination.Subpath, maxSubpathLen, true)
	case DestinationS3:
		b.Destination.Endpoint = d.str("endpoint")
		if ck.err == nil && !validHTTPSURL(b.Destination.Endpoint, false) {
			ck.failf(d.at("endpoint"), "must be https://host[:port] and nothing else")
		}
		b.Destination.Region = d.match("region", reRegion, "must be 1 to 40 lower-case letters, digits or dashes")
		b.Destination.Bucket = d.match("bucket", reBucket, "must be 3 to 63 lower-case letters, digits, dots or dashes, starting and ending with a letter or a digit")
		b.Destination.Prefix = d.optStr("prefix", "")
		if !rePrefix.MatchString(b.Destination.Prefix) || strings.Contains(b.Destination.Prefix, "..") {
			ck.failf(d.at("prefix"), "must be at most 200 letters, digits, dots, underscores, slashes or dashes, without ..")
		}
		b.Destination.AccessKeyID = d.match("access_key_id", reAccessKeyID, "must be 4 to 128 letters or digits")
		b.Destination.Secret = d.str("secret")
		if ck.err == nil && b.Destination.Secret != SecretBackupS3Key {
			ck.failf(d.at("secret"), "must be exactly %s", SecretBackupS3Key)
		}
		refs[SecretBackupS3Key] = true
	}
	d.done()
	b.IncludeModels = o.boolean("include_models")
	b.Keep = int(o.integer("keep", 1, 365))
	o.done()
	return b
}

func parseSchedule(ck *checker, path string, v any, doc *Document) Schedule {
	o := ck.object(path, v)
	s := Schedule{}
	s.ID = o.match("id", reID, "must be a lower-case letter, then up to 30 lower-case letters, digits or dashes")
	s.Job = o.oneOf("job", JobVectorizeSync, JobBackupRun, JobUpdateCheck, JobPluginRestart)
	if s.Job == JobPluginRestart {
		s.Plugin = o.str("plugin")
		if ck.err == nil && !pluginListed(doc.Plugins, s.Plugin) {
			ck.failf(o.at("plugin"), "is not a plugin of this document")
		}
	} else {
		o.forbid("plugin", "only plugin_restart takes a plugin")
	}
	s.Every = o.oneOf("every", schedule.Hourly, schedule.Daily, schedule.Weekly)
	s.Minute = int(o.integer("minute", 0, 59))
	if s.Every == schedule.Hourly {
		o.forbid("hour", "an hourly schedule has no hour")
	} else {
		hour := int(o.integer("hour", 0, 23))
		s.Hour = &hour
	}
	if s.Every == schedule.Weekly {
		weekday := int(o.integer("weekday", 0, 6))
		s.Weekday = &weekday
	} else {
		o.forbid("weekday", "only a weekly schedule has a weekday")
	}
	s.Enabled = o.boolean("enabled")
	o.done()
	if ck.err != nil {
		return s
	}
	// The schedule package has the last word on what it will be asked to compute.
	if err := s.Spec().Validate(); err != nil {
		ck.failf(path, "%s", err.Error())
	}
	for _, other := range doc.Schedules {
		if other.ID == s.ID {
			ck.failf(o.at("id"), "is used twice")
		}
	}
	return s
}

func pluginListed(plugins []PluginConfig, id string) bool {
	for _, p := range plugins {
		if p.ID == id {
			return true
		}
	}
	return false
}

func parseUpdate(o *object) *Update {
	u := &Update{}
	u.Channel = o.oneOf("channel", ChannelStable, ChannelBeta, ChannelNone)
	u.Policy = o.oneOf("policy", PolicyManual, PolicyAuto)
	var w *object
	if u.Policy == PolicyAuto {
		w = o.sub("window")
	} else {
		w = o.optSub("window")
	}
	if w != nil {
		u.Window = &Window{
			StartHour: int(w.integer("start_hour", 0, 23)),
			EndHour:   int(w.integer("end_hour", 0, 23)),
		}
		w.done()
		if o.c.err == nil && u.Window.StartHour == u.Window.EndHour {
			o.c.failf(w.path, "start_hour and end_hour must differ")
		}
	}
	o.done()
	return u
}

// SecretRef is one secret a document refers to.
type SecretRef struct {
	// Name is the secret's name in the document and in sealed values.
	Name string
	// Required: the document cannot be applied completely without it. An
	// optional plugin secret is not required, nor is a required one of a
	// plugin that is disabled.
	Required bool
	// Plugin and Env are set for a plugin secret: the plugin's id and the
	// environment variable its Compose file reads the value from.
	Plugin string
	Env    string
}

// SecretRefs returns every secret the document refers to or may carry,
// sorted by name: NAS passwords, the answer API key, the S3 secret key and
// the secrets the catalog declares for the document's plugins. Under local
// control these are the names `happyminingctl appliance secret set` accepts.
func SecretRefs(doc *Document, c *Catalog) []SecretRef {
	if doc == nil {
		return nil
	}
	refs := map[string]SecretRef{}
	for _, name := range fixedSecretNames(doc) {
		refs[name] = SecretRef{Name: name, Required: true}
	}
	if c != nil {
		for _, plugin := range doc.Plugins {
			entry, ok := c.Plugin(plugin.ID)
			if !ok {
				continue
			}
			for _, secret := range entry.Secrets {
				name := entry.SecretName(secret.Key)
				refs[name] = SecretRef{Name: name, Required: secret.Required && plugin.Enabled, Plugin: entry.ID, Env: secret.Env}
			}
		}
	}
	out := make([]SecretRef, 0, len(refs))
	for _, ref := range refs {
		out = append(out, ref)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// SecretNames returns, sorted and without duplicates, the names of the
// secrets the document itself names: the password of every SMB entry with a
// user name, the answer API key, the S3 secret key, and every name in
// doc.Secrets (which is where a cloud document carries its plugin secrets).
// For a profile document, which has no Secrets, the plugin secrets come from
// SecretRefs.
func SecretNames(doc *Document) []string {
	if doc == nil {
		return nil
	}
	set := map[string]bool{}
	for _, name := range fixedSecretNames(doc) {
		set[name] = true
	}
	for name := range doc.Secrets {
		set[name] = true
	}
	return sortedNames(set)
}

// fixedSecretNames lists the secrets named by the document's own fields.
func fixedSecretNames(doc *Document) []string {
	var names []string
	for _, n := range doc.NAS {
		if n.Secret != "" {
			names = append(names, n.Secret)
		}
	}
	if doc.Vectorizer != nil && doc.Vectorizer.Answer.Secret != "" {
		names = append(names, doc.Vectorizer.Answer.Secret)
	}
	if doc.Backup != nil && doc.Backup.Destination.Secret != "" {
		names = append(names, doc.Backup.Destination.Secret)
	}
	return names
}
