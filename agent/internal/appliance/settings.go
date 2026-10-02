package appliance

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Setting is one typed setting of a catalog entry (section 7). A document
// gives values for settings; the helper hands them to the plugin's Compose
// file as environment variables.
type Setting struct {
	// Name is the key of the setting in the catalog entry and in documents.
	Name string
	// Type is SettingBool, SettingInt, SettingEnum, SettingString or
	// SettingStringList.
	Type string
	// Label is the text shown next to the setting.
	Label string
	// Env is the environment variable that carries the value, HM_SET_….
	Env string
	// Default is the value of a setting a document does not give: a bool, an
	// int64, a string or a []string, according to Type.
	Default any
	// Min and Max bound a SettingInt, both included.
	Min, Max int64
	// Values are the allowed values of a SettingEnum.
	Values []string
	// Pattern is the regular expression a SettingString, or every item of a
	// SettingStringList, must match.
	Pattern string
	// MaxLen is the longest SettingString, in characters.
	MaxLen int
	// MaxItems is the longest SettingStringList.
	MaxItems int

	re *regexp.Regexp
}

// maxPatternLen bounds a setting pattern.
const maxPatternLen = 300

// Check validates one value against the setting and returns it in its
// canonical type: bool, int64, string or []string. It accepts what a strict
// JSON reading produces (json.Number, []any) as well as Go values of the
// canonical types.
//
// Whatever the catalog's pattern says, a string or a list item containing a
// control character, a quote, "$", a backquote or a backslash is refused, and
// so is a list item that is empty or contains a space: such a value cannot be
// passed safely as an environment variable.
func (s *Setting) Check(value any) (any, error) {
	switch s.Type {
	case SettingBool:
		b, ok := value.(bool)
		if !ok {
			return nil, errors.New("must be true or false")
		}
		return b, nil
	case SettingInt:
		n, ok := asInteger(value)
		if !ok {
			return nil, errors.New("must be an integer")
		}
		if n < s.Min || n > s.Max {
			return nil, fmt.Errorf("must be %d to %d", s.Min, s.Max)
		}
		return n, nil
	case SettingEnum:
		text, ok := value.(string)
		if !ok {
			return nil, errors.New("must be a string")
		}
		for _, allowed := range s.Values {
			if text == allowed {
				return text, nil
			}
		}
		return nil, fmt.Errorf("must be one of %v", s.Values)
	case SettingString:
		text, ok := value.(string)
		if !ok {
			return nil, errors.New("must be a string")
		}
		if utf8.RuneCountInString(text) > s.MaxLen {
			return nil, fmt.Errorf("is longer than %d characters", s.MaxLen)
		}
		if err := s.checkText(text, false); err != nil {
			return nil, err
		}
		return text, nil
	case SettingStringList:
		var items []any
		switch list := value.(type) {
		case []any:
			items = list
		case []string:
			for _, item := range list {
				items = append(items, item)
			}
		default:
			return nil, errors.New("must be a list of strings")
		}
		if len(items) > s.MaxItems {
			return nil, fmt.Errorf("has more than %d items", s.MaxItems)
		}
		out := make([]string, 0, len(items))
		for i, item := range items {
			text, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("item %d must be a string", i)
			}
			if text == "" {
				return nil, fmt.Errorf("item %d is empty", i)
			}
			if err := s.checkText(text, true); err != nil {
				return nil, fmt.Errorf("item %d %s", i, err.Error())
			}
			out = append(out, text)
		}
		return out, nil
	}
	return nil, errors.New("has an unknown type")
}

func (s *Setting) checkText(text string, listItem bool) error {
	if !envSafe(text, listItem) {
		return errors.New("contains a character that is not allowed in a setting")
	}
	if s.re == nil || !s.re.MatchString(text) {
		return errors.New("does not match the pattern of this setting")
	}
	return nil
}

// envSafe reports whether text can be written as the value of an environment
// variable without any quoting concern: no control character, quote, "$",
// backquote or backslash, and for a list item no space.
func envSafe(text string, listItem bool) bool {
	if !utf8.ValidString(text) {
		return false
	}
	for _, r := range text {
		switch {
		case r < 0x20, r == 0x7f, r == '"', r == '\'', r == '$', r == '`', r == '\\':
			return false
		case listItem && r == ' ':
			return false
		}
	}
	return true
}

// EnvVar is one environment variable for a plugin's Compose file.
type EnvVar struct {
	Name  string
	Value string
}

// Env turns typed settings into the plugin's HM_SET_… environment variables:
// one per setting of the catalog entry, sorted by variable name. A setting
// missing from settings takes its default; a setting the entry does not have
// is an error. Booleans become "true" or "false", integers decimal digits,
// and a list its items joined by single spaces.
//
// Every value is validated again here, whatever validated it before. No
// returned value contains a control character (so no newline), a quote, "$",
// a backquote or a backslash: a value can be written between single quotes
// in an env file as it is.
func (p *Plugin) Env(settings map[string]any) ([]EnvVar, error) {
	checked, err := p.checkSettings(settings)
	if err != nil {
		return nil, err
	}
	out := make([]EnvVar, 0, len(checked))
	for name, value := range checked {
		var text string
		switch v := value.(type) {
		case bool:
			text = strconv.FormatBool(v)
		case int64:
			text = strconv.FormatInt(v, 10)
		case string:
			text = v
		case []string:
			text = strings.Join(v, " ")
		}
		// The last line of defence, independent of the checks above.
		if !envSafe(text, false) {
			return nil, fmt.Errorf("setting %s: the value cannot be passed safely", name)
		}
		out = append(out, EnvVar{Name: p.Settings[name].Env, Value: text})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// checkSettings validates settings against the entry and returns the
// complete set, defaults included, in canonical types.
func (p *Plugin) checkSettings(settings map[string]any) (map[string]any, error) {
	for name := range settings {
		if _, ok := p.Settings[name]; !ok {
			return nil, fmt.Errorf("unknown setting %s", quoteKey(name))
		}
	}
	out := make(map[string]any, len(p.Settings))
	for name, setting := range p.Settings {
		value, given := settings[name]
		if !given {
			value = setting.Default
		}
		checked, err := setting.Check(value)
		if err != nil {
			return nil, fmt.Errorf("setting %s %s", name, err.Error())
		}
		out[name] = checked
	}
	return out, nil
}

// Command is one command to run inside a service of a plugin after it
// started: an argv array, never a shell line.
type Command struct {
	// Service is the Compose service to run the command in.
	Service string
	// Argv is the command and its arguments.
	Argv []string
	// Timeout bounds the run.
	Timeout time.Duration
}

// PostStartCommands expands the entry's post_start list for the given typed
// settings: an entry with for_each yields one command per item of that list
// setting, with "{item}" replaced in every argument; the others yield one
// command. The settings are validated as in Env.
func (p *Plugin) PostStartCommands(settings map[string]any) ([]Command, error) {
	checked, err := p.checkSettings(settings)
	if err != nil {
		return nil, err
	}
	var out []Command
	for _, step := range p.PostStart {
		timeout := time.Duration(step.TimeoutS) * time.Second
		if step.ForEach == "" {
			out = append(out, Command{Service: step.Service, Argv: append([]string(nil), step.Exec...), Timeout: timeout})
			continue
		}
		items, ok := checked[step.ForEach].([]string)
		if !ok {
			return nil, fmt.Errorf("post_start: %s is not a list setting", step.ForEach)
		}
		for _, item := range items {
			// An item that looks like an option could change what the
			// command does. Catalog patterns start with a letter or a digit;
			// this holds even if one does not.
			if strings.HasPrefix(item, "-") {
				return nil, fmt.Errorf("post_start: an item of %s starts with a dash", step.ForEach)
			}
			argv := make([]string, len(step.Exec))
			for i, arg := range step.Exec {
				argv[i] = strings.ReplaceAll(arg, itemPlaceholder, item)
			}
			out = append(out, Command{Service: step.Service, Argv: argv, Timeout: timeout})
		}
	}
	return out, nil
}

// itemPlaceholder is replaced, in a post_start argument, by each item of the
// for_each list.
const itemPlaceholder = "{item}"

// compilePattern compiles the pattern of a string or string_list setting and
// refuses one that could let a dangerous value through.
//
// The check is made on the parsed expression, not on sample strings, and it
// is conservative: it may refuse a harmless pattern, it never accepts one
// that can match a forbidden character.
//
//  1. The pattern must compile as a Go (RE2) regular expression. Catalog
//     patterns must stay in the syntax Go and Python share.
//  2. It must be anchored: the expression as a whole is "^" … "$" (or \A … \z).
//     "^a|b$" is refused, because it also matches "a; anything". Multi-line
//     mode, where "^" and "$" match at line breaks, is refused.
//  3. No literal, character class or wildcard anywhere in it may include a
//     control character (U+0000–U+001F, U+007F), a single or double quote,
//     "$", a backquote or a backslash, and for a list a space. "." and
//     negated classes such as [^,] include them and are refused.
func compilePattern(pattern string, list bool) (*regexp.Regexp, error) {
	if pattern == "" || len(pattern) > maxPatternLen {
		return nil, fmt.Errorf("must be 1 to %d characters", maxPatternLen)
	}
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, errors.New("is not a valid regular expression")
	}
	if parsed.Op != syntax.OpConcat || len(parsed.Sub) < 2 ||
		parsed.Sub[0].Op != syntax.OpBeginText || parsed.Sub[len(parsed.Sub)-1].Op != syntax.OpEndText {
		return nil, errors.New("must be anchored: ^…$ around the whole expression")
	}
	if err := checkPatternRunes(parsed, list); err != nil {
		return nil, err
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, errors.New("is not a valid regular expression")
	}
	return re, nil
}

// forbiddenRanges are the characters no setting value may contain.
var forbiddenRanges = [][2]rune{
	{0x00, 0x1f}, {0x7f, 0x7f}, {'"', '"'}, {'\'', '\''}, {'$', '$'}, {'`', '`'}, {'\\', '\\'},
}

func checkPatternRunes(re *syntax.Regexp, list bool) error {
	overlaps := func(lo, hi rune) bool {
		for _, f := range forbiddenRanges {
			if lo <= f[1] && f[0] <= hi {
				return true
			}
		}
		return list && lo <= ' ' && ' ' <= hi
	}
	refused := errors.New("can match a control character, a quote, $, a backquote or a backslash")
	if list {
		refused = errors.New("can match a space, a control character, a quote, $, a backquote or a backslash")
	}
	switch re.Op {
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return refused
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if overlaps(r, r) {
				return refused
			}
		}
	case syntax.OpCharClass:
		for i := 0; i+1 < len(re.Rune); i += 2 {
			if overlaps(re.Rune[i], re.Rune[i+1]) {
				return refused
			}
		}
	case syntax.OpBeginLine, syntax.OpEndLine:
		return errors.New("must not use multi-line anchors")
	}
	for _, sub := range re.Sub {
		if err := checkPatternRunes(sub, list); err != nil {
			return err
		}
	}
	return nil
}
