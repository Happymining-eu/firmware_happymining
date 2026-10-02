package appliance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"unicode/utf8"
)

// This file is the strict JSON reader behind the catalog, the document and
// the profile. encoding/json alone is too forgiving for input that is not
// trusted: it takes the last of two equal keys, cannot tell an absent key
// from a zero value, converts 12.0 to an integer and replaces broken text by
// U+FFFD. Here the input is first turned into a plain tree
// (map[string]any, []any, string, json.Number, bool, nil) with every one of
// those cases refused, and the tree is then read through the object type,
// which records the first error and knows which keys were looked at, so that
// an unknown key is an error.

// maxDepth bounds the nesting of the input. The deepest legitimate path
// (document, plugins, entry, settings, list, item) is 6.
const maxDepth = 12

var reInteger = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// decodeStrict parses raw as exactly one JSON value of at most maxBytes
// bytes. It refuses invalid UTF-8, unpaired surrogate escapes, duplicate
// keys, nesting beyond maxDepth and anything after the value.
func decodeStrict(raw []byte, maxBytes int) (any, error) {
	if len(raw) > maxBytes {
		return nil, fmt.Errorf("larger than %d bytes", maxBytes)
	}
	if !utf8.Valid(raw) {
		return nil, errors.New("not UTF-8")
	}
	// json.Valid checks the whole input: one value, nothing after it.
	if !json.Valid(raw) {
		return nil, errors.New("not valid JSON")
	}
	if err := checkSurrogates(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return readValue(dec, 0)
}

func readValue(dec *json.Decoder, depth int) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, errors.New("not valid JSON")
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return tok, nil // string, json.Number, bool or nil
	}
	if depth >= maxDepth {
		return nil, errors.New("nested too deeply")
	}
	switch delim {
	case '{':
		obj := map[string]any{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return nil, errors.New("not valid JSON")
			}
			key, ok := keyTok.(string)
			if !ok {
				return nil, errors.New("not valid JSON")
			}
			if _, dup := obj[key]; dup {
				return nil, fmt.Errorf("duplicate key %s", quoteKey(key))
			}
			value, err := readValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			obj[key] = value
		}
		if _, err := dec.Token(); err != nil {
			return nil, errors.New("not valid JSON")
		}
		return obj, nil
	case '[':
		list := []any{}
		for dec.More() {
			value, err := readValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			list = append(list, value)
		}
		if _, err := dec.Token(); err != nil {
			return nil, errors.New("not valid JSON")
		}
		return list, nil
	}
	return nil, errors.New("not valid JSON")
}

// checkSurrogates refuses a \uD800–\uDFFF escape that is not half of a
// proper pair. encoding/json would silently turn it into U+FFFD. raw is
// valid JSON.
func checkSurrogates(raw []byte) error {
	hex4 := func(i int) (rune, bool) {
		if i+4 > len(raw) {
			return 0, false
		}
		n, err := strconv.ParseUint(string(raw[i:i+4]), 16, 16)
		return rune(n), err == nil
	}
	inString := false
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; {
		case !inString:
			inString = c == '"'
		case c == '"':
			inString = false
		case c == '\\':
			i++
			if i >= len(raw) || raw[i] != 'u' {
				continue
			}
			r, ok := hex4(i + 1)
			i += 4
			if !ok || r < 0xD800 || r > 0xDFFF {
				continue
			}
			paired := false
			if r <= 0xDBFF && i+2 < len(raw) && raw[i+1] == '\\' && raw[i+2] == 'u' {
				if low, ok := hex4(i + 3); ok && low >= 0xDC00 && low <= 0xDFFF {
					paired = true
					i += 6
				}
			}
			if !paired {
				return errors.New("a string holds an unpaired surrogate escape")
			}
		}
	}
	return nil
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func index(path string, i int) string { return path + "[" + strconv.Itoa(i) + "]" }

func pathOrTop(path string) string {
	if path == "" {
		return "top level"
	}
	return path
}

// quoteKey quotes a key that came from the input for an error message,
// bounded so that a hostile key cannot flood a log or a report.
func quoteKey(key string) string {
	if utf8.RuneCountInString(key) > 40 {
		key = string([]rune(key)[:40]) + "…"
	}
	return strconv.Quote(key)
}

// checker records the first validation error. Everything that reads the tree
// reports to one checker and carries on with zero values, so that validation
// code reads top to bottom without an error check on every line; later
// errors are consequences of the first and are dropped.
type checker struct {
	err error
}

func (c *checker) failf(path, format string, args ...any) {
	if c.err != nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	if path == "" {
		c.err = errors.New(msg)
		return
	}
	c.err = fmt.Errorf("%s: %s", path, msg)
}

// str returns v as a string without control characters.
func (c *checker) str(path string, v any) string {
	s, ok := v.(string)
	if !ok {
		c.failf(path, "must be a string")
		return ""
	}
	if hasControl(s) {
		c.failf(path, "contains a control character")
		return ""
	}
	return s
}

// boolean returns v as a JSON boolean.
func (c *checker) boolean(path string, v any) bool {
	b, ok := v.(bool)
	if !ok {
		c.failf(path, "must be true or false")
	}
	return b
}

// integer returns v as a JSON integer within lo..hi. "12", 12.5, 12.0, 1e2
// and true are not integers.
func (c *checker) integer(path string, v any, lo, hi int64) int64 {
	n, ok := asInteger(v)
	if !ok {
		c.failf(path, "must be an integer")
		return 0
	}
	if n < lo || n > hi {
		switch {
		case lo == hi:
			c.failf(path, "must be %d", lo)
		case hi == math.MaxInt64:
			c.failf(path, "must be %d or more", lo)
		default:
			c.failf(path, "must be %d to %d", lo, hi)
		}
		return 0
	}
	return n
}

// list returns v as a JSON array of min to max items.
func (c *checker) list(path string, v any, min, max int) []any {
	l, ok := v.([]any)
	if !ok {
		c.failf(path, "must be a list")
		return nil
	}
	if len(l) < min || len(l) > max {
		switch {
		case min == 0:
			c.failf(path, "has more than %d entries", max)
		case len(l) < min:
			c.failf(path, "needs at least %d", min)
		default:
			c.failf(path, "has more than %d entries", max)
		}
		return nil
	}
	return l
}

// object wraps v, which must be a JSON object, for reading by key.
func (c *checker) object(path string, v any) *object {
	m, ok := v.(map[string]any)
	if !ok {
		c.failf(path, "must be an object")
		m = map[string]any{}
	}
	return &object{c: c, path: path, m: m, used: map[string]bool{}}
}

func asInteger(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		if !reInteger.MatchString(n.String()) {
			return 0, false
		}
		i, err := strconv.ParseInt(n.String(), 10, 64)
		return i, err == nil
	case int:
		return int64(n), true
	case int64:
		return n, true
	}
	return 0, false
}

// hasControl reports whether s contains U+0000–U+001F or U+007F.
func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// object reads one JSON object key by key and remembers which keys were
// asked for.
type object struct {
	c    *checker
	path string
	m    map[string]any
	used map[string]bool
}

func (o *object) at(key string) string { return join(o.path, key) }

// has reports whether key is present, without marking it as known.
func (o *object) has(key string) bool {
	_, ok := o.m[key]
	return ok
}

func (o *object) get(key string) (any, bool) {
	o.used[key] = true
	v, ok := o.m[key]
	return v, ok
}

func (o *object) need(key string) (any, bool) {
	v, ok := o.get(key)
	if !ok {
		o.c.failf(o.at(key), "is required")
	}
	return v, ok
}

// str reads a required string.
func (o *object) str(key string) string {
	if v, ok := o.need(key); ok {
		return o.c.str(o.at(key), v)
	}
	return ""
}

// optStr reads an optional string; def stands in for an absent key.
func (o *object) optStr(key, def string) string {
	if v, ok := o.get(key); ok {
		return o.c.str(o.at(key), v)
	}
	return def
}

// text reads a required string of min to max characters.
func (o *object) text(key string, min, max int) string {
	s := o.str(key)
	o.checkLen(key, s, min, max)
	return s
}

// optText reads an optional string of at most max characters.
func (o *object) optText(key string, max int) string {
	s := o.optStr(key, "")
	o.checkLen(key, s, 0, max)
	return s
}

func (o *object) checkLen(key, s string, min, max int) {
	if n := utf8.RuneCountInString(s); n < min || n > max {
		if min == 0 {
			o.c.failf(o.at(key), "is longer than %d characters", max)
		} else {
			o.c.failf(o.at(key), "must be %d to %d characters", min, max)
		}
	}
}

// oneOf reads a required string that must be one of the allowed values.
func (o *object) oneOf(key string, allowed ...string) string {
	s := o.str(key)
	if o.c.err != nil {
		return ""
	}
	for _, a := range allowed {
		if s == a {
			return s
		}
	}
	o.c.failf(o.at(key), "must be one of %v", allowed)
	return ""
}

// match reads a required string that must match re; rule describes the
// pattern for people.
func (o *object) match(key string, re *regexp.Regexp, rule string) string {
	s := o.str(key)
	if o.c.err == nil && !re.MatchString(s) {
		o.c.failf(o.at(key), "%s", rule)
		return ""
	}
	return s
}

// boolean reads a required boolean.
func (o *object) boolean(key string) bool {
	if v, ok := o.need(key); ok {
		return o.c.boolean(o.at(key), v)
	}
	return false
}

// optBoolean reads an optional boolean.
func (o *object) optBoolean(key string, def bool) bool {
	if v, ok := o.get(key); ok {
		return o.c.boolean(o.at(key), v)
	}
	return def
}

// integer reads a required integer within lo..hi.
func (o *object) integer(key string, lo, hi int64) int64 {
	if v, ok := o.need(key); ok {
		return o.c.integer(o.at(key), v, lo, hi)
	}
	return 0
}

// list reads a required list of min to max items.
func (o *object) list(key string, min, max int) []any {
	if v, ok := o.need(key); ok {
		return o.c.list(o.at(key), v, min, max)
	}
	return nil
}

// optList reads an optional list of at most max items; absent is empty.
func (o *object) optList(key string, max int) []any {
	if v, ok := o.get(key); ok {
		return o.c.list(o.at(key), v, 0, max)
	}
	return nil
}

// sub reads a required object.
func (o *object) sub(key string) *object {
	v, _ := o.need(key)
	return o.c.object(o.at(key), v)
}

// optSub reads an optional object; nil when the key is absent.
func (o *object) optSub(key string) *object {
	if v, ok := o.get(key); ok {
		return o.c.object(o.at(key), v)
	}
	return nil
}

// forbid fails when key is present; why says what it does not belong to.
func (o *object) forbid(key, why string) {
	if _, ok := o.get(key); ok {
		o.c.failf(o.at(key), "%s", why)
	}
}

// done fails on the first key (in sorted order) that nothing asked for.
func (o *object) done() {
	if o.c.err != nil {
		return
	}
	var unknown []string
	for key := range o.m {
		if !o.used[key] {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) == 0 {
		return
	}
	sort.Strings(unknown)
	o.c.failf(pathOrTop(o.path), "unknown key %s", quoteKey(unknown[0]))
}

// sortedKeys returns the keys of the object in sorted order and marks them
// all as known: the caller validates each one.
func (o *object) sortedKeys() []string {
	keys := make([]string, 0, len(o.m))
	for key := range o.m {
		keys = append(keys, key)
		o.used[key] = true
	}
	sort.Strings(keys)
	return keys
}
