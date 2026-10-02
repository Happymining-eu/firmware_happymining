// Package pairing normalises pairing codes as the protocol requires.
//
// Canonical form: the prefix HM, a 6-character locator and a 16-character
// secret in four groups of four, separated by hyphens. Locator and secret use
// upper-case Crockford base32. Input is case-insensitive, hyphens and spaces
// are ignored, O is read as 0 and I or L as 1.
package pairing

import (
	"errors"
	"strings"
)

// crockford is the Crockford base32 alphabet (no I, L, O, U).
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

const (
	prefix     = "HM"
	locatorLen = 6
	secretLen  = 16
)

// ErrInvalid is returned for input that cannot be a pairing code. The message
// never echoes the input.
var ErrInvalid = errors.New("this does not look like a pairing code (expected HM, 6 characters, then 4 groups of 4 characters)")

// Normalize converts operator input to the canonical pairing code.
func Normalize(input string) (string, error) {
	var b strings.Builder
	for _, c := range strings.ToUpper(input) {
		switch c {
		case '-', ' ', '\t', '\r', '\n':
			continue
		}
		b.WriteRune(c)
	}
	s := b.String()
	if !strings.HasPrefix(s, prefix) {
		return "", ErrInvalid
	}
	body := []byte(s[len(prefix):])
	if len(body) != locatorLen+secretLen {
		return "", ErrInvalid
	}
	for i, c := range body {
		switch c {
		case 'O':
			c = '0'
		case 'I', 'L':
			c = '1'
		}
		if strings.IndexByte(crockford, c) < 0 {
			return "", ErrInvalid
		}
		body[i] = c
	}
	out := make([]byte, 0, 29)
	out = append(out, prefix...)
	out = append(out, '-')
	out = append(out, body[:locatorLen]...)
	for i := locatorLen; i < len(body); i += 4 {
		out = append(out, '-')
		out = append(out, body[i:i+4]...)
	}
	return string(out), nil
}

// Mask returns the canonical code with its secret part hidden. The locator is
// not secret and helps an operator check that the right code was typed.
func Mask(canonical string) string {
	parts := strings.Split(canonical, "-")
	if len(parts) != 6 {
		return "HM-******"
	}
	return parts[0] + "-" + parts[1] + "-****-****-****-****"
}
