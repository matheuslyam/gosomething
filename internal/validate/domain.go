// Package validate checks user-supplied domain input without any network
// access. It returns the display form (original) and the lookup form
// (ASCII/punycode) so callers can show one and resolve the other.
package validate

import (
	"regexp"
	"strings"

	"golang.org/x/net/idna"
)

// ErrCode identifies why a domain was rejected. The zero value means valid.
type ErrCode string

const (
	// ErrOK means the input is a valid FQDN.
	ErrOK ErrCode = ""
	// ErrEmpty means the input was empty after trimming.
	ErrEmpty ErrCode = "empty"
	// ErrTooLong means the ASCII form exceeds 253 characters.
	ErrTooLong ErrCode = "tooLong"
	// ErrLabelTooLong means a label exceeds 63 characters.
	ErrLabelTooLong ErrCode = "labelTooLong"
	// ErrBadChars means disallowed characters or malformed labels.
	ErrBadChars ErrCode = "badChars"
	// ErrSingleLabel means no dot was present (e.g. localhost).
	ErrSingleLabel ErrCode = "singleLabel"
	// ErrInvalid is a generic fallback, currently unused by ValidateDomain
	// but kept so callers can represent unknown validation failures.
	ErrInvalid ErrCode = "invalid"
)

// ErrCodeToI18n maps every non-OK code to its i18n message key.
// WHY explicit table instead of string(code): the i18n keys live in another
// package and must stay in sync; the test enforces completeness.
var ErrCodeToI18n = map[ErrCode]string{
	ErrEmpty:        "err.emptyDomain",
	ErrTooLong:      "err.tooLong",
	ErrLabelTooLong: "err.labelTooLong",
	ErrBadChars:     "err.badChars",
	ErrSingleLabel:  "err.singleLabel",
	ErrInvalid:      "err.invalidDomain",
}

var labelRe = regexp.MustCompile(`^[a-z0-9-]+$`)

// ValidateDomain checks input and returns the display form, the ASCII lookup
// form, and the result code. No DNS or HTTP is performed.
//
// Order (PLAN.md v9 §5.4): TrimSpace, remove ONE trailing dot, empty check,
// single-label check (before idna, for a friendlier message), idna conversion
// (no manual ToLower — idna already does UTS46 case folding), length checks
// on the ASCII form (punycode expands), then per-label checks.
func ValidateDomain(input string) (original, ascii string, code ErrCode) {
	trimmed := strings.TrimSpace(input)
	// WHY single removal: "example.com." is a valid FQDN with root dot,
	// while "example.com.." contains an empty label and must fail below.
	original = strings.TrimSuffix(trimmed, ".")
	if original == "" {
		return original, "", ErrEmpty
	}
	// WHY before idna: "localhost" should say "use a FQDN", not "bad chars".
	if !strings.Contains(original, ".") {
		return original, "", ErrSingleLabel
	}
	a, err := idna.Lookup.ToASCII(original)
	if err != nil {
		return original, "", ErrBadChars
	}
	// WHY on the ASCII form: "münchen.de" is short in Unicode but longer
	// as "xn--mnchen-3ya.de"; limits apply to the wire form.
	if len(a) > 253 {
		return original, "", ErrTooLong
	}
	for _, label := range strings.Split(a, ".") {
		switch {
		case len(label) > 63:
			return original, "", ErrLabelTooLong
		case label == "":
			return original, "", ErrBadChars
		case !labelRe.MatchString(label):
			return original, "", ErrBadChars
		case strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-"):
			return original, "", ErrBadChars
		}
	}
	return original, a, ErrOK
}
