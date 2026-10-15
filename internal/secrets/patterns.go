// Package secrets hunts leaked frontend secrets in HTML and JavaScript.
package secrets

import (
	"regexp"
)

// patternDef pairs a stable pattern name with its compiled matcher.
// WHY stable names (not the regexp) in output: the report stays greppable
// (arquivo:linha:padrão) without depending on regexp syntax drift.
type patternDef struct {
	name string
	re   *regexp.Regexp
}

// Patterns are real-world secret shapes from the --secrets handoff.
// Verified signatures: regexp.MustCompile(string) *Regexp,
// (*Regexp).FindAllString(string, int) []string (pkg.go.dev/regexp,
// go1.27.2 docs, fetched 2026-10-15; toolchain go1.27.0 compatible).
var patterns = []patternDef{
	{name: "AWSAccessKey", re: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{name: "GitHubToken", re: regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`)},
	{name: "SlackToken", re: regexp.MustCompile(`xox[bpas]-[A-Za-z0-9-]+`)},
	{name: "PrivateKey", re: regexp.MustCompile(`BEGIN PRIVATE KEY`)},
	{name: "MongoURI", re: regexp.MustCompile(`mongodb(\+srv)?://[^ \t\r\n'"]+:[^ \t\r\n'"]+@`)},
	{name: "APIKey", re: regexp.MustCompile(`(?i)api[_-]?key\s*[:=]\s*['"][^'"]{8,}`)},
	{name: "Secret", re: regexp.MustCompile(`(?i)secret\s*[:=]\s*['"][^'"]{8,}`)},
}

// match is one regexp hit before masking.
type match struct {
	pattern string
	value   string
}

// matchLine returns every pattern hit in a single line.
func matchLine(line string) []match {
	var out []match
	for _, p := range patterns {
		for _, v := range p.re.FindAllString(line, -1) {
			out = append(out, match{pattern: p.name, value: v})
		}
	}
	return out
}

// Mask hides the middle of a secret for safe-by-default output.
// WHY first4+…+last4: proves which key leaked (prefix identifies the
// account) without printing the full value into terminal/CI/video logs.
// Short matches (<8) reveal nothing useful, so they become "****".
func Mask(v string) string {
	if len(v) < 8 {
		return "****"
	}
	return v[:4] + "…" + v[len(v)-4:]
}
