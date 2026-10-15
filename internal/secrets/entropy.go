package secrets

import (
	"math"
	"regexp"
)

// This file implements the phase-2 double verification (ADR-0010): named
// regexps stay the primary signal (matchLine is untouched); prefixless
// collectors below only become findings when Shannon entropy confirms them.
// WHY confirming-only: raw entropy over bundle text is a false-positive
// factory (hashes, UUIDs, prose); shape first, entropy second.

// HighEntropy is the single Pattern name for all entropy confirmations.
// WHY one name: every class means the same triage action ("high-entropy
// blob, investigate"); the masked prefix shows which shape fired.
const HighEntropy = "HighEntropy"

// entropyThresholdHigh gates base64-alphabet classes (AWS-40, base64 runs,
// dotenv values): 64-symbol alphabet, random material lands near 6 bits.
// entropyThresholdHex gates 16-symbol hex: random lands near 4.0, so the
// hex collector ALSO requires weak context (an md5/UUID has exactly the
// same entropy as a token — Shannon alone cannot separate them).
// Both values come from the calibration run (TestEntropyCalibration);
// the test fails loud if the separation ever breaks.
const (
	// Calibrated per rule (TestEntropyCalibration locks each with ≥0.3
	// margin; measured values in ADR-0010):
	// aws40/dotenv 4.4 (real 40-char draws land ~4.5-5.5; 4.6+ would miss
	// a visible share of true 40s — proven by a red run, not by opinion),
	// base64 4.2 (32-char draws clear ~4.3; lows stay <3.8),
	// hex 3.0 (random hex clears ~3.6; uniform/repetitive stay <2.4).
	entropyThresholdAWS    = 4.4
	entropyThresholdBase64 = 4.2
	entropyThresholdEnv    = 4.4
	entropyThresholdHex    = 3.0
)

// entropyRule is one prefixless collector: exactly one capture group holds
// the candidate; needContext demands a weak assignment/label signal on the
// same line before entropy is even measured.
type entropyRule struct {
	name        string
	re          *regexp.Regexp
	threshold   float64
	needContext bool
}

var entropyRules = []entropyRule{
	{
		// WHY context-gated (not bare): the calibration run proved a bare
		// 40-char random blob (H~4.8) and bare base64-English (H~5.0) fully
		// overlap — no threshold separates them, so bare matching at zero
		// FP is impossible. The assignment is the second verification.
		name:        HighEntropy,
		re:          regexp.MustCompile(`(?:^|[^A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?:[^A-Za-z0-9/+=]|$)`),
		threshold:   entropyThresholdAWS,
		needContext: true,
	},
	{
		// WHY context-gated: same proof (random-32 H~4.3 vs english H~4.9).
		name:        HighEntropy,
		re:          regexp.MustCompile(`(?:^|[^A-Za-z0-9+/=])([A-Za-z0-9+/]{32,}={0,2})(?:[^A-Za-z0-9+/=]|$)`),
		threshold:   entropyThresholdBase64,
		needContext: true,
	},
	{
		// WHY line-anchored KEY=value: the assignment IS the weak context;
		// quoted values already belong to the named generics (dedup below).
		name:      HighEntropy,
		re:        regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\s*=\s*["']?([A-Za-z0-9/+=._-]{12,})["']?$`),
		threshold: entropyThresholdEnv,
	},
	{
		name:        HighEntropy,
		re:          regexp.MustCompile(`([0-9a-fA-F]{32,})`),
		threshold:   entropyThresholdHex,
		needContext: true,
	},
}

// contextHint is the weak signal a hex candidate needs on its line.
// WHY so broad: it only opens the door to the entropy measurement, which
// does the actual discrimination; bare hashes/UUIDs never reach it.
var contextHint = regexp.MustCompile(`(?i)(=|:|key|token|secret|auth|password|passwd|pwd|credential|hash|salt|nonce|session|api)`)

// spanMatch is a finding with byte offsets, so overlapping spans dedup.
type spanMatch struct {
	pattern string
	value   string
	start   int
	end     int
}

// matchLineSpans runs the named patterns with positions.
func matchLineSpans(line string) []spanMatch {
	var out []spanMatch
	for _, p := range patterns {
		for _, loc := range p.re.FindAllStringIndex(line, -1) {
			out = append(out, spanMatch{pattern: p.name, value: line[loc[0]:loc[1]], start: loc[0], end: loc[1]})
		}
	}
	return out
}

// entropySpans runs prefixless collectors, skipping spans the named
// patterns already claimed (named always wins → no double report) and
// spans already taken by an earlier rule.
func entropySpans(line string, occupied [][2]int) []spanMatch {
	var out []spanMatch
	for _, r := range entropyRules {
		for _, loc := range r.re.FindAllStringSubmatchIndex(line, -1) {
			s, e := loc[2], loc[3]
			if s < 0 || overlaps(s, e, occupied) {
				continue
			}
			// WHY context is measured OUTSIDE the candidate span: a signal
			// inside the candidate is not context (base64 padding `==`
			// would otherwise fake an assignment signal on bare blobs).
			if r.needContext && !contextHint.MatchString(line[:s]+" "+line[e:]) {
				continue
			}
			if shannon(line[s:e]) < r.threshold {
				continue
			}
			out = append(out, spanMatch{pattern: r.name, value: line[s:e], start: s, end: e})
			occupied = append(occupied, [2]int{s, e})
		}
	}
	return out
}

func overlaps(s, e int, occupied [][2]int) bool {
	for _, o := range occupied {
		if s < o[1] && o[0] < e {
			return true
		}
	}
	return false
}

// shannon returns per-character Shannon entropy in bits over the raw bytes.
// Short or uniform strings score ~0; random base64 lands near 6.
// math.Log2 needs no conversion table: it is exact for this use.
func shannon(s string) float64 {
	if len(s) < 2 {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	var h float64
	n := float64(len(s))
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
