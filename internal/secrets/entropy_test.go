package secrets

import (
	"context"
	"math/rand"
	"strings"
	"testing"

	"github.com/matheuslyam/gosomething/internal/httpfetch"
)

// Deterministic corpora: each test builds its fakes from math/rand with a
// FIXED per-test seed, so NO committed line contains a complete secret
// (push-protection convention), every length is exact by construction, and
// `-run` subsets behave identically to full runs (no shared stream).
// If a future Go release ever changes the NewSource stream, the count and
// separation assertions below fail loud — recalibrate then.
func randStr(rng *rand.Rand, alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rng.Intn(len(alphabet))]
	}
	return string(b)
}

const (
	alphaB64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	alphaHex = "0123456789abcdef"
)

func TestShannon_KnownValues(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want float64
	}{
		{"", 0},
		{"a", 0},
		{"aaaa", 0},
		{"ab", 1.0},
		{"abcabc", 1.584962500721156},
	}
	for _, tt := range cases {
		if got := shannon(tt.in); got < tt.want-0.001 || got > tt.want+0.001 {
			t.Errorf("shannon(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

// calibPos builds the 24 prefixless true positives (6 per collector class).
func calibPos(rng *rand.Rand) (aws, b64, env, hex []string) {
	for i := 0; i < 6; i++ {
		aws = append(aws, randStr(rng, alphaB64, 40))
		hex = append(hex, randStr(rng, alphaHex, []int{32, 32, 40, 40, 64, 64}[i]))
	}
	for _, n := range []int{32, 32, 48, 48, 64, 88} {
		b64 = append(b64, randStr(rng, alphaB64, n))
	}
	for i := 0; i < 6; i++ {
		env = append(env, randStr(rng, alphaB64[:62], 40))
	}
	return aws, b64, env, hex
}

// Shape-valid negatives: strings some collector CAN match but entropy must
// reject. WHY shape-valid only: prose with spaces never becomes a candidate
// (collector alphabets exclude space), so measuring it against a threshold
// proves nothing — prose is covered at line level in the table test.
// Counts locked: drift fails loud. Totals: 24 pos / (5+5+6+5=21 lock-neg +
// 13 table-neg) = 34 neg; english-with-assignment fires by design
// (residuals, asserted firing in the table test).
func calibNeg() (aws, b64, env, hex []string) {
	aws = []string{
		strings.Repeat("a", 40), strings.Repeat("deadbeef", 5)[:40],
		strings.Repeat("abcdefghij", 4), strings.Repeat("0123456789", 4),
		strings.Repeat("Password", 5)[:40],
	}
	b64 = []string{
		strings.Repeat("a", 32), strings.Repeat("a", 48),
		strings.Repeat("ab", 32), strings.Repeat("deadbeef", 8),
		strings.Repeat("abcdefghij", 5),
	}
	env = []string{
		"true", "production", "123456", "password",
		"abcdefghijklmnop", "0123456789abcdef",
	}
	hex = []string{
		strings.Repeat("a", 32), strings.Repeat("f", 40),
		strings.Repeat("deadbeef", 4), strings.Repeat("ab", 20),
		strings.Repeat("c0ffee", 6),
	}
	return aws, b64, env, hex
}

func minMax(ss []string) (float64, float64) {
	min, max := shannon(ss[0]), shannon(ss[0])
	for _, s := range ss[1:] {
		if h := shannon(s); h < min {
			min = h
		} else if h > max {
			max = h
		}
	}
	return min, max
}

func TestEntropyCalibration(t *testing.T) {
	// WHY this test exists: thresholds are measured, never chosen. Each
	// rule's positives must clear its threshold and its shape-valid true
	// negatives must stay below with ≥0.3 margin, or the test fails loud
	// instead of leaking FPs into exit 3 (which drives conditional video).
	// Proven by the calibration runs: bare-shape matching is IMPOSSIBLE at
	// zero FP (random-40 H~4.8 vs english-40 H~5.0 overlap fully), so
	// aws40/b64 join hex in requiring weak context; english-with-assignment
	// fires by design (decode-oracle is future work, residuals asserted in
	// the table test, never smuggled into the silence set).
	rng := rand.New(rand.NewSource(11))
	awsPos, b64Pos, envPos, hexPos := calibPos(rng)
	awsNeg, b64Neg, envNeg, hexNeg := calibNeg()
	if len(awsPos) != 6 || len(b64Pos) != 6 || len(envPos) != 6 || len(hexPos) != 6 ||
		len(awsNeg) != 5 || len(b64Neg) != 5 || len(envNeg) != 6 || len(hexNeg) != 5 {
		t.Fatalf("corpus drift: pos 6/6/6/6 neg 5/5/6/5, got %d/%d/%d/%d %d/%d/%d/%d",
			len(awsPos), len(b64Pos), len(envPos), len(hexPos),
			len(awsNeg), len(b64Neg), len(envNeg), len(hexNeg))
	}
	lock := []struct {
		name string
		pos  []string
		neg  []string
		thr  float64
	}{
		{"aws40", awsPos, awsNeg, entropyThresholdAWS},
		{"base64", b64Pos, b64Neg, entropyThresholdBase64},
		{"dotenv", envPos, envNeg, entropyThresholdEnv},
		{"hex", hexPos, hexNeg, entropyThresholdHex},
	}
	for _, l := range lock {
		minPos, _ := minMax(l.pos)
		_, maxNeg := minMax(l.neg)
		t.Logf("%-7s minPos=%.3f maxNeg=%.3f T=%.3f", l.name, minPos, maxNeg, l.thr)
		if !(minPos > l.thr) {
			t.Errorf("%s: min positive H=%.3f must clear T=%.3f", l.name, minPos, l.thr)
		}
		if !(maxNeg < l.thr) {
			t.Errorf("%s: max negative H=%.3f must stay below T=%.3f", l.name, maxNeg, l.thr)
		}
		if minPos-maxNeg < 0.3 {
			t.Errorf("%s: separation %.3f below 0.3 margin", l.name, minPos-maxNeg)
		}
	}
}

func TestEntropyCollectors_Table(t *testing.T) {
	t.Parallel()

	rng := rand.New(rand.NewSource(22))
	md5hello := "5d41402abc4b2a76b9719d911017c592" // md5("hello"), public
	uuidNil := "123e4567-e89b-12d3-a456-426614174000"
	shaTest := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00" // sha256("test"), public
	hexTok := randStr(rng, alphaHex, 32)
	b64blob := randStr(rng, alphaB64, 48)
	aws40 := randStr(rng, alphaB64, 40)
	eng60 := "dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw=="
	eng40 := "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0"
	cases := []struct {
		name string
		line string
		want bool // true = ≥1 HighEntropy finding
	}{
		// aws40/b64 need weak context (calibration-proven); bare goes silent.
		{"aws40 assigned fires", "key = " + aws40, true},
		{"aws40 bare silent (deviation, documented)", aws40, false},
		{"base64 assigned fires", "data = " + b64blob, true},
		{"base64 bare silent (deviation, documented)", b64blob, false},
		{"base64 short token fires", "token = " + randStr(rng, alphaB64, 32), true},
		{"dotenv unquoted fires", "DB_PASSWORD=" + randStr(rng, alphaB64[:62], 40), true},
		{"dotenv token fires", "APP_TOKEN=" + randStr(rng, alphaB64[:62], 48), true},
		{"hex with context fires", "token = " + hexTok, true},
		// WHY these fire by design: high-entropy English (or an md5) beside
		// an assignment is indistinguishable from a token without decoding;
		// Shannon is order-blind. Documented residuals, not bugs.
		{"english base64 assigned fires (residual)", "msg = " + eng60, true},
		{"english base64-40 assigned fires (residual)", "data = " + eng40, true},
		{"md5 with assignment fires (residual)", "hash = " + md5hello, true},
		{"bare md5 rejected (no context)", md5hello, false},
		{"bare uuid rejected (no context + dashes)", uuidNil, false},
		{"bare sha256 rejected (no context)", shaTest, false},
		{"bare english base64 silent (no context)", eng60, false},
		{"bare english base64-40 silent (no context)", eng40, false},
		{"short hex rejected by floor", "token = deadbeef", false},
		{"uniform hex rejected by entropy", "token = " + strings.Repeat("a", 32), false},
		{"dotenv boolean rejected", "DEBUG=true", false},
		{"dotenv port rejected", "PORT=3000", false},
		{"dotenv empty rejected", "EMPTY=", false},
		{"header short rejected", "X-Api-Key: short", false},
		{"prose rejected", "nothing to see here", false},
		{"kebab rejected", "data-foo-bar-baz-qux-quux-corge-grault", false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var hits []spanMatch
			for _, e := range entropySpans(tt.line, nil) {
				if e.pattern == HighEntropy {
					hits = append(hits, e)
				}
			}
			if tt.want && len(hits) == 0 {
				t.Errorf("line %q: want ≥1 HighEntropy, got none", tt.line)
			}
			if !tt.want && len(hits) != 0 {
				t.Errorf("line %q: want none, got %+v", tt.line, hits)
			}
		})
	}
}

func TestEntropyDedup(t *testing.T) {
	t.Parallel()

	// WHY: a value the named patterns already claim must not double-report
	// (e.g. sb_secret_ in dotenv also matches the 40-char collectors).
	line := "KEY=sb_secret_" + strings.Repeat("b", 24)
	named := matchLineSpans(line)
	occ := make([][2]int, 0, len(named))
	for _, n := range named {
		occ = append(occ, [2]int{n.start, n.end})
	}
	if len(named) == 0 {
		t.Fatalf("precondition: named must fire on %q", line)
	}
	if got := entropySpans(line, occ); len(got) != 0 {
		t.Errorf("dedup: entropy must skip named-claimed spans, got %+v", got)
	}
}

func TestScanEntropyBundle(t *testing.T) {
	t.Parallel()

	rng := rand.New(rand.NewSource(33))
	js := "const a = \"AKIAIOSFODNN7EXAMPLE\";\n" +
		"DB_PASSWORD=" + randStr(rng, alphaB64[:62], 40) + "\n" +
		"token = " + randStr(rng, alphaHex, 32) + "\n"
	deps := Deps{Fetch: stubBody{bodies: map[string]httpfetch.BodyResult{
		"https://example.com": {
			Body:     []byte(`<html><head><script src="/app.js"></script></head></html>`),
			FinalURL: "https://example.com/",
		},
		"https://example.com/app.js": {Body: []byte(js), FinalURL: "https://example.com/app.js"},
	}}}
	res, err := Scan(context.Background(), "example.com", "example.com", deps, false)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	var named, high int
	for _, f := range res.Findings {
		if f.Pattern == HighEntropy {
			high++
		} else {
			named++
		}
	}
	if named == 0 || high < 2 {
		t.Errorf("want named≥1 and HighEntropy≥2, got named=%d high=%d (%+v)", named, high, res.Findings)
	}
}
