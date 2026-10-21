// Command exposcan scans a domain for exposure signals: resolved IPs,
// CDN presence, security headers and open 80/443 ports. With --secrets it
// hunts leaked frontend secrets in HTML and JavaScript instead.
//
// Exit codes: 0 scan completed (even partial with warnings, or --secrets
// with no findings), 1 network failure or timeout, 2 usage or validation
// error, 3 --secrets found at least one potential secret.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/matheuslyam/gosomething/internal/dns"
	"github.com/matheuslyam/gosomething/internal/exposcan"
	"github.com/matheuslyam/gosomething/internal/httpfetch"
	"github.com/matheuslyam/gosomething/internal/i18n"
	"github.com/matheuslyam/gosomething/internal/ports"
	"github.com/matheuslyam/gosomething/internal/secrets"
	"github.com/matheuslyam/gosomething/internal/validate"
)

// allowedTimeouts is the closed set for --timeout (PLAN.md v9 §5.2).
var allowedTimeouts = map[string]time.Duration{
	"5s":  5 * time.Second,
	"10s": 10 * time.Second,
	"15s": 15 * time.Second,
	"30s": 30 * time.Second,
}

// ErrorEnvelope is the JSON shape for failures (Result has no error field).
type ErrorEnvelope struct {
	Domain string `json:"domain"`
	Error  string `json:"error"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout))
}

// peekLang finds --lang (both "--lang pt" and "--lang=pt") for early language
// detection. It only decides the message language, never flag validity.
func peekLang(args []string) string {
	for i, a := range args {
		if a == "--lang" && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(a, "--lang=") {
			return strings.TrimPrefix(a, "--lang=")
		}
	}
	return ""
}

// secretsDeps builds the production body fetcher already capped by the
// global timeout (no inner timeout may exceed it).
func secretsDeps(global time.Duration) secrets.Deps {
	bodyTimeout := 10 * time.Second
	if global < bodyTimeout {
		bodyTimeout = global
	}
	return secrets.Deps{Fetch: httpfetch.New(bodyTimeout)}
}

// realDeps builds production collaborators already capped by the global
// timeout (no inner timeout may exceed it).
func realDeps(global time.Duration) exposcan.Deps {
	httpTimeout := 10 * time.Second
	if global < httpTimeout {
		httpTimeout = global
	}
	dialTimeout := 5 * time.Second
	if global < dialTimeout {
		dialTimeout = global
	}
	return exposcan.Deps{
		DNS:  dns.NetResolver{},
		HTTP: httpfetch.New(httpTimeout),
		Dial: ports.NetDialer{Timeout: dialTimeout},
	}
}

// run executes the CLI returning the process exit code instead of exiting,
// so tests can assert exits without killing the test process.
func run(args []string, getenv func(string) string, stdout io.Writer) int {
	lang := i18n.Detect(peekLang(args), getenv)

	fs := flag.NewFlagSet("exposcan", flag.ContinueOnError)
	// WHY SetOutput(stdout): default CommandLine writes to stderr and exits;
	// routing to stdout makes --help and errors capturable in tests.
	fs.SetOutput(stdout)
	fs.Usage = func() {
		fmt.Fprintln(stdout, i18n.T(lang, "usage"))
		fs.PrintDefaults()
	}
	var langFlag, timeoutFlag string
	var jsonOut, secretsMode, reveal, showCookies, verbose bool
	fs.StringVar(&langFlag, "lang", "", "output language: en|pt (default auto)")
	fs.StringVar(&timeoutFlag, "timeout", "15s", "global timeout: 5s|10s|15s|30s")
	fs.BoolVar(&jsonOut, "json", false, "machine-readable JSON output")
	fs.BoolVar(&showCookies, "show-cookies", false, "show full Set-Cookie values (masked by default)")
	fs.BoolVar(&verbose, "verbose", false, "explain which signal fired each heuristic")
	fs.BoolVar(&secretsMode, "secrets", false, "hunt leaked frontend secrets instead of the exposure scan")
	fs.BoolVar(&reveal, "reveal", false, "show full secret values (leaks to logs/video)")
	// WHY alias "rv" shares the same var: Go flag accepts -/-- equivalently,
	// so this gives --reveal plus the short -rv the user asked for (and --rv
	// as a bonus). Short flags use one hyphen by CLI convention (--help/-h).
	fs.BoolVar(&reveal, "rv", false, "alias for --reveal")
	if err := fs.Parse(args); err != nil {
		// WHY ErrHelp → 0: asking for help is not an error (Unix convention).
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if timeoutFlag == "" {
		timeoutFlag = "15s"
	}
	global, ok := allowedTimeouts[timeoutFlag]
	if !ok {
		emitError(stdout, jsonOut, "", i18n.T(lang, "err.badTimeout", timeoutFlag))
		return 2
	}
	if langFlag != "" {
		switch strings.ToLower(strings.TrimSpace(langFlag)) {
		case "en", "en-us", "en_us", "pt", "pt-br", "pt_br":
			lang = i18n.Detect(langFlag, getenv)
		default:
			emitError(stdout, jsonOut, "", i18n.T(lang, "err.badLang", langFlag))
			return 2
		}
	}
	// WHY --reveal needs --secrets: the normal scan never handles secrets,
	// so a stray --reveal there would silently do nothing (or worse, train
	// users to pass a leak flag by default). Fail loud with exit 2.
	if reveal && !secretsMode {
		emitError(stdout, jsonOut, "", i18n.T(lang, "err.badReveal"))
		return 2
	}
	// WHY strict NArg: the contract is exactly 1 FQDN; 0 args and 2+ args
	// (including flags placed after the positional) both fail instead of
	// silently using the first.
	if fs.NArg() != 1 {
		domain := ""
		if fs.NArg() > 0 {
			domain = fs.Arg(0)
		}
		emitError(stdout, jsonOut, domain, i18n.T(lang, "err.noDomain"))
		return 2
	}
	original, ascii, code := validate.ValidateDomain(fs.Arg(0))
	if code != validate.ErrOK {
		emitError(stdout, jsonOut, original, i18n.T(lang, validate.ErrCodeToI18n[code], original))
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), global)
	defer cancel()
	if secretsMode {
		return runSecrets(ctx, stdout, lang, jsonOut, original, ascii, global, reveal)
	}
	if !jsonOut {
		fmt.Fprintln(stdout, i18n.T(lang, "msg.scanning", original))
	}
	res, err := exposcan.Scan(ctx, original, ascii, realDeps(global))
	if err != nil {
		// WHY message mapping here (not in Scan): Scan preserves the error
		// chain; only the CLI knows the user language.
		msg := i18n.T(lang, "err.dnsFail", original, err)
		if httpfetch.IsTimeout(err) {
			msg = i18n.T(lang, "err.timeout", original)
		}
		emitError(stdout, jsonOut, original, msg)
		return 1
	}
	if jsonOut {
		// WHY mask at the edge like human output: Result.Cookies always
		// holds raw values (collection), redaction happens on render;
		// --json without the flag must never exfiltrate sessions to disk.
		if !showCookies {
			res.Cookies = exposcan.MaskCookies(res.Cookies)
		}
		_ = json.NewEncoder(stdout).Encode(res)
	} else {
		printHuman(stdout, lang, res, showCookies, verbose)
		fmt.Fprintln(stdout, i18n.T(lang, "msg.done"))
	}
	return 0
}

// runSecrets executes the --secrets mode with production collaborators.
func runSecrets(ctx context.Context, stdout io.Writer, lang i18n.Lang, jsonOut bool, original, ascii string, global time.Duration, reveal bool) int {
	return runSecretsWith(ctx, stdout, lang, jsonOut, original, ascii, secretsDeps(global), reveal)
}

// runSecretsWith is the testable core of --secrets (Deps injected): exit 0
// clean, 3 with findings, 1 on total network/timeout failure. Partial
// single-file failures never abort (skipped inside secrets.Scan).
// WHY split from runSecrets: run() hardcodes production deps (like the
// normal scan path), so the exit-3 mapping would otherwise be untestable
// without real network (QA round 1, SC-01).
func runSecretsWith(ctx context.Context, stdout io.Writer, lang i18n.Lang, jsonOut bool, original, ascii string, deps secrets.Deps, reveal bool) int {
	if !jsonOut {
		fmt.Fprintln(stdout, i18n.T(lang, "msg.scanningSecrets", original))
	}
	res, err := secrets.Scan(ctx, original, ascii, deps, reveal)
	if err != nil {
		// WHY httpFail (not dnsFail): --secrets never does a DNS lookup, it
		// fetches HTTP bodies directly; only the CLI knows the language.
		msg := i18n.T(lang, "err.httpFail", original, err)
		if httpfetch.IsTimeout(err) {
			msg = i18n.T(lang, "err.timeout", original)
		}
		emitError(stdout, jsonOut, original, msg)
		return 1
	}
	if jsonOut {
		_ = json.NewEncoder(stdout).Encode(res)
	} else {
		printSecretsHuman(stdout, lang, res, reveal)
		fmt.Fprintln(stdout, i18n.T(lang, "msg.done"))
	}
	// WHY exit 3: scripts (conditional video) need a distinct code for
	// "completed with findings" vs "completed clean" (0).
	if len(res.Findings) > 0 {
		return 3
	}
	return 0
}

// printSecretsHuman renders arquivo:linha:padrão plus mask (and full value
// only with --reveal). Tests assert keys, not full snapshots.
func printSecretsHuman(stdout io.Writer, lang i18n.Lang, res secrets.SecretsResult, reveal bool) {
	fmt.Fprintln(stdout, i18n.T(lang, "label.domain")+": "+res.Domain)
	fmt.Fprintln(stdout, i18n.T(lang, "msg.filesScanned", res.FilesScanned, res.Truncated))
	if len(res.Findings) == 0 {
		fmt.Fprintln(stdout, i18n.T(lang, "msg.secretsClean"))
		return
	}
	fmt.Fprintln(stdout, i18n.T(lang, "msg.secretsFound", len(res.Findings)))
	fmt.Fprintln(stdout, i18n.T(lang, "label.secrets")+":")
	for _, f := range res.Findings {
		if reveal && f.Value != "" {
			fmt.Fprintf(stdout, "  %s:%d:%s %s %s\n", f.File, f.Line, f.Pattern, f.Masked, f.Value)
		} else {
			fmt.Fprintf(stdout, "  %s:%d:%s %s\n", f.File, f.Line, f.Pattern, f.Masked)
		}
	}
}

// emitError prints either the JSON envelope or the plain message.
func emitError(stdout io.Writer, jsonOut bool, domain, msg string) {
	if jsonOut {
		_ = json.NewEncoder(stdout).Encode(ErrorEnvelope{Domain: domain, Error: msg})
		return
	}
	fmt.Fprintln(stdout, msg)
}

// printHuman renders the k: v contract (PLAN.md v9 §5.10): fixed keys plus
// headers, cookies and warnings sections. verbose adds the why section
// (Reasons, fixed key order). Tests assert keys, not full snapshots,
// because i18n wording may evolve.
func printHuman(stdout io.Writer, lang i18n.Lang, res exposcan.Result, showCookies, verbose bool) {
	fmt.Fprintln(stdout, i18n.T(lang, "label.domain")+": "+res.Domain)
	fmt.Fprintln(stdout, i18n.T(lang, "label.punycode")+": "+res.Punycode)
	fmt.Fprintln(stdout, i18n.T(lang, "label.ips")+": "+strings.Join(res.IPs, ", "))
	fmt.Fprintln(stdout, i18n.T(lang, "label.cname")+": "+res.CNAME)
	fmt.Fprintln(stdout, i18n.T(lang, "label.cdn")+": "+res.CDN)
	fmt.Fprintln(stdout, i18n.T(lang, "label.waf")+": "+res.WAF)
	fmt.Fprintln(stdout, i18n.T(lang, "label.asns")+":")
	for _, a := range res.ASNs {
		fmt.Fprintln(stdout, "  "+formatASN(a))
	}
	fmt.Fprintf(stdout, "%s: 80=%s 443=%s\n", i18n.T(lang, "label.ports"), openClosed(res.Ports[80]), openClosed(res.Ports[443]))
	fmt.Fprintf(stdout, "%s: %v\n", i18n.T(lang, "label.hsts"), res.HSTS)
	fmt.Fprintf(stdout, "%s: %v\n", i18n.T(lang, "label.csp"), res.CSP)
	fmt.Fprintf(stdout, "%s: %v\n", i18n.T(lang, "label.server"), res.ServerPresent)
	fmt.Fprintln(stdout, i18n.T(lang, "label.headers")+":")
	for k, v := range res.Headers {
		fmt.Fprintln(stdout, "  "+k+": "+v)
	}
	if res.HasSetCookie {
		fmt.Fprintln(stdout, "  set-cookie: (present)")
	}
	cookies := res.Cookies
	if !showCookies {
		cookies = exposcan.MaskCookies(cookies)
	}
	fmt.Fprintln(stdout, i18n.T(lang, "label.cookies")+":")
	for _, c := range cookies {
		fmt.Fprintln(stdout, "  "+c)
	}
	if verbose {
		fmt.Fprintln(stdout, i18n.T(lang, "label.why")+":")
		for _, k := range []string{"cdn", "waf", "hsts", "csp", "server"} {
			fmt.Fprintln(stdout, "  "+k+": "+res.Reasons[k])
		}
	}
	if res.HTTPError != "" {
		fmt.Fprintln(stdout, "warnings: "+res.HTTPError)
	}
}

// formatASN renders one ASN record. CC/registry print with a "reg" prefix
// on purpose: they are registry provenance (which RIR holds the record),
// never geolocation — anycast makes "CC as server location" false.
func formatASN(a dns.ASNRecord) string {
	if a.Org == "unknown" {
		return a.IP + " -> unknown"
	}
	return fmt.Sprintf("%s -> AS%d (%s, %s, reg %s/%s)", a.IP, a.ASN, a.Org, a.Prefix, a.CC, a.Registry)
}

func openClosed(open bool) string {
	if open {
		return "open"
	}
	return "closed"
}
