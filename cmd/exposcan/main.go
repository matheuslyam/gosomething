// Command exposcan scans a domain for exposure signals: resolved IPs,
// CDN presence, security headers and open 80/443 ports.
//
// Exit codes: 0 scan completed (even partial with warnings), 1 network
// failure or timeout, 2 usage or validation error.
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
	var jsonOut bool
	fs.StringVar(&langFlag, "lang", "", "output language: en|pt (default auto)")
	fs.StringVar(&timeoutFlag, "timeout", "15s", "global timeout: 5s|10s|15s|30s")
	fs.BoolVar(&jsonOut, "json", false, "machine-readable JSON output")
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
		_ = json.NewEncoder(stdout).Encode(res)
	} else {
		printHuman(stdout, lang, res)
		fmt.Fprintln(stdout, i18n.T(lang, "msg.done"))
	}
	return 0
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
// headers and warnings sections. Tests assert keys, not full snapshots,
// because i18n wording may evolve.
func printHuman(stdout io.Writer, lang i18n.Lang, res exposcan.Result) {
	fmt.Fprintln(stdout, i18n.T(lang, "label.domain")+": "+res.Domain)
	fmt.Fprintln(stdout, i18n.T(lang, "label.punycode")+": "+res.Punycode)
	fmt.Fprintln(stdout, i18n.T(lang, "label.ips")+": "+strings.Join(res.IPs, ", "))
	fmt.Fprintln(stdout, i18n.T(lang, "label.cname")+": "+res.CNAME)
	fmt.Fprintln(stdout, i18n.T(lang, "label.cdn")+": "+res.CDN)
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
	if res.HTTPError != "" {
		fmt.Fprintln(stdout, "warnings: "+res.HTTPError)
	}
}

func openClosed(open bool) string {
	if open {
		return "open"
	}
	return "closed"
}
