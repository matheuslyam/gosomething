package secrets

import (
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// MaxScripts caps external .js fetches in --secrets mode.
// WHY 10: frontend pages often reference 5-15 bundles; 10 bounds total time
// under the global timeout while covering the common case. Overflow sets
// SecretsResult.Truncated instead of silently dropping.
const MaxScripts = 10

// ExtractScripts parses HTML and returns inline script bodies plus raw
// <script src> values in document order.
// Verified: html.Parse(io.Reader) (*Node, error),
// (*Node).Descendants() iter.Seq[*Node] (pkg.go.dev/golang.org/x/net/html,
// v0.61.0 docs, fetched 2026-10-15; already required in go.mod).
// WHY html.Parse over regexp: <script src> with single quotes, whitespace,
// case variants and comments break naive regexps; the parser is robust.
func ExtractScripts(body []byte) (inlines []string, srcs []string) {
	inlines = []string{}
	srcs = []string{}
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return inlines, srcs
	}
	for n := range doc.Descendants() {
		if n.Type != html.ElementNode || !strings.EqualFold(n.Data, "script") {
			continue
		}
		src := ""
		for _, a := range n.Attr {
			if strings.EqualFold(a.Key, "src") {
				src = strings.TrimSpace(a.Val)
				break
			}
		}
		if src != "" {
			srcs = append(srcs, src)
			continue
		}
		// WHY collect text children: inline secrets live in script bodies;
		// empty inline blocks contribute nothing and are skipped.
		var sb strings.Builder
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if c.Type == html.TextNode {
				sb.WriteString(c.Data)
			}
		}
		if sb.Len() > 0 {
			inlines = append(inlines, sb.String())
		}
	}
	return inlines, srcs
}

// SplitScripts resolves raw srcs against baseURL and orders same-origin
// first (document order preserved inside each group), capping at MaxScripts.
// WHY same-origin first: user decision 2026-10-15 — when >10 scripts, third
// parties are cut first because the authorized domain is the priority.
// Third parties are still fetched (user chose "tudo incluindo terceiros").
// Verified: url.Parse(string) (*URL, error),
// (*URL).ResolveReference(*URL) *URL, (*URL).Hostname() string
// (pkg.go.dev/net/url, go1.27.2 docs, fetched 2026-10-15).
func SplitScripts(rawSrcs []string, baseURL string) (ordered []string, truncated bool) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return []string{}, false
	}
	baseHost := strings.ToLower(strings.TrimSuffix(base.Hostname(), "."))
	var same, third []string
	for _, raw := range rawSrcs {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		l := strings.ToLower(s)
		// WHY skip non-fetchable: data:/blob:/javascript: are not HTTP and
		// would error noisily on fetch.
		if strings.HasPrefix(l, "data:") || strings.HasPrefix(l, "blob:") || strings.HasPrefix(l, "javascript:") {
			continue
		}
		ref, err := url.Parse(s)
		if err != nil {
			continue
		}
		resolved := base.ResolveReference(ref)
		if resolved.Scheme != "http" && resolved.Scheme != "https" {
			continue
		}
		h := strings.ToLower(strings.TrimSuffix(resolved.Hostname(), "."))
		if h == baseHost {
			same = append(same, resolved.String())
		} else {
			third = append(third, resolved.String())
		}
	}
	ordered = append(same, third...)
	if len(ordered) > MaxScripts {
		return ordered[:MaxScripts], true
	}
	return ordered, false
}
