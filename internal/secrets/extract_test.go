package secrets

import (
	"strings"
	"testing"
)

func TestExtractScripts(t *testing.T) {
	t.Parallel()

	html := `<html><head><script src="/app.js"></script><script src="https://cdn.example.net/x.js"></script></head><body><script>var secret="12345678"</script></body></html>`
	inlines, srcs := ExtractScripts([]byte(html))
	if len(inlines) != 1 || !strings.Contains(inlines[0], "secret") {
		t.Errorf("inlines = %v, want 1 with secret", inlines)
	}
	if len(srcs) != 2 || srcs[0] != "/app.js" {
		t.Errorf("srcs = %v, want [/app.js cdn]", srcs)
	}
}

func TestExtractIgnoresDataBlob(t *testing.T) {
	t.Parallel()

	html := `<script src="data:text/javascript,alert(1)"></script><script src=""></script><script>ok</script>`
	_, srcs := ExtractScripts([]byte(html))
	if len(srcs) != 1 || !strings.HasPrefix(srcs[0], "data:") {
		t.Errorf("raw srcs = %v", srcs)
	}
	ordered, _ := SplitScripts(srcs, "https://example.com/")
	if len(ordered) != 0 {
		t.Errorf("data: must not be fetched, got %v", ordered)
	}
}

func TestSplitSameOriginFirst(t *testing.T) {
	t.Parallel()

	raw := []string{"https://third.example.net/a.js", "/app.js"}
	ordered, trunc := SplitScripts(raw, "https://example.com/page")
	if trunc {
		t.Error("2 scripts must not truncate")
	}
	if len(ordered) != 2 || !strings.Contains(ordered[0], "example.com/app.js") {
		t.Errorf("same-origin first, got %v", ordered)
	}
}

func TestSplitLimit10(t *testing.T) {
	t.Parallel()

	var raw []string
	for i := 0; i < 11; i++ {
		raw = append(raw, "/a.js")
	}
	ordered, trunc := SplitScripts(raw, "https://example.com/")
	if !trunc || len(ordered) != 10 {
		t.Errorf("11 scripts → 10 + truncated, got %d/%v", len(ordered), trunc)
	}
}
