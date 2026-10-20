// Package i18n provides bilingual user-facing messages for exposcan.
//
// Supported languages are American English (default, for building in public)
// and Brazilian Portuguese. Every string shown to the user must go through
// T so both languages are always available; technical logs stay in English.
package i18n

import (
	"fmt"
	"strings"
)

// Lang is a BCP 47 language tag supported by the CLI.
type Lang string

const (
	// EN is American English, the default language.
	EN Lang = "en-US"
	// PT is Brazilian Portuguese, selected via --lang pt or LANG/LC_ALL=pt*.
	PT Lang = "pt-BR"
)

// Detect resolves the effective language.
//
// Precedence: explicit --lang flag, then LC_ALL, then LANG, then default EN.
// WHY LC_ALL before LANG: standard libc precedence (LC_ALL overrides LANG).
// WHY unknown flag values map to EN here instead of erroring: flag validity
// (err.badLang) is reported by main; Detect only chooses the language used to
// render that error, and defaulting to EN keeps the message readable.
func Detect(flag string, getEnv func(string) string) Lang {
	switch strings.ToLower(strings.TrimSpace(flag)) {
	case "pt", "pt-br", "pt_br":
		return PT
	case "en", "en-us", "en_us":
		return EN
	case "":
		// Fall through to environment lookup below.
	default:
		return EN
	}
	for _, key := range []string{"LC_ALL", "LANG"} {
		v := strings.ToLower(strings.TrimSpace(getEnv(key)))
		if v == "" {
			continue
		}
		// WHY first set variable wins: LC_ALL=en + LANG=pt must resolve
		// to EN (standard libc precedence). A non-pt value is a decision
		// for EN, not a reason to keep looking.
		if strings.HasPrefix(v, "pt") {
			return PT
		}
		return EN
	}
	return EN
}

// T translates key into language l, formatting with args.
//
// Fallback: requested language, then EN, then "[missing:key]" (never "").
// WHY never "": a missing key must be loud in tests and output instead of
// rendering an empty line that looks like success.
func T(l Lang, key string, args ...any) string {
	if m, ok := messages[l]; ok {
		if s, ok := m[key]; ok {
			return fmt.Sprintf(s, args...)
		}
	}
	if s, ok := messages[EN][key]; ok {
		return fmt.Sprintf(s, args...)
	}
	return "[missing:" + key + "]"
}

var messages = map[Lang]map[string]string{
	EN: {
		"usage":               "Usage: exposcan [--lang en|pt] [--timeout 5s|10s|15s|30s] [--json] [--secrets] [--reveal|-rv] <domain>",
		"msg.scanning":        "Scanning %s...",
		"msg.done":            "Done.",
		"err.noDomain":        "Oops! No domain given. Try: exposcan example.com",
		"err.emptyDomain":     "Oops! %q doesn't look like a valid domain. Try: example.com",
		"err.invalidDomain":   "Oops! %q doesn't look like a valid domain. Try: example.com",
		"err.tooLong":         "Oops! %q is too long (max 253 characters). Try: example.com",
		"err.labelTooLong":    "Oops! A label in %q is too long (max 63 characters per label).",
		"err.badChars":        "Oops! %q has invalid characters. Use letters, numbers, hyphens and dots. Try: example.com",
		"err.singleLabel":     "Oops! %q is not a fully-qualified domain. Try a FQDN like: example.com",
		"err.badTimeout":      "Oops! Invalid --timeout %q. Use one of: 5s, 10s, 15s, 30s.",
		"err.badLang":         "Oops! Invalid --lang %q. Use: en or pt.",
		"err.dnsFail":         "Network error: could not resolve %q (%v). Check your connection and try again.",
		"err.httpFail":        "Network error: could not fetch %q (%v). The site may be down.",
		"err.timeout":         "Timed out while scanning %q. Try again or use --timeout 30s.",
		"err.badReveal":       "Oops! --reveal needs --secrets. Try: exposcan --secrets example.com",
		"msg.scanningSecrets": "Scanning %s for leaked secrets...",
		"msg.secretsFound":    "Found %d potential secrets.",
		"msg.secretsClean":    "No secrets found.",
		"msg.filesScanned":    "files: %d scanned (truncated: %v)",
		"label.domain":        "domain",
		"label.punycode":      "punycode",
		"label.ips":           "ips",
		"label.cname":         "cname",
		"label.cdn":           "cdn",
		"label.waf":           "waf",
		"label.ports":         "ports",
		"label.headers":       "headers",
		"label.hsts":          "hsts",
		"label.csp":           "csp",
		"label.server":        "server",
		"label.secrets":       "secrets",
		"label.files":         "files",
		"cdn.unknown":         "unknown",
		"waf.unknown":         "unknown",
	},
	PT: {
		"usage":               "Uso: exposcan [--lang en|pt] [--timeout 5s|10s|15s|30s] [--json] [--secrets] [--reveal|-rv] <dominio>",
		"msg.scanning":        "Analisando %s...",
		"msg.done":            "Concluído.",
		"err.noDomain":        "Ops! Nenhum domínio informado. Tente: exposcan exemplo.com",
		"err.emptyDomain":     "Ops! %q não parece um domínio válido. Tente: exemplo.com",
		"err.invalidDomain":   "Ops! %q não parece um domínio válido. Tente: exemplo.com",
		"err.tooLong":         "Ops! %q é longo demais (máximo 253 caracteres). Tente: exemplo.com",
		"err.labelTooLong":    "Ops! Um rótulo de %q é longo demais (máximo 63 caracteres por rótulo).",
		"err.badChars":        "Ops! %q tem caracteres inválidos. Use letras, números, hífen e ponto. Tente: exemplo.com",
		"err.singleLabel":     "Ops! %q não é um domínio totalmente qualificado. Tente um FQDN como: exemplo.com",
		"err.badTimeout":      "Ops! --timeout %q inválido. Use um de: 5s, 10s, 15s, 30s.",
		"err.badLang":         "Ops! --lang %q inválido. Use: en ou pt.",
		"err.dnsFail":         "Erro de rede: não foi possível resolver %q (%v). Verifique sua conexão e tente de novo.",
		"err.httpFail":        "Erro de rede: não foi possível buscar %q (%v). O site pode estar fora do ar.",
		"err.timeout":         "Tempo esgotado analisando %q. Tente de novo ou use --timeout 30s.",
		"err.badReveal":       "Ops! --reveal precisa de --secrets. Tente: exposcan --secrets exemplo.com",
		"msg.scanningSecrets": "Analisando %s em busca de segredos vazados...",
		"msg.secretsFound":    "%d possíveis segredos encontrados.",
		"msg.secretsClean":    "Nenhum segredo encontrado.",
		"msg.filesScanned":    "arquivos: %d analisados (truncado: %v)",
		"label.domain":        "dominio",
		"label.punycode":      "punycode",
		"label.ips":           "ips",
		"label.cname":         "cname",
		"label.cdn":           "cdn",
		"label.waf":           "waf",
		"label.ports":         "portas",
		"label.headers":       "cabecalhos",
		"label.hsts":          "hsts",
		"label.csp":           "csp",
		"label.server":        "servidor",
		"label.secrets":       "segredos",
		"label.files":         "arquivos",
		"cdn.unknown":         "desconhecido",
		"waf.unknown":         "desconhecido",
	},
}
