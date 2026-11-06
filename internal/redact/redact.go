// Package redact removes secrets from strings before they reach reports or logs.
package redact

import (
	"context"
	"log/slog"
	"regexp"
	"strings"
)

// Mask is the replacement token for redacted secrets.
const Mask = "****REDACTED****"

// patterns that always indicate a secret value. The secret is the whole match
// unless the regex has a capture group, in which case only group 1 is masked.
var patterns = []*regexp.Regexp{
	regexp.MustCompile(`\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b`),
	regexp.MustCompile(`(gh[pousr]_[0-9a-zA-Z]{36,255})`),
	regexp.MustCompile(`(github_pat_\w{60,90})`),
	regexp.MustCompile(`(glpat-[\w-]{20})`),
	regexp.MustCompile(`(xox[baprs]-[0-9a-zA-Z-]{10,})`),
	regexp.MustCompile(`\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})`),
	regexp.MustCompile(`\b(AIza[\w-]{35})`),
	regexp.MustCompile(`\b(sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,})`),
	regexp.MustCompile(`\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9/\\_-]{17,}\.[a-zA-Z0-9/\\_-]{10,}={0,2})`),
	// PEM private key bodies (single line or the header itself).
	regexp.MustCompile(`(?s)(-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----|$))`),
	// password=... / token: "..." style assignments
	regexp.MustCompile(`(?i)(?:passw(?:or)?d|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth)["']?\s*(?:=|:|=>)\s*["']?([^\s"'` + "`" + `,;]{6,})`),
	// credentials in URLs: scheme://user:pass@host
	regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:([^\s@/]{3,})@`),
}

// String redacts every known secret pattern in s.
func String(s string) string {
	if s == "" {
		return s
	}
	for _, re := range patterns {
		s = replaceGroup(re, s)
	}
	return s
}

// Value masks an exact secret value wherever it appears in s, in addition to
// pattern redaction. Use it when a tool reports the raw secret separately.
func Value(s, secret string) string {
	if secret != "" && len(secret) >= 4 && secret != Mask {
		s = strings.ReplaceAll(s, secret, Mask)
	}
	return String(s)
}

func replaceGroup(re *regexp.Regexp, s string) string {
	if re.NumSubexp() == 0 {
		return re.ReplaceAllString(s, Mask)
	}
	return re.ReplaceAllStringFunc(s, func(m string) string {
		sub := re.FindStringSubmatchIndex(m)
		if len(sub) < 4 || sub[2] < 0 {
			return Mask
		}
		val := m[sub[2]:sub[3]]
		if val == Mask || strings.Contains(val, "REDACTED") || strings.HasPrefix(val, "${") || strings.HasPrefix(val, "$(") {
			return m
		}
		// A function call (os.getenv("X"), process.env.get(...)) is not a literal secret.
		if strings.ContainsAny(val, "()") {
			if i := strings.IndexByte(val, '('); i > 0 {
				return m[:sub[2]] + val[:i] + m[sub[2]+i:]
			}
		}
		return m[:sub[2]] + Mask + m[sub[3]:]
	})
}

// Handler is a slog.Handler wrapper that redacts message text and string attributes.
type Handler struct{ inner slog.Handler }

// NewHandler wraps h so that nothing secret-looking is ever logged.
func NewHandler(h slog.Handler) *Handler { return &Handler{inner: h} }

// Enabled implements slog.Handler.
func (h *Handler) Enabled(ctx context.Context, l slog.Level) bool { return h.inner.Enabled(ctx, l) }

// Handle implements slog.Handler.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	nr := slog.NewRecord(r.Time, r.Level, String(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		nr.AddAttrs(redactAttr(a))
		return true
	})
	return h.inner.Handle(ctx, nr)
}

// WithAttrs implements slog.Handler.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		out[i] = redactAttr(a)
	}
	return &Handler{inner: h.inner.WithAttrs(out)}
}

// WithGroup implements slog.Handler.
func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{inner: h.inner.WithGroup(name)}
}

func redactAttr(a slog.Attr) slog.Attr {
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindString:
		return slog.String(a.Key, String(v.String()))
	case slog.KindGroup:
		g := v.Group()
		out := make([]any, 0, len(g))
		for _, ga := range g {
			out = append(out, redactAttr(ga))
		}
		return slog.Group(a.Key, out...)
	default:
		return a
	}
}
