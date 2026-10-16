package aarvion

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	SummaryMax     = 200
	summaryMissing = "?"
)

func FallbackCatalog() map[string]any {
	return map[string]any{
		"fallback": map[string]any{"http": "{method} {host}{path}", "tool": "Run {tool}"},
		"packs":    map[string]any{},
	}
}

var (
	parkRuleID    = regexp.MustCompile(`^starter\.([a-z0-9_]+)(?:\.(.+))?\.v[0-9]+$`)
	parkName      = `[a-z]+(?:\.[A-Za-z0-9_.-]+)?`
	parkToken     = regexp.MustCompile(`\{(` + parkName + `(?:\|` + parkName + `)*)\}`)
	parkControl   = regexp.MustCompile(`[\x00-\x1f\x{7f}-\x{9f}\x{2028}\x{2029}]`)
	parkSpaces    = regexp.MustCompile(` {2,}`)
	parkPercentRe = regexp.MustCompile(`%([0-9A-Fa-f]{2})`)
)

type catalogPack struct {
	pack map[string]any
	rule string
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

func strOr(v any) string {
	s, _ := v.(string)
	return s
}

func catalogPacks(ruleIDs []string, catalog map[string]any) []catalogPack {
	seen := map[string]bool{}
	ids := []string{}
	for _, id := range ruleIDs {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	packs := asMap(catalog["packs"])
	out := []catalogPack{}
	for _, id := range ids {
		m := parkRuleID.FindStringSubmatch(id)
		if m == nil {
			continue
		}
		if p, ok := packs[m[1]]; ok {
			out = append(out, catalogPack{pack: asMap(p), rule: m[2]})
		}
	}
	return out
}

func VolatileFor(ruleIDs []string, kind string, catalog map[string]any) []string {
	fields := map[string]bool{}
	for _, cp := range catalogPacks(ruleIDs, catalog) {
		list, _ := asMap(cp.pack["volatile"])[kind].([]any)
		for _, f := range list {
			if s, ok := f.(string); ok {
				fields[s] = true
			}
		}
	}
	out := make([]string, 0, len(fields))
	for f := range fields {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

func TemplateFor(ruleIDs []string, kind string, catalog map[string]any) string {
	type entry struct {
		summary map[string]any
		rule    string
	}
	var entries []entry
	for _, cp := range catalogPacks(ruleIDs, catalog) {
		entries = append(entries, entry{asMap(asMap(cp.pack["summary"])[kind]), cp.rule})
	}
	for _, e := range entries {
		if t, ok := asMap(e.summary["rules"])[e.rule].(string); ok {
			return t
		}
	}
	for _, e := range entries {
		if t, ok := e.summary["default"].(string); ok {
			return t
		}
	}
	if t, ok := asMap(catalog["fallback"])[kind].(string); ok {
		return t
	}
	return asMap(FallbackCatalog()["fallback"])[kind].(string)
}

func capSummary(text string) string {
	if utf8.RuneCountInString(text) <= SummaryMax {
		return text
	}
	return string([]rune(text)[:SummaryMax-3]) + "..."
}

func cleanSummary(text string) string {
	return strings.Trim(parkSpaces.ReplaceAllString(parkControl.ReplaceAllString(text, " "), " "), " ")
}

func summaryText(v any) string {
	switch x := v.(type) {
	case string:
		return cleanSummary(x)
	case bool:
		if x {
			return "true"
		}
		return "false"
	case int64, int, float64:
		s, err := Canonicalize(x)
		if err != nil {
			return ""
		}
		return s
	}
	if _, ok := v.(interface{ IsInt64() bool }); ok {
		s, err := Canonicalize(v)
		if err != nil {
			return ""
		}
		return s
	}
	return ""
}

func formDecode(raw string) (string, bool) {
	b := []byte(strings.ReplaceAll(raw, "+", " "))
	b = parkPercentRe.ReplaceAllFunc(b, func(m []byte) []byte {
		n, _ := strconv.ParseUint(string(m[1:]), 16, 8)
		return []byte{byte(n)}
	})
	if !utf8.Valid(b) {
		return "", false
	}
	return string(b), true
}

func formFields(encoded string) map[string]any {
	fields := map[string]any{}
	for _, part := range strings.Split(encoded, "&") {
		k, v, _ := strings.Cut(part, "=")
		key, ok := formDecode(k)
		if !ok || key == "" {
			continue
		}
		val, ok := formDecode(v)
		if !ok {
			continue
		}
		if _, exists := fields[key]; !exists {
			fields[key] = val
		}
	}
	return fields
}

func bodyFields(body []byte, contentType string) map[string]any {
	if isJSONContentType(contentType) {
		v, err := loadsStrictJSON(body)
		if err != nil {
			return map[string]any{}
		}
		if m, ok := v.(map[string]any); ok {
			return m
		}
		return map[string]any{}
	}
	mime, _, _ := strings.Cut(contentType, ";")
	if strings.ToLower(pyStrip(mime)) == "application/x-www-form-urlencoded" {
		if !utf8.Valid(body) {
			return map[string]any{}
		}
		return formFields(string(body))
	}
	return map[string]any{}
}

type SummaryAction struct {
	Kind        string
	Method      string
	Host        string
	Path        string
	Query       string
	ContentType string
	Body        []byte
	Tool        string
	Args        any
}

func (a SummaryAction) values() map[string]any {
	if a.Kind == "tool" {
		values := map[string]any{"tool": a.Tool}
		for k, v := range asMap(a.Args) {
			values["args."+k] = v
		}
		return values
	}
	values := map[string]any{"method": strings.ToUpper(a.Method), "host": strings.ToLower(a.Host), "path": a.Path}
	i := 0
	for _, seg := range strings.Split(a.Path, "/") {
		if seg == "" {
			continue
		}
		i++
		values["path."+strconv.Itoa(i)] = seg
	}
	for k, v := range formFields(a.Query) {
		values["query."+k] = v
	}
	for k, v := range bodyFields(a.Body, a.ContentType) {
		values["body."+k] = v
	}
	return values
}

func RenderSummary(template string, action SummaryAction) string {
	values := action.values()
	out := parkToken.ReplaceAllStringFunc(template, func(tok string) string {
		for _, name := range strings.Split(tok[1:len(tok)-1], "|") {
			if text := summaryText(values[name]); text != "" {
				return text
			}
		}
		return summaryMissing
	})
	return capSummary(cleanSummary(out))
}

func SummaryFor(ruleIDs []string, action SummaryAction, catalog map[string]any) string {
	return RenderSummary(TemplateFor(ruleIDs, action.Kind, catalog), action)
}
