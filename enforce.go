package aarvion

import (
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const BodyLimitPolicy = "sdk.body_inspection_limit"

var (
	MaxBodyBytes    int64 = 16 * 1024 * 1024
	maxBodyBytesErr error
)

func init() {
	if raw := os.Getenv("AARVION_MAX_BODY_BYTES"); raw != "" {
		v, err := pyInt(raw)
		if err != nil {
			maxBodyBytesErr = err
			return
		}
		MaxBodyBytes = v
	}
}

type piiKind struct {
	re          *regexp.Regexp
	finder      func(string) []Span
	placeholder string
}

var patterns = map[string]piiKind{
	"email address": {re: regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`),
		placeholder: "[redacted: email address per data-protection policy]"},
	"US SSN": {finder: ssnSpans,
		placeholder: "[redacted: US Social Security number per data-protection policy]"},
	"credit card number": {finder: CardSpans,
		placeholder: "[redacted: credit card number per data-protection policy]"},
	"IBAN": {finder: IBANSpans,
		placeholder: "[redacted: bank account (IBAN) per data-protection policy]"},
	"SWIFT/BIC": {re: regexp.MustCompile(`\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b`),
		placeholder: "[redacted: bank SWIFT/BIC code per data-protection policy]"},
	"IFSC code": {re: regexp.MustCompile(`\b[A-Z]{4}0[A-Z0-9]{6}\b`),
		placeholder: "[redacted: bank IFSC code per data-protection policy]"},
	"Aadhaar": {finder: aadhaarSpans,
		placeholder: "[redacted: Indian Aadhaar number per data-protection policy]"},
	"PAN": {re: regexp.MustCompile(`\b[A-Z]{5}[0-9]{4}[A-Z]\b`),
		placeholder: "[redacted: Indian PAN per data-protection policy]"},
	"GSTIN": {re: regexp.MustCompile(`\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][0-9][A-Z][0-9A-Z]\b`),
		placeholder: "[redacted: Indian GSTIN per data-protection policy]"},
	"IP address": {re: regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`),
		placeholder: "[redacted: IP address per data-protection policy]"},
	"postal code": {re: regexp.MustCompile(`\b[0-9]{5}(?:-[0-9]{4})?\b`),
		placeholder: "[redacted: postal code per data-protection policy]"},
}

func isDigitByte(c byte) bool {
	return c >= '0' && c <= '9'
}

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'
}

func digitsAt(s string, i, n int) bool {
	if i < 0 || i+n > len(s) {
		return false
	}
	for k := 0; k < n; k++ {
		if !isDigitByte(s[i+k]) {
			return false
		}
	}
	return true
}

func ssnSpans(s string) []Span {
	var out []Span
	for i := 0; i+11 <= len(s); i++ {
		if i > 0 && isDigitByte(s[i-1]) {
			continue
		}
		if digitsAt(s, i, 3) && s[i+3] == '-' && digitsAt(s, i+4, 2) && s[i+6] == '-' && digitsAt(s, i+7, 4) &&
			(i+11 == len(s) || !isDigitByte(s[i+11])) {
			out = append(out, Span{i, i + 11})
			i += 10
		}
	}
	return out
}

func aadhaarSpans(s string) []Span {
	endOK := func(j int) bool {
		return j == len(s) || !(isDigitByte(s[j]) || isSpaceByte(s[j]))
	}
	var out []Span
	for i := 0; i < len(s); i++ {
		if i > 0 && isDigitByte(s[i-1]) {
			continue
		}
		end := -1
		if digitsAt(s, i, 12) && endOK(i+12) {
			end = i + 12
		} else if i+14 <= len(s) && digitsAt(s, i, 4) && isSpaceByte(s[i+4]) && digitsAt(s, i+5, 4) &&
			isSpaceByte(s[i+9]) && digitsAt(s, i+10, 4) && endOK(i+14) {
			end = i + 14
		}
		if end > 0 {
			out = append(out, Span{i, end})
			i = end - 1
		}
	}
	return out
}

var PIIKinds = []string{"email address", "US SSN", "credit card number", "IBAN", "SWIFT/BIC", "IFSC code",
	"Aadhaar", "PAN", "GSTIN", "IP address", "postal code"}

var maskEntryRe = regexp.MustCompile(translatePyRegex(`^\s*(.*?)\s*=mask:(.):(\d+)\s*\z`))

type maskStyle struct {
	char string
	keep *big.Int
}

func parseMaskStyles(style string) map[string]maskStyle {
	masks := map[string]maskStyle{}
	if style == "" {
		return masks
	}
	for _, entry := range strings.Split(style, ",") {
		m := maskEntryRe.FindStringSubmatch(entry)
		if m != nil && m[1] != "" {
			keep, _ := parsePyIntLiteral(m[3])
			masks[m[1]] = maskStyle{char: m[2], keep: keep}
		}
	}
	return masks
}

func maskSpan(span, char string, keep *big.Int) string {
	n := pyLen(span)
	k := 0
	if keep.IsInt64() && keep.Int64() < int64(n) {
		k = int(keep.Int64())
	}
	out := strings.Repeat(char, n-k)
	if k > 0 {
		rs := []rune(span)
		out += string(rs[len(rs)-k:])
	}
	return out
}

func replaceSpans(text string, spans []Span, sub func(string) string) string {
	var b strings.Builder
	last := 0
	for _, s := range spans {
		b.WriteString(text[last:s[0]])
		b.WriteString(sub(text[s[0]:s[1]]))
		last = s[1]
	}
	b.WriteString(text[last:])
	return b.String()
}

func rewriteText(text string, kinds []string, masks map[string]maskStyle) string {
	for _, kind := range kinds {
		entry, ok := patterns[kind]
		if !ok {
			continue
		}
		var sub func(string) string
		if mask, ok := masks[kind]; ok {
			sub = func(s string) string { return maskSpan(s, mask.char, mask.keep) }
		} else {
			p := entry.placeholder
			sub = func(string) string { return p }
		}
		if entry.re != nil {
			text = entry.re.ReplaceAllStringFunc(text, sub)
		} else {
			text = replaceSpans(text, entry.finder(text), sub)
		}
	}
	return text
}

func RewriteBody(body, redactions, style string) string {
	if redactions == "" {
		return body
	}
	masks := parseMaskStyles(style)
	var kinds []string
	for _, k := range strings.Split(redactions, ",") {
		kinds = append(kinds, pyStrip(k))
	}
	if looksLikeJSON(body) {
		if out, ok := rewriteJSON(body, kinds, masks); ok {
			return out
		}
	}
	return rewritePlain(body, kinds, masks)
}

func rewritePlain(body string, kinds []string, masks map[string]maskStyle) string {
	var b strings.Builder
	last := 0
	for _, s := range BlobSpans(body) {
		b.WriteString(rewriteText(body[last:s[0]], kinds, masks))
		b.WriteString(body[s[0]:s[1]])
		last = s[1]
	}
	b.WriteString(rewriteText(body[last:], kinds, masks))
	return b.String()
}

func looksLikeJSON(body string) bool {
	t := strings.TrimLeftFunc(body, unicode.IsSpace)
	return strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[")
}

func validJSONStream(body string) bool {
	dec := json.NewDecoder(strings.NewReader(body))
	n := 0
	for {
		var v json.RawMessage
		err := dec.Decode(&v)
		if err == io.EOF {
			return n > 0
		}
		if err != nil {
			return false
		}
		n++
	}
}

func rewriteJSON(body string, kinds []string, masks map[string]maskStyle) (string, bool) {
	if !utf8.ValidString(body) || !validJSONStream(body) {
		return "", false
	}
	blobs := BlobSpans(body)
	var b strings.Builder
	last := 0
	replace := func(start, end int, rewritten string) {
		b.WriteString(body[last:start])
		b.WriteByte('"')
		b.WriteString(quoteJSON(rewritten))
		b.WriteByte('"')
		last = end
	}
	for i := 0; i < len(body); {
		c := body[i]
		switch {
		case c == '"':
			end := jsonStringEnd(body, i)
			if end < 0 {
				return "", false
			}
			if !insideAny(blobs, i, end) {
				var value string
				if err := json.Unmarshal([]byte(body[i:end]), &value); err != nil {
					return "", false
				}
				if rewritten := rewritePlain(value, kinds, masks); rewritten != value {
					replace(i, end, rewritten)
				}
			}
			i = end
		case c == '-' || isDigitByte(c):
			end := i
			for end < len(body) && strings.IndexByte("+-.eE0123456789", body[end]) >= 0 {
				end++
			}
			value := body[i:end]
			if !insideAny(blobs, i, end) {
				if rewritten := rewritePlain(value, kinds, masks); rewritten != value {
					replace(i, end, rewritten)
				}
			}
			i = end
		default:
			i++
		}
	}
	b.WriteString(body[last:])
	return b.String(), true
}

func jsonStringEnd(body string, start int) int {
	for i := start + 1; i < len(body); i++ {
		switch body[i] {
		case '\\':
			i++
		case '"':
			return i + 1
		}
	}
	return -1
}

func insideAny(spans []Span, start, end int) bool {
	for _, s := range spans {
		if s[0] <= start && end <= s[1]+1 {
			return true
		}
	}
	return false
}

func quoteJSON(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 {
				b.WriteString(`\u00`)
				b.WriteByte(hex[r>>4])
				b.WriteByte(hex[r&0xF])
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

func BuildExtAuthzInput(method, host, path string, headers map[string]string, body any) map[string]any {
	var text string
	switch x := body.(type) {
	case []byte:
		if s, ok := decodeStrict(x); ok {
			text = s
		}
	case string:
		text = x
	}
	h := map[string]any{}
	for k, v := range headers {
		h[k] = v
	}
	return map[string]any{
		"attributes": map[string]any{
			"request": map[string]any{
				"http": map[string]any{
					"method":  method,
					"host":    host,
					"path":    path,
					"headers": h,
					"body":    text,
				},
			},
		},
	}
}

func BodyTooLarge(body string) map[string]any {
	n := int64(len(body))
	if n <= MaxBodyBytes {
		return nil
	}
	return map[string]any{
		"allowed":     false,
		"http_status": int64(413),
		"headers": map[string]any{
			"x-policy-violated": BodyLimitPolicy,
			"x-policy-reason": fmt.Sprintf("body of %d bytes exceeds the %d-byte inspection limit (AARVION_MAX_BODY_BYTES)",
				n, MaxBodyBytes),
		},
	}
}

func attrString(v any, attr string) (string, error) {
	switch x := v.(type) {
	case string:
		return x, nil
	}
	return "", pyAttributeError(fmt.Sprintf("'%s' object has no attribute '%s'", pyTypeName(v), attr))
}

func PolicyIDs(headers map[string]any) ([]string, error) {
	all := headers["x-aarvion-policies-violated"]
	joined := ""
	if pyTruthy(all) {
		s, err := attrString(all, "split")
		if err != nil {
			return nil, err
		}
		joined = s
	}
	var ids []string
	for _, p := range strings.Split(joined, ",") {
		if p != "" {
			ids = append(ids, p)
		}
	}
	if len(ids) > 0 {
		return ids, nil
	}
	if single := headers["x-policy-violated"]; pyTruthy(single) {
		return []string{pyStr(single)}, nil
	}
	return nil, nil
}

func headerOr(headers map[string]any, key, dflt string) string {
	if v, ok := headers[key]; ok {
		return pyStr(v)
	}
	return dflt
}

func deniedFromDecision(decision, headers map[string]any) error {
	status, err := pyInt(dictGet(decision, "http_status", int64(403)))
	if err != nil {
		return err
	}
	ids, err := PolicyIDs(headers)
	if err != nil {
		return err
	}
	return NewPolicyDenied(headerOr(headers, "x-policy-violated", "policy"),
		headerOr(headers, "x-policy-reason", "blocked by policy"), int(status), ids)
}

func ApplyDecision(decision map[string]any, body string) (string, error) {
	headers, err := dictOrEmpty(decision["headers"])
	if !pyTruthy(dictGet(decision, "allowed", true)) {
		if err != nil {
			return "", err
		}
		return "", deniedFromDecision(decision, headers)
	}
	if err != nil {
		return "", err
	}
	redactions := headers["x-aarvion-redactions"]
	if pyTruthy(redactions) {
		r, err := attrString(redactions, "split")
		if err != nil {
			return "", err
		}
		style := ""
		if sv := headers["x-aarvion-redact-style"]; pyTruthy(sv) {
			if style, err = attrString(sv, "split"); err != nil {
				return "", err
			}
		}
		return RewriteBody(body, r, style), nil
	}
	return body, nil
}
