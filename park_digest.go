package aarvion

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const DigestVersion = 1

const maxSafeInt = int64(1) << 53

func Canonicalize(v any) (string, error) {
	var b strings.Builder
	if err := writeCanonical(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

func writeCanonical(b *strings.Builder, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case int:
		return writeCanonical(b, int64(x))
	case int64:
		if x <= maxSafeInt && x >= -maxSafeInt {
			b.WriteString(strconv.FormatInt(x, 10))
			return nil
		}
		s, err := esNumber(float64(x))
		if err != nil {
			return err
		}
		b.WriteString(s)
	case *big.Int:
		if x.IsInt64() {
			return writeCanonical(b, x.Int64())
		}
		f, _ := new(big.Float).SetInt(x).Float64()
		if math.IsInf(f, 0) {
			return pyOverflowError("int too large to convert to float")
		}
		s, err := esNumber(f)
		if err != nil {
			return err
		}
		b.WriteString(s)
	case float64:
		s, err := esNumber(x)
		if err != nil {
			return err
		}
		b.WriteString(s)
	case string:
		writeJSONString(b, x, false)
	case []string:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSONString(b, e, false)
		}
		b.WriteByte(']')
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case [][]string:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case *jsonObject:
		return writeCanonical(b, x.plain())
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSONString(b, k, false)
			b.WriteByte(':')
			if err := writeCanonical(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return pyTypeError("not JSON-serialisable: " + pyTypeName(v))
	}
	return nil
}

func utf16Units(s string) []uint16 {
	var rs []rune
	for i := 0; i < len(s); {
		r, w := decodeWTF8(s[i:])
		rs = append(rs, r)
		i += w
	}
	return utf16.Encode(rs)
}

func utf16Less(a, b string) bool {
	ua, ub := utf16Units(a), utf16Units(b)
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func esNumber(x float64) (string, error) {
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return "", pyValueError("NaN and Infinity are not valid JSON")
	}
	if x == 0 {
		return "0", nil
	}
	sign := ""
	if x < 0 {
		sign = "-"
		x = -x
	}
	repr := strconv.FormatFloat(x, 'e', -1, 64)
	mant, expPart, _ := strings.Cut(repr, "e")
	e, err := strconv.Atoi(expPart)
	if err != nil {
		return "", err
	}
	all := strings.Replace(mant, ".", "", 1)
	digits := strings.TrimRight(all, "0")
	k := len(digits)
	n := e + 1
	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		ex := n - 1
		m := digits[:1]
		if k > 1 {
			m += "." + digits[1:]
		}
		s := "+"
		if ex < 0 {
			s = "-"
			ex = -ex
		}
		out = m + "e" + s + strconv.Itoa(ex)
	}
	return sign + out, nil
}

func Digest(action map[string]any) (string, error) {
	text, err := Canonicalize(action)
	if err != nil {
		return "", err
	}
	if !utf8.ValidString(text) {
		return "", pyValueError("surrogates not allowed")
	}
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:]), nil
}

func ScopeFor(callerPrincipalID, sessionID string) string {
	if callerPrincipalID != "" {
		return "caller:" + callerPrincipalID
	}
	if sessionID != "" {
		return "session:" + sessionID
	}
	return "agent"
}

func without(v any, volatile []string) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	drop := make(map[string]bool, len(volatile))
	for _, f := range volatile {
		drop[f] = true
	}
	out := make(map[string]any, len(m))
	for k, val := range m {
		if !drop[k] {
			out[k] = val
		}
	}
	return out
}

func isJSONContentType(contentType string) bool {
	mime, _, _ := strings.Cut(contentType, ";")
	mime = strings.ToLower(pyStrip(mime))
	return mime == "application/json" || strings.HasSuffix(mime, "+json")
}

func queryPairs(query string) [][]string {
	pairs := [][]string{}
	for _, part := range strings.Split(query, "&") {
		if part == "" {
			continue
		}
		key, val, _ := strings.Cut(part, "=")
		pairs = append(pairs, []string{key, val})
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		if pairs[i][0] != pairs[j][0] {
			return pairs[i][0] < pairs[j][0]
		}
		return pairs[i][1] < pairs[j][1]
	})
	return pairs
}

func loadsStrictJSON(b []byte) (any, error) {
	v, err := pyLoadsBytes(b)
	if err != nil {
		return nil, err
	}
	if hasJSONConstant(b) {
		return nil, pyValueError("NaN or Infinity is not valid JSON")
	}
	return toPlain(v), nil
}

func hasJSONConstant(b []byte) bool {
	inString := false
	escaped := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case 'N', 'I':
			return true
		}
	}
	return false
}

func digestBody(body []byte, contentType string, volatile []string) any {
	if len(body) == 0 {
		return nil
	}
	if isJSONContentType(contentType) {
		if v, err := loadsStrictJSON(body); err == nil {
			return without(v, volatile)
		}
	}
	sum := sha256.Sum256(body)
	return map[string]any{"sha256": hex.EncodeToString(sum[:])}
}

type HTTPAction struct {
	Scope       string
	Method      string
	Host        string
	Path        string
	Query       string
	ContentType string
	Body        []byte
	Volatile    []string
}

func (a HTTPAction) Object() map[string]any {
	return map[string]any{
		"v":      int64(DigestVersion),
		"kind":   "http",
		"scope":  a.Scope,
		"method": strings.ToUpper(a.Method),
		"host":   strings.ToLower(a.Host),
		"path":   a.Path,
		"query":  queryPairs(a.Query),
		"body":   digestBody(a.Body, a.ContentType, a.Volatile),
	}
}

type ToolAction struct {
	Scope    string
	EntityID string
	Tool     string
	Args     any
	ToolDef  string
	Volatile []string
}

func (a ToolAction) Object() map[string]any {
	return map[string]any{
		"v":         int64(DigestVersion),
		"kind":      "tool",
		"scope":     a.Scope,
		"entity_id": a.EntityID,
		"tool":      a.Tool,
		"args":      without(a.Args, a.Volatile),
		"tool_def":  a.ToolDef,
	}
}
