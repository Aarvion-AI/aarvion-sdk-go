package aarvion

import (
	"fmt"
	"math"
	"math/big"
	"os"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

func typeName(v any) string { return fmt.Sprintf("%T", v) }

func pyTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case int:
		return x != 0
	case int64:
		return x != 0
	case int32:
		return x != 0
	case uint64:
		return x != 0
	case float64:
		return x != 0
	case float32:
		return x != 0
	case *big.Int:
		return x.Sign() != 0
	case *jsonObject:
		return len(x.keys) > 0
	case map[string]any:
		return len(x) > 0
	case map[string]string:
		return len(x) > 0
	case []any:
		return len(x) > 0
	case []string:
		return len(x) > 0
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Map, reflect.Slice, reflect.Array, reflect.String:
		return rv.Len() > 0
	case reflect.Ptr, reflect.Interface:
		return !rv.IsNil()
	}
	return true
}

func pyTypeName(v any) string {
	switch v.(type) {
	case nil:
		return "NoneType"
	case bool:
		return "bool"
	case string:
		return "str"
	case int, int64, int32, int16, int8, uint, uint64, uint32, uint16, uint8, *big.Int:
		return "int"
	case float64, float32:
		return "float"
	case []any, []string:
		return "list"
	case map[string]any, map[string]string, *jsonObject:
		return "dict"
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		return "list"
	case reflect.Map:
		return "dict"
	}
	return typeName(v)
}

func asDict(v any) (map[string]any, bool) {
	switch x := v.(type) {
	case map[string]any:
		return x, true
	case *jsonObject:
		return x.plain(), true
	case map[string]string:
		m := make(map[string]any, len(x))
		for k, s := range x {
			m[k] = s
		}
		return m, true
	}
	return nil, false
}

func dictOrEmpty(v any) (map[string]any, error) {
	if !pyTruthy(v) {
		return map[string]any{}, nil
	}
	if m, ok := asDict(v); ok {
		return m, nil
	}
	return nil, pyAttributeError(fmt.Sprintf("'%s' object has no attribute 'get'", pyTypeName(v)))
}

func dictGet(m map[string]any, key string, dflt any) any {
	if v, ok := m[key]; ok {
		return v
	}
	return dflt
}

func pyStr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case string:
		return x
	case bool:
		if x {
			return "True"
		}
		return "False"
	case float64:
		return floatRepr(x, false)
	case float32:
		return floatRepr(float64(x), false)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case int32:
		return strconv.FormatInt(int64(x), 10)
	case uint64:
		return strconv.FormatUint(x, 10)
	case *big.Int:
		return x.String()
	}
	return pyRepr(v)
}

func pyRepr(v any) string {
	switch x := v.(type) {
	case string:
		return reprString(x)
	case nil, bool, float64, float32, int, int64, int32, uint64, *big.Int:
		return pyStr(v)
	case []string:
		parts := make([]string, len(x))
		for i, s := range x {
			parts[i] = reprString(s)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case []any:
		parts := make([]string, len(x))
		for i, s := range x {
			parts[i] = pyRepr(s)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case *jsonObject:
		parts := make([]string, 0, len(x.keys))
		for _, k := range x.keys {
			parts = append(parts, reprString(k)+": "+pyRepr(x.vals[k]))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, reprString(k)+": "+pyRepr(x[k]))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return fmt.Sprint(v)
}

func reprString(s string) string {
	q := byte('\'')
	if strings.Contains(s, "'") && !strings.Contains(s, "\"") {
		q = '"'
	}
	var b strings.Builder
	b.WriteByte(q)
	for i := 0; i < len(s); {
		r, w := decodeWTF8(s[i:])
		i += w
		switch {
		case r == rune(q) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\t':
			b.WriteString("\\t")
		case r == '\n':
			b.WriteString("\\n")
		case r == '\r':
			b.WriteString("\\r")
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, "\\x%02x", r)
		case r < 0x7f:
			b.WriteRune(r)
		case r >= 0xd800 && r <= 0xdfff:
			fmt.Fprintf(&b, "\\u%04x", r)
		case isPrintable(r):
			b.WriteRune(r)
		case r <= 0xff:
			fmt.Fprintf(&b, "\\x%02x", r)
		case r <= 0xffff:
			fmt.Fprintf(&b, "\\u%04x", r)
		default:
			fmt.Fprintf(&b, "\\U%08x", r)
		}
	}
	b.WriteByte(q)
	return b.String()
}

func isPrintable(r rune) bool {
	if r == ' ' {
		return true
	}
	return unicode.IsPrint(r)
}

func decodeWTF8(s string) (rune, int) {
	if len(s) >= 3 && s[0] == 0xed && s[1] >= 0xa0 && s[1] <= 0xbf && s[2] >= 0x80 && s[2] <= 0xbf {
		return rune(0xd000) | rune(s[1]&0x3f)<<6 | rune(s[2]&0x3f), 3
	}
	return utf8.DecodeRuneInString(s)
}

func pyIsSpace(r rune) bool {
	return (r >= 0x09 && r <= 0x0d) || (r >= 0x1c && r <= 0x20) || r == 0x85 || r == 0xa0 ||
		r == 0x1680 || (r >= 0x2000 && r <= 0x200a) || r == 0x2028 || r == 0x2029 ||
		r == 0x202f || r == 0x205f || r == 0x3000
}

func pyStrip(s string) string { return strings.TrimFunc(s, pyIsSpace) }

func pyRStrip(s string) string { return strings.TrimRightFunc(s, pyIsSpace) }

func pyLen(s string) int { return utf8.RuneCountInString(s) }

func pyPrefix(s string, n int) string {
	i := 0
	for j := range s {
		if i == n {
			return s[:j]
		}
		i++
	}
	return s
}

func pyInt(v any) (int64, error) {
	switch x := v.(type) {
	case nil:
		return 0, pyTypeError("int() argument must be a string, a bytes-like object or a real number, not 'NoneType'")
	case bool:
		if x {
			return 1, nil
		}
		return 0, nil
	case int:
		return int64(x), nil
	case int64:
		return x, nil
	case int32:
		return int64(x), nil
	case uint64:
		if x > math.MaxInt64 {
			return math.MaxInt64, nil
		}
		return int64(x), nil
	case *big.Int:
		return clampBig(x), nil
	case float64:
		return floatToInt(x)
	case float32:
		return floatToInt(float64(x))
	case string:
		b, ok := parsePyIntLiteral(x)
		if !ok {
			return 0, pyValueError("invalid literal for int() with base 10: " + pyRepr(x))
		}
		return clampBig(b), nil
	}
	return 0, pyTypeError(fmt.Sprintf("int() argument must be a string, a bytes-like object or a real number, not '%s'", pyTypeName(v)))
}

func floatToInt(f float64) (int64, error) {
	if math.IsNaN(f) {
		return 0, pyValueError("cannot convert float NaN to integer")
	}
	if math.IsInf(f, 0) {
		return 0, pyOverflowError("cannot convert float infinity to integer")
	}
	bf := new(big.Float).SetFloat64(math.Trunc(f))
	bi, _ := bf.Int(nil)
	return clampBig(bi), nil
}

func clampBig(b *big.Int) int64 {
	if b.IsInt64() {
		return b.Int64()
	}
	if b.Sign() > 0 {
		return math.MaxInt64
	}
	return math.MinInt64
}

func parsePyIntLiteral(s string) (*big.Int, bool) {
	t := pyStrip(s)
	if t == "" {
		return nil, false
	}
	neg := false
	if t[0] == '+' || t[0] == '-' {
		neg = t[0] == '-'
		t = t[1:]
	}
	var digits strings.Builder
	lastUnderscore := true
	for _, r := range t {
		if r == '_' {
			if lastUnderscore {
				return nil, false
			}
			lastUnderscore = true
			continue
		}
		d, ok := unicodeDigitValue(r)
		if !ok {
			return nil, false
		}
		digits.WriteByte(byte('0' + d))
		lastUnderscore = false
	}
	if lastUnderscore || digits.Len() == 0 {
		return nil, false
	}
	b, _ := new(big.Int).SetString(digits.String(), 10)
	if neg {
		b.Neg(b)
	}
	return b, true
}

func unicodeDigitValue(r rune) (int, bool) {
	if r >= '0' && r <= '9' {
		return int(r - '0'), true
	}
	for _, rg := range pyDigitRanges {
		if r >= rg[0] && r <= rg[1] {
			return int(r-rg[0]) % 10, true
		}
	}
	return 0, false
}

func pyRStripChars(s, chars string) string { return strings.TrimRight(s, chars) }

func pyLStripChars(s, chars string) string { return strings.TrimLeft(s, chars) }

func pyStripChars(s, chars string) string { return strings.Trim(s, chars) }

func isWindows() bool { return runtime.GOOS == "windows" }

func expandUser(path string) string {
	if !strings.HasPrefix(path, "~") {
		return path
	}
	if isWindows() {
		i := 1
		for i < len(path) && path[i] != '/' && path[i] != '\\' {
			i++
		}
		if i != 1 {
			return path
		}
		userhome, ok := os.LookupEnv("USERPROFILE")
		if !ok {
			homepath, ok2 := os.LookupEnv("HOMEPATH")
			if !ok2 {
				return path
			}
			userhome = os.Getenv("HOMEDRIVE") + homepath
		}
		return userhome + path[i:]
	}
	i := strings.IndexByte(path[1:], '/')
	if i < 0 {
		i = len(path)
	} else {
		i++
	}
	if i != 1 {
		return path
	}
	userhome, ok := os.LookupEnv("HOME")
	if !ok {
		h, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		userhome = h
	}
	userhome = strings.TrimRight(userhome, "/")
	out := userhome + path[i:]
	if out == "" {
		return "/"
	}
	return out
}

func pyPath(p string) string {
	if isWindows() {
		return pyPathWindows(p)
	}
	if p == "" {
		return "."
	}
	root := ""
	rest := p
	if strings.HasPrefix(p, "//") && !strings.HasPrefix(p, "///") {
		root = "//"
		rest = p[2:]
	} else if strings.HasPrefix(p, "/") {
		root = "/"
		rest = strings.TrimLeft(p, "/")
	}
	var parts []string
	for _, s := range strings.Split(rest, "/") {
		if s == "" || s == "." {
			continue
		}
		parts = append(parts, s)
	}
	out := root + strings.Join(parts, "/")
	if out == "" {
		return "."
	}
	return out
}

func pyPathWindows(p string) string {
	s := strings.ReplaceAll(p, "/", "\\")
	if s == "" {
		return "."
	}
	drive := ""
	root := ""
	rest := s
	if strings.HasPrefix(s, "\\\\") && !strings.HasPrefix(s, "\\\\\\") {
		parts := strings.SplitN(s[2:], "\\", 3)
		if len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
			drive = "\\\\" + parts[0] + "\\" + parts[1]
			root = "\\"
			if len(parts) == 3 {
				rest = parts[2]
			} else {
				rest = ""
			}
		}
	} else if len(s) >= 2 && s[1] == ':' {
		drive = s[:2]
		rest = s[2:]
		if strings.HasPrefix(rest, "\\") {
			root = "\\"
		}
	} else if strings.HasPrefix(s, "\\") {
		root = "\\"
	}
	var parts []string
	for _, seg := range strings.Split(rest, "\\") {
		if seg == "" || seg == "." {
			continue
		}
		parts = append(parts, seg)
	}
	out := drive + root + strings.Join(parts, "\\")
	if out == "" {
		return "."
	}
	return out
}

func pyJoinPath(dir, name string) string {
	if dir == "" {
		return name
	}
	last := dir[len(dir)-1]
	if last == '/' || (isWindows() && (last == '\\' || last == ':')) {
		return dir + name
	}
	if isWindows() {
		return dir + "\\" + name
	}
	return dir + "/" + name
}

func utf8Scan(b []byte, i int) (int, bool) {
	n := len(b)
	c := b[i]
	if c < 0x80 {
		return 1, true
	}
	need := 0
	lo, hi := byte(0x80), byte(0xbf)
	switch {
	case c >= 0xc2 && c <= 0xdf:
		need = 1
	case c == 0xe0:
		need, lo = 2, 0xa0
	case (c >= 0xe1 && c <= 0xec) || c == 0xee || c == 0xef:
		need = 2
	case c == 0xed:
		need, hi = 2, 0x9f
	case c == 0xf0:
		need, lo = 3, 0x90
	case c >= 0xf1 && c <= 0xf3:
		need = 3
	case c == 0xf4:
		need, hi = 3, 0x8f
	default:
		return 1, false
	}
	for k := 1; k <= need; k++ {
		if i+k >= n {
			return k, false
		}
		cb := b[i+k]
		if k == 1 {
			if cb < lo || cb > hi {
				return k, false
			}
		} else if cb < 0x80 || cb > 0xbf {
			return k, false
		}
	}
	return need + 1, true
}

func decodeUTF8(b []byte, replace bool) string {
	var out strings.Builder
	out.Grow(len(b))
	for i := 0; i < len(b); {
		w, ok := utf8Scan(b, i)
		if ok {
			out.Write(b[i : i+w])
		} else if replace {
			out.WriteRune(utf8.RuneError)
		}
		i += w
	}
	return out.String()
}

func decodeIgnore(b []byte) string { return decodeUTF8(b, false) }

func decodeReplace(b []byte) string { return decodeUTF8(b, true) }

func decodeStrict(b []byte) (string, bool) {
	if utf8.Valid(b) {
		return string(b), true
	}
	return "", false
}

func utf8DecodeErrorMessage(b []byte) string {
	n := len(b)
	for i := 0; i < n; {
		w, ok := utf8Scan(b, i)
		if ok {
			i += w
			continue
		}
		c := b[i]
		var reason string
		switch {
		case c < 0xc2 || c > 0xf4:
			reason = "invalid start byte"
		case i+w >= n:
			reason = "unexpected end of data"
		default:
			reason = "invalid continuation byte"
		}
		if w == 1 {
			return fmt.Sprintf("'utf-8' codec can't decode byte 0x%02x in position %d: %s", c, i, reason)
		}
		return fmt.Sprintf("'utf-8' codec can't decode bytes in position %d-%d: %s", i, i+w-1, reason)
	}
	return ""
}
