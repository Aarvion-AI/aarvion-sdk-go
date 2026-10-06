package aarvion

import (
	"fmt"
	"math"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

type jsonObject struct {
	keys []string
	vals map[string]any
}

func newJSONObject() *jsonObject { return &jsonObject{vals: map[string]any{}} }

func (o *jsonObject) set(k string, v any) *jsonObject {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
	return o
}

func (o *jsonObject) get(k string) (any, bool) {
	v, ok := o.vals[k]
	return v, ok
}

func (o *jsonObject) plain() map[string]any {
	m := make(map[string]any, len(o.keys))
	for _, k := range o.keys {
		m[k] = toPlain(o.vals[k])
	}
	return m
}

func toPlain(v any) any {
	switch x := v.(type) {
	case *jsonObject:
		return x.plain()
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = toPlain(e)
		}
		return out
	}
	return v
}

func obj(kv ...any) *jsonObject {
	o := newJSONObject()
	for i := 0; i+1 < len(kv); i += 2 {
		o.set(kv[i].(string), kv[i+1])
	}
	return o
}

type jsonStyle struct {
	sortKeys    bool
	itemSep     string
	keySep      string
	ensureASCII bool
	allowNaN    bool
}

var (
	jsonDefault = jsonStyle{false, ", ", ": ", true, true}
	jsonSorted  = jsonStyle{true, ",", ":", true, true}
	jsonHttpx   = jsonStyle{false, ",", ":", false, false}
)

func pyDumps(v any, st jsonStyle) (string, error) {
	var b strings.Builder
	if err := writeJSON(&b, v, st); err != nil {
		return "", err
	}
	return b.String(), nil
}

func httpxJSONBody(v any) ([]byte, error) {
	s, err := pyDumps(v, jsonHttpx)
	if err != nil {
		return nil, err
	}
	if pos := surrogateIndex(s); pos >= 0 {
		return nil, &pyError{kind: "UnicodeEncodeError", msg: "'utf-8' codec can't encode character '\\u" +
			fmt.Sprintf("%04x", surrogateAt(s, pos)) + "' in position " + strconv.Itoa(pos) + ": surrogates not allowed"}
	}
	return []byte(s), nil
}

func surrogateIndex(s string) int {
	idx := 0
	for i := 0; i < len(s); {
		r, w := decodeWTF8(s[i:])
		if r >= 0xd800 && r <= 0xdfff {
			return idx
		}
		i += w
		idx++
	}
	return -1
}

func surrogateAt(s string, pos int) rune {
	idx := 0
	for i := 0; i < len(s); {
		r, w := decodeWTF8(s[i:])
		if idx == pos {
			return r
		}
		i += w
		idx++
	}
	return 0
}

func writeJSON(b *strings.Builder, v any, st jsonStyle) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeJSONString(b, x, st.ensureASCII)
	case int:
		b.WriteString(strconv.Itoa(x))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case int32:
		b.WriteString(strconv.FormatInt(int64(x), 10))
	case uint64:
		b.WriteString(strconv.FormatUint(x, 10))
	case uint32:
		b.WriteString(strconv.FormatUint(uint64(x), 10))
	case *big.Int:
		b.WriteString(x.String())
	case float64:
		return writeJSONFloat(b, x, st)
	case float32:
		return writeJSONFloat(b, float64(x), st)
	case *jsonObject:
		if len(x.keys) == 0 {
			b.WriteString("{}")
			return nil
		}
		keys := x.keys
		if st.sortKeys {
			keys = append([]string(nil), keys...)
			sort.Strings(keys)
		}
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteString(st.itemSep)
			}
			writeJSONString(b, k, st.ensureASCII)
			b.WriteString(st.keySep)
			if err := writeJSON(b, x.vals[k], st); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	case map[string]any:
		return writeJSONMap(b, len(x), func() []string {
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			return keys
		}, func(k string) any { return x[k] }, st)
	case map[string]string:
		return writeJSONMap(b, len(x), func() []string {
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			return keys
		}, func(k string) any { return x[k] }, st)
	case []any:
		return writeJSONList(b, len(x), func(i int) any { return x[i] }, st)
	case []string:
		return writeJSONList(b, len(x), func(i int) any { return x[i] }, st)
	default:
		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.Slice, reflect.Array:
			return writeJSONList(b, rv.Len(), func(i int) any { return rv.Index(i).Interface() }, st)
		case reflect.Map:
			if rv.Type().Key().Kind() == reflect.String {
				return writeJSONMap(b, rv.Len(), func() []string {
					keys := make([]string, 0, rv.Len())
					for _, k := range rv.MapKeys() {
						keys = append(keys, k.String())
					}
					return keys
				}, func(k string) any { return rv.MapIndex(reflect.ValueOf(k).Convert(rv.Type().Key())).Interface() }, st)
			}
		case reflect.Int, reflect.Int8, reflect.Int16:
			b.WriteString(strconv.FormatInt(rv.Int(), 10))
			return nil
		case reflect.Uint, reflect.Uint8, reflect.Uint16:
			b.WriteString(strconv.FormatUint(rv.Uint(), 10))
			return nil
		case reflect.String:
			writeJSONString(b, rv.String(), st.ensureASCII)
			return nil
		}
		return pyTypeError(fmt.Sprintf("Object of type %s is not JSON serializable", typeName(v)))
	}
	return nil
}

func writeJSONMap(b *strings.Builder, n int, keysFn func() []string, get func(string) any, st jsonStyle) error {
	if n == 0 {
		b.WriteString("{}")
		return nil
	}
	keys := keysFn()
	sort.Strings(keys)
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteString(st.itemSep)
		}
		writeJSONString(b, k, st.ensureASCII)
		b.WriteString(st.keySep)
		if err := writeJSON(b, get(k), st); err != nil {
			return err
		}
	}
	b.WriteByte('}')
	return nil
}

func writeJSONList(b *strings.Builder, n int, get func(int) any, st jsonStyle) error {
	if n == 0 {
		b.WriteString("[]")
		return nil
	}
	b.WriteByte('[')
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(st.itemSep)
		}
		if err := writeJSON(b, get(i), st); err != nil {
			return err
		}
	}
	b.WriteByte(']')
	return nil
}

func writeJSONFloat(b *strings.Builder, f float64, st jsonStyle) error {
	if (math.IsNaN(f) || math.IsInf(f, 0)) && !st.allowNaN {
		return pyValueError("Out of range float values are not JSON compliant: " + floatRepr(f, false))
	}
	b.WriteString(floatRepr(f, true))
	return nil
}

const hexDigits = "0123456789abcdef"

func writeU(b *strings.Builder, c rune) {
	b.WriteString(`\u`)
	b.WriteByte(hexDigits[(c>>12)&0xf])
	b.WriteByte(hexDigits[(c>>8)&0xf])
	b.WriteByte(hexDigits[(c>>4)&0xf])
	b.WriteByte(hexDigits[c&0xf])
}

func writeJSONString(b *strings.Builder, s string, ensureASCII bool) {
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, w := decodeWTF8(s[i:])
		chunk := s[i : i+w]
		i += w
		switch r {
		case '"':
			b.WriteString(`\"`)
			continue
		case '\\':
			b.WriteString(`\\`)
			continue
		case '\n':
			b.WriteString(`\n`)
			continue
		case '\r':
			b.WriteString(`\r`)
			continue
		case '\t':
			b.WriteString(`\t`)
			continue
		case '\b':
			b.WriteString(`\b`)
			continue
		case '\f':
			b.WriteString(`\f`)
			continue
		}
		if r < 0x20 {
			writeU(b, r)
			continue
		}
		if ensureASCII && r > 0x7e {
			if r == utf8.RuneError && w == 1 {
				writeU(b, 0xfffd)
				continue
			}
			if r >= 0x10000 {
				v := r - 0x10000
				writeU(b, 0xd800|((v>>10)&0x3ff))
				writeU(b, 0xdc00|(v&0x3ff))
			} else {
				writeU(b, r)
			}
			continue
		}
		b.WriteString(chunk)
	}
	b.WriteByte('"')
}

func floatRepr(d float64, jsonMode bool) string {
	if math.IsNaN(d) {
		if jsonMode {
			return "NaN"
		}
		return "nan"
	}
	if math.IsInf(d, 0) {
		if jsonMode {
			if d > 0 {
				return "Infinity"
			}
			return "-Infinity"
		}
		if d > 0 {
			return "inf"
		}
		return "-inf"
	}
	if d == 0 {
		if math.Signbit(d) {
			return "-0.0"
		}
		return "0.0"
	}
	e := strconv.FormatFloat(math.Abs(d), 'e', -1, 64)
	mant, expStr, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	exp, _ := strconv.Atoi(expStr)
	decpt := exp + 1
	var b strings.Builder
	if d < 0 {
		b.WriteByte('-')
	}
	switch {
	case decpt <= -4 || decpt > 16:
		b.WriteByte(digits[0])
		if len(digits) > 1 {
			b.WriteByte('.')
			b.WriteString(digits[1:])
		}
		x := decpt - 1
		if x < 0 {
			b.WriteString("e-")
			x = -x
		} else {
			b.WriteString("e+")
		}
		if x < 10 {
			b.WriteByte('0')
		}
		b.WriteString(strconv.Itoa(x))
	case decpt <= 0:
		b.WriteString("0.")
		b.WriteString(strings.Repeat("0", -decpt))
		b.WriteString(digits)
	case decpt >= len(digits):
		b.WriteString(digits)
		b.WriteString(strings.Repeat("0", decpt-len(digits)))
		b.WriteString(".0")
	default:
		b.WriteString(digits[:decpt])
		b.WriteByte('.')
		b.WriteString(digits[decpt:])
	}
	return b.String()
}

type jsonDecodeError struct {
	msg    string
	doc    string
	pos    int
	lineno int
	colno  int
}

func (e *jsonDecodeError) Error() string {
	return fmt.Sprintf("%s: line %d column %d (char %d)", e.msg, e.lineno, e.colno, e.pos)
}

type jsonParser struct {
	s     string
	runes []rune
	i     int
}

func (p *jsonParser) fail(msg string, pos int) error {
	lineno := 1
	last := -1
	for k := 0; k < pos && k < len(p.runes); k++ {
		if p.runes[k] == '\n' {
			lineno++
			last = k
		}
	}
	return &pyError{kind: "JSONDecodeError", msg: (&jsonDecodeError{msg: msg, pos: pos, lineno: lineno, colno: pos - last}).Error()}
}

func pyLoads(s string) (any, error) {
	p := &jsonParser{s: s, runes: []rune(s)}
	p.skipWS()
	v, err := p.value()
	if err != nil {
		return nil, err
	}
	p.skipWS()
	if p.i != len(p.runes) {
		return nil, p.fail("Extra data", p.i)
	}
	return v, nil
}

func pyLoadsBytes(b []byte) (any, error) {
	if len(b) >= 3 && b[0] == 0xef && b[1] == 0xbb && b[2] == 0xbf {
		b = b[3:]
	}
	if !utf8.Valid(b) {
		return nil, &pyError{kind: "UnicodeDecodeError", msg: utf8DecodeErrorMessage(b)}
	}
	return pyLoads(string(b))
}

func pyLoadsPlain(b []byte) (any, error) {
	v, err := pyLoadsBytes(b)
	if err != nil {
		return nil, err
	}
	return toPlain(v), nil
}

func (p *jsonParser) skipWS() {
	for p.i < len(p.runes) {
		switch p.runes[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *jsonParser) hasPrefix(lit string) bool {
	rs := []rune(lit)
	if p.i+len(rs) > len(p.runes) {
		return false
	}
	for k, r := range rs {
		if p.runes[p.i+k] != r {
			return false
		}
	}
	return true
}

func (p *jsonParser) value() (any, error) {
	if p.i >= len(p.runes) {
		return nil, p.fail("Expecting value", p.i)
	}
	c := p.runes[p.i]
	switch {
	case c == '"':
		return p.str()
	case c == '{':
		return p.object()
	case c == '[':
		return p.array()
	case c == 'n' && p.hasPrefix("null"):
		p.i += 4
		return nil, nil
	case c == 't' && p.hasPrefix("true"):
		p.i += 4
		return true, nil
	case c == 'f' && p.hasPrefix("false"):
		p.i += 5
		return false, nil
	case c == 'N' && p.hasPrefix("NaN"):
		p.i += 3
		return math.NaN(), nil
	case c == 'I' && p.hasPrefix("Infinity"):
		p.i += 8
		return math.Inf(1), nil
	case c == '-' && p.hasPrefix("-Infinity"):
		p.i += 9
		return math.Inf(-1), nil
	}
	return p.number()
}

func isASCIIDigit(r rune) bool { return r >= '0' && r <= '9' }

func (p *jsonParser) number() (any, error) {
	start := p.i
	k := p.i
	n := len(p.runes)
	if k < n && p.runes[k] == '-' {
		k++
	}
	if k < n && p.runes[k] == '0' {
		k++
	} else if k < n && p.runes[k] >= '1' && p.runes[k] <= '9' {
		for k < n && isASCIIDigit(p.runes[k]) {
			k++
		}
	} else {
		return nil, p.fail("Expecting value", start)
	}
	intEnd := k
	isFloat := false
	if k+1 < n && p.runes[k] == '.' && isASCIIDigit(p.runes[k+1]) {
		k += 2
		for k < n && isASCIIDigit(p.runes[k]) {
			k++
		}
		isFloat = true
	}
	if k < n && (p.runes[k] == 'e' || p.runes[k] == 'E') {
		j := k + 1
		if j < n && (p.runes[j] == '+' || p.runes[j] == '-') {
			j++
		}
		if j < n && isASCIIDigit(p.runes[j]) {
			for j < n && isASCIIDigit(p.runes[j]) {
				j++
			}
			k = j
			isFloat = true
		}
	}
	lit := string(p.runes[start:k])
	p.i = k
	if isFloat {
		f, err := strconv.ParseFloat(lit, 64)
		if err != nil {
			if ne, ok := err.(*strconv.NumError); ok && ne.Err == strconv.ErrRange {
				return f, nil
			}
			return nil, p.fail("Expecting value", start)
		}
		return f, nil
	}
	_ = intEnd
	bi, ok := new(big.Int).SetString(lit, 10)
	if !ok {
		return nil, p.fail("Expecting value", start)
	}
	if bi.IsInt64() {
		return bi.Int64(), nil
	}
	return bi, nil
}

func hexVal(rs []rune) (rune, bool) {
	if len(rs) != 4 {
		return 0, false
	}
	var v rune
	for _, r := range rs {
		v <<= 4
		switch {
		case r >= '0' && r <= '9':
			v |= r - '0'
		case r >= 'a' && r <= 'f':
			v |= r - 'a' + 10
		case r >= 'A' && r <= 'F':
			v |= r - 'A' + 10
		default:
			return 0, false
		}
	}
	return v, true
}

func appendWTF8(b *strings.Builder, r rune) {
	if r >= 0xd800 && r <= 0xdfff {
		b.WriteByte(0xed)
		b.WriteByte(byte(0x80 | ((r >> 6) & 0x3f)))
		b.WriteByte(byte(0x80 | (r & 0x3f)))
		return
	}
	b.WriteRune(r)
}

func (p *jsonParser) str() (any, error) {
	begin := p.i
	p.i++
	var b strings.Builder
	n := len(p.runes)
	for {
		if p.i >= n {
			return nil, p.fail("Unterminated string starting at", begin)
		}
		c := p.runes[p.i]
		if c == '"' {
			p.i++
			return b.String(), nil
		}
		if c < 0x20 {
			return nil, p.fail("Invalid control character at", p.i)
		}
		if c != '\\' {
			b.WriteRune(c)
			p.i++
			continue
		}
		if p.i+1 >= n {
			return nil, p.fail("Unterminated string starting at", begin)
		}
		e := p.runes[p.i+1]
		switch e {
		case '"', '\\', '/':
			b.WriteRune(e)
			p.i += 2
		case 'b':
			b.WriteByte('\b')
			p.i += 2
		case 'f':
			b.WriteByte('\f')
			p.i += 2
		case 'n':
			b.WriteByte('\n')
			p.i += 2
		case 'r':
			b.WriteByte('\r')
			p.i += 2
		case 't':
			b.WriteByte('\t')
			p.i += 2
		case 'u':
			if p.i+6 > n {
				return nil, p.fail("Invalid \\uXXXX escape", p.i+1)
			}
			u, ok := hexVal(p.runes[p.i+2 : p.i+6])
			if !ok {
				return nil, p.fail("Invalid \\uXXXX escape", p.i+1)
			}
			p.i += 6
			if u >= 0xd800 && u <= 0xdbff && p.i+6 <= n && p.runes[p.i] == '\\' && p.runes[p.i+1] == 'u' {
				if u2, ok2 := hexVal(p.runes[p.i+2 : p.i+6]); ok2 && u2 >= 0xdc00 && u2 <= 0xdfff {
					b.WriteRune(0x10000 + ((u - 0xd800) << 10) + (u2 - 0xdc00))
					p.i += 6
					continue
				}
			}
			appendWTF8(&b, u)
		default:
			return nil, p.fail("Invalid \\escape", p.i)
		}
	}
}

func (p *jsonParser) object() (any, error) {
	o := newJSONObject()
	p.i++
	p.skipWS()
	n := len(p.runes)
	if p.i < n && p.runes[p.i] == '}' {
		p.i++
		return o, nil
	}
	for {
		if p.i >= n || p.runes[p.i] != '"' {
			return nil, p.fail("Expecting property name enclosed in double quotes", p.i)
		}
		kv, err := p.str()
		if err != nil {
			return nil, err
		}
		key := kv.(string)
		p.skipWS()
		if p.i >= n || p.runes[p.i] != ':' {
			return nil, p.fail("Expecting ':' delimiter", p.i)
		}
		p.i++
		p.skipWS()
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		o.set(key, v)
		p.skipWS()
		if p.i < n && p.runes[p.i] == '}' {
			p.i++
			return o, nil
		}
		if p.i >= n || p.runes[p.i] != ',' {
			return nil, p.fail("Expecting ',' delimiter", p.i)
		}
		comma := p.i
		p.i++
		p.skipWS()
		if p.i < n && p.runes[p.i] == '}' {
			return nil, p.fail("Illegal trailing comma before end of object", comma)
		}
	}
}

func (p *jsonParser) array() (any, error) {
	out := []any{}
	p.i++
	p.skipWS()
	n := len(p.runes)
	if p.i < n && p.runes[p.i] == ']' {
		p.i++
		return out, nil
	}
	for {
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		p.skipWS()
		if p.i < n && p.runes[p.i] == ']' {
			p.i++
			return out, nil
		}
		if p.i >= n || p.runes[p.i] != ',' {
			return nil, p.fail("Expecting ',' delimiter", p.i)
		}
		comma := p.i
		p.i++
		p.skipWS()
		if p.i < n && p.runes[p.i] == ']' {
			return nil, p.fail("Illegal trailing comma before end of array", comma)
		}
	}
}
