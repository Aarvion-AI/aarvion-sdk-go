package aarvion

import (
	"regexp"
	"strings"
)

type Span [2]int

var (
	blobRe = regexp.MustCompile(translatePyRegex(
		`"(?:bytes|data|b64_json|file_data)"\s*:\s*"[A-Za-z0-9+/=\\]{64,}(?:"|\z)` +
			`|data:[A-Za-z0-9.+/-]+;base64,[A-Za-z0-9+/=\\]+`))
	cardRunRe = regexp.MustCompile(`\.?[0-9](?:[ -]?[0-9])*`)
	cardIINRe = regexp.MustCompile(
		`^(?:4[0-9]{12}(?:[0-9]{3}){0,2}|5[1-5][0-9]{14}|2(?:22[1-9]|2[3-9][0-9]|[3-6][0-9]{2}|7[01][0-9]|720)[0-9]{12}` +
			`|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11,16}|6(?:011|5[0-9]{2}|4[4-9][0-9])[0-9]{12,15}` +
			`|35(?:2[89]|[3-8][0-9])[0-9]{12,15}|62[0-9]{14,17})\z`)
	ibanRunRe = regexp.MustCompile(`\b[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]){11,30}\b`)
)

var IBANLengths = map[string]int{
	"AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22, "BI": 27,
	"BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DJ": 27, "DK": 18, "DO": 28,
	"EE": 20, "EG": 29, "ES": 24, "FI": 18, "FK": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23,
	"GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27,
	"JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "LY": 25,
	"MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20, "MR": 27, "MT": 31, "MU": 30, "NI": 28, "NL": 18,
	"NO": 15, "OM": 23, "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "RU": 33,
	"SA": 24, "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "SO": 23, "ST": 25, "SV": 28,
	"TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20, "YE": 30,
}

func BlobSpans(body string) []Span {
	text := body
	if strings.HasSuffix(text, "\n") {
		text = text[:len(text)-1]
	}
	var out []Span
	for _, m := range blobRe.FindAllStringIndex(text, -1) {
		out = append(out, Span{m[0], m[1]})
	}
	return out
}

func LuhnValid(digits string) bool {
	total := 0
	n := len(digits)
	for i := 0; i < n; i++ {
		d := int(digits[n-1-i]) - 48
		if i%2 == 1 {
			if d > 4 {
				d = d*2 - 9
			} else {
				d = d * 2
			}
		}
		total += d
	}
	return total%10 == 0
}

func CardSpans(text string) []Span {
	var out []Span
	for _, m := range cardRunRe.FindAllStringIndex(text, -1) {
		g := text[m[0]:m[1]]
		if strings.HasPrefix(g, ".") {
			continue
		}
		digits := strings.ReplaceAll(strings.ReplaceAll(g, " ", ""), "-", "")
		if len(digits) >= 13 && len(digits) <= 19 && cardIINRe.MatchString(digits) && LuhnValid(digits) {
			out = append(out, Span{m[0], m[1]})
		}
	}
	return out
}

func IBANMod97Valid(iban string) bool {
	rem := 0
	s := iban[4:] + iban[:4]
	for i := 0; i < len(s); i++ {
		c := int(s[i])
		if c >= 65 {
			rem = (rem*100 + c - 55) % 97
		} else {
			rem = (rem*10 + c - 48) % 97
		}
	}
	return rem == 1
}

func IBANSpans(text string) []Span {
	var out []Span
	for _, m := range ibanRunRe.FindAllStringIndex(text, -1) {
		run := text[m[0]:m[1]]
		compact := strings.ReplaceAll(run, " ", "")
		n := IBANLengths[compact[:2]]
		if n == 0 || len(compact) < n || !IBANMod97Valid(compact[:n]) {
			continue
		}
		seen := 0
		for i := 0; i < len(run); i++ {
			if run[i] != ' ' {
				seen++
				if seen == n {
					out = append(out, Span{m[0], m[0] + i + 1})
					break
				}
			}
		}
	}
	return out
}
