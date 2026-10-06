package aarvion

import (
	"reflect"
	"strings"
	"testing"
)

func TestCardSpansIgnoreFloatsAndLuhnFailures(t *testing.T) {
	if s := CardSpans(`{"ltv":0.1791044776119403,"x":0.4111111111111111}`); len(s) != 0 {
		t.Fatal(s)
	}
	if s := CardSpans("card 4111 1111 1111 1112"); len(s) != 0 {
		t.Fatal(s)
	}
	if s := CardSpans("card 4242-4242-4242-4242 ok"); !reflect.DeepEqual(s, []Span{{5, 24}}) {
		t.Fatal(s)
	}
	if !LuhnValid("378282246310005") {
		t.Fatal("luhn")
	}
}

func TestIBANSpansValidateChecksumAndTrimToCountryLength(t *testing.T) {
	if s := IBANSpans("GB29NWBK60161331926819 IS"); !reflect.DeepEqual(s, []Span{{0, 22}}) {
		t.Fatal(s)
	}
	if s := IBANSpans("GB28NWBK60161331926819"); len(s) != 0 {
		t.Fatal(s)
	}
	if s := IBANSpans("x DE89 3704 0044 0532 0130 00."); !reflect.DeepEqual(s, []Span{{2, 29}}) {
		t.Fatal(s)
	}
}

func TestBlobSpansCoverConverseBytesAndDataURLs(t *testing.T) {
	b64 := strings.Repeat("A", 100)
	if s := BlobSpans(`{"bytes":"` + b64 + `"}`); len(s) != 1 {
		t.Fatal(s)
	}
	if s := BlobSpans(`{"url":"data:image/png;base64,` + b64 + `"}`); len(s) != 1 {
		t.Fatal(s)
	}
	if s := BlobSpans(`{"data":"GB29NWBK60161331926819"}`); len(s) != 0 {
		t.Fatal(s)
	}
}

func TestBlobDollarMatchesBeforeFinalNewlineLikePython(t *testing.T) {
	body := `"bytes":"` + strings.Repeat("Q", 70) + "\n"
	if s := BlobSpans(body); !reflect.DeepEqual(s, []Span{{0, len(body) - 1}}) {
		t.Fatal(s)
	}
	if s := BlobSpans(`"bytes":"` + strings.Repeat("Q", 70) + "\n\n"); len(s) != 0 {
		t.Fatal(s)
	}
}

func TestOnlyASCIIDigitsAndSpacesMatchLikeThePolicy(t *testing.T) {
	got := RewriteBody("\u0661\u0662\u0663\u0664\u0665 and 1234\u20035678\u30009012 and 12345 and 1234 5678 9012",
		"postal code,Aadhaar", "")
	want := "\u0661\u0662\u0663\u0664\u0665 and 1234\u20035678\u30009012 and " +
		"[redacted: postal code per data-protection policy] and [redacted: Indian Aadhaar number per data-protection policy]"
	if got != want {
		t.Fatalf("got %q", got)
	}
}
