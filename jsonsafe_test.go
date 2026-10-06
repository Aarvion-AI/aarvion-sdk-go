package aarvion

import (
	"encoding/json"
	"strings"
	"testing"
)

const postalPlaceholder = "[redacted: postal code per data-protection policy]"

func parseJSONMap(t *testing.T, s string) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, s)
	}
	return v
}

func TestNumbersThatOnlyContainFiveDigitsAreLeftAlone(t *testing.T) {
	body := `{"traveller":{"phone":"+91 98765 43210"},"budget":{"amount":250000,"currency":"JPY"}}`
	v := parseJSONMap(t, RewriteBody(body, "postal code", ""))
	if got := v["budget"].(map[string]any)["amount"]; got != float64(250000) {
		t.Fatalf("amount changed: %v", got)
	}
	want := "+91 " + postalPlaceholder + " " + postalPlaceholder
	if got := v["traveller"].(map[string]any)["phone"]; got != want {
		t.Fatalf("phone: %v", got)
	}
}

func TestASensitiveNumberBecomesAQuotedString(t *testing.T) {
	v := parseJSONMap(t, RewriteBody(`{"zip":94107,"card":4111111111111111}`, "postal code,credit card number", ""))
	if v["zip"] != postalPlaceholder {
		t.Fatalf("zip: %v", v["zip"])
	}
	if v["card"] != "[redacted: credit card number per data-protection policy]" {
		t.Fatalf("card: %v", v["card"])
	}
}

func TestEscapedTextIsMaskedAndStaysValid(t *testing.T) {
	body := `{"t":"line one\nmail jane@acme.com \"quoted\" café"}`
	v := parseJSONMap(t, RewriteBody(body, "email address", ""))
	want := "line one\nmail [redacted: email address per data-protection policy] \"quoted\" café"
	if v["t"] != want {
		t.Fatalf("got %q", v["t"])
	}
}

func TestUntouchedPartsKeepTheirExactBytes(t *testing.T) {
	body := "{ \"a\" : 250000 ,\n  \"note\" : \"plain\",\n  \"e\":\"x@y.com\" }"
	want := "{ \"a\" : 250000 ,\n  \"note\" : \"plain\",\n  \"e\":\"[redacted: email address per data-protection policy]\" }"
	if got := RewriteBody(body, "email address,postal code", ""); got != want {
		t.Fatalf("got %q", got)
	}
}

func TestPlainTextUsesWholeNumbersOnly(t *testing.T) {
	if got := RewriteBody("zip 94107 and 250000 and 12345-", "postal code", ""); got !=
		"zip "+postalPlaceholder+" and 250000 and "+postalPlaceholder+"-" {
		t.Fatalf("got %q", got)
	}
	if got := RewriteBody("zip 94107-1234", "postal code", ""); got != "zip "+postalPlaceholder {
		t.Fatalf("got %q", got)
	}
}

func TestCodesInsideLongerWordsAreLeftAlone(t *testing.T) {
	if got := RewriteBody("CONTENTTYPEHEADER", "SWIFT/BIC", ""); got != "CONTENTTYPEHEADER" {
		t.Fatalf("got %q", got)
	}
	if got := RewriteBody("pay DEUTDEFF500 now", "SWIFT/BIC", ""); got !=
		"pay [redacted: bank SWIFT/BIC code per data-protection policy] now" {
		t.Fatalf("got %q", got)
	}
	if got := RewriteBody("build 1.2.3.4567", "IP address", ""); got != "build 1.2.3.4567" {
		t.Fatalf("got %q", got)
	}
}

func TestInvalidJSONFallsBackToText(t *testing.T) {
	got := RewriteBody("{not json, mail jane@acme.com", "email address", "")
	if strings.Contains(got, "jane@acme.com") ||
		!strings.Contains(got, "[redacted: email address per data-protection policy]") {
		t.Fatalf("got %q", got)
	}
}

func TestTravelAgentTripListStaysValidJSON(t *testing.T) {
	body := `{"messages":[{"role":"user","content":[{"toolResult":{"content":[{"json":` +
		`{"traveller":{"phone":"+91 98765 43210","email":"asha@example.com"},` +
		`"trips":[{"id":"T1002","budget":{"amount":250000,"currency":"JPY"}},` +
		`{"id":"T1003","budget":{"amount":60000,"currency":"INR"}}]}}]}}]}]}`
	out := RewriteBody(body, "email address,postal code", "")
	parseJSONMap(t, out)
	if !strings.Contains(out, `"amount":250000`) {
		t.Fatalf("250000 changed: %s", out)
	}
	if !strings.Contains(out, `"amount":"`+postalPlaceholder+`"`) {
		t.Fatalf("60000 not masked as text: %s", out)
	}
	if strings.Contains(out, "asha@example.com") {
		t.Fatalf("email leaked: %s", out)
	}
}
