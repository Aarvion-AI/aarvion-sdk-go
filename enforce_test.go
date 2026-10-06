package aarvion

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

type rewriteCase struct {
	Name        string  `json:"name"`
	Body        string  `json:"body"`
	Redactions  string  `json:"redactions"`
	RedactStyle *string `json:"redact_style"`
	Expected    string  `json:"expected"`
	JavaExpect  *string `json:"java_expected"`
}

func loadRewriteCases(t *testing.T, path string) []rewriteCase {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cases []rewriteCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	return cases
}

func styleOf(c rewriteCase) string {
	if c.RedactStyle == nil {
		return ""
	}
	return *c.RedactStyle
}

func TestRewriteMatchesLuaConformance(t *testing.T) {
	cases := loadRewriteCases(t, "testdata/redact_conformance.json")
	if len(cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			if got := RewriteBody(c.Body, c.Redactions, styleOf(c)); got != c.Expected {
				t.Fatalf("got %q want %q", got, c.Expected)
			}
		})
	}
}

func TestRewriteMatchesJavaOnFuzzCorpus(t *testing.T) {
	cases := loadRewriteCases(t, "testdata/rewrite_fuzz_corpus.json")
	bad := 0
	for i, c := range cases {
		want := c.Expected
		if c.JavaExpect != nil {
			want = *c.JavaExpect
		}
		if got := RewriteBody(c.Body, c.Redactions, styleOf(c)); got != want {
			if bad < 5 {
				t.Errorf("case %d: got %q want %q", i, got, want)
			}
			bad++
		}
	}
	if bad > 0 || len(cases) < 1000 {
		t.Fatalf("%d mismatches of %d", bad, len(cases))
	}
}

func TestBuildInputShapeAndWholeBody(t *testing.T) {
	doc := BuildExtAuthzInput("POST", "api.openai.com", "/v1/chat", map[string]string{"x-k": "v"}, "hello")
	http := doc["attributes"].(map[string]any)["request"].(map[string]any)["http"].(map[string]any)
	if http["method"] != "POST" || http["host"] != "api.openai.com" || http["body"] != "hello" {
		t.Fatal(http)
	}
	if !reflect.DeepEqual(http["headers"], map[string]any{"x-k": "v"}) {
		t.Fatal(http["headers"])
	}
	big := strings.Repeat("a", 200_000) + " SSN 412-55-9087"
	doc = BuildExtAuthzInput("POST", "h", "/", nil, big)
	if doc["attributes"].(map[string]any)["request"].(map[string]any)["http"].(map[string]any)["body"] != big {
		t.Fatal("body truncated")
	}
}

func TestBodyTooLargeFailsClosedPastTheLimitOnly(t *testing.T) {
	if BodyTooLarge(strings.Repeat("a", 120_000)) != nil {
		t.Fatal("limited too early")
	}
	d := BodyTooLarge(strings.Repeat("a", int(MaxBodyBytes)+1))
	if d["allowed"] != false || d["headers"].(map[string]any)["x-policy-violated"] != BodyLimitPolicy {
		t.Fatal(d)
	}
}

func TestPolicyIDsPrefersTheFullList(t *testing.T) {
	ids, _ := PolicyIDs(map[string]any{"x-policy-violated": "a", "x-aarvion-policies-violated": "a,b"})
	if !reflect.DeepEqual(ids, []string{"a", "b"}) {
		t.Fatal(ids)
	}
	ids, _ = PolicyIDs(map[string]any{"x-policy-violated": "a"})
	if !reflect.DeepEqual(ids, []string{"a"}) {
		t.Fatal(ids)
	}
	ids, _ = PolicyIDs(map[string]any{})
	if ids != nil {
		t.Fatal(ids)
	}
}

func TestNonUTF8BodySkipsDetectors(t *testing.T) {
	doc := BuildExtAuthzInput("POST", "h", "/", nil, []byte("\xff\xfe\x00bad"))
	if doc["attributes"].(map[string]any)["request"].(map[string]any)["http"].(map[string]any)["body"] != "" {
		t.Fatal("expected empty body")
	}
}

func TestApplyDecisionDenyRaises(t *testing.T) {
	decision := map[string]any{
		"allowed":     false,
		"http_status": int64(403),
		"headers":     map[string]any{"x-policy-violated": "starter.prod_blast_radius.v1", "x-policy-reason": "blocked"},
	}
	_, err := ApplyDecision(decision, "body")
	var d *PolicyDenied
	if !errors.As(err, &d) {
		t.Fatalf("got %v", err)
	}
	if d.PolicyID != "starter.prod_blast_radius.v1" || d.HTTPStatus != 403 {
		t.Fatal(d)
	}
}

func TestApplyDecisionRedactsOnAllowWithDirectives(t *testing.T) {
	out, err := ApplyDecision(map[string]any{"allowed": true, "headers": map[string]any{"x-aarvion-redactions": "email address"}},
		"mail jane@acme.com end")
	if err != nil || out != "mail [redacted: email address per data-protection policy] end" {
		t.Fatalf("got %q %v", out, err)
	}
}

func TestApplyDecisionMasksWithStyle(t *testing.T) {
	out, err := ApplyDecision(map[string]any{"allowed": true, "headers": map[string]any{
		"x-aarvion-redactions":   "credit card number",
		"x-aarvion-redact-style": "credit card number=mask:*:4",
	}}, "card 4111111111111111 ok")
	if err != nil || out != "card ************1111 ok" {
		t.Fatalf("got %q %v", out, err)
	}
}

func TestApplyDecisionPlainAllowPassesThrough(t *testing.T) {
	out, err := ApplyDecision(map[string]any{"allowed": true}, "untouched")
	if err != nil || out != "untouched" {
		t.Fatalf("got %q %v", out, err)
	}
}

func TestPythonSemanticsOnOddDecisions(t *testing.T) {
	_, err := ApplyDecision(map[string]any{"allowed": int64(0), "http_status": "418"}, "b")
	if d := asPolicyDenied(err); d == nil || d.HTTPStatus != 418 || d.PolicyID != "policy" || d.Reason != "blocked by policy" ||
		d.Error() != "policy: blocked by policy" || !reflect.DeepEqual(d.PolicyIDs, []string{"policy"}) {
		t.Fatalf("got %v", err)
	}
	_, err = ApplyDecision(map[string]any{"allowed": false, "http_status": nil}, "b")
	if err == nil || err.Error() != "int() argument must be a string, a bytes-like object or a real number, not 'NoneType'" {
		t.Fatalf("got %v", err)
	}
	_, err = ApplyDecision(map[string]any{"allowed": true, "headers": []any{"x"}}, "b")
	if err == nil || err.Error() != "'list' object has no attribute 'get'" {
		t.Fatalf("got %v", err)
	}
	out, err := ApplyDecision(map[string]any{"allowed": "yes", "headers": map[string]any{}}, "b")
	if err != nil || out != "b" {
		t.Fatalf("got %q %v", out, err)
	}
}

func TestMaskStylesParsing(t *testing.T) {
	m := parseMaskStyles(" email address =mask:#:\u0663 , garbage,US SSN=mask:\U0001F600:0\n")
	if m["email address"].char != "#" || m["email address"].keep.Int64() != 3 {
		t.Fatal(m)
	}
	if m["US SSN"].char != "\U0001F600" || m["US SSN"].keep.Int64() != 0 {
		t.Fatal(m)
	}
	if len(m) != 2 {
		t.Fatal(m)
	}
}
