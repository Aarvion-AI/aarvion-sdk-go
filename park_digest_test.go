package aarvion

import (
	"os"
	"reflect"
	"testing"
)

type parkFixtures struct {
	raw map[string]any
}

func loadParkFixtures(t *testing.T) parkFixtures {
	t.Helper()
	b, err := os.ReadFile("testdata/park_digest.json")
	if err != nil {
		t.Fatal(err)
	}
	v, err := pyLoadsPlain(b)
	if err != nil {
		t.Fatal(err)
	}
	return parkFixtures{raw: v.(map[string]any)}
}

func (f parkFixtures) cases(t *testing.T, key string) []map[string]any {
	t.Helper()
	list, ok := f.raw[key].([]any)
	if !ok {
		t.Fatalf("fixture section %s missing", key)
	}
	out := make([]map[string]any, len(list))
	for i, c := range list {
		out[i] = c.(map[string]any)
	}
	return out
}

func strs(v any) []string {
	out := []string{}
	for _, s := range asList(v) {
		out = append(out, s.(string))
	}
	return out
}

func TestParkFixtureVersion(t *testing.T) {
	f := loadParkFixtures(t)
	if f.raw["digest_version"] != int64(DigestVersion) {
		t.Fatalf("fixture digest_version %v, want %d", f.raw["digest_version"], DigestVersion)
	}
	if f.raw["summary_max"] != int64(SummaryMax) {
		t.Fatalf("fixture summary_max %v, want %d", f.raw["summary_max"], SummaryMax)
	}
}

func TestParkCanonicalJSON(t *testing.T) {
	f := loadParkFixtures(t)
	for _, c := range f.cases(t, "jcs") {
		t.Run(c["name"].(string), func(t *testing.T) {
			v, err := pyLoads(c["json"].(string))
			if err != nil {
				t.Fatal(err)
			}
			got, err := Canonicalize(toPlain(v))
			if err != nil {
				t.Fatal(err)
			}
			if got != c["canonical"] {
				t.Fatalf("got  %s\nwant %s", got, c["canonical"])
			}
		})
	}
}

func TestParkHTTPAction(t *testing.T) {
	f := loadParkFixtures(t)
	for _, c := range f.cases(t, "http") {
		t.Run(c["name"].(string), func(t *testing.T) {
			in := c["input"].(map[string]any)
			action := HTTPAction{
				Scope: in["scope"].(string), Method: in["method"].(string), Host: in["host"].(string),
				Path: in["path"].(string), Query: strOr(in["query"]), ContentType: strOr(in["content_type"]),
				Body: []byte(in["body"].(string)), Volatile: strs(in["volatile"]),
			}.Object()
			got, err := Canonicalize(action)
			if err != nil {
				t.Fatal(err)
			}
			if got != c["canonical"] {
				t.Fatalf("got  %s\nwant %s", got, c["canonical"])
			}
			d, err := Digest(action)
			if err != nil {
				t.Fatal(err)
			}
			if d != c["digest"] {
				t.Fatalf("digest %s, want %s", d, c["digest"])
			}
			if ids, ok := c["rule_ids"]; ok {
				vol := VolatileFor(strs(ids), "http", f.raw["park_catalog"].(map[string]any))
				if !reflect.DeepEqual(vol, strs(in["volatile"])) {
					t.Fatalf("volatile %v, want %v", vol, in["volatile"])
				}
			}
		})
	}
}

func TestParkToolAction(t *testing.T) {
	f := loadParkFixtures(t)
	for _, c := range f.cases(t, "tool") {
		t.Run(c["name"].(string), func(t *testing.T) {
			in := c["input"].(map[string]any)
			action := ToolAction{
				Scope: in["scope"].(string), EntityID: in["entity_id"].(string), Tool: in["tool"].(string),
				Args: in["args"], ToolDef: strOr(in["tool_def"]), Volatile: strs(in["volatile"]),
			}.Object()
			got, err := Canonicalize(action)
			if err != nil {
				t.Fatal(err)
			}
			if got != c["canonical"] {
				t.Fatalf("got  %s\nwant %s", got, c["canonical"])
			}
			d, err := Digest(action)
			if err != nil {
				t.Fatal(err)
			}
			if d != c["digest"] {
				t.Fatalf("digest %s, want %s", d, c["digest"])
			}
		})
	}
}

func TestParkScope(t *testing.T) {
	f := loadParkFixtures(t)
	for _, c := range f.cases(t, "scope") {
		if got := ScopeFor(strOr(c["caller_principal_id"]), strOr(c["session_id"])); got != c["expected"] {
			t.Fatalf("scope %q, want %q", got, c["expected"])
		}
	}
}

func TestParkFallbackMatchesFixture(t *testing.T) {
	f := loadParkFixtures(t)
	want := f.raw["park_catalog"].(map[string]any)["fallback"]
	if !reflect.DeepEqual(FallbackCatalog()["fallback"], want) {
		t.Fatalf("fallback %v, want %v", FallbackCatalog()["fallback"], want)
	}
}

func TestParkVolatileFor(t *testing.T) {
	f := loadParkFixtures(t)
	catalog := f.raw["park_catalog"].(map[string]any)
	for _, c := range f.cases(t, "volatile") {
		t.Run(c["name"].(string), func(t *testing.T) {
			got := VolatileFor(strs(c["rule_ids"]), c["kind"].(string), catalog)
			if !reflect.DeepEqual(got, strs(c["expected"])) {
				t.Fatalf("got %v, want %v", got, c["expected"])
			}
		})
	}
}

func TestParkSummary(t *testing.T) {
	f := loadParkFixtures(t)
	catalog := f.raw["park_catalog"].(map[string]any)
	for _, c := range f.cases(t, "summary") {
		t.Run(c["name"].(string), func(t *testing.T) {
			a := c["action"].(map[string]any)
			action := SummaryAction{Kind: a["kind"].(string)}
			if action.Kind == "http" {
				action.Method, action.Host, action.Path = a["method"].(string), a["host"].(string), a["path"].(string)
				action.Query, action.ContentType = strOr(a["query"]), strOr(a["content_type"])
				action.Body = []byte(strOr(a["body"]))
			} else {
				action.Tool, action.Args = a["tool"].(string), a["args"]
			}
			var got string
			if tpl, ok := c["template"].(string); ok {
				got = RenderSummary(tpl, action)
			} else {
				got = SummaryFor(strs(c["rule_ids"]), action, catalog)
			}
			if got != c["expected"] {
				t.Fatalf("got  %q\nwant %q", got, c["expected"])
			}
		})
	}
}
