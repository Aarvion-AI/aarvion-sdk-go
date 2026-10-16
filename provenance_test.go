package aarvion

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func provConfig() *Config {
	return NewConfig("agt_x", "aav_dev_abc123def456.theSecretPart",
		"https://cp/api/v1/bundles/acme/agt_x/policy.tar.gz", "s", "https://cp")
}

func newRec(t *testing.T, dir string) *Recorder {
	t.Helper()
	r, err := NewRecorder(provConfig(), filepath.Join(dir, "prov.db"), "acme", 0)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func mustRecord(t *testing.T, r *Recorder, in RecordInput) map[string]any {
	t.Helper()
	out, err := r.Record(in)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAutoflushThreadStartsWhenEnabledAndStopsOnClose(t *testing.T) {
	r, err := NewRecorder(provConfig(), filepath.Join(t.TempDir(), "prov.db"), "acme", 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if !r.flusherAlive() {
		t.Fatal("flusher not running")
	}
	r.Close()
	if r.flusherAlive() {
		t.Fatal("flusher still running")
	}
}

func TestNoAutoflushThreadWhenDisabled(t *testing.T) {
	r := newRec(t, t.TempDir())
	defer r.Close()
	if r.done != nil {
		t.Fatal("flusher created")
	}
}

func TestReplicaIDIsTheDevKeyID(t *testing.T) {
	if got := replicaID(provConfig().RuntimeKey); got != "abc123def456" {
		t.Fatal(got)
	}
}

func TestRowHashMatchesShipperRecipe(t *testing.T) {
	sum := sha256.Sum256([]byte(`0|{"a":1,"b":null}`))
	got, err := rowHash("0", obj("a", int64(1), "b", nil))
	if err != nil || got != hex.EncodeToString(sum[:]) {
		t.Fatalf("got %s %v", got, err)
	}
}

func TestChainLinksAndSeedsZero(t *testing.T) {
	r := newRec(t, t.TempDir())
	defer r.Close()
	r1 := mustRecord(t, r, RecordInput{Method: "POST", Path: "/a", Host: "h", Decision: "allow"})
	r2 := mustRecord(t, r, RecordInput{Method: "POST", Path: "/b", Host: "h", Decision: "deny", PolicyID: "p.v1"})
	if r1["prev_hash"] != "0" || r2["prev_hash"] != r1["row_hash"] || r1["replica_id"] != "abc123def456" {
		t.Fatal(r1, r2)
	}
}

func TestChainContinuesAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	r := newRec(t, dir)
	r1 := mustRecord(t, r, RecordInput{Method: "GET", Path: "/", Host: "h", Decision: "allow"})
	r.Close()
	r2db := newRec(t, dir)
	defer r2db.Close()
	r2 := mustRecord(t, r2db, RecordInput{Method: "GET", Path: "/2", Host: "h", Decision: "allow"})
	if r2["prev_hash"] != r1["row_hash"] || r2["seq"] != int64(2) {
		t.Fatal(r2)
	}
}

func TestEnforcedFlagRecorded(t *testing.T) {
	r := newRec(t, t.TempDir())
	defer r.Close()
	out := mustRecord(t, r, RecordInput{Method: "POST", Path: "/x", Host: "h", Decision: "deny", Enforced: Bool(false)})
	if out["enforced"] != false {
		t.Fatal(out)
	}
}

func TestFlushPushesBatchAndMarksPushed(t *testing.T) {
	r := newRec(t, t.TempDir())
	defer r.Close()
	mustRecord(t, r, RecordInput{Method: "POST", Path: "/a", Host: "h", Decision: "allow"})
	mustRecord(t, r, RecordInput{Method: "POST", Path: "/b", Host: "h", Decision: "deny", PolicyID: "p.v1"})
	if n, _ := r.PendingCount(); n != 2 {
		t.Fatal(n)
	}
	seen := map[string]any{}
	pushed, err := r.FlushWith(mockClient(func(req *http.Request) (*http.Response, error) {
		seen["url"] = req.URL.String()
		seen["auth"] = req.Header.Get("Authorization")
		var body map[string]any
		json.Unmarshal([]byte(readBody(t, req)), &body)
		seen["body"] = body
		return jsonResponse(200, `{"ingested": 2}`), nil
	}))
	if err != nil || pushed != 2 {
		t.Fatalf("pushed %d %v", pushed, err)
	}
	if n, _ := r.PendingCount(); n != 0 {
		t.Fatal(n)
	}
	body := seen["body"].(map[string]any)
	decisions := body["decisions"].([]any)
	if seen["url"] != "https://cp/api/v1/agents/acme/agt_x/decisions" || seen["auth"] != "Bearer aav_dev_abc123def456.theSecretPart" ||
		body["dp_id"] != "sdk" || len(decisions) != 2 || decisions[0].(map[string]any)["seq"] != float64(1) {
		t.Fatal(seen)
	}
}

func TestFlushKeepsQueueOnNetworkError(t *testing.T) {
	r := newRec(t, t.TempDir())
	defer r.Close()
	mustRecord(t, r, RecordInput{Method: "POST", Path: "/a", Host: "h", Decision: "allow"})
	pushed, err := r.FlushWith(mockClient(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("offline")
	}))
	if err != nil || pushed != 0 {
		t.Fatalf("pushed %d %v", pushed, err)
	}
	if n, _ := r.PendingCount(); n != 1 {
		t.Fatal(n)
	}
}

func TestFlushEmptyIsNoop(t *testing.T) {
	r := newRec(t, t.TempDir())
	defer r.Close()
	n, err := r.FlushWith(mockClient(func(*http.Request) (*http.Response, error) { return textResponse(200, ""), nil }))
	if err != nil || n != 0 {
		t.Fatal(n, err)
	}
}

func TestFlushKeepsQueueOnHTTPErrorStatus(t *testing.T) {
	r := newRec(t, t.TempDir())
	defer r.Close()
	mustRecord(t, r, RecordInput{Method: "POST", Path: "/a", Host: "h", Decision: "allow"})
	for _, status := range []int{302, 500} {
		n, err := r.FlushWith(mockClient(func(*http.Request) (*http.Response, error) { return textResponse(status, ""), nil }))
		if err != nil || n != 0 {
			t.Fatal(n, err)
		}
	}
}

func TestRowHashMatchesPythonVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/row_hash_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	v, err := pyLoads(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	cases := v.([]any)
	if len(cases) < 1000 {
		t.Fatal(len(cases))
	}
	bad := 0
	for i, c := range cases {
		o := c.(*jsonObject)
		prev, _ := o.get("prev")
		payload, _ := o.get("payload")
		expected, _ := o.get("expected")
		got, err := rowHash(prev.(string), payload)
		if err != nil || got != expected {
			if bad < 3 {
				t.Errorf("case %d: %s %v", i, got, err)
			}
			bad++
		}
	}
	if bad != 0 {
		t.Fatalf("%d mismatches", bad)
	}
}

func TestTimestampsUsePythonIsoformat(t *testing.T) {
	if !regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{6})?\+00:00$`).MatchString(isoNow()) {
		t.Fatal(isoNow())
	}
	if got := isoformat(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)); got != "2026-01-02T03:04:05+00:00" {
		t.Fatal(got)
	}
	if got := isoformat(time.Date(2026, 1, 2, 3, 4, 5, 1999, time.UTC)); got != "2026-01-02T03:04:05.000001+00:00" {
		t.Fatal(got)
	}
}

func TestRecordJSONMatchesPythonDumps(t *testing.T) {
	r := newRec(t, t.TempDir())
	defer r.Close()
	mustRecord(t, r, RecordInput{Method: "POST", Path: "/\u00e9", Host: "h", Decision: "deny", PolicyID: "a",
		PolicyIDs: []string{"a", "b"}, Reason: "r\u2029\x7f", LatencyMs: 7.25, OnBehalfOf: "\U0001F680", CallSite: "x.go:1"})
	var text string
	if err := r.db.QueryRow("SELECT record_json FROM decisions").Scan(&text); err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`"timestamp": "[^"]+"|"row_hash": "[0-9a-f]+"`)
	got := re.ReplaceAllString(text, "X")
	want := strings.ReplaceAll(`{"replica_id": "abc123def456", X, "on_behalf_of": "#ud83d#ude80", "risk_tier": null, "method": "POST", `+
		`"path": "/#u00e9", "host": "h", "decision": "deny", "policy_id": "a", "policy_ids": ["a", "b"], "reason": "r#u2029#u007f", `+
		`"redactions": null, "latency_ms": 7.25, "enforced": true, "call_site": "x.go:1", "sdk_version": "0.2.0", "prev_hash": "0", X}`, "#", "\\")
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}
