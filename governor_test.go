package aarvion

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestProcessAllowPassesBodyThroughAndRecords(t *testing.T) {
	rec := &stubRecorder{}
	gov := NewGovernor(&stubEvaluator{decision: map[string]any{"allowed": true}}, rec, false)
	out, err := gov.Process("POST", "https://api.openai.com/v1/chat", nil, []byte("hello"))
	if err != nil || out != "hello" {
		t.Fatalf("got %q %v", out, err)
	}
	if rec.rows[0].Decision != "allow" || *rec.rows[0].Enforced != true {
		t.Fatal(rec.rows[0])
	}
}

func TestProcessDenyRaisesAndRecords(t *testing.T) {
	decision := map[string]any{"allowed": false, "http_status": int64(403),
		"headers": map[string]any{"x-policy-violated": "starter.prod_blast_radius.v1", "x-policy-reason": "no"}}
	rec := &stubRecorder{}
	gov := NewGovernor(&stubEvaluator{decision: decision}, rec, false)
	_, err := gov.Process("DELETE", "https://api-prod.acme.com/x", nil, nil)
	d := asPolicyDenied(err)
	if d == nil || d.PolicyID != "starter.prod_blast_radius.v1" {
		t.Fatalf("got %v", err)
	}
	if rec.rows[0].Decision != "deny" || *rec.rows[0].Enforced != true {
		t.Fatal(rec.rows[0])
	}
}

func TestMonitorModeRecordsUnenforcedAndDoesNotBlock(t *testing.T) {
	rec := &stubRecorder{}
	gov := NewGovernor(&stubEvaluator{decision: map[string]any{"allowed": false, "headers": map[string]any{"x-policy-violated": "p.v1"}}}, rec, true)
	out, err := gov.Process("DELETE", "https://h/x", nil, []byte("body"))
	if err != nil || out != "body" {
		t.Fatalf("got %q %v", out, err)
	}
	if *rec.rows[0].Enforced != false {
		t.Fatal(rec.rows[0])
	}
}

func TestProcessRedactsBody(t *testing.T) {
	gov := NewGovernor(&stubEvaluator{decision: map[string]any{"allowed": true,
		"headers": map[string]any{"x-aarvion-redactions": "email address"}}}, &stubRecorder{}, false)
	out, err := gov.Process("POST", "https://api.openai.com/v1/chat", nil, []byte("to jane@acme.com now"))
	if err != nil || out != "to [redacted: email address per data-protection policy] now" {
		t.Fatalf("got %q %v", out, err)
	}
}

func TestMonitorModeStillRedactsAllowedBodies(t *testing.T) {
	gov := NewGovernor(&stubEvaluator{decision: map[string]any{"allowed": true,
		"headers": map[string]any{"x-aarvion-redactions": "email address"}}}, &stubRecorder{}, true)
	out, _ := gov.Process("POST", "https://h/", nil, []byte("to jane@acme.com"))
	if out != "to [redacted: email address per data-protection policy]" {
		t.Fatal(out)
	}
}

func TestInputDocBuiltFromRequest(t *testing.T) {
	ev := &stubEvaluator{decision: map[string]any{"allowed": true}}
	if _, err := NewGovernor(ev, nil, false).Process("POST", "https://api.openai.com/v1/chat?x=1", map[string]string{"h": "v"}, []byte("b")); err != nil {
		t.Fatal(err)
	}
	http := ev.lastInput["attributes"].(map[string]any)["request"].(map[string]any)["http"].(map[string]any)
	if http["method"] != "POST" || http["host"] != "api.openai.com" || http["path"] != "/v1/chat" {
		t.Fatal(http)
	}
}

func denyGovernor() *Governor {
	return NewGovernor(&stubEvaluator{decision: map[string]any{"allowed": false, "http_status": int64(403),
		"headers": map[string]any{"x-policy-violated": "p.v1", "x-policy-reason": "no prod deletes"}}}, nil, false)
}

func redactGovernor() *Governor {
	return NewGovernor(&stubEvaluator{decision: map[string]any{"allowed": true,
		"headers": map[string]any{"x-aarvion-redactions": "email address"}}}, nil, false)
}

func TestWrapReturns403ForDeniedRequestBeforeItIsSent(t *testing.T) {
	sent := 0
	client := mockClient(func(r *http.Request) (*http.Response, error) {
		sent++
		return textResponse(200, ""), nil
	})
	WrapClient(client, denyGovernor())
	resp, err := client.Post("https://api-prod.acme.com/x", "", strings.NewReader("data"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != 403 || body["reason"] != "no prod deletes" || resp.Header.Get("x-policy-violated") != "p.v1" {
		t.Fatal(resp.StatusCode, body, resp.Header)
	}
	if sent != 0 {
		t.Fatal("inner transport reached")
	}
}

func TestWrapRewritesRedactedBodyBeforeSend(t *testing.T) {
	seen := ""
	client := mockClient(func(r *http.Request) (*http.Response, error) {
		seen = readBody(t, r)
		return textResponse(200, ""), nil
	})
	WrapClient(client, redactGovernor())
	if _, err := client.Post("https://api.openai.com/v1/chat", "", strings.NewReader("hi jane@acme.com end")); err != nil {
		t.Fatal(err)
	}
	if seen != "hi [redacted: email address per data-protection policy] end" {
		t.Fatal(seen)
	}
}

func TestWrapAllowsCleanRequest(t *testing.T) {
	seen := ""
	client := mockClient(func(r *http.Request) (*http.Response, error) {
		seen = readBody(t, r)
		return textResponse(200, ""), nil
	})
	WrapClient(client, NewGovernor(&stubEvaluator{decision: map[string]any{"allowed": true}}, nil, false))
	if _, err := client.Post("https://api.openai.com/v1/chat", "", strings.NewReader("clean payload")); err != nil {
		t.Fatal(err)
	}
	if seen != "clean payload" {
		t.Fatal(seen)
	}
}

func TestEveryViolatedPolicyIDIsRecordedAndRaised(t *testing.T) {
	rec := &stubRecorder{}
	gov := NewGovernor(&stubEvaluator{decision: map[string]any{"allowed": false, "headers": map[string]any{
		"x-policy-violated": "a", "x-policy-reason": "no", "x-aarvion-policies-violated": "a,b"}}}, rec, false)
	_, err := gov.Process("POST", "https://h/p", nil, []byte("b"))
	d := asPolicyDenied(err)
	if d == nil || !reflect.DeepEqual(d.PolicyIDs, []string{"a", "b"}) {
		t.Fatalf("got %v", err)
	}
	if rec.rows[0].PolicyID != "a" || !reflect.DeepEqual(rec.rows[0].PolicyIDs, []string{"a", "b"}) {
		t.Fatal(rec.rows[0])
	}
}

func TestOverLimitBodyDeniedWithoutEvaluating(t *testing.T) {
	ev := &stubEvaluator{decision: map[string]any{"allowed": true}}
	_, err := NewGovernor(ev, nil, false).Process("POST", "https://h/p", nil, []byte(strings.Repeat("x", int(MaxBodyBytes)+1)))
	d := asPolicyDenied(err)
	if d == nil || d.PolicyID != BodyLimitPolicy || d.HTTPStatus != 413 {
		t.Fatalf("got %v", err)
	}
	if ev.lastInput != nil {
		t.Fatal("evaluated")
	}
}

func TestDeniedResponseBodyMatchesHttpx(t *testing.T) {
	client := mockClient(func(r *http.Request) (*http.Response, error) { return textResponse(200, ""), nil })
	WrapClient(client, NewGovernor(&stubEvaluator{decision: map[string]any{"allowed": false,
		"headers": map[string]any{"x-policy-violated": "p.v1", "x-policy-reason": "n\u00f6 \"x\""}}}, nil, false))
	resp, err := client.Get("https://h/")
	if err != nil {
		t.Fatal(err)
	}
	got := readBody(t, &http.Request{Body: resp.Body})
	if got != "{\"error\":\"policy_denied\",\"policy\":\"p.v1\",\"policies\":[\"p.v1\"],\"reason\":\"n\u00f6 \\\"x\\\"\"}" {
		t.Fatal(got)
	}
	if resp.Header.Get("Content-Type") != "application/json" || resp.Header.Get("x-aarvion-policies-violated") != "p.v1" {
		t.Fatal(resp.Header)
	}
}
