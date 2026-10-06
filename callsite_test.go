package aarvion_test

import (
	"net/http"
	"strings"
	"testing"

	aarvion "github.com/Aarvion-AI/aarvion-sdk-go"
)

type allowAll struct{}

func (allowAll) Evaluate(map[string]any) (map[string]any, error) {
	return map[string]any{"allowed": true}, nil
}

type rowCapture struct{ rows []aarvion.RecordInput }

func (r *rowCapture) Record(in aarvion.RecordInput) (map[string]any, error) {
	r.rows = append(r.rows, in)
	return map[string]any{}, nil
}

func TestCallSiteIsCaptured(t *testing.T) {
	rec := &rowCapture{}
	gov := aarvion.NewGovernor(allowAll{}, rec, false)
	if _, err := gov.Process("GET", "https://h/", nil, nil); err != nil {
		t.Fatal(err)
	}
	cs, _ := rec.rows[0].CallSite.(string)
	if cs == "" || !strings.Contains(cs, "callsite_test.go") {
		t.Fatalf("call site %q", cs)
	}
}

type okTransport struct{}

func (okTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: http.NoBody, Header: http.Header{}, Request: r}, nil
}

func TestCallSiteSkipsSDKAndNetHTTPFrames(t *testing.T) {
	rec := &rowCapture{}
	client := aarvion.WrapClient(&http.Client{Transport: okTransport{}}, aarvion.NewGovernor(allowAll{}, rec, false))
	resp, err := client.Get("https://h/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cs, _ := rec.rows[0].CallSite.(string)
	if !strings.Contains(cs, "callsite_test.go:") {
		t.Fatalf("call site %q", cs)
	}
}
