package aarvion

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"os"
	"sync"
	"testing"
)

var envVars = []string{"AARVION_CONFIG", "AARVION_AGENT_ID", "AARVION_RUNTIME_KEY", "AARVION_BUNDLE_URL",
	"AARVION_SIGNING_SECRET", "AARVION_CP_URL", "AARVION_EVALUATOR_URL", "AARVION_OPA_PATH",
	"AARVION_OPA_AUTODOWNLOAD", "AARVION_OPA_PORT"}

func unsetEnv(t *testing.T, keys ...string) {
	t.Helper()
	for _, k := range keys {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
}

func chdir(t *testing.T, dir string) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
}

func cleanEnv(t *testing.T) string {
	t.Helper()
	unsetEnv(t, envVars...)
	dir := t.TempDir()
	chdir(t, dir)
	return dir
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mockClient(f roundTripFunc) *http.Client { return &http.Client{Transport: f} }

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}
}

func textResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}
}

type stubEvaluator struct {
	mu        sync.Mutex
	decision  map[string]any
	lastInput map[string]any
}

func (s *stubEvaluator) Evaluate(input map[string]any) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastInput = input
	return s.decision, nil
}

type stubRecorder struct {
	mu   sync.Mutex
	rows []RecordInput
}

func (s *stubRecorder) Record(r RecordInput) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows = append(s.rows, r)
	return map[string]any{}, nil
}

func readBody(t *testing.T, r *http.Request) string {
	t.Helper()
	if r.Body == nil {
		return ""
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func asPolicyDenied(err error) *PolicyDenied {
	var d *PolicyDenied
	if errors.As(err, &d) {
		return d
	}
	return nil
}

func httpHeaders(m map[string]any) map[string]any { return map[string]any{"headers": m} }
