package openai

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	aarvion "github.com/Aarvion-AI/aarvion-sdk-go"
	oai "github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
)

func TestMain(m *testing.M) {
	for _, k := range []string{"OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_ORG_ID", "OPENAI_PROJECT_ID", "OPENAI_WEBHOOK_SECRET"} {
		os.Unsetenv(k)
	}
	os.Exit(m.Run())
}

type stubEvaluator struct{ decision map[string]any }

func (s stubEvaluator) Evaluate(map[string]any) (map[string]any, error) { return s.decision, nil }

type server struct {
	mu     sync.Mutex
	bodies []string
	srv    *httptest.Server
}

func newServer(t *testing.T) *server {
	s := &server{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.bodies = append(s.bodies, string(b))
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"c1","object":"chat.completion","created":1,"model":"gpt-4o-mini","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}]}`))
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func chat(c oai.Client, text string) (*oai.ChatCompletion, error) {
	return c.Chat.Completions.New(context.Background(), oai.ChatCompletionNewParams{
		Model:    "gpt-4o-mini",
		Messages: []oai.ChatCompletionMessageParamUnion{oai.UserMessage(text)},
	})
}

func client(s *server, g *aarvion.Governor) oai.Client {
	return oai.NewClient(option.WithAPIKey("test-key"), option.WithBaseURL(s.srv.URL), option.WithMaxRetries(0), OptionWith(g, nil))
}

func TestOpenAIRedactsBodyBeforeSend(t *testing.T) {
	s := newServer(t)
	g := aarvion.NewGovernor(stubEvaluator{map[string]any{"allowed": true, "headers": map[string]any{"x-aarvion-redactions": "email address"}}}, nil, false)
	resp, err := chat(client(s, g), "mail jane@acme.com now")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Choices[0].Message.Content != "ok" {
		t.Fatal(resp)
	}
	if !strings.Contains(s.bodies[0], "mail [redacted: email address per data-protection policy] now") || strings.Contains(s.bodies[0], "jane@") {
		t.Fatal(s.bodies)
	}
}

func TestOpenAIDeniedRequestComesBackAs403(t *testing.T) {
	s := newServer(t)
	g := aarvion.NewGovernor(stubEvaluator{map[string]any{"allowed": false, "http_status": int64(403),
		"headers": map[string]any{"x-policy-violated": "p.v1", "x-policy-reason": "no"}}}, nil, false)
	var raw *http.Response
	c := client(s, g)
	_, err := c.Chat.Completions.New(context.Background(), oai.ChatCompletionNewParams{
		Model:    "gpt-4o-mini",
		Messages: []oai.ChatCompletionMessageParamUnion{oai.UserMessage("hi")},
	}, option.WithResponseInto(&raw))
	if err == nil {
		t.Fatal("expected an error")
	}
	var apiErr *oai.Error
	if errors.As(err, &apiErr) {
		t.Fatalf("openai-go parsed the sidecar body: %v", err)
	}
	if raw == nil || raw.StatusCode != 403 || raw.Header.Get("x-policy-violated") != "p.v1" || raw.Header.Get("x-policy-reason") != "no" {
		t.Fatalf("raw %v", raw)
	}
	if len(s.bodies) != 0 {
		t.Fatal("request reached the server")
	}
}

func TestOpenAICleanRequestPassesThrough(t *testing.T) {
	s := newServer(t)
	g := aarvion.NewGovernor(stubEvaluator{map[string]any{"allowed": true}}, nil, false)
	if _, err := chat(client(s, g), "clean payload"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s.bodies[0], "clean payload") {
		t.Fatal(s.bodies)
	}
}

func TestOptionRequiresInit(t *testing.T) {
	if _, err := Option(); err == nil || err.Error() != "aarvion.init() has not been called" {
		t.Fatalf("got %v", err)
	}
	if _, err := NewClient(); err == nil {
		t.Fatal("expected error")
	}
}
