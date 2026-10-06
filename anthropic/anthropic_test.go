package anthropic

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
	sdk "github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

func TestMain(m *testing.M) {
	for _, k := range []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL"} {
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
		w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant","model":"claude-haiku-4-5","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func send(c sdk.Client, text string) (*sdk.Message, error) {
	return c.Messages.New(context.Background(), sdk.MessageNewParams{
		Model:     "claude-haiku-4-5",
		MaxTokens: 16,
		Messages:  []sdk.MessageParam{sdk.NewUserMessage(sdk.NewTextBlock(text))},
	})
}

func client(s *server, g *aarvion.Governor) sdk.Client {
	return sdk.NewClient(option.WithAPIKey("test-key"), option.WithBaseURL(s.srv.URL), option.WithMaxRetries(0), OptionWith(g, nil))
}

func TestAnthropicRedactsBodyBeforeSend(t *testing.T) {
	s := newServer(t)
	g := aarvion.NewGovernor(stubEvaluator{map[string]any{"allowed": true, "headers": map[string]any{"x-aarvion-redactions": "email address"}}}, nil, false)
	msg, err := send(client(s, g), "mail jane@acme.com now")
	if err != nil {
		t.Fatal(err)
	}
	if msg.Content[0].Text != "ok" {
		t.Fatal(msg)
	}
	if !strings.Contains(s.bodies[0], "mail [redacted: email address per data-protection policy] now") || strings.Contains(s.bodies[0], "jane@") {
		t.Fatal(s.bodies)
	}
}

func TestAnthropicDeniedRequestComesBackAs403(t *testing.T) {
	s := newServer(t)
	g := aarvion.NewGovernor(stubEvaluator{map[string]any{"allowed": false, "http_status": int64(403),
		"headers": map[string]any{"x-policy-violated": "p.v1", "x-policy-reason": "no"}}}, nil, false)
	_, err := send(client(s, g), "hi")
	var apiErr *sdk.Error
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 403 {
		t.Fatalf("got %v", err)
	}
	if len(s.bodies) != 0 {
		t.Fatal("request reached the server")
	}
}

func TestAnthropicCleanRequestPassesThrough(t *testing.T) {
	s := newServer(t)
	g := aarvion.NewGovernor(stubEvaluator{map[string]any{"allowed": true}}, nil, false)
	if _, err := send(client(s, g), "clean payload"); err != nil {
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
