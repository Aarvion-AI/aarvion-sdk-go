package aarvion

import (
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func lastRecord(t *testing.T, s *Session) map[string]any {
	t.Helper()
	var text string
	if err := s.Recorder.db.QueryRow("SELECT record_json FROM decisions ORDER BY seq DESC LIMIT 1").Scan(&text); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal([]byte(text), &m)
	return m
}

func sampleTurn() Turn {
	intent := "voice"
	return Turn{SessionID: "s1", TurnNumber: 1, UserMsg: "hi", BotResponse: "hello", Intent: &intent,
		SourceData: map[string]any{"channel": "voice"}}
}

func TestEnforceTurnPostsTurnShapeAndReturnsVerdict(t *testing.T) {
	seen := map[string]any{}
	c := mockClient(func(r *http.Request) (*http.Response, error) {
		seen["url"] = r.URL.String()
		var body map[string]any
		json.Unmarshal([]byte(readBody(t, r)), &body)
		seen["body"] = body
		return jsonResponse(200, `{"action": "release", "response": "hello", "verdict": "allow", "reason": "", "latency_ms": 12}`), nil
	})
	result, err := EnforceTurn("http://evaluator:8090", sampleTurn(), c)
	if err != nil {
		t.Fatal(err)
	}
	if seen["url"] != "http://evaluator:8090/enforce" {
		t.Fatal(seen["url"])
	}
	want := map[string]any{"session_id": "s1", "turn_number": float64(1), "user_msg": "hi", "bot_response": "hello",
		"intent": "voice", "source_data": map[string]any{"channel": "voice"}}
	if !reflect.DeepEqual(seen["body"], want) {
		t.Fatal(seen["body"])
	}
	if result["action"] != "release" {
		t.Fatal(result)
	}
}

func TestEnforceTurnStripsTrailingSlashOnEvaluatorURL(t *testing.T) {
	seen := ""
	c := mockClient(func(r *http.Request) (*http.Response, error) {
		seen = r.URL.String()
		return jsonResponse(200, `{"action": "release"}`), nil
	})
	if _, err := EnforceTurn("http://evaluator:8090/", sampleTurn(), c); err != nil {
		t.Fatal(err)
	}
	if seen != "http://evaluator:8090/enforce" {
		t.Fatal(seen)
	}
}

func TestEnforceTurnRaisesOnHTTPError(t *testing.T) {
	c := mockClient(func(r *http.Request) (*http.Response, error) { return textResponse(500, ""), nil })
	_, err := EnforceTurn("http://evaluator:8090", sampleTurn(), c)
	var se *statusError
	if !errors.As(err, &se) || se.status != 500 {
		t.Fatalf("got %v", err)
	}
}

func TestEnforceTurnRaisesOnNonDictResponse(t *testing.T) {
	c := mockClient(func(r *http.Request) (*http.Response, error) { return jsonResponse(200, `["not", "a", "dict"]`), nil })
	_, err := EnforceTurn("http://evaluator:8090", sampleTurn(), c)
	if !isPyError(err, "ValueError") || err.Error() != "evaluator /enforce returned non-object JSON: list" {
		t.Fatalf("got %v", err)
	}
}

func TestMonitorTurnSwallowsTransportErrors(t *testing.T) {
	c := mockClient(func(r *http.Request) (*http.Response, error) { return nil, errors.New("offline") })
	if err := MonitorTurn("http://evaluator:8090", sampleTurn(), c); err != nil {
		t.Fatal(err)
	}
}

func TestMonitorTurnPostsToEvaluate(t *testing.T) {
	seen := ""
	c := mockClient(func(r *http.Request) (*http.Response, error) {
		seen = r.URL.String()
		return textResponse(200, ""), nil
	})
	MonitorTurn("http://evaluator:8090", sampleTurn(), c)
	if seen != "http://evaluator:8090/evaluate" {
		t.Fatal(seen)
	}
}

func initForTurns(t *testing.T, opts ...Option) *Session {
	t.Helper()
	cleanEnv(t)
	if _, err := SaveConfig(NewConfig("agt_x", "aav_dev_abc.secret", "https://cp/api/v1/bundles/acme/agt_x/policy.tar.gz", "s", "http://127.0.0.1:9"), ""); err != nil {
		t.Fatal(err)
	}
	all := append([]Option{WithStartRuntime(false), WithStateDir(filepath.Join(t.TempDir(), "state"))}, opts...)
	s, err := Init(all...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { setActive(nil) })
	return s
}

func stubEnforce(t *testing.T, fn func(string, Turn, time.Duration, *http.Client) (map[string]any, error)) {
	old := enforceTurnFn
	enforceTurnFn = fn
	t.Cleanup(func() { enforceTurnFn = old })
}

func stubMonitor(t *testing.T, fn func(string, Turn, time.Duration, *http.Client) error) {
	old := monitorTurnFn
	monitorTurnFn = fn
	t.Cleanup(func() { monitorTurnFn = old })
}

func fixedResult(m map[string]any) func(string, Turn, time.Duration, *http.Client) (map[string]any, error) {
	return func(string, Turn, time.Duration, *http.Client) (map[string]any, error) { return m, nil }
}

func TestGovernReplyRequiresEvaluatorURL(t *testing.T) {
	s := initForTurns(t)
	defer s.Close()
	_, err := GovernReply("s1", 1, "hi", "hello")
	var ce *ConfigError
	if !errors.As(err, &ce) {
		t.Fatalf("got %v", err)
	}
}

func TestGovernReplyReleaseReturnsOriginal(t *testing.T) {
	s := initForTurns(t, WithEvaluatorURL("http://evaluator:8090"))
	defer s.Close()
	stubEnforce(t, fixedResult(map[string]any{"action": "release", "response": "hello", "verdict": "allow", "reason": "", "latency_ms": int64(10)}))
	out, err := GovernReply("s1", 1, "hi", "hello", WithIntent("voice"))
	if err != nil || out != "hello" {
		t.Fatalf("got %q %v", out, err)
	}
	if n, _ := s.Recorder.PendingCount(); n != 1 {
		t.Fatal(n)
	}
	if lastRecord(t, s)["enforced"] != true {
		t.Fatal(lastRecord(t, s))
	}
}

func TestGovernReplyBlockEnforceModeIsRecordedEnforced(t *testing.T) {
	s := initForTurns(t, WithEvaluatorURL("http://evaluator:8090"))
	defer s.Close()
	stubEnforce(t, fixedResult(map[string]any{"action": "replace", "response": "safe reply", "verdict": "blocked", "reason": "pii", "latency_ms": int64(10)}))
	GovernReply("s1", 1, "hi", "bad reply")
	rec := lastRecord(t, s)
	if rec["enforced"] != true || rec["decision"] != "blocked" || rec["path"] != "s1#1" || rec["host"] != "evaluator" || rec["method"] != "TURN" {
		t.Fatal(rec)
	}
}

func TestGovernReplyMonitorModeCallsMonitorTurnNotEnforceTurn(t *testing.T) {
	calls := map[string]int{}
	stubEnforce(t, func(string, Turn, time.Duration, *http.Client) (map[string]any, error) {
		calls["enforce"]++
		return nil, nil
	})
	stubMonitor(t, func(_ string, _ Turn, timeout time.Duration, _ *http.Client) error {
		calls["monitor"]++
		if timeout != 5*time.Second {
			t.Fatal(timeout)
		}
		return nil
	})
	s := initForTurns(t, WithEvaluatorURL("http://evaluator:8090"), WithMonitor(true))
	defer s.Close()
	GovernReply("s1", 1, "hi", "bad reply")
	if !reflect.DeepEqual(calls, map[string]int{"monitor": 1}) {
		t.Fatal(calls)
	}
	if lastRecord(t, s)["enforced"] != false {
		t.Fatal(lastRecord(t, s))
	}
}

func TestGovernReplyReusesClientAcrossCalls(t *testing.T) {
	var seen []*http.Client
	stubEnforce(t, func(_ string, turn Turn, _ time.Duration, c *http.Client) (map[string]any, error) {
		seen = append(seen, c)
		return map[string]any{"action": "release", "response": turn.BotResponse}, nil
	})
	s := initForTurns(t, WithEvaluatorURL("http://evaluator:8090"))
	defer s.Close()
	GovernReply("s1", 1, "hi", "one")
	GovernReply("s1", 2, "hi again", "two")
	if seen[0] == nil || seen[0] != seen[1] {
		t.Fatal(seen)
	}
}

func TestGovernReplyBlockReturnsSubstitute(t *testing.T) {
	s := initForTurns(t, WithEvaluatorURL("http://evaluator:8090"))
	defer s.Close()
	stubEnforce(t, fixedResult(map[string]any{"action": "replace", "response": "safe reply", "verdict": "blocked", "reason": "pii", "latency_ms": int64(10)}))
	out, _ := GovernReply("s1", 1, "hi", "here's your card 4111 1111 1111 1111")
	if out != "safe reply" {
		t.Fatal(out)
	}
}

func TestGovernReplyMonitorModeNeverSubstitutes(t *testing.T) {
	stubMonitor(t, func(string, Turn, time.Duration, *http.Client) error { return nil })
	s := initForTurns(t, WithEvaluatorURL("http://evaluator:8090"), WithMonitor(true))
	defer s.Close()
	out, _ := GovernReply("s1", 1, "hi", "the original draft")
	if out != "the original draft" {
		t.Fatal(out)
	}
}

func TestGovernReplyHonorsIntentionalEmptyStringSubstitute(t *testing.T) {
	s := initForTurns(t, WithEvaluatorURL("http://evaluator:8090"))
	defer s.Close()
	stubEnforce(t, fixedResult(map[string]any{"action": "replace", "response": "", "verdict": "blocked", "reason": "pii", "latency_ms": int64(10)}))
	out, err := GovernReply("s1", 1, "hi", "here's your card 4111 1111 1111 1111")
	if err != nil || out != "" {
		t.Fatalf("got %q %v", out, err)
	}
}

func TestGovernReplyClientLazyInitIsRaceSafe(t *testing.T) {
	stubEnforce(t, fixedResult(map[string]any{"action": "release", "response": "ok"}))
	s := initForTurns(t, WithEvaluatorURL("http://evaluator:8090"))
	defer s.Close()
	var mu sync.Mutex
	var seen []*http.Client
	var start, wg sync.WaitGroup
	start.Add(1)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			start.Wait()
			GovernReply("s1", i, "hi", "reply")
			mu.Lock()
			seen = append(seen, s.convClient)
			mu.Unlock()
		}(i)
	}
	start.Done()
	wg.Wait()
	if len(seen) != 8 {
		t.Fatal(len(seen))
	}
	for _, c := range seen {
		if c != seen[0] {
			t.Fatal("more than one client created")
		}
	}
}

func TestGovernReplyFailsOpenOnTransportError(t *testing.T) {
	s := initForTurns(t, WithEvaluatorURL("http://evaluator:8090"))
	defer s.Close()
	stubEnforce(t, func(string, Turn, time.Duration, *http.Client) (map[string]any, error) {
		return nil, &transportError{msg: "offline"}
	})
	out, err := GovernReply("s1", 1, "hi", "the original draft")
	if err != nil || out != "the original draft" {
		t.Fatalf("got %q %v", out, err)
	}
	rec := lastRecord(t, s)
	if rec["decision"] != "fail_open" || rec["reason"] != "evaluator unreachable" || rec["enforced"] != false {
		t.Fatal(rec)
	}
}

func TestEvaluatorURLFromEnv(t *testing.T) {
	cleanEnv(t)
	SaveConfig(NewConfig("agt_x", "aav_dev_abc.secret", "https://cp/api/v1/bundles/acme/agt_x/policy.tar.gz", "s", "http://127.0.0.1:9"), "")
	t.Setenv("AARVION_EVALUATOR_URL", "http://from-env:8090")
	s, err := Init(WithStartRuntime(false), WithStateDir(filepath.Join(t.TempDir(), "state")))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer setActive(nil)
	if s.Config.EvaluatorURL != "http://from-env:8090" {
		t.Fatal(s.Config.EvaluatorURL)
	}
}

func TestInitWithAPIKeyPersistsEvaluatorURLToDisk(t *testing.T) {
	cleanEnv(t)
	old := exchangeFn
	exchangeFn = func(apiKey, agent, apiURL string) (*Config, error) {
		return NewConfig("agt_x", "aav_dev_abc.secret", "https://cp/api/v1/bundles/acme/agt_x/policy.tar.gz", "s", "http://127.0.0.1:9"), nil
	}
	t.Cleanup(func() { exchangeFn = old })
	s, err := Init(WithAPIKey("k"), WithAgent("a"), WithEvaluatorURL("http://evaluator:8090"), WithStartRuntime(false),
		WithStateDir(filepath.Join(t.TempDir(), "state")))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer setActive(nil)
	if s.Config.EvaluatorURL != "http://evaluator:8090" {
		t.Fatal(s.Config.EvaluatorURL)
	}
	p, _ := ConfigPath()
	onDisk, err := LoadConfig(p)
	if err != nil || onDisk.EvaluatorURL != "http://evaluator:8090" {
		t.Fatalf("got %+v %v", onDisk, err)
	}
}
