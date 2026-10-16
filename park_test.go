package aarvion

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	parkBase = "/api/v1/agents/acme/agt_x/park"
	parkURL  = "https://api.stripe.com/v1/refunds"
	parkBody = `{"charge":"ch_1","amount":500}`
)

func parkDecision() map[string]any {
	return map[string]any{
		"allowed":     false,
		"http_status": int64(403),
		"headers": map[string]any{"x-policy-violated": "refunds.v1", "x-policy-reason": "refunds need approval",
			"x-aarvion-action": "park"},
		"park": map[string]any{"rules": []any{map[string]any{"id": "refunds.v1", "reason": "refunds need approval"}}},
	}
}

type stubEval struct{ decision map[string]any }

func (s stubEval) Evaluate(map[string]any) (map[string]any, error) { return s.decision, nil }

type fakeCP struct {
	mu       sync.Mutex
	parks    map[string]map[string]any
	receipts map[string]map[string]any
	requests []fakeCall
	onPoll   func(cp *fakeCP, ticket string)
	polls    int
	waits    []int
	down     bool
	hook     func(req *http.Request) (*http.Response, bool)
}

type fakeCall struct {
	method string
	path   string
	body   map[string]any
}

func newFakeCP() *fakeCP {
	return &fakeCP{parks: map[string]map[string]any{}, receipts: map[string]map[string]any{}}
}

func fakeToken(claims map[string]any) string {
	b, _ := json.Marshal(claims)
	return "hdr." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
}

func fakeClaims(token string) map[string]any {
	raw, _ := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m
}

func jsonResp(status int, v any) *http.Response {
	b, _ := json.Marshal(v)
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(bytes.NewReader(b))}
}

func (cp *fakeCP) decide(ticket, status string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.parks[ticket]["status"] = status
}

func (cp *fakeCP) view(row map[string]any) map[string]any {
	out := map[string]any{"ticket_id": row["ticket_id"], "status": row["status"],
		"status_url": parkBase + "/" + row["ticket_id"].(string)}
	if row["status"] == "approved" {
		out["approval_token"] = fakeToken(map[string]any{"ticket": row["ticket_id"], "digest": row["action_digest"],
			"scope": row["scope"], "exp": float64(time.Now().Unix() + 900)})
	}
	return out
}

func (cp *fakeCP) same(digest, scope, status string) []map[string]any {
	var out []map[string]any
	for i := 1; i <= len(cp.parks); i++ {
		r := cp.parks["pk_"+strconv.Itoa(i)]
		if r["action_digest"] == digest && r["scope"] == scope && r["status"] == status {
			out = append(out, r)
		}
	}
	return out
}

func (cp *fakeCP) RoundTrip(req *http.Request) (*http.Response, error) {
	if cp.hook != nil {
		if resp, ok := cp.hook(req); ok {
			return resp, nil
		}
	}
	cp.mu.Lock()
	if cp.down {
		cp.mu.Unlock()
		return nil, errors.New("connection refused")
	}
	if req.Header.Get("Authorization") != "Bearer aav_dev_k.s" {
		cp.mu.Unlock()
		return jsonResp(401, map[string]any{"detail": "bad key"}), nil
	}
	var body map[string]any
	if req.Body != nil {
		raw, _ := io.ReadAll(req.Body)
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &body)
		}
	}
	path := strings.TrimPrefix(req.URL.Path, parkBase)
	cp.requests = append(cp.requests, fakeCall{req.Method, path, body})
	switch {
	case req.Method == "POST" && path == "":
		defer cp.mu.Unlock()
		return cp.create(body), nil
	case path == "/consume":
		defer cp.mu.Unlock()
		return cp.consume(body), nil
	case strings.HasSuffix(path, "/receipt"):
		defer cp.mu.Unlock()
		ticket := strings.Split(path, "/")[1]
		rec := cp.receipts[ticket]
		rec["state"], rec["status_code"], rec["response_b64"] = "done", body["status_code"], body["response_b64"]
		return jsonResp(200, map[string]any{"ticket_id": ticket, "state": "done"}), nil
	}
	ticket := strings.TrimPrefix(path, "/")
	cp.polls++
	wait, _ := strconv.Atoi(req.URL.Query().Get("wait"))
	cp.waits = append(cp.waits, wait)
	onPoll := cp.onPoll
	cp.mu.Unlock()
	if onPoll != nil {
		onPoll(cp, ticket)
	}
	cp.mu.Lock()
	pending := cp.parks[ticket]["status"] == "pending"
	cp.mu.Unlock()
	if pending {
		time.Sleep(10 * time.Millisecond)
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return jsonResp(200, cp.view(cp.parks[ticket])), nil
}

func (cp *fakeCP) create(body map[string]any) *http.Response {
	if existing := cp.same(body["action_digest"].(string), body["scope"].(string), "pending"); len(existing) > 0 {
		v := cp.view(existing[0])
		v["outcome"] = "existing"
		return jsonResp(200, v)
	}
	ticket := "pk_" + strconv.Itoa(len(cp.parks)+1)
	row := map[string]any{"ticket_id": ticket, "status": "pending"}
	for k, v := range body {
		row[k] = v
	}
	cp.parks[ticket] = row
	v := cp.view(row)
	v["outcome"] = "created"
	return jsonResp(201, v)
}

func (cp *fakeCP) consume(body map[string]any) *http.Response {
	digest, scope := body["action_digest"].(string), body["scope"].(string)
	ticket, _ := body["ticket"].(string)
	if token, _ := body["approval_token"].(string); token != "" {
		claims := fakeClaims(token)
		if claims["digest"] != digest || claims["scope"] != scope {
			return jsonResp(403, map[string]any{"detail": "approval token does not match this action"})
		}
		if ticket == "" {
			ticket = claims["ticket"].(string)
		}
	}
	for t, rec := range cp.receipts {
		if rec["digest"] == digest && rec["scope"] == scope {
			if rec["state"] == "executing" {
				return jsonResp(200, map[string]any{"result": "in_progress", "ticket_id": t, "executed_at": "now"})
			}
			return jsonResp(200, map[string]any{"result": "replay", "ticket_id": t, "executed_at": "now",
				"status_code": rec["status_code"], "response_b64": rec["response_b64"]})
		}
	}
	var rows []map[string]any
	if ticket != "" {
		rows = []map[string]any{cp.parks[ticket]}
	} else {
		rows = cp.same(digest, scope, "approved")
	}
	if len(rows) > 0 && rows[0]["status"] == "approved" {
		row := rows[0]
		row["status"] = "consumed"
		cp.receipts[row["ticket_id"].(string)] = map[string]any{"digest": digest, "scope": scope, "state": "executing"}
		return jsonResp(200, map[string]any{"result": "go", "ticket_id": row["ticket_id"]})
	}
	return jsonResp(200, map[string]any{"result": "not_approved", "ticket_id": nil, "status": nil})
}

func (cp *fakeCP) posts(suffix string) []map[string]any {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	var out []map[string]any
	for _, c := range cp.requests {
		if c.method == "POST" && strings.HasSuffix(c.path, suffix) && (suffix != "" || c.path == "") {
			out = append(out, c.body)
		}
	}
	return out
}

func approveOnPoll(n int) func(*fakeCP, string) {
	return func(cp *fakeCP, ticket string) {
		cp.mu.Lock()
		defer cp.mu.Unlock()
		if cp.polls >= n && cp.parks[ticket]["status"] == "pending" {
			cp.parks[ticket]["status"] = "approved"
		}
	}
}

type upstream struct {
	mu   sync.Mutex
	sent int
}

func (u *upstream) RoundTrip(*http.Request) (*http.Response, error) {
	u.mu.Lock()
	u.sent++
	n := u.sent
	u.mu.Unlock()
	return jsonResp(200, map[string]any{"id": "re_" + strconv.Itoa(n), "status": "succeeded"}), nil
}

func (u *upstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.sent
}

func setupPark(cp *fakeCP, hold Hold, decision map[string]any) (*http.Client, *upstream) {
	parker := NewParker(NewParkClient("https://cp", "acme", "agt_x", "aav_dev_k.s", &http.Client{Transport: cp}), hold)
	up := &upstream{}
	gov := NewGovernor(stubEval{decision}, nil, false).SetParker(parker, nil)
	return &http.Client{Transport: NewTransport(up, gov)}, up
}

func post(t *testing.T, c *http.Client, rawURL, body string, headers map[string]string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest("POST", rawURL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return c.Do(req)
}

func readJSON(t *testing.T, r *http.Response) map[string]any {
	t.Helper()
	defer r.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestParkHoldApprovedSendsOnceAndWritesTheReceipt(t *testing.T) {
	cp := newFakeCP()
	cp.onPoll = approveOnPoll(1)
	c, up := setupPark(cp, Hold{Seconds: 5}, parkDecision())
	resp, err := post(t, c, parkURL, parkBody, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || readJSON(t, resp)["id"] != "re_1" || up.count() != 1 {
		t.Fatalf("status %d sent %d", resp.StatusCode, up.count())
	}
	created := cp.posts("")[0]
	if created["surface"] != "sdk" || created["hold_state"] != "held_live" || created["scope"] != "agent" {
		t.Fatalf("created %v", created)
	}
	if ids := created["rule_ids"].([]any); len(ids) != 1 || ids[0] != "refunds.v1" {
		t.Fatalf("rule_ids %v", ids)
	}
	consumes := cp.posts("/consume")
	last := consumes[len(consumes)-1]
	if last["ticket"] != "pk_1" || last["approval_token"] == nil {
		t.Fatalf("consume %v", last)
	}
	receipt := cp.posts("/receipt")[0]
	raw, _ := base64.StdEncoding.DecodeString(receipt["response_b64"].(string))
	if receipt["status_code"] != float64(200) || !strings.Contains(string(raw), `"re_1"`) {
		t.Fatalf("receipt %v", receipt)
	}
}

func TestParkDigestMatchesTheSharedRecipe(t *testing.T) {
	cp := newFakeCP()
	cp.onPoll = approveOnPoll(1)
	c, _ := setupPark(cp, Hold{Seconds: 5}, parkDecision())
	if _, err := post(t, c, parkURL+"?b=2&a=1", `{"amount":500,"charge":"ch_1"}`,
		map[string]string{"x-aarvion-session-id": "s-1"}); err != nil {
		t.Fatal(err)
	}
	want, _ := Digest(HTTPAction{Scope: "session:s-1", Method: "POST", Host: "api.stripe.com", Path: "/v1/refunds",
		Query: "b=2&a=1", ContentType: "application/json", Body: []byte(parkBody)}.Object())
	created := cp.posts("")[0]
	if created["scope"] != "session:s-1" || created["action_digest"] != want {
		t.Fatalf("created %v want digest %s", created, want)
	}
}

func TestParkDeniedInHoldReturnsA403NamingTheTicket(t *testing.T) {
	cp := newFakeCP()
	cp.onPoll = func(cp *fakeCP, ticket string) { cp.decide(ticket, "denied") }
	c, up := setupPark(cp, Hold{Seconds: 5}, parkDecision())
	resp, err := post(t, c, parkURL, parkBody, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := readJSON(t, resp)
	if resp.StatusCode != 403 || resp.Header.Get("x-aarvion-park-ticket") != "pk_1" || body["ticket"] != "pk_1" {
		t.Fatalf("status %d headers %v body %v", resp.StatusCode, resp.Header, body)
	}
	if !strings.Contains(body["reason"].(string), "pk_1 was denied") || up.count() != 0 {
		t.Fatalf("reason %v sent %d", body["reason"], up.count())
	}
}

func TestParkWindowOverThenWaitThenRetryRunsOnceAndThirdCallReplays(t *testing.T) {
	cp := newFakeCP()
	c, up := setupPark(cp, Hold{Seconds: 0.05}, parkDecision())
	_, err := post(t, c, parkURL, parkBody, nil)
	var parked *ActionParked
	if !errors.As(err, &parked) {
		t.Fatalf("want ActionParked, got %v", err)
	}
	if parked.Ticket != "pk_1" || parked.StatusURL != "https://cp"+parkBase+"/pk_1" || parked.RetryAfter != 60 || up.count() != 0 {
		t.Fatalf("parked %+v sent %d", parked, up.count())
	}
	short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	ok, err := parked.Wait(short)
	cancel()
	if ok || err != nil {
		t.Fatalf("wait during pending: %v %v", ok, err)
	}
	cp.mu.Lock()
	cp.onPoll = approveOnPoll(0)
	cp.mu.Unlock()
	if ok, err := parked.Wait(context.Background()); !ok || err != nil {
		t.Fatalf("wait after approval: %v %v", ok, err)
	}
	second, err := post(t, c, parkURL, parkBody, nil)
	if err != nil {
		t.Fatal(err)
	}
	if second.StatusCode != 200 || second.Header.Get("x-aarvion-replayed") != "" || readJSON(t, second)["id"] != "re_1" {
		t.Fatalf("second call %d", second.StatusCode)
	}
	consumes := cp.posts("/consume")
	if fakeClaims(consumes[len(consumes)-1]["approval_token"].(string))["ticket"] != "pk_1" {
		t.Fatalf("retry did not carry the approval token")
	}
	third, err := post(t, c, parkURL, parkBody, nil)
	if err != nil {
		t.Fatal(err)
	}
	if third.StatusCode != 200 || third.Header.Get("x-aarvion-replayed") != "pk_1" || readJSON(t, third)["id"] != "re_1" {
		t.Fatalf("third call %d %v", third.StatusCode, third.Header)
	}
	if up.count() != 1 || len(cp.parks) != 1 {
		t.Fatalf("sent %d parks %d", up.count(), len(cp.parks))
	}
}

func TestParkWaitRaisesWhenDenied(t *testing.T) {
	cp := newFakeCP()
	c, _ := setupPark(cp, Hold{Seconds: 0}, parkDecision())
	_, err := post(t, c, parkURL, parkBody, nil)
	var parked *ActionParked
	if !errors.As(err, &parked) {
		t.Fatalf("want ActionParked, got %v", err)
	}
	if cp.posts("")[0]["hold_state"] != "ticket" {
		t.Fatalf("hold 0 must only make a ticket")
	}
	cp.decide("pk_1", "expired")
	_, err = parked.Wait(context.Background())
	var denied *PolicyDenied
	if !errors.As(err, &denied) || denied.Ticket != "pk_1" {
		t.Fatalf("want PolicyDenied with ticket, got %v", err)
	}
}

func TestParkInProgressRaisesWithoutSending(t *testing.T) {
	cp := newFakeCP()
	cp.onPoll = approveOnPoll(1)
	dropReceipts := &dropping{inner: cp}
	parker := NewParker(NewParkClient("https://cp", "acme", "agt_x", "aav_dev_k.s", &http.Client{Transport: dropReceipts}),
		Hold{Seconds: 5})
	up := &upstream{}
	c := &http.Client{Transport: NewTransport(up, NewGovernor(stubEval{parkDecision()}, nil, false).SetParker(parker, nil))}
	resp, err := post(t, c, parkURL, parkBody, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("first call %v %v", resp, err)
	}
	_, err = post(t, c, parkURL, parkBody, nil)
	var running *ActionInProgress
	if !errors.As(err, &running) || running.Ticket != "pk_1" || up.count() != 1 {
		t.Fatalf("want ActionInProgress, got %v sent %d", err, up.count())
	}
}

type dropping struct{ inner http.RoundTripper }

func (d *dropping) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasSuffix(req.URL.Path, "/receipt") {
		return nil, errors.New("connection reset")
	}
	return d.inner.RoundTrip(req)
}

func TestParkAlreadyExecutedRaisesWithoutSending(t *testing.T) {
	cp := newFakeCP()
	cp.hook = func(req *http.Request) (*http.Response, bool) {
		if strings.HasSuffix(req.URL.Path, "/consume") {
			return jsonResp(200, map[string]any{"result": "already_executed", "ticket_id": "pk_9",
				"executed_at": "2026-10-16T10:00:00Z", "status_code": 201}), true
		}
		return nil, false
	}
	c, up := setupPark(cp, Hold{Seconds: 5}, parkDecision())
	_, err := post(t, c, parkURL, parkBody, nil)
	var done *ActionAlreadyExecuted
	if !errors.As(err, &done) || done.Ticket != "pk_9" || done.StatusCode != 201 || up.count() != 0 {
		t.Fatalf("want ActionAlreadyExecuted, got %v", err)
	}
}

func TestParkCPDownFailsClosed(t *testing.T) {
	cp := newFakeCP()
	cp.down = true
	c, up := setupPark(cp, Hold{Seconds: 5}, parkDecision())
	resp, err := post(t, c, parkURL, parkBody, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := readJSON(t, resp)
	if resp.StatusCode != 503 || !strings.Contains(body["reason"].(string), "unreachable") || up.count() != 0 {
		t.Fatalf("status %d body %v sent %d", resp.StatusCode, body, up.count())
	}
}

func TestParkCPDownAtResumeFailsClosed(t *testing.T) {
	cp := newFakeCP()
	c, up := setupPark(cp, Hold{Seconds: 0}, parkDecision())
	_, err := post(t, c, parkURL, parkBody, nil)
	var parked *ActionParked
	if !errors.As(err, &parked) {
		t.Fatalf("want ActionParked, got %v", err)
	}
	cp.decide("pk_1", "approved")
	cp.mu.Lock()
	cp.down = true
	cp.mu.Unlock()
	_, err = parked.Wait(context.Background())
	var denied *PolicyDenied
	if !errors.As(err, &denied) || denied.HTTPStatus != 503 {
		t.Fatalf("want 503 PolicyDenied, got %v", err)
	}
	resp, err := post(t, c, parkURL, parkBody, nil)
	if err != nil || resp.StatusCode != 503 || up.count() != 0 {
		t.Fatalf("retry %v %v sent %d", resp, err, up.count())
	}
}

func TestParkUntilDecisionHoldsPastManyPolls(t *testing.T) {
	cp := newFakeCP()
	cp.onPoll = approveOnPoll(8)
	c, up := setupPark(cp, Hold{UntilDecision: true}, parkDecision())
	resp, err := post(t, c, parkURL, parkBody, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", resp, err)
	}
	if cp.polls != 8 || up.count() != 1 {
		t.Fatalf("polls %d sent %d", cp.polls, up.count())
	}
	for _, w := range cp.waits {
		if w != 30 {
			t.Fatalf("waits %v", cp.waits)
		}
	}
}

func TestParkDisabledFailsClosed(t *testing.T) {
	cp := newFakeCP()
	cp.hook = func(req *http.Request) (*http.Response, bool) {
		if req.Method == "POST" && req.URL.Path == parkBase {
			return jsonResp(403, map[string]any{"detail": map[string]any{"error": "park_disabled",
				"message": "Park is not enabled for this tenant"}}), true
		}
		return nil, false
	}
	c, up := setupPark(cp, Hold{Seconds: 5}, parkDecision())
	resp, err := post(t, c, parkURL, parkBody, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := readJSON(t, resp)
	if resp.StatusCode != 403 || !strings.Contains(body["reason"].(string), "Park is not enabled") || up.count() != 0 {
		t.Fatalf("status %d body %v", resp.StatusCode, body)
	}
}

func TestParkVerdictWithoutAParkerIsAPlainDeny(t *testing.T) {
	up := &upstream{}
	c := &http.Client{Transport: NewTransport(up, NewGovernor(stubEval{parkDecision()}, nil, false))}
	resp, err := post(t, c, parkURL, parkBody, nil)
	if err != nil || resp.StatusCode != 403 || resp.Header.Get("x-aarvion-park-ticket") != "" || up.count() != 0 {
		t.Fatalf("%v %v", resp, err)
	}
}

func TestParkAllowNeverTouchesTheCP(t *testing.T) {
	cp := newFakeCP()
	c, up := setupPark(cp, Hold{Seconds: 5}, map[string]any{"allowed": true})
	resp, err := post(t, c, parkURL, parkBody, nil)
	if err != nil || resp.StatusCode != 200 || len(cp.requests) != 0 || up.count() != 1 {
		t.Fatalf("%v %v requests %d", resp, err, len(cp.requests))
	}
}

func TestParkMonitorModeNeverParks(t *testing.T) {
	cp := newFakeCP()
	parker := NewParker(NewParkClient("https://cp", "acme", "agt_x", "aav_dev_k.s", &http.Client{Transport: cp}),
		Hold{Seconds: 5})
	up := &upstream{}
	c := &http.Client{Transport: NewTransport(up, NewGovernor(stubEval{parkDecision()}, nil, true).SetParker(parker, nil))}
	resp, err := post(t, c, parkURL, parkBody, nil)
	if err != nil || resp.StatusCode != 200 || len(cp.requests) != 0 || up.count() != 1 {
		t.Fatalf("%v %v requests %d", resp, err, len(cp.requests))
	}
}

func TestParkPreviewHidesCredentialsAndPII(t *testing.T) {
	cp := newFakeCP()
	cp.onPoll = approveOnPoll(1)
	c, _ := setupPark(cp, Hold{Seconds: 5}, parkDecision())
	if _, err := post(t, c, parkURL, `{"api_key":"sk_live_1","email":"jane@acme.com","amount":500}`, nil); err != nil {
		t.Fatal(err)
	}
	preview := cp.posts("")[0]["preview"].(string)
	if strings.Contains(preview, "sk_live_1") || strings.Contains(preview, "jane@acme.com") ||
		!strings.Contains(preview, `"amount":500`) {
		t.Fatalf("preview %s", preview)
	}
}

func TestParkUsesTheBundleCatalogForTheSummary(t *testing.T) {
	cp := newFakeCP()
	cp.onPoll = approveOnPoll(1)
	parker := NewParker(NewParkClient("https://cp", "acme", "agt_x", "aav_dev_k.s", &http.Client{Transport: cp}),
		Hold{Seconds: 5})
	catalog := map[string]any{
		"fallback": map[string]any{"http": "{method} {host}{path}", "tool": "Run {tool}"},
		"packs": map[string]any{"stripe": map[string]any{
			"volatile": map[string]any{"http": []any{"idempotency_key"}},
			"summary":  map[string]any{"http": map[string]any{"rules": map[string]any{"refund": "Refund {body.amount} on {body.charge}"}}},
		}},
	}
	decision := parkDecision()
	decision["park"] = map[string]any{"rules": []any{map[string]any{"id": "starter.stripe.refund.v1", "reason": "refunds"}}}
	gov := NewGovernor(stubEval{decision}, nil, false).SetParker(parker, func() map[string]any { return catalog })
	c := &http.Client{Transport: NewTransport(&upstream{}, gov)}
	if _, err := post(t, c, parkURL, `{"charge":"ch_1","amount":500,"idempotency_key":"k1"}`, nil); err != nil {
		t.Fatal(err)
	}
	created := cp.posts("")[0]
	if created["summary"] != "Refund 500 on ch_1" {
		t.Fatalf("summary %v", created["summary"])
	}
	if v := created["volatile_fields"].([]any); len(v) != 1 || v[0] != "idempotency_key" {
		t.Fatalf("volatile %v", v)
	}
}

func TestParkWithoutABundleCatalogUsesTheFallbackSummary(t *testing.T) {
	cp := newFakeCP()
	cp.onPoll = approveOnPoll(1)
	c, _ := setupPark(cp, Hold{Seconds: 5}, parkDecision())
	if _, err := post(t, c, parkURL, parkBody, nil); err != nil {
		t.Fatal(err)
	}
	if got := cp.posts("")[0]["summary"]; got != "POST api.stripe.com/v1/refunds" {
		t.Fatalf("summary %v", got)
	}
}

func TestParkSummaryIsRedactedThenCapped(t *testing.T) {
	long := strings.Repeat("x", 300)
	got := capSummary(RewriteBody("Pay jane@acme.com "+long, previewPII, ""))
	if strings.Contains(got, "jane@acme.com") || len([]rune(got)) != SummaryMax || !strings.HasSuffix(got, "...") {
		t.Fatalf("summary %q", got)
	}
}

func TestParseHold(t *testing.T) {
	good := []struct {
		in   any
		want Hold
	}{
		{nil, Hold{Seconds: 50}}, {0, Hold{Seconds: 0}}, {"12.5", Hold{Seconds: 12.5}}, {int64(30), Hold{Seconds: 30}},
		{HoldUntilDecision, Hold{UntilDecision: true}}, {2 * time.Second, Hold{Seconds: 2}},
	}
	for _, c := range good {
		got, err := ParseHold(c.in)
		if err != nil || got != c.want {
			t.Fatalf("ParseHold(%v) = %v %v", c.in, got, err)
		}
	}
	for _, bad := range []any{true, "soon", -1.0, "inf", "nan"} {
		if _, err := ParseHold(bad); err == nil {
			t.Fatalf("ParseHold(%v) should fail", bad)
		}
	}
}

func TestParkConcurrentIdenticalCallsSendOnce(t *testing.T) {
	cp := newFakeCP()
	cp.onPoll = approveOnPoll(1)
	c, up := setupPark(cp, Hold{Seconds: 5}, parkDecision())
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := post(t, c, parkURL, parkBody, nil)
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	if up.count() != 1 {
		t.Fatalf("sent %d times", up.count())
	}
}

func TestParkDashboardHoldIsUsedWhenTheAppSetsNone(t *testing.T) {
	cp := newFakeCP()
	client := NewParkClient("https://cp", "acme", "agt_x", "aav_dev_k.s", &http.Client{Transport: cp})
	parker := NewParkerWithDashboard(client, nil, func() any { return int64(0) })
	up := &upstream{}
	c := &http.Client{Transport: NewTransport(up, NewGovernor(stubEval{parkDecision()}, nil, false).SetParker(parker, nil))}
	_, err := post(t, c, parkURL, parkBody, nil)
	var parked *ActionParked
	if !errors.As(err, &parked) || cp.posts("")[0]["hold_state"] != "ticket" {
		t.Fatalf("want a ticket-only park from the dashboard hold 0, got %v", err)
	}
	five := Hold{Seconds: 5}
	cases := []struct {
		p    *Parker
		want Hold
	}{
		{NewParkerWithDashboard(nil, nil, func() any { return int64(30) }), Hold{Seconds: 30}},
		{NewParkerWithDashboard(nil, nil, func() any { return 12.5 }), Hold{Seconds: 12.5}},
		{NewParkerWithDashboard(nil, nil, func() any { return Hold{UntilDecision: true} }), Hold{UntilDecision: true}},
		{NewParkerWithDashboard(nil, nil, func() any { return nil }), Hold{Seconds: 50}},
		{NewParkerWithDashboard(nil, nil, func() any { return "nonsense" }), Hold{Seconds: 50}},
		{NewParkerWithDashboard(nil, nil, func() any { return true }), Hold{Seconds: 50}},
		{NewParkerWithDashboard(nil, nil, nil), Hold{Seconds: 50}},
		{NewParkerWithDashboard(nil, &five, func() any { return int64(30) }), Hold{Seconds: 5}},
	}
	for i, c := range cases {
		if got := c.p.Hold(); got != c.want {
			t.Fatalf("case %d: hold %v, want %v", i, got, c.want)
		}
	}
}

func TestParkApprovedSendAndReplayWriteAnAllowedRow(t *testing.T) {
	cp := newFakeCP()
	cp.onPoll = approveOnPoll(1)
	rec := &stubRecorder{}
	parker := NewParker(NewParkClient("https://cp", "acme", "agt_x", "aav_dev_k.s", &http.Client{Transport: cp}), Hold{Seconds: 5})
	up := &upstream{}
	c := &http.Client{Transport: NewTransport(up, NewGovernor(stubEval{parkDecision()}, rec, false).SetParker(parker, nil))}
	if resp, err := post(t, c, parkURL, parkBody, nil); err != nil || resp.StatusCode != 200 {
		t.Fatalf("first call %v %v", resp, err)
	}
	if len(rec.rows) != 2 || rec.rows[0].Decision != "deny" {
		t.Fatalf("rows %+v", rec.rows)
	}
	sent := rec.rows[1]
	if sent.Decision != "allow" || sent.Reason != "approved under ticket pk_1, sent (HTTP 200)" ||
		sent.Method != "POST" || sent.Host != "api.stripe.com" || sent.Path != "/v1/refunds" ||
		sent.PolicyID != "refunds.v1" || sent.Enforced == nil || !*sent.Enforced {
		t.Fatalf("allowed row %+v", sent)
	}
	if resp, err := post(t, c, parkURL, parkBody, nil); err != nil || resp.StatusCode != 200 {
		t.Fatalf("replay %v %v", resp, err)
	}
	if len(rec.rows) != 4 || rec.rows[2].Decision != "deny" || rec.rows[3].Decision != "allow" ||
		rec.rows[3].Reason != "replayed the saved result of approval ticket pk_1, not sent again" {
		t.Fatalf("rows after replay %+v", rec.rows)
	}
	if up.count() != 1 {
		t.Fatalf("sent %d times", up.count())
	}
}

func TestParkDeniedTicketWritesNoAllowedRow(t *testing.T) {
	cp := newFakeCP()
	cp.onPoll = func(cp *fakeCP, ticket string) { cp.decide(ticket, "denied") }
	rec := &stubRecorder{}
	parker := NewParker(NewParkClient("https://cp", "acme", "agt_x", "aav_dev_k.s", &http.Client{Transport: cp}), Hold{Seconds: 5})
	c := &http.Client{Transport: NewTransport(&upstream{}, NewGovernor(stubEval{parkDecision()}, rec, false).SetParker(parker, nil))}
	if resp, err := post(t, c, parkURL, parkBody, nil); err != nil || resp.StatusCode != 403 {
		t.Fatalf("%v %v", resp, err)
	}
	if len(rec.rows) != 1 || rec.rows[0].Decision != "deny" {
		t.Fatalf("rows %+v", rec.rows)
	}
}
