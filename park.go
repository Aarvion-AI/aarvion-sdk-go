package aarvion

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	DefaultHoldSeconds = 50.0
	HoldUntilDecision  = "until_decision"
	retryAfterSeconds  = 60
	longPollCap        = 30
	previewPII         = "email address,US SSN,credit card number,IBAN"
	previewMax         = 4000
	parkCallTimeout    = 10 * time.Second
)

var parkSecretKey = regexp.MustCompile(`(?i)pass(word)?|secret|token|api[_-]?key|authorization|cookie|credential|private[_-]?key`)

type Hold struct {
	Seconds       float64
	UntilDecision bool
}

func DefaultHold() Hold { return Hold{Seconds: DefaultHoldSeconds} }

func ParseHold(v any) (Hold, error) {
	switch x := v.(type) {
	case nil:
		return DefaultHold(), nil
	case Hold:
		return x, nil
	case bool:
		return Hold{}, newConfigError(fmt.Sprintf("hold must be a number of seconds or %q, got %v", HoldUntilDecision, x), nil)
	case string:
		s := pyStrip(x)
		if s == HoldUntilDecision {
			return Hold{UntilDecision: true}, nil
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return Hold{}, newConfigError(fmt.Sprintf("hold must be a number of seconds or %q, got %q", HoldUntilDecision, x), nil)
		}
		return ParseHold(f)
	case time.Duration:
		return ParseHold(x.Seconds())
	case int:
		return ParseHold(float64(x))
	case int64:
		return ParseHold(float64(x))
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) || x < 0 {
			return Hold{}, newConfigError(fmt.Sprintf("hold must be a number of seconds or %q, got %v", HoldUntilDecision, x), nil)
		}
		return Hold{Seconds: x}, nil
	}
	return Hold{}, newConfigError(fmt.Sprintf("hold must be a number of seconds or %q, got %v", HoldUntilDecision, v), nil)
}

type ParkAction struct {
	Digest    string
	Scope     string
	Create    map[string]any
	PolicyID  string
	PolicyIDs []string
	Reason    string
	Method    string
	Host      string
	Path      string
}

func runePrefix(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

func redactSecrets(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if parkSecretKey.MatchString(k) && val != nil && val != "" {
				out[k] = "[redacted]"
			} else {
				out[k] = redactSecrets(val)
			}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = redactSecrets(e)
		}
		return out
	}
	return v
}

func parkPreview(text string) any {
	if text == "" {
		return nil
	}
	if v, err := pyLoads(text); err == nil {
		if canon, err := Canonicalize(redactSecrets(toPlain(v))); err == nil {
			text = canon
		}
	}
	return runePrefix(RewriteBody(text, previewPII, ""), previewMax)
}

func parkRules(denied *PolicyDenied, decision map[string]any) ([]string, []string) {
	park := asMap(decision["park"])
	ids, reasons := []string{}, []string{}
	for _, r := range asList(park["rules"]) {
		rule := asMap(r)
		id, ok := rule["id"].(string)
		if !ok || id == "" {
			continue
		}
		if len(ids) < 50 {
			ids = append(ids, id)
		}
		if reason, ok := rule["reason"].(string); ok && reason != "" && len(reasons) < 50 {
			reasons = append(reasons, reason)
		}
	}
	if len(ids) == 0 {
		ids = []string{denied.PolicyID}
	}
	return ids, reasons
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func buildParkAction(method, rawURL string, headers map[string]string, body []byte, denied *PolicyDenied,
	decision, catalog map[string]any) (*ParkAction, error) {
	parts, err := urlSplit(rawURL)
	if err != nil {
		return nil, err
	}
	hdrs := make(map[string]string, len(headers))
	for k, v := range headers {
		hdrs[strings.ToLower(k)] = v
	}
	hostname, _ := parts.hostname()
	host := strings.ToLower(hostname)
	path := parts.path
	if path == "" {
		path = "/"
	}
	contentType := hdrs["content-type"]
	sessionID := runePrefix(hdrs["x-aarvion-session-id"], 200)
	scope := ScopeFor("", sessionID)
	ruleIDs, reasons := parkRules(denied, decision)
	volatile := VolatileFor(ruleIDs, "http", catalog)
	digest, err := Digest(HTTPAction{
		Scope: scope, Method: method, Host: host, Path: path, Query: parts.query,
		ContentType: contentType, Body: body, Volatile: volatile,
	}.Object())
	if err != nil {
		return nil, err
	}
	summary := SummaryFor(ruleIDs, SummaryAction{
		Kind: "http", Method: method, Host: host, Path: path, Query: parts.query, ContentType: contentType, Body: body,
	}, catalog)
	create := map[string]any{
		"surface":         "sdk",
		"entity_kind":     "agent",
		"scope":           scope,
		"action_digest":   digest,
		"digest_version":  DigestVersion,
		"rule_ids":        ruleIDs,
		"reasons":         reasons,
		"volatile_fields": volatile,
		"summary":         capSummary(RewriteBody(summary, previewPII, "")),
		"target":          runePrefix(host+path, 500),
		"preview":         parkPreview(decodeIgnore(body)),
		"session_id":      nilIfEmpty(sessionID),
	}
	return &ParkAction{Digest: digest, Scope: scope, Create: create, PolicyID: denied.PolicyID,
		PolicyIDs: denied.PolicyIDs, Reason: denied.Reason, Method: strings.ToUpper(method), Host: host, Path: path}, nil
}

type cpUnavailable struct{ msg string }

func (e *cpUnavailable) Error() string { return e.msg }

type parkRefused struct{ msg string }

func (e *parkRefused) Error() string { return e.msg }

type ParkClient struct {
	base   string
	auth   string
	client *http.Client
}

func NewParkClient(cpURL, tenant, agentID, token string, client *http.Client) *ParkClient {
	if client == nil {
		client = &http.Client{}
	}
	return &ParkClient{
		base:   strings.TrimRight(cpURL, "/") + "/api/v1/agents/" + tenant + "/" + agentID + "/park",
		auth:   "Bearer " + token,
		client: client,
	}
}

func (c *ParkClient) StatusURL(ticket string) string { return c.base + "/" + ticket }

type parkResponse struct {
	status int
	body   map[string]any
}

func parkDetail(r parkResponse) string {
	d := r.body["detail"]
	if m, ok := d.(map[string]any); ok {
		if msg, ok := m["message"].(string); ok && msg != "" {
			d = msg
		} else {
			d = m["error"]
		}
	}
	if s := pyStr(d); d != nil && s != "" {
		return s
	}
	return fmt.Sprintf("CP returned %d", r.status)
}

func (c *ParkClient) call(ctx context.Context, method, path string, body map[string]any, timeout time.Duration) (parkResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return parkResponse{}, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return parkResponse{}, err
	}
	req.Header.Set("Authorization", c.auth)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return parkResponse{}, &cpUnavailable{msg: err.Error()}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return parkResponse{}, &cpUnavailable{msg: err.Error()}
	}
	if resp.StatusCode >= 500 {
		return parkResponse{}, &cpUnavailable{msg: fmt.Sprintf("CP returned %d", resp.StatusCode)}
	}
	out := parkResponse{status: resp.StatusCode, body: map[string]any{}}
	if v, err := pyLoadsPlain(raw); err == nil {
		if m, ok := v.(map[string]any); ok {
			out.body = m
		}
	}
	return out, nil
}

func (c *ParkClient) consume(ctx context.Context, a *ParkAction, ticket, token string) (map[string]any, error) {
	body := map[string]any{"action_digest": a.Digest, "scope": a.Scope}
	if ticket != "" {
		body["ticket"] = ticket
	}
	if token != "" {
		body["approval_token"] = token
	}
	r, err := c.call(ctx, "POST", "/consume", body, parkCallTimeout)
	if err != nil {
		return nil, err
	}
	if r.status != 200 {
		return nil, &parkRefused{msg: parkDetail(r)}
	}
	return r.body, nil
}

func (c *ParkClient) create(ctx context.Context, body map[string]any) (map[string]any, error) {
	r, err := c.call(ctx, "POST", "", body, parkCallTimeout)
	if err != nil {
		return nil, err
	}
	if r.status != 200 && r.status != 201 {
		return nil, &parkRefused{msg: parkDetail(r)}
	}
	return r.body, nil
}

func (c *ParkClient) status(ctx context.Context, ticket string, wait int) (map[string]any, error) {
	path := "/" + url.PathEscape(ticket) + "?wait=" + strconv.Itoa(wait)
	r, err := c.call(ctx, "GET", path, nil, time.Duration(wait)*time.Second+parkCallTimeout)
	if err != nil {
		return nil, err
	}
	if r.status != 200 {
		return nil, &parkRefused{msg: parkDetail(r)}
	}
	return r.body, nil
}

func (c *ParkClient) receipt(ticket string, statusCode int, content []byte) error {
	body := map[string]any{"status_code": statusCode}
	if content != nil {
		body["response_b64"] = base64.StdEncoding.EncodeToString(content)
	}
	_, err := c.call(context.Background(), "POST", "/"+url.PathEscape(ticket)+"/receipt", body, parkCallTimeout)
	return err
}

func (c *ParkClient) Close() { c.client.CloseIdleConnections() }

type parkRelease struct {
	ticket  string
	replay  bool
	status  int
	content []byte
}

const maxOpenTickets = 1000

type openTicket struct {
	action  *ParkAction
	started time.Time
}

type Parker struct {
	client    *ParkClient
	explicit  *Hold
	dashboard func() any
	mu        sync.Mutex
	tokens    map[[2]string]string
	open      map[string]openTicket
	order     []string
	recorder  DecisionRecorder
}

func NewParker(client *ParkClient, hold Hold) *Parker {
	return NewParkerWithDashboard(client, &hold, nil)
}

func NewParkerWithDashboard(client *ParkClient, explicit *Hold, dashboard func() any) *Parker {
	return &Parker{client: client, explicit: explicit, dashboard: dashboard, tokens: map[[2]string]string{},
		open: map[string]openTicket{}}
}

func (p *Parker) Hold() Hold {
	if p.explicit != nil {
		return *p.explicit
	}
	if p.dashboard != nil {
		if v := p.dashboard(); v != nil {
			if _, isBool := v.(bool); !isBool {
				if h, err := ParseHold(v); err == nil {
					return h
				}
			}
		}
	}
	return DefaultHold()
}

func (p *Parker) setRecorder(r DecisionRecorder) {
	p.mu.Lock()
	p.recorder = r
	p.mu.Unlock()
}

func (p *Parker) record(a *ParkAction, reason string, latencyMs int64) {
	p.mu.Lock()
	r := p.recorder
	p.mu.Unlock()
	if r == nil || a.Method == "" {
		return
	}
	_, _ = r.Record(RecordInput{
		Method:    a.Method,
		Path:      a.Path,
		Host:      a.Host,
		Decision:  "allow",
		PolicyID:  a.PolicyID,
		PolicyIDs: a.PolicyIDs,
		Reason:    reason,
		LatencyMs: latencyMs,
		Enforced:  Bool(true),
		CallSite:  callerFrame(),
	})
}

func (p *Parker) remember(ticket string, a *ParkAction) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.open[ticket]; !ok {
		p.order = append(p.order, ticket)
	}
	p.open[ticket] = openTicket{action: a, started: time.Now()}
	for len(p.order) > maxOpenTickets {
		delete(p.open, p.order[0])
		p.order = p.order[1:]
	}
}

func (p *Parker) forget(ticket string) (openTicket, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	o, ok := p.open[ticket]
	if ok {
		delete(p.open, ticket)
		for i, t := range p.order {
			if t == ticket {
				p.order = append(p.order[:i], p.order[i+1:]...)
				break
			}
		}
	}
	return o, ok
}

func (p *Parker) Close() { p.client.Close() }

func tokenLive(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return false
	}
	var claims map[string]any
	if json.Unmarshal(raw, &claims) != nil {
		return false
	}
	exp, ok := claims["exp"].(float64)
	return ok && exp > float64(time.Now().UnixNano())/1e9
}

func settle(c map[string]any) (*parkRelease, error) {
	ticket := pyStr(dictGet(c, "ticket_id", ""))
	if c["ticket_id"] == nil {
		ticket = ""
	}
	executedAt, _ := c["executed_at"].(string)
	switch c["result"] {
	case "go":
		return &parkRelease{ticket: ticket}, nil
	case "replay":
		code, _ := pyInt(dictGet(c, "status_code", int64(200)))
		content, _ := base64.StdEncoding.DecodeString(strOr(c["response_b64"]))
		return &parkRelease{ticket: ticket, replay: true, status: int(code), content: content}, nil
	case "in_progress":
		return nil, &ActionInProgress{
			AarvionError: AarvionError{Msg: "an identical request is already running under approval ticket " + ticket},
			Ticket:       ticket, ExecutedAt: executedAt,
		}
	case "already_executed":
		code, _ := pyInt(dictGet(c, "status_code", int64(0)))
		return nil, &ActionAlreadyExecuted{
			AarvionError: AarvionError{Msg: fmt.Sprintf("already ran at %s under approval ticket %s", executedAt, ticket)},
			Ticket:       ticket, ExecutedAt: executedAt, StatusCode: int(code),
		}
	}
	return nil, nil
}

func (p *Parker) unreachable(a *ParkAction, err error, ticket string) error {
	return NewPolicyDenied(a.PolicyID, fmt.Sprintf("parked for approval, but the approval service is unreachable "+
		"so nothing was sent (%v)", err), 503, a.PolicyIDs).withTicket(ticket)
}

func (p *Parker) mapErr(a *ParkAction, err error, ticket, prefix string) error {
	var down *cpUnavailable
	if errors.As(err, &down) {
		return p.unreachable(a, err, ticket)
	}
	var refused *parkRefused
	if errors.As(err, &refused) {
		reason := fmt.Sprintf("%s (%v)", a.Reason, err)
		if prefix != "" {
			reason = fmt.Sprintf("%s: %v", prefix, err)
		}
		return NewPolicyDenied(a.PolicyID, reason, 403, a.PolicyIDs).withTicket(ticket)
	}
	return err
}

func (p *Parker) denied(a *ParkAction, ticket, status string) error {
	return NewPolicyDenied(a.PolicyID, fmt.Sprintf("approval ticket %s was %s", ticket, status), 403, a.PolicyIDs).
		withTicket(ticket)
}

func (p *Parker) resolve(ctx context.Context, a *ParkAction) (*parkRelease, error) {
	rel, err := p.resolveRaw(ctx, a)
	if err != nil {
		return nil, p.mapErr(a, err, "", "")
	}
	if rel.replay {
		p.record(a, "replayed the saved result of approval ticket "+rel.ticket+", not sent again", 0)
	} else if rel.ticket != "" {
		p.remember(rel.ticket, a)
	}
	return rel, nil
}

func (p *Parker) resolveRaw(ctx context.Context, a *ParkAction) (*parkRelease, error) {
	key := [2]string{a.Digest, a.Scope}
	p.mu.Lock()
	token := p.tokens[key]
	delete(p.tokens, key)
	p.mu.Unlock()
	if token != "" && !tokenLive(token) {
		token = ""
	}
	c, err := p.client.consume(ctx, a, "", token)
	if err != nil {
		return nil, err
	}
	if rel, err := settle(c); rel != nil || err != nil {
		return rel, err
	}
	view, err := p.holdView(ctx, a)
	if err != nil {
		return nil, err
	}
	ticket, status := strOr(view["ticket_id"]), strOr(view["status"])
	var rel *parkRelease
	switch status {
	case "pending":
		return nil, &ActionParked{
			AarvionError: AarvionError{Msg: fmt.Sprintf("parked for approval as ticket %s: %s", ticket, a.Reason)},
			Ticket:       ticket, StatusURL: p.client.StatusURL(ticket), RetryAfter: retryAfterSeconds,
			PolicyID: a.PolicyID, Reason: a.Reason,
			waiter: func(ctx context.Context) (bool, error) { return p.wait(ctx, a, ticket) },
		}
	case "approved":
		c, err := p.client.consume(ctx, a, ticket, strOr(view["approval_token"]))
		if err != nil {
			return nil, err
		}
		if rel, err = settle(c); err != nil {
			return nil, err
		}
	case "consumed":
		c, err := p.client.consume(ctx, a, "", "")
		if err != nil {
			return nil, err
		}
		if rel, err = settle(c); err != nil {
			return nil, err
		}
	}
	if rel == nil {
		return nil, p.denied(a, ticket, status)
	}
	return rel, nil
}

func (p *Parker) holdView(ctx context.Context, a *ParkAction) (map[string]any, error) {
	hold := p.Hold()
	holdState := "held_live"
	if !hold.UntilDecision && hold.Seconds == 0 {
		holdState = "ticket"
	}
	body := make(map[string]any, len(a.Create)+1)
	for k, v := range a.Create {
		body[k] = v
	}
	body["hold_state"] = holdState
	view, err := p.client.create(ctx, body)
	if err != nil {
		return nil, err
	}
	var deadline *time.Time
	if !hold.UntilDecision {
		d := time.Now().Add(time.Duration(hold.Seconds * float64(time.Second)))
		deadline = &d
	}
	return p.await(ctx, strOr(view["ticket_id"]), deadline, view)
}

func (p *Parker) await(ctx context.Context, ticket string, deadline *time.Time, view map[string]any) (map[string]any, error) {
	for strOr(view["status"]) == "pending" {
		wait := longPollCap
		if deadline != nil {
			remaining := time.Until(*deadline)
			if remaining <= 0 {
				break
			}
			wait = int(math.Min(longPollCap, math.Ceil(remaining.Seconds())))
		}
		next, err := p.client.status(ctx, ticket, wait)
		if err != nil {
			return nil, err
		}
		view = next
	}
	return view, nil
}

func (p *Parker) wait(ctx context.Context, a *ParkAction, ticket string) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var deadline *time.Time
	if d, ok := ctx.Deadline(); ok {
		deadline = &d
	}
	first, err := p.client.status(ctx, ticket, 0)
	if err == nil {
		first, err = p.await(ctx, ticket, deadline, first)
	}
	if err != nil {
		if ctx.Err() != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return false, nil
			}
			return false, ctx.Err()
		}
		return false, p.mapErr(a, err, ticket, "ticket "+ticket)
	}
	switch status := strOr(first["status"]); status {
	case "pending":
		return false, nil
	case "approved":
		p.mu.Lock()
		p.tokens[[2]string{a.Digest, a.Scope}] = strOr(first["approval_token"])
		p.mu.Unlock()
		return true, nil
	case "consumed":
		return true, nil
	default:
		return false, p.denied(a, ticket, status)
	}
}

func (p *Parker) writeReceipt(ticket string, status int, content []byte) {
	if o, ok := p.forget(ticket); ok {
		reason := fmt.Sprintf("approved under ticket %s, sent (HTTP %d)", ticket, status)
		if content == nil {
			reason = "approved under ticket " + ticket + ", but sending failed"
		}
		p.record(o.action, reason, time.Since(o.started).Milliseconds())
	}
	_ = p.client.receipt(ticket, status, content)
}
