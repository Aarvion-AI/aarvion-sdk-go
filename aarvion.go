package aarvion

import (
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const Version = "0.2.0"

func TenantFromBundleURL(url string) (string, error) {
	p, err := urlSplit(url)
	if err != nil {
		return "", err
	}
	parts := strings.Split(pyStripChars(p.path, "/"), "/")
	for i, s := range parts {
		if s == "bundles" {
			if i+1 < len(parts) {
				return parts[i+1], nil
			}
			break
		}
	}
	return "", newConfigError("cannot derive tenant from bundle_url: "+url, nil)
}

type Session struct {
	Config   *Config
	Runtime  *OpaRuntime
	Recorder *Recorder
	Governor *Governor
	Parker   *Parker

	convMu     sync.Mutex
	convClient *http.Client
}

func (s *Session) AgentID() string { return s.Config.AgentID }

func (s *Session) CPURL() string { return s.Config.CPURL }

func (s *Session) Flush() (int, error) { return s.Recorder.Flush() }

func (s *Session) Close() error {
	if _, err := s.Recorder.Flush(); err != nil {
		return err
	}
	if err := s.Runtime.Stop(); err != nil {
		return err
	}
	if err := s.Recorder.Close(); err != nil {
		return err
	}
	if s.Parker != nil {
		s.Parker.Close()
	}
	s.convMu.Lock()
	c := s.convClient
	s.convMu.Unlock()
	if c != nil {
		c.CloseIdleConnections()
	}
	return nil
}

func (s *Session) Wrap(client *http.Client) *http.Client { return WrapClient(client, s.Governor) }

func (s *Session) Transport(inner http.RoundTripper) http.RoundTripper {
	return NewTransport(inner, s.Governor)
}

func (s *Session) conversationClient() *http.Client {
	s.convMu.Lock()
	defer s.convMu.Unlock()
	if s.convClient == nil {
		s.convClient = newPyHTTPClient(DefaultEnforceTimeout, false)
	}
	return s.convClient
}

type initOptions struct {
	apiKey       string
	apiKeySet    bool
	agent        string
	apiURL       string
	evaluatorURL string
	persist      bool
	monitor      bool
	stateDir     string
	startRuntime bool
	hold         any
}

type Option func(*initOptions)

func WithAPIKey(key string) Option {
	return func(o *initOptions) { o.apiKey, o.apiKeySet = key, true }
}

func WithAgent(agent string) Option { return func(o *initOptions) { o.agent = agent } }

func WithAPIURL(url string) Option { return func(o *initOptions) { o.apiURL = url } }

func WithEvaluatorURL(url string) Option { return func(o *initOptions) { o.evaluatorURL = url } }

func WithPersist(persist bool) Option { return func(o *initOptions) { o.persist = persist } }

func WithMonitor(monitor bool) Option { return func(o *initOptions) { o.monitor = monitor } }

func WithStateDir(dir string) Option { return func(o *initOptions) { o.stateDir = dir } }

func WithStartRuntime(start bool) Option { return func(o *initOptions) { o.startRuntime = start } }

func WithHold(d time.Duration) Option { return func(o *initOptions) { o.hold = d } }

func WithHoldUntilDecision() Option { return func(o *initOptions) { o.hold = HoldUntilDecision } }

var (
	activeMu sync.RWMutex
	active   *Session
)

var exchangeFn = func(apiKey, agent, apiURL string) (*Config, error) { return Exchange(apiKey, agent, apiURL, nil) }

func Init(opts ...Option) (*Session, error) {
	o := initOptions{persist: true, startRuntime: true}
	for _, opt := range opts {
		opt(&o)
	}
	if maxBodyBytesErr != nil {
		return nil, maxBodyBytesErr
	}
	var cfg *Config
	var err error
	if o.apiKeySet {
		if o.agent == "" {
			return nil, newConfigError("agent is required when exchanging an api_key", nil)
		}
		cfg, err = exchangeFn(o.apiKey, o.agent, o.apiURL)
	} else {
		cfg, err = LoadConfig("")
	}
	if err != nil {
		return nil, err
	}

	ev := o.evaluatorURL
	if ev == "" {
		ev = os.Getenv("AARVION_EVALUATOR_URL")
	}
	if ev == "" {
		ev = cfg.EvaluatorURL
	}
	cfg.EvaluatorURL = ev

	if o.apiKeySet && o.persist {
		if _, err := SaveConfig(cfg, ""); err != nil {
			return nil, err
		}
	}

	tenant, err := TenantFromBundleURL(cfg.BundleURL)
	if err != nil {
		return nil, err
	}
	state := o.stateDir
	if state == "" {
		state = expandUser("~/.aarvion/" + cfg.AgentID)
	}
	if err := os.MkdirAll(state, 0o777); err != nil {
		return nil, err
	}
	persistDir := ""
	if o.persist {
		persistDir = pyPath(state)
	}
	rt, err := NewOpaRuntime(cfg, 0, persistDir)
	if err != nil {
		return nil, err
	}
	recorder, err := NewRecorder(cfg, pyJoinPath(pyPath(state), "provenance.db"), tenant, DefaultAutoflushInterval)
	if err != nil {
		return nil, err
	}
	holdValue := o.hold
	if holdValue == nil {
		if env := os.Getenv("AARVION_PARK_HOLD"); env != "" {
			holdValue = env
		}
	}
	var explicit *Hold
	if holdValue != nil {
		h, err := ParseHold(holdValue)
		if err != nil {
			return nil, err
		}
		explicit = &h
	}
	var fileHold any
	if cfg.Hold != nil {
		h, err := ParseHold(cfg.Hold)
		if err != nil {
			return nil, err
		}
		fileHold = h
	}
	parker := NewParkerWithDashboard(NewParkClient(cfg.CPURL, tenant, cfg.AgentID, cfg.RuntimeKey, nil), explicit,
		func() any {
			if v := rt.ParkHoldSeconds(); v != nil {
				return v
			}
			return fileHold
		})
	governor := NewGovernor(rt, recorder, o.monitor).SetParker(parker, rt.ParkCatalog)
	if o.startRuntime {
		if err := rt.Start(DefaultReadyTimeout); err != nil {
			return nil, err
		}
	}
	s := &Session{Config: cfg, Runtime: rt, Recorder: recorder, Governor: governor, Parker: parker}
	activeMu.Lock()
	active = s
	activeMu.Unlock()
	return s, nil
}

func Active() (*Session, error) {
	activeMu.RLock()
	s := active
	activeMu.RUnlock()
	if s == nil {
		return nil, newAarvionError("aarvion.init() has not been called")
	}
	return s, nil
}

func setActive(s *Session) {
	activeMu.Lock()
	active = s
	activeMu.Unlock()
}

func Wrap(client *http.Client) (*http.Client, error) {
	s, err := Active()
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, pyTypeError("cannot govern NoneType: no httpx client found")
	}
	return WrapClient(client, s.Governor), nil
}

func Transport(inner http.RoundTripper) (http.RoundTripper, error) {
	s, err := Active()
	if err != nil {
		return nil, err
	}
	return NewTransport(inner, s.Governor), nil
}

type ReplyOption func(*Turn)

func WithIntent(intent string) ReplyOption { return func(t *Turn) { t.Intent = &intent } }

func WithSourceData(data map[string]any) ReplyOption { return func(t *Turn) { t.SourceData = data } }

var (
	enforceTurnFn = enforceTurn
	monitorTurnFn = monitorTurn
)

func GovernReply(sessionID string, turnNumber int, userMsg, botResponse string, opts ...ReplyOption) (string, error) {
	session, err := Active()
	if err != nil {
		return "", err
	}
	evaluatorURL := session.Config.EvaluatorURL
	if evaluatorURL == "" {
		return "", newConfigError("no evaluator_url configured - pass init(evaluator_url=...) or set "+
			"AARVION_EVALUATOR_URL", nil)
	}
	turn := Turn{SessionID: sessionID, TurnNumber: turnNumber, UserMsg: userMsg, BotResponse: botResponse}
	for _, opt := range opts {
		opt(&turn)
	}
	monitor := session.Governor.monitor
	client := session.conversationClient()

	if monitor {
		if err := monitorTurnFn(evaluatorURL, turn, DefaultMonitorTimeout, client); err != nil {
			return "", err
		}
		if err := recordTurn(session, turn, "monitor", "monitor mode - evaluated async, not blocked", nil, false); err != nil {
			return "", err
		}
		return botResponse, nil
	}

	result, err := enforceTurnFn(evaluatorURL, turn, DefaultEnforceTimeout, client)
	if err != nil {
		if rerr := recordTurn(session, turn, "fail_open", "evaluator unreachable", nil, false); rerr != nil {
			return "", rerr
		}
		return botResponse, nil
	}

	action := result["action"]
	actionStr, isStr := action.(string)
	blocked := !(isStr && (actionStr == "release" || actionStr == "allow"))
	decision := result["verdict"]
	if !pyTruthy(decision) {
		decision = action
	}
	if err := recordTurn(session, turn, decision, dictGet(result, "reason", ""), result["latency_ms"], true); err != nil {
		return "", err
	}
	if blocked {
		response, ok := result["response"]
		if ok && response != nil {
			return pyStr(response), nil
		}
		return botResponse, nil
	}
	return botResponse, nil
}

func recordTurn(session *Session, turn Turn, decision, reason, latencyMs any, enforced bool) error {
	host := "evaluator"
	if p, err := urlSplit(session.Config.EvaluatorURL); err == nil {
		if h, ok := p.hostname(); ok && h != "" {
			host = h
		}
	} else {
		return err
	}
	_, err := session.Recorder.Record(RecordInput{
		Method:      "TURN",
		Path:        turn.SessionID + "#" + pyStr(int64(turn.TurnNumber)),
		Host:        host,
		Decision:    decision,
		Reason:      reason,
		LatencyMs:   latencyMs,
		Enforced:    Bool(enforced),
		RequestBody: turn.BotResponse,
	})
	return err
}
