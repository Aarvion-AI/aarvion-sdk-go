package aarvion

import (
	"errors"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Evaluator interface {
	Evaluate(input map[string]any) (map[string]any, error)
}

type DecisionRecorder interface {
	Record(r RecordInput) (map[string]any, error)
}

var callSiteSkip = []string{
	"github.com/Aarvion-AI/aarvion-sdk-go.",
	"github.com/Aarvion-AI/aarvion-sdk-go/",
	"net/http.",
	"net/http/",
}

func skipFrame(function string) bool {
	for _, p := range callSiteSkip {
		if strings.HasPrefix(function, p) {
			return true
		}
	}
	return strings.HasPrefix(function, "runtime.") && !strings.Contains(function, "/")
}

func callerFrame() any {
	pcs := make([]uintptr, 128)
	n := runtime.Callers(2, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	for {
		f, more := frames.Next()
		if f.Function != "" && !skipFrame(f.Function) {
			return f.File + ":" + strconv.Itoa(f.Line)
		}
		if !more {
			return nil
		}
	}
}

type Governor struct {
	eval     Evaluator
	recorder DecisionRecorder
	monitor  bool
	parker   *Parker
	catalog  func() map[string]any
}

func NewGovernor(evaluator Evaluator, recorder DecisionRecorder, monitor bool) *Governor {
	return &Governor{eval: evaluator, recorder: recorder, monitor: monitor}
}

func (g *Governor) Monitor() bool { return g.monitor }

func (g *Governor) SetParker(parker *Parker, catalog func() map[string]any) *Governor {
	g.parker = parker
	g.catalog = catalog
	if parker != nil {
		parker.setRecorder(g.recorder)
	}
	return g
}

func (g *Governor) Parker() *Parker { return g.parker }

func (g *Governor) parkCatalog() map[string]any {
	if g.catalog != nil {
		if c := g.catalog(); c != nil {
			return c
		}
	}
	return FallbackCatalog()
}

func (g *Governor) Evaluator() Evaluator { return g.eval }

func (g *Governor) Recorder() DecisionRecorder { return g.recorder }

func (g *Governor) Process(method, rawURL string, headers map[string]string, body []byte) (string, error) {
	return g.process(method, rawURL, headers, decodeIgnore(body), body)
}

func (g *Governor) ProcessText(method, rawURL string, headers map[string]string, text string) (string, error) {
	return g.process(method, rawURL, headers, text, []byte(text))
}

func (g *Governor) process(method, rawURL string, headers map[string]string, text string, raw []byte) (string, error) {
	if maxBodyBytesErr != nil {
		return "", maxBodyBytesErr
	}
	parts, err := urlSplit(rawURL)
	if err != nil {
		return "", err
	}
	host, _ := parts.hostname()
	path := parts.path
	if path == "" {
		path = "/"
	}

	t0 := time.Now()
	decision := BodyTooLarge(text)
	if decision == nil {
		h := make(map[string]string, len(headers))
		for k, v := range headers {
			h[k] = v
		}
		decision, err = g.eval.Evaluate(BuildExtAuthzInput(method, host, path, h, text))
		if err != nil {
			return "", err
		}
	}
	latencyMs := int64(time.Since(t0) / time.Millisecond)
	callSite := callerFrame()
	hdrs, err := dictOrEmpty(decision["headers"])
	if err != nil {
		return "", err
	}

	if !pyTruthy(dictGet(decision, "allowed", true)) {
		if err := g.record(method, host, path, "deny", hdrs, latencyMs, callSite, !g.monitor); err != nil {
			return "", err
		}
		if g.monitor {
			return text, nil
		}
		err := deniedFromDecision(decision, hdrs)
		var denied *PolicyDenied
		if g.parker != nil && headerOr(hdrs, "x-aarvion-action", "") == "park" && errors.As(err, &denied) {
			action, aerr := buildParkAction(method, rawURL, headers, raw, denied, decision, g.parkCatalog())
			if aerr != nil {
				return "", aerr
			}
			return "", &Parked{Denied: denied, Action: action}
		}
		return "", err
	}

	newBody, err := ApplyDecision(decision, text)
	if err != nil {
		return "", err
	}
	if err := g.record(method, host, path, "allow", hdrs, latencyMs, callSite, true); err != nil {
		return "", err
	}
	return newBody, nil
}

func (g *Governor) record(method, host, path, decision string, hdrs map[string]any, latencyMs int64, callSite any, enforced bool) error {
	if g.recorder == nil {
		return nil
	}
	ids, err := PolicyIDs(hdrs)
	if err != nil {
		return err
	}
	_, err = g.recorder.Record(RecordInput{
		Method:     method,
		Path:       path,
		Host:       host,
		Decision:   decision,
		PolicyID:   hdrs["x-policy-violated"],
		PolicyIDs:  ids,
		Reason:     hdrs["x-policy-reason"],
		Redactions: hdrs["x-aarvion-redactions"],
		LatencyMs:  latencyMs,
		Enforced:   Bool(enforced),
		CallSite:   callSite,
	})
	return err
}

func Bool(v bool) *bool { return &v }
