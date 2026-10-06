package aarvion

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func runtimeConfig() *Config {
	return NewConfig("agt_x", "aav_dev_abc.secret",
		"https://cp.aarvion.ai/api/v1/bundles/acme/agt_x/policy.tar.gz", "devkey-signing-secret", "https://cp.aarvion.ai")
}

func TestConfigPullsSignedBundleWithDevKey(t *testing.T) {
	cfg, err := BuildOpaConfig(runtimeConfig(), "")
	if err != nil {
		t.Fatal(err)
	}
	svc := cfg["services"].(map[string]any)["aarvion-cp"].(map[string]any)
	if svc["url"] != "https://cp.aarvion.ai" {
		t.Fatal(svc["url"])
	}
	if svc["headers"].(map[string]any)["Authorization"] != "Bearer aav_dev_abc.secret" {
		t.Fatal(svc["headers"])
	}
	if !reflect.DeepEqual(cfg["keys"].(map[string]any)["aarvion"], map[string]any{"algorithm": "HS256", "key": "devkey-signing-secret"}) {
		t.Fatal(cfg["keys"])
	}
	policy := cfg["bundles"].(map[string]any)["policy"].(map[string]any)
	if policy["resource"] != "api/v1/bundles/acme/agt_x/policy.tar.gz" {
		t.Fatal(policy["resource"])
	}
	if policy["signing"].(map[string]any)["keyid"] != "aarvion" {
		t.Fatal(policy["signing"])
	}
}

func TestConfigOmitsEnvoyPluginAndDecisionLogs(t *testing.T) {
	cfg, _ := BuildOpaConfig(runtimeConfig(), "")
	if _, ok := cfg["plugins"]; ok {
		t.Fatal("plugins present")
	}
	if _, ok := cfg["decision_logs"]; ok {
		t.Fatal("decision_logs present")
	}
}

func TestPersistTogglesWithDir(t *testing.T) {
	a, _ := BuildOpaConfig(runtimeConfig(), "")
	b, _ := BuildOpaConfig(runtimeConfig(), "/tmp/x")
	if a["bundles"].(map[string]any)["policy"].(map[string]any)["persist"] != false {
		t.Fatal("persist should be false")
	}
	if b["bundles"].(map[string]any)["policy"].(map[string]any)["persist"] != true {
		t.Fatal("persist should be true")
	}
}

func TestOpaConfigFileBytesMatchPython(t *testing.T) {
	doc, _ := opaConfigObject(runtimeConfig(), true)
	got, _ := pyDumps(doc, jsonDefault)
	want := `{"services": {"aarvion-cp": {"url": "https://cp.aarvion.ai", "headers": {"Authorization": "Bearer aav_dev_abc.secret"}}}, ` +
		`"keys": {"aarvion": {"algorithm": "HS256", "key": "devkey-signing-secret"}}, ` +
		`"bundles": {"policy": {"service": "aarvion-cp", "resource": "api/v1/bundles/acme/agt_x/policy.tar.gz", ` +
		`"signing": {"keyid": "aarvion"}, "polling": {"min_delay_seconds": 60, "max_delay_seconds": 120}, "persist": true}}}`
	if got != want {
		t.Fatalf("got %s", got)
	}
}

func TestResolveBinaryHonorsOverride(t *testing.T) {
	cleanEnv(t)
	fake := filepath.Join(t.TempDir(), "opa")
	os.WriteFile(fake, []byte("#!/bin/sh\n"), 0o644)
	t.Setenv("AARVION_OPA_PATH", fake)
	got, err := ResolveOpaBinary()
	if err != nil || got != fake {
		t.Fatalf("got %q %v", got, err)
	}
}

func TestResolveBinaryOverrideMissingRaises(t *testing.T) {
	cleanEnv(t)
	t.Setenv("AARVION_OPA_PATH", "/nope/opa")
	_, err := ResolveOpaBinary()
	var ae *AarvionError
	if !errors.As(err, &ae) || !strings.Contains(err.Error(), "does not point") {
		t.Fatalf("got %v", err)
	}
}

func stubWhich(t *testing.T, result string) {
	old := whichFn
	whichFn = func(string) string { return result }
	t.Cleanup(func() { whichFn = old })
}

func TestResolveBinaryNotFoundRaisesWhenAutodownloadDisabled(t *testing.T) {
	cleanEnv(t)
	t.Setenv("AARVION_OPA_AUTODOWNLOAD", "0")
	stubWhich(t, "")
	_, err := ResolveOpaBinary()
	var ae *AarvionError
	if !errors.As(err, &ae) || !strings.Contains(err.Error(), "opa binary not found") {
		t.Fatalf("got %v", err)
	}
}

func TestResolveBinaryAutoDownloadsWhenMissing(t *testing.T) {
	cleanEnv(t)
	stubWhich(t, "")
	old := downloadOpaFn
	downloadOpaFn = func() (string, error) { return "/cached/opa", nil }
	t.Cleanup(func() { downloadOpaFn = old })
	got, err := ResolveOpaBinary()
	if err != nil || got != "/cached/opa" {
		t.Fatalf("got %q %v", got, err)
	}
}

func runtimeWithMock(t *testing.T, handler roundTripFunc) *OpaRuntime {
	rt, err := NewOpaRuntime(runtimeConfig(), 0, "")
	if err != nil {
		t.Fatal(err)
	}
	rt.client = mockClient(handler)
	rt.baseURL = "http://127.0.0.1:8181"
	return rt
}

func TestEvaluateReturnsDecisionAndWrapsInput(t *testing.T) {
	seen := map[string]any{}
	rt := runtimeWithMock(t, func(r *http.Request) (*http.Response, error) {
		seen["path"] = r.URL.Path
		var doc any
		json.Unmarshal([]byte(readBody(t, r)), &doc)
		seen["json"] = doc
		return jsonResponse(200, `{"result": {"allowed": false, "http_status": 403, "headers": {"x-policy-violated": "p.v1"}}}`), nil
	})
	d, err := rt.Evaluate(map[string]any{"attributes": map[string]any{"x": 1}})
	if err != nil {
		t.Fatal(err)
	}
	if seen["path"] != "/v1/data/envoy/authz/allow" {
		t.Fatal(seen["path"])
	}
	if !reflect.DeepEqual(seen["json"], map[string]any{"input": map[string]any{"attributes": map[string]any{"x": float64(1)}}}) {
		t.Fatal(seen["json"])
	}
	if d["allowed"] != false || d["headers"].(map[string]any)["x-policy-violated"] != "p.v1" {
		t.Fatal(d)
	}
}

func TestEvaluateUndefinedResultFailsClosed(t *testing.T) {
	rt := runtimeWithMock(t, func(r *http.Request) (*http.Response, error) { return jsonResponse(200, `{}`), nil })
	d, err := rt.Evaluate(map[string]any{"attributes": map[string]any{}})
	if err != nil || d["allowed"] != false {
		t.Fatalf("got %v %v", d, err)
	}
}

func TestHealthyBundlesParamHitsBundleHealth(t *testing.T) {
	seen := ""
	rt := runtimeWithMock(t, func(r *http.Request) (*http.Response, error) {
		seen = r.URL.String()
		return textResponse(200, ""), nil
	})
	if !rt.Healthy(true) {
		t.Fatal("not healthy")
	}
	if !strings.Contains(seen, "bundles=true") {
		t.Fatal(seen)
	}
}

type fakeProc struct {
	dead bool
}

func (f *fakeProc) exited() bool              { return f.dead }
func (f *fakeProc) terminate()                {}
func (f *fakeProc) kill()                     {}
func (f *fakeProc) wait(t time.Duration) bool { return true }

func stubStart(t *testing.T, fn func([]string) (opaProcess, error)) {
	old := startProcessFn
	startProcessFn = fn
	t.Cleanup(func() { startProcessFn = old })
}

func TestStartUsesAFreePortNot8181(t *testing.T) {
	cleanEnv(t)
	t.Setenv("TMPDIR", t.TempDir())
	started := map[string]string{}
	stubStart(t, func(argv []string) (opaProcess, error) {
		for i, a := range argv {
			if a == "--addr" {
				started["addr"] = argv[i+1]
			}
		}
		return &fakeProc{}, nil
	})
	rt, _ := NewOpaRuntime(runtimeConfig(), 0, "")
	rt.binaryFn = func() (string, error) { return "/bin/opa", nil }
	rt.healthyFn = func(bool) bool { return true }
	if err := rt.Start(0); err != nil {
		t.Fatal(err)
	}
	addr := started["addr"]
	port, _ := strconv.Atoi(addr[strings.LastIndex(addr, ":")+1:])
	if port == 8181 {
		t.Fatal("used 8181")
	}
	if rt.BaseURL() != "http://127.0.0.1:"+strconv.Itoa(port) {
		t.Fatal(rt.BaseURL())
	}
	os.Remove(rt.cfgPath)
}

func TestStartFailsIfOurOpaExitsEvenWhenPortAnswers(t *testing.T) {
	cleanEnv(t)
	t.Setenv("TMPDIR", t.TempDir())
	stubStart(t, func(argv []string) (opaProcess, error) { return &fakeProc{dead: true}, nil })
	rt, _ := NewOpaRuntime(runtimeConfig(), 8181, "")
	rt.binaryFn = func() (string, error) { return "/bin/opa", nil }
	rt.healthyFn = func(bool) bool { return true }
	err := rt.Start(0)
	var ae *AarvionError
	if !errors.As(err, &ae) || !strings.Contains(err.Error(), "exited during startup") {
		t.Fatalf("got %v", err)
	}
	os.Remove(rt.cfgPath)
}

func TestEvaluateBeforeStartAndAfterStop(t *testing.T) {
	rt, _ := NewOpaRuntime(runtimeConfig(), 0, "")
	_, err := rt.Evaluate(map[string]any{})
	if err == nil || err.Error() != "Request URL is missing an 'http://' or 'https://' protocol." {
		t.Fatalf("got %v", err)
	}
	if rt.Healthy(false) {
		t.Fatal("healthy before start")
	}
	rt.Stop()
	_, err = rt.Evaluate(map[string]any{})
	if err == nil || err.Error() != "Cannot send a request, as the client has been closed." {
		t.Fatalf("got %v", err)
	}
}

func TestPlatformKeyAndPinnedAssets(t *testing.T) {
	if len(OPAAssets) != 5 {
		t.Fatal(len(OPAAssets))
	}
	if OPAAssets["win32-x64"].SHA256 != "459ad6f8fc9da7a9fb569cc364255517ea820e7c05a222763b752ce921b16a55" {
		t.Fatal("pin changed")
	}
	if !strings.Contains(platformKey(), "-") {
		t.Fatal(platformKey())
	}
}
