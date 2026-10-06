package aarvion

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

const okSessionBody = `{"agent_id": "agt_x", "runtime_key": "aav_dev_minted",
 "bundle_url": "https://cp/api/v1/bundles/acme/agt_x/policy.tar.gz",
 "bundle_signing_secret": "minted-secret", "cp_url": "https://cp", "format_version": 1}`

func TestExchangeParsesSessionResponse(t *testing.T) {
	seen := map[string]string{}
	c := mockClient(func(r *http.Request) (*http.Response, error) {
		seen["url"] = r.URL.String()
		seen["auth"] = r.Header.Get("Authorization")
		return jsonResponse(200, okSessionBody), nil
	})
	cfg, err := Exchange("aav_org_key", "my-agent", "https://api.test", c)
	if err != nil {
		t.Fatal(err)
	}
	if seen["url"] != "https://api.test/api/sdk/sessions" || seen["auth"] != "Bearer aav_org_key" {
		t.Fatalf("seen %v", seen)
	}
	if cfg.AgentID != "agt_x" || cfg.RuntimeKey != "aav_dev_minted" || cfg.SigningSecret != "minted-secret" {
		t.Fatalf("cfg %+v", cfg)
	}
}

func TestExchange401IsSessionError(t *testing.T) {
	c := mockClient(func(r *http.Request) (*http.Response, error) { return textResponse(401, "nope"), nil })
	_, err := Exchange("bad", "a", "", c)
	var se *SessionError
	if !errors.As(err, &se) || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("got %v", err)
	}
}

func TestExchangeBadShapeIsSessionError(t *testing.T) {
	c := mockClient(func(r *http.Request) (*http.Response, error) { return jsonResponse(200, `{"agent_id": "x"}`), nil })
	_, err := Exchange("k", "a", "", c)
	var se *SessionError
	if !errors.As(err, &se) || !strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("got %v", err)
	}
	if err.Error() != "unexpected session response shape: 'runtime_key'" {
		t.Fatalf("message %q", err.Error())
	}
}

func TestResolveBuildsConfigFromKey(t *testing.T) {
	seen := map[string]string{}
	c := mockClient(func(r *http.Request) (*http.Response, error) {
		seen["url"] = r.URL.String()
		seen["auth"] = r.Header.Get("Authorization")
		return jsonResponse(200, `{"agent_id": "agt_x", "tenant": "acme", "signing_secret": "sek", "format_version": 1}`), nil
	})
	cfg, err := Resolve("aav_dev_k.s", "https://cp.test", c)
	if err != nil {
		t.Fatal(err)
	}
	if seen["url"] != "https://cp.test/api/v1/sdk/resolve" || seen["auth"] != "Bearer aav_dev_k.s" {
		t.Fatalf("seen %v", seen)
	}
	if cfg.AgentID != "agt_x" || cfg.SigningSecret != "sek" || cfg.CPURL != "https://cp.test" ||
		cfg.BundleURL != "https://cp.test/api/v1/bundles/acme/agt_x/policy.tar.gz" {
		t.Fatalf("cfg %+v", cfg)
	}
}

func TestResolveRejectedKeyRaises(t *testing.T) {
	c := mockClient(func(r *http.Request) (*http.Response, error) { return textResponse(403, ""), nil })
	_, err := Resolve("bad", "https://cp.test", c)
	var se *SessionError
	if !errors.As(err, &se) || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("got %v", err)
	}
	var base *AarvionError
	if !errors.As(err, &base) {
		t.Fatal("SessionError must be an AarvionError")
	}
}
