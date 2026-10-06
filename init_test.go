package aarvion

import (
	"errors"
	"net/http"
	"path/filepath"
	"testing"
)

func saveInitConfig(t *testing.T) {
	t.Helper()
	if _, err := SaveConfig(NewConfig("agt_x", "aav_dev_abc.secret", "https://cp/api/v1/bundles/acme/agt_x/policy.tar.gz", "s", "http://127.0.0.1:9"), ""); err != nil {
		t.Fatal(err)
	}
}

func TestTenantDerivedFromBundleURL(t *testing.T) {
	got, err := TenantFromBundleURL("https://cp/api/v1/bundles/acme/agt_x/policy.tar.gz")
	if err != nil || got != "acme" {
		t.Fatalf("got %q %v", got, err)
	}
	_, err = TenantFromBundleURL("https://cp/nothing/bundles")
	var ce *ConfigError
	if !errors.As(err, &ce) || err.Error() != "cannot derive tenant from bundle_url: https://cp/nothing/bundles" {
		t.Fatalf("got %v", err)
	}
}

func TestInitAssemblesPipelineWithoutStartingOPA(t *testing.T) {
	cleanEnv(t)
	saveInitConfig(t)
	s, err := Init(WithStartRuntime(false), WithStateDir(filepath.Join(t.TempDir(), "state")))
	if err != nil {
		t.Fatal(err)
	}
	defer setActive(nil)
	if s.AgentID() != "agt_x" || s.Governor == nil || s.Recorder == nil {
		t.Fatal(s)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWrapUsesActiveSessionGovernor(t *testing.T) {
	cleanEnv(t)
	saveInitConfig(t)
	if _, err := Init(WithStartRuntime(false), WithStateDir(filepath.Join(t.TempDir(), "state"))); err != nil {
		t.Fatal(err)
	}
	defer setActive(nil)
	client := mockClient(func(r *http.Request) (*http.Response, error) { return textResponse(200, ""), nil })
	if _, err := Wrap(client); err != nil {
		t.Fatal(err)
	}
	if _, ok := client.Transport.(*governingTransport); !ok {
		t.Fatal("not governed")
	}
	s, _ := Active()
	s.Close()
}

func TestWrapBeforeInitRaises(t *testing.T) {
	setActive(nil)
	_, err := Wrap(&http.Client{})
	var ae *AarvionError
	if !errors.As(err, &ae) || err.Error() != "aarvion.init() has not been called" {
		t.Fatalf("got %v", err)
	}
	if _, err := Transport(nil); !errors.As(err, &ae) {
		t.Fatalf("got %v", err)
	}
}
