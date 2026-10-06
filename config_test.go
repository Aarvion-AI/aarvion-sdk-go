package aarvion

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func sampleConfig() *Config {
	return &Config{
		AgentID:       "agt_x",
		RuntimeKey:    "aav_dev_abc123def456",
		BundleURL:     "https://cp.aarvion.ai/api/v1/bundles/acme/agt_x/policy.tar.gz",
		SigningSecret: "s3cr3t-signing-key",
		CPURL:         "https://cp.aarvion.ai",
		FormatVersion: 1,
	}
}

func TestSaveThenLoadRoundtrips(t *testing.T) {
	dir := cleanEnv(t)
	p := filepath.Join(dir, ".aarvion.toml")
	if _, err := SaveConfig(sampleConfig(), p); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, sampleConfig()) {
		t.Fatalf("got %+v", got)
	}
}

func TestSavedFileIs0600(t *testing.T) {
	dir := cleanEnv(t)
	p, err := SaveConfig(sampleConfig(), filepath.Join(dir, ".aarvion.toml"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	want := os.FileMode(0o600)
	if runtime.GOOS == "windows" {
		want = 0o666
	}
	if st.Mode().Perm() != want {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
}

func TestLoadMissingRaises(t *testing.T) {
	dir := cleanEnv(t)
	_, err := LoadConfig(filepath.Join(dir, "nope.toml"))
	var ce *ConfigError
	if !errors.As(err, &ce) {
		t.Fatalf("got %v", err)
	}
}

func TestRuntimeKeyEnvResolvesViaCP(t *testing.T) {
	cleanEnv(t)
	seen := map[string]string{}
	old := resolveFn
	resolveFn = func(key, cp string) (*Config, error) {
		seen["key"] = key
		seen["cp_url"] = cp
		return sampleConfig(), nil
	}
	t.Cleanup(func() { resolveFn = old })
	t.Setenv("AARVION_RUNTIME_KEY", "aav_dev_k.s")
	t.Setenv("AARVION_CP_URL", "https://self-hosted-cp")
	got, err := LoadConfig("")
	if err != nil || !reflect.DeepEqual(got, sampleConfig()) {
		t.Fatalf("got %+v %v", got, err)
	}
	if seen["key"] != "aav_dev_k.s" || seen["cp_url"] != "https://self-hosted-cp" {
		t.Fatalf("seen %v", seen)
	}
}

func TestRuntimeKeyUsesDefaultCPURL(t *testing.T) {
	cleanEnv(t)
	seen := ""
	old := resolveFn
	resolveFn = func(key, cp string) (*Config, error) {
		seen = cp
		return sampleConfig(), nil
	}
	t.Cleanup(func() { resolveFn = old })
	t.Setenv("AARVION_RUNTIME_KEY", "aav_dev_k.s")
	if _, err := LoadConfig(""); err != nil {
		t.Fatal(err)
	}
	if seen != DefaultCPURL {
		t.Fatalf("seen %q", seen)
	}
}

func TestConfigEnvOverridePointsPath(t *testing.T) {
	dir := cleanEnv(t)
	p := filepath.Join(dir, "custom.toml")
	if _, err := SaveConfig(sampleConfig(), p); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AARVION_CONFIG", p)
	got, err := LoadConfig("")
	if err != nil || !reflect.DeepEqual(got, sampleConfig()) {
		t.Fatalf("got %+v %v", got, err)
	}
}

func TestRedactedHidesSecrets(t *testing.T) {
	r := sampleConfig().Redacted()
	rk := r["runtime_key"].(string)
	if !strings.HasPrefix(rk, "aav_dev_ab") || strings.Contains(rk, "def456") {
		t.Fatalf("runtime_key %q", rk)
	}
	if r["signing_secret"] == sampleConfig().SigningSecret {
		t.Fatal("signing secret not redacted")
	}
}

func TestSavedTomlBytesMatchTomliW(t *testing.T) {
	dir := cleanEnv(t)
	cfg := sampleConfig()
	cfg.SigningSecret = "s\\back\x07x\u00e9 \"q\" \t\x7f\n"
	cfg.EvaluatorURL = "http://ev:1"
	p := filepath.Join(dir, "c.toml")
	if _, err := SaveConfig(cfg, p); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	want := "agent_id = \"agt_x\"\nruntime_key = \"aav_dev_abc123def456\"\n" +
		"bundle_url = \"https://cp.aarvion.ai/api/v1/bundles/acme/agt_x/policy.tar.gz\"\n" +
		"signing_secret = \"s\\\\back\\u0007x\u00e9 \\\"q\\\" \t\\u007f\\n\"\n" +
		"cp_url = \"https://cp.aarvion.ai\"\nformat_version = 1\nevaluator_url = \"http://ev:1\"\n"
	if string(got) != want {
		t.Fatalf("got\n%q\nwant\n%q", got, want)
	}
	back, err := LoadConfig(p)
	if err != nil || !reflect.DeepEqual(back, cfg) {
		t.Fatalf("roundtrip %+v %v", back, err)
	}
}
