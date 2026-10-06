package aarvion

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func cliConfig() *Config {
	return NewConfig("agt_x", "aav_dev_abc.secret", "https://cp/api/v1/bundles/acme/agt_x/policy.tar.gz", "s", "https://cp")
}

func runCLI(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := CLI(args, strings.NewReader(""), &out, &errb)
	return code, strings.ReplaceAll(out.String(), "\r\n", "\n"), strings.ReplaceAll(errb.String(), "\r\n", "\n")
}

func TestReadBodyLiteralAndFile(t *testing.T) {
	dir := cleanEnv(t)
	if got, _ := cliReadBody("hello"); got != "hello" {
		t.Fatal(got)
	}
	if got, _ := cliReadBody(""); got != "" {
		t.Fatal(got)
	}
	f := filepath.Join(dir, "b.json")
	os.WriteFile(f, []byte(`{"x":1}`), 0o644)
	if got, err := cliReadBody("@" + f); err != nil || got != `{"x":1}` {
		t.Fatalf("got %q %v", got, err)
	}
}

func TestFormatDecision(t *testing.T) {
	if got, _ := formatDecision(map[string]any{"allowed": true}); got != "ALLOW" {
		t.Fatal(got)
	}
	if got, _ := formatDecision(map[string]any{"allowed": true, "headers": map[string]any{"x-aarvion-redactions": "email address"}}); got != "ALLOW  (redact: email address)" {
		t.Fatal(got)
	}
	got, _ := formatDecision(map[string]any{"allowed": false, "headers": map[string]any{"x-policy-violated": "p.v1", "x-policy-reason": "no"}})
	if !strings.HasPrefix(got, "DENY") || !strings.Contains(got, "p.v1") || !strings.Contains(got, "no") {
		t.Fatal(got)
	}
	if got, _ := formatDecision(map[string]any{"allowed": false}); got != "DENY   ?" {
		t.Fatalf("%q", got)
	}
}

func TestStatusEmpty(t *testing.T) {
	dir := cleanEnv(t)
	SaveConfig(cliConfig(), "")
	code, out, _ := runCLI("status", "--state-dir", filepath.Join(dir, "state"))
	if code != 0 || !strings.Contains(out, "agent:        agt_x") || !strings.Contains(out, "no decisions recorded yet") {
		t.Fatal(code, out)
	}
}

func TestStatusWithRecordedDecisions(t *testing.T) {
	dir := cleanEnv(t)
	SaveConfig(cliConfig(), "")
	state := filepath.Join(dir, "state")
	os.Mkdir(state, 0o777)
	rec, err := NewRecorder(cliConfig(), filepath.Join(state, "provenance.db"), "acme", DefaultAutoflushInterval)
	if err != nil {
		t.Fatal(err)
	}
	rec.Record(RecordInput{Method: "POST", Path: "/a", Host: "h", Decision: "allow"})
	rec.Record(RecordInput{Method: "POST", Path: "/b", Host: "h", Decision: "deny"})
	rec.Close()
	code, out, _ := runCLI("status", "--state-dir", state)
	if code != 0 || !strings.Contains(out, "chain seq:    2") || !strings.Contains(out, "pending push: 2") {
		t.Fatal(code, out)
	}
}

func TestArgparseErrorsMatchPython(t *testing.T) {
	cleanEnv(t)
	code, out, errs := runCLI("bogus")
	if code != 2 || out != "" || errs != "usage: aarvion [-h] {init,whoami,check,status} ...\n"+
		"aarvion: error: argument cmd: invalid choice: 'bogus' (choose from 'init', 'whoami', 'check', 'status')\n" {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	code, _, errs = runCLI("check", "--h", "x")
	if code != 2 || !strings.HasSuffix(errs, "aarvion check: error: ambiguous option: --h could match --help, --host\n") {
		t.Fatalf("%d %q", code, errs)
	}
	code, out, _ = runCLI("-hx")
	if code != 0 || out != mainHelp {
		t.Fatalf("%d %q", code, out)
	}
}

func TestWhoamiAndMissingConfig(t *testing.T) {
	cleanEnv(t)
	code, _, errs := runCLI("whoami")
	if code != 1 || !strings.HasPrefix(errs, "error: no Aarvion config at ") {
		t.Fatalf("%d %q", code, errs)
	}
	SaveConfig(cliConfig(), "")
	code, out, _ := runCLI("whoami")
	want := "agent_id:       agt_x\ncp_url:         https://cp\nbundle_url:     https://cp/api/v1/bundles/acme/agt_x/policy.tar.gz\n" +
		"runtime_key:    aav_dev_ab\u2026\nformat_version: 1\n"
	if code != 0 || out != want {
		t.Fatalf("%d %q", code, out)
	}
}
