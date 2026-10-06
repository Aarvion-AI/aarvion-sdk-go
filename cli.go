package aarvion

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type cliWriter struct {
	w io.Writer
}

func (c cliWriter) print(s string) {
	if isWindows() {
		s = strings.ReplaceAll(s, "\n", "\r\n")
	}
	_, _ = io.WriteString(c.w, s)
}

func (c cliWriter) println(s string) { c.print(s + "\n") }

func StateDir(agentID string) string {
	return pyPath(expandUser("~/.aarvion/" + agentID))
}

func cliStateDir(agentID, override string) string {
	if override != "" {
		return pyPath(override)
	}
	return StateDir(agentID)
}

func defaultAgentName() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	base := filepath.Base(cwd)
	if base == string(filepath.Separator) || base == "." || strings.HasSuffix(base, ":\\") {
		return ""
	}
	return base
}

func cliReadBody(spec string) (string, error) {
	if spec == "" {
		return "", nil
	}
	if strings.HasPrefix(spec, "@") {
		raw, err := os.ReadFile(spec[1:])
		if err != nil {
			return "", osErrorToPy(err, spec[1:])
		}
		return universalNewlines(decodeReplace(raw)), nil
	}
	return spec, nil
}

func osErrorToPy(err error, name string) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return pyErrorf("FileNotFoundError", fmt.Sprintf("[Errno 2] No such file or directory: %s", pyRepr(name)))
	case errors.Is(err, fs.ErrPermission):
		return pyErrorf("PermissionError", fmt.Sprintf("[Errno 13] Permission denied: %s", pyRepr(name)))
	}
	return err
}

func formatDecision(d map[string]any) (string, error) {
	headers, err := dictOrEmpty(d["headers"])
	if !pyTruthy(dictGet(d, "allowed", true)) {
		if err != nil {
			return "", err
		}
		line := "DENY   " + pyStr(dictGet(headers, "x-policy-violated", "?")) + "   " + pyStr(dictGet(headers, "x-policy-reason", ""))
		return pyRStrip(line), nil
	}
	if err != nil {
		return "", err
	}
	if r := headers["x-aarvion-redactions"]; pyTruthy(r) {
		return "ALLOW  (redact: " + pyStr(r) + ")", nil
	}
	return "ALLOW", nil
}

type cliRun struct {
	in  io.Reader
	out cliWriter
	err cliWriter
}

func (c *cliRun) cmdInit(args map[string]string) (int, error) {
	apiKey := args["--api-key"]
	if apiKey == "" {
		apiKey = os.Getenv("AARVION_API_KEY")
	}
	if apiKey == "" {
		c.out.print("Org dev key (aav_\u2026): ")
		line, rerr := bufio.NewReader(c.in).ReadString('\n')
		if rerr != nil && line == "" {
			return 0, pyErrorf("EOFError", "EOF when reading a line")
		}
		apiKey = pyStrip(strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"))
	}
	if apiKey == "" {
		c.err.print("error: an api key is required\n")
		return 2, nil
	}
	agent := args["--agent"]
	if agent == "" {
		agent = defaultAgentName()
	}
	cfg, err := Exchange(apiKey, agent, args["--api-url"], nil)
	if err != nil {
		return 0, err
	}
	path, err := SaveConfig(cfg, "")
	if err != nil {
		return 0, err
	}
	c.out.println("\u2713 agent '" + cfg.AgentID + "' connected \u2014 config written to " + path)
	c.out.println("\nAdd to your agent:\n")
	c.out.println("    import aarvion")
	c.out.println("    aarvion.init()")
	c.out.println("    client = aarvion.wrap(openai.OpenAI())\n")
	return 0, nil
}

func (c *cliRun) cmdWhoami() (int, error) {
	cfg, err := LoadConfig("")
	if err != nil {
		return 0, err
	}
	r := cfg.Redacted()
	c.out.println("agent_id:       " + pyStr(r["agent_id"]))
	c.out.println("cp_url:         " + pyStr(r["cp_url"]))
	c.out.println("bundle_url:     " + pyStr(r["bundle_url"]))
	c.out.println("runtime_key:    " + pyStr(r["runtime_key"]))
	c.out.println("format_version: " + pyStr(r["format_version"]))
	return 0, nil
}

func (c *cliRun) cmdCheck(args map[string]string) (int, error) {
	cfg, err := LoadConfig("")
	if err != nil {
		return 0, err
	}
	body, err := cliReadBody(args["--body"])
	if err != nil {
		return 0, err
	}
	method, ok := args["--method"]
	if !ok {
		method = "POST"
	}
	path, ok := args["--path"]
	if !ok {
		path = "/"
	}
	input := BuildExtAuthzInput(method, args["--host"], path, map[string]string{}, body)
	rt, err := NewOpaRuntime(cfg, 0, "")
	if err != nil {
		return 0, err
	}
	if err := rt.Start(DefaultReadyTimeout); err != nil {
		return 0, err
	}
	decision, evalErr := rt.Evaluate(input)
	if err := rt.Stop(); err != nil && evalErr == nil {
		return 0, err
	}
	if evalErr != nil {
		return 0, evalErr
	}
	line, err := formatDecision(decision)
	if err != nil {
		return 0, err
	}
	c.out.println(line)
	if pyTruthy(dictGet(decision, "allowed", true)) {
		return 0, nil
	}
	return 3, nil
}

func (c *cliRun) cmdStatus(args map[string]string) (int, error) {
	cfg, err := LoadConfig("")
	if err != nil {
		return 0, err
	}
	db := pyJoinPath(cliStateDir(cfg.AgentID, args["--state-dir"]), "provenance.db")
	c.out.println("agent:        " + cfg.AgentID)
	c.out.println("cp:           " + cfg.CPURL)
	if _, err := os.Stat(db); err == nil {
		tenant, err := TenantFromBundleURL(cfg.BundleURL)
		if err != nil {
			return 0, err
		}
		rec, err := NewRecorder(cfg, db, tenant, DefaultAutoflushInterval)
		if err != nil {
			return 0, err
		}
		seq, err := rec.ChainSeq()
		if err != nil {
			return 0, err
		}
		c.out.println(fmt.Sprintf("chain seq:    %d", seq))
		n, err := rec.PendingCount()
		if err != nil {
			return 0, err
		}
		c.out.println(fmt.Sprintf("pending push: %d", n))
		if err := rec.Close(); err != nil {
			return 0, err
		}
	} else {
		c.out.println("chain seq:    0 (no decisions recorded yet)")
		c.out.println("pending push: 0")
	}
	return 0, nil
}

func CLI(argv []string, stdin io.Reader, stdout, stderr io.Writer) int {
	c := &cliRun{in: stdin, out: cliWriter{stdout}, err: cliWriter{stderr}}
	args, ex := parseCLIArgs(argv)
	if ex != nil {
		c.out.print(ex.stdout)
		c.err.print(ex.stderr)
		return ex.code
	}
	var code int
	var err error
	switch args.cmd {
	case "init":
		code, err = c.cmdInit(args.values)
	case "whoami":
		code, err = c.cmdWhoami()
	case "check":
		code, err = c.cmdCheck(args.values)
	default:
		code, err = c.cmdStatus(args.values)
	}
	if err != nil {
		if IsAarvionError(err) {
			c.err.print("error: " + err.Error() + "\n")
			return 1
		}
		c.err.print("Traceback (most recent call last):\n" + pyErrorName(err) + ": " + err.Error() + "\n")
		return 1
	}
	return code
}
