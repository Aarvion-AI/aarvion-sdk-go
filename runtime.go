package aarvion

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	Entrypoint = "envoy/authz/allow"
	OPAVersion = "1.17.1"
	OPABase    = "https://openpolicyagent.org/downloads/v" + OPAVersion
)

type opaAsset struct {
	Name   string
	SHA256 string
}

var OPAAssets = map[string]opaAsset{
	"darwin-arm64": {"opa_darwin_arm64_static", "9d43153a802b5befd3f1c4f76b301d135aaf8e2153a4de921a9426e0ccc00eb8"},
	"darwin-x64":   {"opa_darwin_amd64", "a94988f2a8eecad499e9f3c287074802c90b7f05a6c6e7e33742a0a538186282"},
	"linux-x64":    {"opa_linux_amd64_static", "3d4bb88482958d990351ec5d2f7558509992776bc473bc1b78d86d76cb993ca3"},
	"linux-arm64":  {"opa_linux_arm64_static", "2733c6cb81ce26b5b0d42efc3f55860ce0e3470e7077d795d4b219a54052db74"},
	"win32-x64":    {"opa_windows_amd64.exe", "459ad6f8fc9da7a9fb569cc364255517ea820e7c05a222763b752ce921b16a55"},
}

const (
	opaClientTimeout    = 10 * time.Second
	opaDownloadTimeout  = 120 * time.Second
	DefaultReadyTimeout = 30 * time.Second
)

func denyUndefined() map[string]any {
	return map[string]any{
		"allowed":     false,
		"http_status": int64(403),
		"headers":     map[string]any{"x-policy-reason": "policy undefined"},
	}
}

func opaConfigObject(cfg *Config, persist bool) (*jsonObject, error) {
	parts, err := urlSplit(cfg.BundleURL)
	if err != nil {
		return nil, err
	}
	resource := pyLStripChars(parts.path, "/")
	bundle := obj("policy", obj(
		"service", "aarvion-cp",
		"resource", resource,
		"signing", obj("keyid", "aarvion"),
		"polling", obj("min_delay_seconds", int64(60), "max_delay_seconds", int64(120)),
		"persist", persist,
	))
	return obj(
		"services", obj("aarvion-cp", obj(
			"url", cfg.CPURL,
			"headers", obj("Authorization", "Bearer "+cfg.RuntimeKey),
		)),
		"keys", obj("aarvion", obj("algorithm", "HS256", "key", cfg.SigningSecret)),
		"bundles", bundle,
	), nil
}

func BuildOpaConfig(cfg *Config, persistDir string) (map[string]any, error) {
	o, err := opaConfigObject(cfg, persistDir != "")
	if err != nil {
		return nil, err
	}
	return o.plain(), nil
}

func platformKey() string {
	osName := "linux"
	switch runtime.GOOS {
	case "windows":
		osName = "win32"
	case "darwin":
		osName = "darwin"
	}
	arch := runtime.GOARCH
	switch arch {
	case "amd64":
		arch = "x64"
	case "arm64":
		arch = "arm64"
	case "386":
		if runtime.GOOS == "windows" {
			arch = "x86"
		} else {
			arch = "i686"
		}
	case "arm":
		arch = "armv7l"
	case "loong64":
		arch = "loongarch64"
	case "mips64le":
		arch = "mips64"
	}
	return osName + "-" + arch
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

var downloadOpaFn = downloadOpa

func downloadOpa() (string, error) {
	key := platformKey()
	meta, ok := OPAAssets[key]
	if !ok {
		return "", newAarvionError(fmt.Sprintf("no pinned OPA build for %s - install OPA manually or set AARVION_OPA_PATH", key))
	}
	exe := ""
	if isWindows() {
		exe = ".exe"
	}
	destDir := expandUser("~/.aarvion/opa/" + OPAVersion)
	dest := pyJoinPath(destDir, "opa"+exe)
	if st, err := os.Stat(dest); err == nil && st.Mode().IsRegular() {
		if data, err := os.ReadFile(dest); err == nil && sha256Hex(data) == meta.SHA256 {
			return pyPath(dest), nil
		}
	}
	if err := os.MkdirAll(destDir, 0o777); err != nil {
		return "", err
	}
	url := OPABase + "/" + meta.Name
	client := newPyHTTPClient(opaDownloadTimeout, true)
	resp, err := pyDo(client, "GET", url, nil, nil, opaDownloadTimeout)
	client.CloseIdleConnections()
	if err == nil {
		err = resp.raiseForStatus()
	}
	if err != nil {
		if isHTTPError(err) {
			return "", &AarvionError{Msg: fmt.Sprintf("OPA download failed from %s: %s", url, err.Error()), Err: err}
		}
		return "", err
	}
	got := sha256Hex(resp.body)
	if got != meta.SHA256 {
		return "", newAarvionError(fmt.Sprintf("OPA checksum mismatch for %s (expected %s, got %s) - refusing to run an unverified binary",
			meta.Name, meta.SHA256, got))
	}
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, resp.body, 0o666); err != nil {
		return "", err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return "", err
	}
	return pyPath(dest), nil
}

var whichFn = pyWhich

func ResolveOpaBinary() (string, error) {
	if override := os.Getenv("AARVION_OPA_PATH"); override != "" {
		st, err := os.Stat(override)
		if err != nil || !st.Mode().IsRegular() {
			return "", newAarvionError("AARVION_OPA_PATH does not point to a file: " + override)
		}
		return override, nil
	}
	if found := whichFn("opa"); found != "" {
		return found, nil
	}
	if os.Getenv("AARVION_OPA_AUTODOWNLOAD") == "0" {
		return "", newAarvionError("opa binary not found and auto-download disabled - install OPA or set AARVION_OPA_PATH")
	}
	return downloadOpaFn()
}

const winDefaultPathext = ".COM;.EXE;.BAT;.CMD;.VBS;.JS;.WS;.MSC"

func pyWhich(cmd string) string {
	sep := ":"
	if isWindows() {
		sep = ";"
	}
	path, ok := os.LookupEnv("PATH")
	if !ok {
		if isWindows() {
			path = ".;C:\\bin"
		} else if runtime.GOOS == "darwin" {
			path = "/usr/bin:/bin:/usr/sbin:/sbin"
		} else {
			path = "/bin:/usr/bin"
		}
	}
	if path == "" {
		return ""
	}
	dirs := strings.Split(path, sep)
	var files []string
	if isWindows() {
		if _, set := os.LookupEnv("NoDefaultCurrentDirectoryInExePath"); !set {
			dirs = append([]string{"."}, dirs...)
		}
		src := os.Getenv("PATHEXT")
		if src == "" {
			src = winDefaultPathext
		}
		var exts []string
		for _, e := range strings.Split(src, ";") {
			if e != "" {
				exts = append(exts, strings.TrimRight(e, "."))
			}
		}
		for _, e := range exts {
			files = append(files, cmd+e)
		}
		norm := strings.ToUpper(cmd)
		for _, e := range exts {
			if strings.HasSuffix(norm, strings.ToUpper(e)) {
				files = append([]string{cmd}, files...)
				break
			}
		}
	} else {
		files = []string{cmd}
	}
	seen := map[string]bool{}
	for _, dir := range dirs {
		normdir := dir
		if isWindows() {
			normdir = strings.ToLower(strings.ReplaceAll(dir, "/", "\\"))
		}
		if seen[normdir] {
			continue
		}
		seen[normdir] = true
		for _, f := range files {
			name := pyJoinPath(dir, f)
			st, err := os.Stat(name)
			if err != nil || st.IsDir() {
				continue
			}
			if !isWindows() && st.Mode().Perm()&0o111 == 0 {
				continue
			}
			return name
		}
	}
	return ""
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

type opaProcess interface {
	exited() bool
	terminate()
	kill()
	wait(timeout time.Duration) bool
}

type execProcess struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func (p *execProcess) exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

func (p *execProcess) terminate() {
	if isWindows() {
		_ = p.cmd.Process.Kill()
		return
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
}

func (p *execProcess) kill() { _ = p.cmd.Process.Kill() }

func (p *execProcess) wait(timeout time.Duration) bool {
	select {
	case <-p.done:
		return true
	case <-time.After(timeout):
		return false
	}
}

var startProcessFn = func(argv []string) (opaProcess, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &execProcess{cmd: cmd, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(p.done)
	}()
	return p, nil
}

type OpaRuntime struct {
	config     *Config
	persistDir string
	mu         sync.Mutex
	port       int
	proc       opaProcess
	cfgPath    string
	baseURL    string
	closed     atomic.Bool
	client     *http.Client
	healthyFn  func(bool) bool
	binaryFn   func() (string, error)
}

func NewOpaRuntime(cfg *Config, port int, persistDir string) (*OpaRuntime, error) {
	rt := &OpaRuntime{config: cfg, persistDir: persistDir, client: newPyHTTPClient(opaClientTimeout, false)}
	if port != 0 {
		rt.port = port
	} else if envPort := os.Getenv("AARVION_OPA_PORT"); envPort != "" {
		p, err := pyInt(envPort)
		if err != nil {
			return nil, err
		}
		rt.port = int(p)
	}
	rt.binaryFn = ResolveOpaBinary
	return rt, nil
}

func (rt *OpaRuntime) Port() int { return rt.port }

func (rt *OpaRuntime) BaseURL() string { return rt.baseURL }

func (rt *OpaRuntime) Start(readyTimeout time.Duration) error {
	if readyTimeout <= 0 {
		readyTimeout = DefaultReadyTimeout
	}
	binary, err := rt.binaryFn()
	if err != nil {
		return err
	}
	if rt.port == 0 {
		p, err := freePort()
		if err != nil {
			return err
		}
		rt.port = p
	}
	rt.baseURL = "http://127.0.0.1:" + strconv.Itoa(rt.port)
	doc, err := opaConfigObject(rt.config, rt.persistDir != "")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(pyTempDir(), "aarvion-opa-*.json")
	if err != nil {
		return err
	}
	rt.cfgPath = f.Name()
	text, err := pyDumps(doc, jsonDefault)
	if err == nil {
		_, err = f.WriteString(text)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	proc, err := startProcessFn([]string{binary, "run", "--server", "--addr", "127.0.0.1:" + strconv.Itoa(rt.port),
		"--config-file", rt.cfgPath})
	if err != nil {
		return err
	}
	rt.proc = proc
	deadline := time.Now().Add(readyTimeout)
	for time.Now().Before(deadline) {
		if proc.exited() {
			return newAarvionError(fmt.Sprintf("opa exited during startup (is port %d already in use?)", rt.port))
		}
		if rt.Healthy(true) {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err := rt.Stop(); err != nil {
		return err
	}
	return newAarvionError("opa bundle did not activate in time (signature or pull failure?)")
}

func (rt *OpaRuntime) Healthy(bundles bool) bool {
	if rt.healthyFn != nil {
		return rt.healthyFn(bundles)
	}
	if rt.closed.Load() {
		return false
	}
	u := rt.baseURL + "/health"
	if bundles {
		u += "?bundles=true"
	}
	resp, err := pyDo(rt.client, "GET", u, nil, nil, opaClientTimeout)
	if err != nil {
		return false
	}
	return resp.status == 200
}

func (rt *OpaRuntime) Evaluate(input map[string]any) (map[string]any, error) {
	if rt.closed.Load() {
		return nil, pyRuntimeError("Cannot send a request, as the client has been closed.")
	}
	body, err := httpxJSONBody(obj("input", orderedInput(input)))
	if err != nil {
		return nil, err
	}
	u := rt.baseURL + "/v1/data/" + Entrypoint
	resp, err := pyDo(rt.client, "POST", u, map[string]string{"Content-Type": "application/json"}, body, opaClientTimeout)
	if err != nil {
		return nil, err
	}
	if err := resp.raiseForStatus(); err != nil {
		return nil, err
	}
	doc, err := pyLoadsPlain(resp.body)
	if err != nil {
		return nil, err
	}
	m, ok := doc.(map[string]any)
	if !ok {
		return nil, pyAttributeError(fmt.Sprintf("'%s' object has no attribute 'get'", pyTypeName(doc)))
	}
	if result, ok := m["result"].(map[string]any); ok {
		return result, nil
	}
	return denyUndefined(), nil
}

func (rt *OpaRuntime) ParkCatalog() map[string]any {
	result, _ := rt.data("config/park/catalog").(map[string]any)
	return result
}

func (rt *OpaRuntime) ParkHoldSeconds() any {
	return rt.data("config/park/hold_seconds")
}

func (rt *OpaRuntime) data(path string) any {
	if rt.closed.Load() || rt.baseURL == "" {
		return nil
	}
	resp, err := pyDo(rt.client, "GET", rt.baseURL+"/v1/data/"+path, nil, nil, opaClientTimeout)
	if err != nil || resp.status != 200 {
		return nil
	}
	doc, err := pyLoadsPlain(resp.body)
	if err != nil {
		return nil
	}
	return asMap(doc)["result"]
}

func (rt *OpaRuntime) Stop() error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.proc != nil {
		rt.proc.terminate()
		if !rt.proc.wait(5 * time.Second) {
			rt.proc.kill()
		}
		rt.proc = nil
	}
	if rt.cfgPath != "" {
		if _, err := os.Stat(rt.cfgPath); err == nil {
			if err := os.Remove(rt.cfgPath); err != nil {
				return err
			}
			rt.cfgPath = ""
		}
	}
	rt.closed.Store(true)
	rt.client.CloseIdleConnections()
	return nil
}

var httpFieldOrder = []string{"method", "host", "path", "headers", "body"}

func orderedInput(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	o := newJSONObject()
	isHTTP := true
	for _, k := range httpFieldOrder {
		if _, ok := m[k]; !ok {
			isHTTP = false
		}
	}
	if isHTTP {
		for _, k := range httpFieldOrder {
			o.set(k, orderedInput(m[k]))
		}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, done := o.vals[k]; !done {
			o.set(k, orderedInput(m[k]))
		}
	}
	return o
}

func pyTempDir() string {
	for _, env := range []string{"TMPDIR", "TEMP", "TMP"} {
		if d := os.Getenv(env); d != "" {
			if st, err := os.Stat(d); err == nil && st.IsDir() {
				return d
			}
		}
	}
	return os.TempDir()
}
