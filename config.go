package aarvion

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

const (
	ConfigFilename = ".aarvion.toml"
	DefaultAPIURL  = "https://api.aarvion.ai"
	DefaultCPURL   = "https://cp.aarvion.ai"
)

type Config struct {
	AgentID       string
	RuntimeKey    string
	BundleURL     string
	SigningSecret string
	CPURL         string
	FormatVersion int
	EvaluatorURL  string
	Hold          any
}

func NewConfig(agentID, runtimeKey, bundleURL, signingSecret, cpURL string) *Config {
	return &Config{
		AgentID:       agentID,
		RuntimeKey:    runtimeKey,
		BundleURL:     bundleURL,
		SigningSecret: signingSecret,
		CPURL:         cpURL,
		FormatVersion: 1,
	}
}

func (c *Config) asObject() *jsonObject {
	o := obj(
		"agent_id", c.AgentID,
		"runtime_key", c.RuntimeKey,
		"bundle_url", c.BundleURL,
		"signing_secret", c.SigningSecret,
		"cp_url", c.CPURL,
		"format_version", int64(c.FormatVersion),
	)
	if c.EvaluatorURL != "" {
		o.set("evaluator_url", c.EvaluatorURL)
	} else {
		o.set("evaluator_url", nil)
	}
	return o
}

func (c *Config) Redacted() map[string]any {
	d := c.asObject().plain()
	for _, k := range []string{"runtime_key", "signing_secret"} {
		v, _ := d[k].(string)
		if v == "" {
			d[k] = ""
		} else {
			d[k] = pyPrefix(v, 10) + "\u2026"
		}
	}
	return d
}

var resolveFn = func(runtimeKey, cpURL string) (*Config, error) { return Resolve(runtimeKey, cpURL, nil) }

func ConfigPath() (string, error) {
	if override := os.Getenv("AARVION_CONFIG"); override != "" {
		return override, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return pyJoinPath(cwd, ConfigFilename), nil
}

func LoadConfig(path string) (*Config, error) {
	if runtimeKey := os.Getenv("AARVION_RUNTIME_KEY"); runtimeKey != "" {
		cpURL, ok := os.LookupEnv("AARVION_CP_URL")
		if !ok {
			cpURL = DefaultCPURL
		}
		return resolveFn(runtimeKey, cpURL)
	}
	p := path
	if p == "" {
		var err error
		if p, err = ConfigPath(); err != nil {
			return nil, err
		}
	}
	shown := pyPath(p)
	if _, err := os.Stat(p); err != nil {
		return nil, newConfigError(fmt.Sprintf("no Aarvion config at %s - run `aarvion init`, or set "+
			"AARVION_RUNTIME_KEY (and AARVION_CP_URL for self-hosted)", shown), nil)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	text := universalNewlines(decodeReplace(raw))
	data := map[string]any{}
	if _, err := toml.Decode(text, &data); err != nil {
		return nil, newConfigError(fmt.Sprintf("malformed config at %s: %s", shown, tomlErrorMessage(err)), err)
	}
	cfg := &Config{}
	fields := []struct {
		key string
		dst *string
	}{
		{"agent_id", &cfg.AgentID},
		{"runtime_key", &cfg.RuntimeKey},
		{"bundle_url", &cfg.BundleURL},
		{"signing_secret", &cfg.SigningSecret},
		{"cp_url", &cfg.CPURL},
	}
	for _, f := range fields {
		v, ok := data[f.key]
		if !ok {
			return nil, newConfigError(fmt.Sprintf("config at %s is missing %s", shown, pyRepr(f.key)), nil)
		}
		*f.dst = tomlValueString(v)
	}
	fv, err := pyInt(tomlValue(dictGet(data, "format_version", int64(1))))
	if err != nil {
		return nil, err
	}
	cfg.FormatVersion = int(fv)
	if ev, ok := data["evaluator_url"]; ok && ev != nil {
		cfg.EvaluatorURL = tomlValueString(ev)
	}
	if hold, ok := data["hold"]; ok && hold != nil {
		cfg.Hold = tomlValue(hold)
	}
	return cfg, nil
}

func universalNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\r", "\n")
}

func tomlValue(v any) any {
	switch x := v.(type) {
	case []map[string]any:
		out := make([]any, len(x))
		for i, m := range x {
			out[i] = m
		}
		return out
	}
	return v
}

func tomlValueString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case time.Time:
		frac := ""
		if us := x.Nanosecond() / 1000; us != 0 {
			frac = fmt.Sprintf(".%06d", us)
		}
		switch x.Location().String() {
		case "date-local":
			return x.Format("2006-01-02")
		case "time-local":
			return x.Format("15:04:05") + frac
		case "datetime-local":
			return x.Format("2006-01-02 15:04:05") + frac
		}
		return x.Format("2006-01-02 15:04:05") + frac + x.Format("-07:00")
	}
	return pyStr(tomlValue(v))
}

var tomllibMessages = [][2]string{
	{"Expected value but found", "Invalid value"},
	{"Unexpected EOF; expected value", "Invalid value"},
	{"Expected '.' or '=', but got", "Expected '=' after a key in a key/value pair"},
	{"Strings cannot contain newlines", "Illegal character '\\n'"},
	{"Key '", "Cannot overwrite a value"},
	{"Expected '.' or ']' to end table name", "Expected ']' at the end of a table declaration"},
	{"Expected a top-level item to end with a newline", "Expected newline or end of document after a statement"},
	{"Unexpected '=': key name appears blank", "Invalid statement"},
}

func tomlErrorMessage(err error) string {
	var pe toml.ParseError
	if errors.As(err, &pe) {
		msg := pe.Message
		if msg != "" {
			msg = strings.ToUpper(msg[:1]) + msg[1:]
		}
		where := fmt.Sprintf("(at line %d, column %d)", pe.Position.Line, pe.Position.Col)
		for _, m := range tomllibMessages {
			if strings.HasPrefix(msg, m[0]) || (strings.HasPrefix(m[0], "Key '") && strings.HasSuffix(msg, "has already been defined.")) {
				msg = m[1]
				if m[0] == "Unexpected EOF; expected value" {
					where = "(at end of document)"
				}
				break
			}
		}
		return msg + " " + where
	}
	return err.Error()
}

func SaveConfig(cfg *Config, path string) (string, error) {
	p := path
	if p == "" {
		var err error
		if p, err = ConfigPath(); err != nil {
			return "", err
		}
	}
	var b strings.Builder
	o := cfg.asObject()
	for _, k := range o.keys {
		v := o.vals[k]
		if v == nil {
			continue
		}
		b.WriteString(k)
		b.WriteString(" = ")
		switch x := v.(type) {
		case string:
			b.WriteString(tomlString(x))
		default:
			b.WriteString(pyStr(x))
		}
		b.WriteByte('\n')
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o666); err != nil {
		return "", err
	}
	if err := os.Chmod(p, 0o600); err != nil {
		return "", err
	}
	return pyPath(p), nil
}

func tomlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\b':
			b.WriteString(`\b`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		default:
			if (r < 0x20 && r != '\t') || r == 0x7f {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
