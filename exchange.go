package aarvion

import (
	"fmt"
	"net/http"
	"time"
)

const (
	SessionPath = "/api/sdk/sessions"
	ResolvePath = "/api/v1/sdk/resolve"
)

const sessionTimeout = 15 * time.Second

func clientOrDefault(client *http.Client, timeout time.Duration) *http.Client {
	if client != nil {
		return client
	}
	return newPyHTTPClient(timeout, false)
}

func closeIfOwned(own bool, c *http.Client) {
	if own {
		c.CloseIdleConnections()
	}
}

func Resolve(runtimeKey, cpURL string, client *http.Client) (*Config, error) {
	base := pyRStripChars(cpURL, "/")
	own := client == nil
	c := clientOrDefault(client, sessionTimeout)
	resp, err := pyDo(c, "GET", base+ResolvePath, map[string]string{"Authorization": "Bearer " + runtimeKey}, nil, sessionTimeout)
	closeIfOwned(own, c)
	if err != nil {
		if isHTTPError(err) {
			return nil, newSessionError(fmt.Sprintf("could not reach %s%s: %s", base, ResolvePath, err.Error()), err)
		}
		return nil, err
	}
	if resp.status == 401 || resp.status == 403 {
		return nil, newSessionError("runtime key rejected \u2014 check AARVION_RUNTIME_KEY", nil)
	}
	if resp.status >= 400 {
		return nil, newSessionError(fmt.Sprintf("key resolve failed (%d): %s", resp.status, resp.text()), nil)
	}
	cfg, err := func() (*Config, error) {
		raw, err := pyLoadsPlain(resp.body)
		if err != nil {
			return nil, err
		}
		body, err := subscriptable(raw)
		if err != nil {
			return nil, err
		}
		agentID, err := requireKey(body, "agent_id")
		if err != nil {
			return nil, err
		}
		tenant, err := requireKey(body, "tenant")
		if err != nil {
			return nil, err
		}
		secret, err := requireKey(body, "signing_secret")
		if err != nil {
			return nil, err
		}
		fv, err := pyInt(dictGet(body, "format_version", int64(1)))
		if err != nil {
			return nil, err
		}
		return &Config{
			AgentID:       pyStr(agentID),
			RuntimeKey:    runtimeKey,
			BundleURL:     fmt.Sprintf("%s/api/v1/bundles/%s/%s/policy.tar.gz", base, pyStr(tenant), pyStr(agentID)),
			SigningSecret: pyStr(secret),
			CPURL:         base,
			FormatVersion: int(fv),
		}, nil
	}()
	if err != nil {
		if isPyError(err, "KeyError", "ValueError") {
			return nil, newSessionError("unexpected resolve response shape: "+err.Error(), err)
		}
		return nil, err
	}
	return cfg, nil
}

func Exchange(apiKey, agent, apiURL string, client *http.Client) (*Config, error) {
	base := apiURL
	if base == "" {
		base = DefaultAPIURL
	}
	base = pyRStripChars(base, "/")
	own := client == nil
	c := clientOrDefault(client, sessionTimeout)
	payload, err := httpxJSONBody(obj("agent_name", agent))
	if err != nil {
		return nil, err
	}
	resp, err := pyDo(c, "POST", base+SessionPath, map[string]string{
		"Authorization": "Bearer " + apiKey,
		"Content-Type":  "application/json",
	}, payload, sessionTimeout)
	closeIfOwned(own, c)
	if err != nil {
		if isHTTPError(err) {
			return nil, newSessionError(fmt.Sprintf("could not reach %s%s: %s", base, SessionPath, err.Error()), err)
		}
		return nil, err
	}
	if resp.status == 401 {
		return nil, newSessionError("api key rejected (401) \u2014 check the key and tenant", nil)
	}
	if resp.status >= 400 {
		return nil, newSessionError(fmt.Sprintf("session exchange failed (%d): %s", resp.status, resp.text()), nil)
	}
	cfg, err := func() (*Config, error) {
		raw, err := pyLoadsPlain(resp.body)
		if err != nil {
			return nil, err
		}
		body, err := subscriptable(raw)
		if err != nil {
			return nil, err
		}
		vals := make([]string, 5)
		for i, k := range []string{"agent_id", "runtime_key", "bundle_url", "bundle_signing_secret", "cp_url"} {
			v, err := requireKey(body, k)
			if err != nil {
				return nil, err
			}
			vals[i] = pyStr(v)
		}
		fv, err := pyInt(dictGet(body, "format_version", int64(1)))
		if err != nil {
			return nil, err
		}
		return &Config{
			AgentID:       vals[0],
			RuntimeKey:    vals[1],
			BundleURL:     vals[2],
			SigningSecret: vals[3],
			CPURL:         vals[4],
			FormatVersion: int(fv),
		}, nil
	}()
	if err != nil {
		if isPyError(err, "KeyError", "ValueError") {
			return nil, newSessionError("unexpected session response shape: "+err.Error(), err)
		}
		return nil, err
	}
	return cfg, nil
}

func subscriptable(v any) (map[string]any, error) {
	switch x := v.(type) {
	case map[string]any:
		return x, nil
	case []any:
		return nil, pyTypeError("list indices must be integers or slices, not str")
	case string:
		return nil, pyTypeError("string indices must be integers, not 'str'")
	}
	return nil, pyTypeError(fmt.Sprintf("'%s' object is not subscriptable", pyTypeName(v)))
}

func requireKey(m map[string]any, k string) (any, error) {
	v, ok := m[k]
	if !ok {
		return nil, pyKeyError(k)
	}
	return v, nil
}
