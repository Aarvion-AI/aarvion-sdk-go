package aarvion

import (
	"fmt"
	"net/http"
	"time"
)

const (
	DefaultEnforceTimeout = 3 * time.Second
	DefaultMonitorTimeout = 5 * time.Second
)

type Turn struct {
	SessionID   string
	TurnNumber  int
	UserMsg     string
	BotResponse string
	Intent      *string
	SourceData  map[string]any
}

func turnObject(t Turn) *jsonObject {
	d := obj(
		"session_id", t.SessionID,
		"turn_number", int64(t.TurnNumber),
		"user_msg", t.UserMsg,
		"bot_response", t.BotResponse,
	)
	if t.Intent != nil {
		d.set("intent", *t.Intent)
	}
	if t.SourceData != nil {
		d.set("source_data", t.SourceData)
	}
	return d
}

func EnforceTurn(evaluatorURL string, turn Turn, client *http.Client) (map[string]any, error) {
	return enforceTurn(evaluatorURL, turn, DefaultEnforceTimeout, client)
}

func enforceTurn(evaluatorURL string, turn Turn, timeout time.Duration, client *http.Client) (map[string]any, error) {
	own := client == nil
	c := clientOrDefault(client, timeout)
	defer closeIfOwned(own, c)
	body, err := httpxJSONBody(turnObject(turn))
	if err != nil {
		return nil, err
	}
	resp, err := pyDo(c, "POST", pyRStripChars(evaluatorURL, "/")+"/enforce",
		map[string]string{"Content-Type": "application/json"}, body, timeout)
	if err != nil {
		return nil, err
	}
	if err := resp.raiseForStatus(); err != nil {
		return nil, err
	}
	data, err := pyLoadsPlain(resp.body)
	if err != nil {
		return nil, err
	}
	m, ok := data.(map[string]any)
	if !ok {
		return nil, pyValueError(fmt.Sprintf("evaluator /enforce returned non-object JSON: %s", pyTypeName(data)))
	}
	return m, nil
}

func MonitorTurn(evaluatorURL string, turn Turn, client *http.Client) error {
	return monitorTurn(evaluatorURL, turn, DefaultMonitorTimeout, client)
}

func monitorTurn(evaluatorURL string, turn Turn, timeout time.Duration, client *http.Client) error {
	own := client == nil
	c := clientOrDefault(client, timeout)
	defer closeIfOwned(own, c)
	body, err := httpxJSONBody(turnObject(turn))
	if err != nil {
		return err
	}
	_, err = pyDo(c, "POST", pyRStripChars(evaluatorURL, "/")+"/evaluate",
		map[string]string{"Content-Type": "application/json"}, body, timeout)
	if err != nil && !isHTTPError(err) {
		return err
	}
	return nil
}
