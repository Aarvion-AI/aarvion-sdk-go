package aarvion

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
)

func TestConcurrentWrapReturns403ForDeniedRequest(t *testing.T) {
	var mu sync.Mutex
	sent := 0
	client := mockClient(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		sent++
		mu.Unlock()
		return textResponse(200, ""), nil
	})
	WrapClient(client, denyGovernor())
	var wg sync.WaitGroup
	errs := make(chan string, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Post("https://api-prod.acme.com/x", "", strings.NewReader("data"))
			if err != nil {
				errs <- err.Error()
				return
			}
			var body map[string]any
			json.NewDecoder(resp.Body).Decode(&body)
			resp.Body.Close()
			if resp.StatusCode != 403 || body["reason"] != "no prod deletes" {
				errs <- "bad response"
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	if sent != 0 {
		t.Fatal("sent")
	}
}

func TestConcurrentWrapRewritesRedactedBody(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	client := mockClient(func(r *http.Request) (*http.Response, error) {
		b := readBody(t, r)
		mu.Lock()
		seen = append(seen, b)
		mu.Unlock()
		return textResponse(200, ""), nil
	})
	WrapClient(client, redactGovernor())
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Post("https://api.openai.com/v1/chat", "", strings.NewReader("hi jane@acme.com end"))
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	if len(seen) != 8 {
		t.Fatal(len(seen))
	}
	for _, s := range seen {
		if s != "hi [redacted: email address per data-protection policy] end" {
			t.Fatal(s)
		}
	}
}

type fakeSDK struct {
	client *http.Client
}

func TestWrapReachesSDKUnderlyingHTTPClient(t *testing.T) {
	sdk := &fakeSDK{client: mockClient(func(r *http.Request) (*http.Response, error) { return textResponse(200, ""), nil })}
	returned := WrapClient(sdk.client, NewGovernor(&stubEvaluator{decision: map[string]any{"allowed": true}}, nil, false))
	if returned != sdk.client {
		t.Fatal("not the same client")
	}
	if _, ok := sdk.client.Transport.(*governingTransport); !ok {
		t.Fatal("not governed")
	}
}

func TestWrapIsIdempotent(t *testing.T) {
	client := mockClient(func(r *http.Request) (*http.Response, error) { return textResponse(200, ""), nil })
	gov := NewGovernor(&stubEvaluator{decision: map[string]any{"allowed": true}}, nil, false)
	WrapClient(client, gov)
	t1 := client.Transport
	WrapClient(client, gov)
	if client.Transport != t1 {
		t.Fatal("nested")
	}
}

func TestWrapUnknownObjectRaises(t *testing.T) {
	cleanEnv(t)
	setActive(&Session{Governor: NewGovernor(&stubEvaluator{decision: map[string]any{"allowed": true}}, nil, false)})
	t.Cleanup(func() { setActive(nil) })
	_, err := Wrap(nil)
	if err == nil || err.Error() != "cannot govern NoneType: no httpx client found" {
		t.Fatalf("got %v", err)
	}
}

type captureTransport struct {
	captured *http.Request
	body     string
}

func (c *captureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.captured = r
	if r.Body != nil {
		buf := new(strings.Builder)
		b := make([]byte, 512)
		for {
			n, err := r.Body.Read(b)
			buf.Write(b[:n])
			if err != nil {
				break
			}
		}
		c.body = buf.String()
	}
	return textResponse(200, "ok"), nil
}

func captureClient(gov *Governor) (*http.Client, *captureTransport) {
	ct := &captureTransport{}
	return &http.Client{Transport: NewTransport(ct, gov)}, ct
}

func TestTransportDispatchesToRoundTripper(t *testing.T) {
	ct := &captureTransport{}
	rt := NewTransport(ct, NewGovernor(&stubEvaluator{decision: map[string]any{"allowed": true}}, nil, false))
	if g, ok := rt.(*governingTransport); !ok || g.Inner() != ct {
		t.Fatal("not governed")
	}
}

func TestTransportDenyReturns403BeforeSend(t *testing.T) {
	c, ct := captureClient(denyGovernor())
	resp, err := c.Post("https://api-prod.acme.com/x", "", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != 403 || body["reason"] != "no prod deletes" {
		t.Fatal(resp.StatusCode, body)
	}
	if ct.captured != nil {
		t.Fatal("sent")
	}
}

func TestTransportRedactsBody(t *testing.T) {
	c, ct := captureClient(redactGovernor())
	if _, err := c.Post("https://api.openai.com/v1/chat", "", strings.NewReader("hi jane@acme.com end")); err != nil {
		t.Fatal(err)
	}
	if ct.body != "hi [redacted: email address per data-protection policy] end" {
		t.Fatal(ct.body)
	}
	if ct.captured.ContentLength != int64(len(ct.body)) {
		t.Fatal(ct.captured.ContentLength)
	}
}

func TestTransportCleanPassesThrough(t *testing.T) {
	c, ct := captureClient(NewGovernor(&stubEvaluator{decision: map[string]any{"allowed": true}}, nil, false))
	if _, err := c.Post("https://api.openai.com/v1/chat", "", strings.NewReader("clean payload")); err != nil {
		t.Fatal(err)
	}
	if ct.body != "clean payload" {
		t.Fatal(ct.body)
	}
}

func TestTransportWrapIdempotent(t *testing.T) {
	gov := NewGovernor(&stubEvaluator{decision: map[string]any{"allowed": true}}, nil, false)
	first := NewTransport(&captureTransport{}, gov)
	if NewTransport(first, gov) != first {
		t.Fatal("re-wrapped")
	}
}
