package aarvion

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type governingTransport struct {
	inner    http.RoundTripper
	governor *Governor
}

func NewTransport(inner http.RoundTripper, governor *Governor) http.RoundTripper {
	if inner == nil {
		inner = http.DefaultTransport
	}
	if _, ok := inner.(*governingTransport); ok {
		return inner
	}
	return &governingTransport{inner: inner, governor: governor}
}

func WrapClient(client *http.Client, governor *Governor) *http.Client {
	if _, ok := client.Transport.(*governingTransport); !ok {
		client.Transport = NewTransport(client.Transport, governor)
	}
	return client
}

func (t *governingTransport) Governor() *Governor { return t.governor }

func (t *governingTransport) Inner() http.RoundTripper { return t.inner }

func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vs := range h {
		lk := strings.ToLower(k)
		joined := strings.Join(vs, ", ")
		if prev, ok := out[lk]; ok {
			out[lk] = prev + ", " + joined
		} else {
			out[lk] = joined
		}
	}
	return out
}

func readRequestBody(req *http.Request) ([]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}
	data, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (t *governingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	original, err := readRequestBody(req)
	if err != nil {
		return nil, err
	}
	newBody, err := t.governor.Process(req.Method, req.URL.String(), flattenHeaders(req.Header), original)
	if err != nil {
		var denied *PolicyDenied
		if errors.As(err, &denied) {
			return deniedResponse(denied, req)
		}
		return nil, err
	}
	out := req.Clone(req.Context())
	if newBody == decodeIgnore(original) {
		if original != nil {
			out.Body = io.NopCloser(bytes.NewReader(original))
			out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(original)), nil }
		}
		return t.inner.RoundTrip(out)
	}
	data := []byte(newBody)
	out.Body = io.NopCloser(bytes.NewReader(data))
	out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }
	out.ContentLength = int64(len(data))
	out.Header.Del("Content-Length")
	out.TransferEncoding = nil
	return t.inner.RoundTrip(out)
}

func deniedPayload(d *PolicyDenied) *jsonObject {
	return obj("error", "policy_denied", "policy", d.PolicyID, "policies", d.PolicyIDs, "reason", d.Reason)
}

func deniedResponse(d *PolicyDenied, req *http.Request) (*http.Response, error) {
	body, err := httpxJSONBody(deniedPayload(d))
	if err != nil {
		return nil, err
	}
	h := http.Header{}
	h.Set("x-policy-violated", d.PolicyID)
	h.Set("x-policy-reason", d.Reason)
	h.Set("x-aarvion-policies-violated", strings.Join(d.PolicyIDs, ","))
	h.Set("Content-Length", strconv.Itoa(len(body)))
	h.Set("Content-Type", "application/json")
	status := strconv.Itoa(d.HTTPStatus)
	if text := http.StatusText(d.HTTPStatus); text != "" {
		status += " " + text
	}
	return &http.Response{
		Status:        status,
		StatusCode:    d.HTTPStatus,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        h,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}, nil
}
