package aarvion

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type timeoutKey struct{}

type deadlineConn struct {
	net.Conn
	mu      sync.Mutex
	timeout time.Duration
}

func (c *deadlineConn) setTimeout(t time.Duration) {
	c.mu.Lock()
	c.timeout = t
	c.mu.Unlock()
}

func (c *deadlineConn) current() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.timeout
}

func (c *deadlineConn) Read(b []byte) (int, error) {
	if t := c.current(); t > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(t))
	}
	return c.Conn.Read(b)
}

func (c *deadlineConn) Write(b []byte) (int, error) {
	if t := c.current(); t > 0 {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(t))
	}
	return c.Conn.Write(b)
}

func timeoutFrom(ctx context.Context, dflt time.Duration) time.Duration {
	if t, ok := ctx.Value(timeoutKey{}).(time.Duration); ok {
		return t
	}
	return dflt
}

func newPyTransport(dflt time.Duration) *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			t := timeoutFrom(ctx, dflt)
			d := &net.Dialer{Timeout: t}
			c, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &deadlineConn{Conn: c, timeout: t}, nil
		},
		TLSHandshakeTimeout: dflt,
		ForceAttemptHTTP2:   false,
		TLSNextProto:        map[string]func(string, *tls.Conn) http.RoundTripper{},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     5 * time.Second,
	}
}

func newPyHTTPClient(timeout time.Duration, followRedirects bool) *http.Client {
	c := &http.Client{Transport: newPyTransport(timeout)}
	if followRedirects {
		c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 20 {
				return pyErrorf("TooManyRedirects", "Exceeded maximum allowed redirects.")
			}
			return nil
		}
	} else {
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return c
}

func pyErrorf(kind, msg string) error { return &pyError{kind: kind, msg: msg} }

type pyResponse struct {
	status   int
	reason   string
	header   http.Header
	body     []byte
	url      string
	location string
}

func checkURLProtocol(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return pyErrorf("InvalidURL", err.Error())
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		if u.Host == "" {
			return pyErrorf("UnsupportedProtocol", "Request URL is missing an 'http://' or 'https://' protocol.")
		}
		return nil
	case "":
		return pyErrorf("UnsupportedProtocol", "Request URL is missing an 'http://' or 'https://' protocol.")
	}
	return pyErrorf("UnsupportedProtocol", fmt.Sprintf("Request URL has an unsupported protocol '%s://'.", strings.ToLower(u.Scheme)))
}

func pyDo(client *http.Client, method, rawURL string, header map[string]string, body []byte, timeout time.Duration) (*pyResponse, error) {
	if err := checkURLProtocol(rawURL); err != nil {
		return nil, err
	}
	ctx := context.WithValue(context.Background(), timeoutKey{}, timeout)
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			conn := info.Conn
			if tc, ok := conn.(*tls.Conn); ok {
				conn = tc.NetConn()
			}
			if dc, ok := conn.(*deadlineConn); ok {
				dc.setTimeout(timeout)
			}
		},
	})
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rd)
	if err != nil {
		return nil, pyErrorf("InvalidURL", err.Error())
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, wrapTransportError(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, wrapTransportError(err)
	}
	reason := strings.TrimSpace(strings.TrimPrefix(resp.Status, strconv.Itoa(resp.StatusCode)))
	finalURL := req.URL.String()
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	return &pyResponse{
		status:   resp.StatusCode,
		reason:   reason,
		header:   resp.Header,
		body:     data,
		url:      finalURL,
		location: resp.Header.Get("Location"),
	}, nil
}

type transportError struct {
	msg string
	err error
}

func (e *transportError) Error() string { return e.msg }

func (e *transportError) Unwrap() error { return e.err }

func wrapTransportError(err error) error {
	var te *transportError
	if errors.As(err, &te) {
		return te
	}
	var pe *pyError
	if errors.As(err, &pe) {
		return pe
	}
	return &transportError{msg: pyTransportMessage(err), err: err}
}

func isHTTPError(err error) bool {
	var te *transportError
	if errors.As(err, &te) {
		return true
	}
	var se *statusError
	if errors.As(err, &se) {
		return true
	}
	var pe *pyError
	if errors.As(err, &pe) {
		return pe.kind == "UnsupportedProtocol" || pe.kind == "TooManyRedirects"
	}
	return false
}

func pyTransportMessage(err error) string {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return "timed out"
	}
	var dns *net.DNSError
	if errors.As(err, &dns) && dns.IsNotFound {
		switch runtime.GOOS {
		case "windows":
			return "[Errno 11001] getaddrinfo failed"
		case "darwin":
			return "[Errno 8] nodename nor servname provided, or not known"
		default:
			return "[Errno -2] Name or service not known"
		}
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		msg := strings.TrimRight(errno.Error(), ". \r\n")
		if runtime.GOOS == "windows" {
			return fmt.Sprintf("[WinError %d] %s", int(errno), msg)
		}
		if msg != "" {
			msg = strings.ToUpper(msg[:1]) + msg[1:]
		}
		return fmt.Sprintf("[Errno %d] %s", int(errno), msg)
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err.Error()
	}
	return err.Error()
}

type statusError struct {
	status int
	msg    string
}

func (e *statusError) Error() string { return e.msg }

func (r *pyResponse) isSuccess() bool { return r.status >= 200 && r.status < 300 }

func (r *pyResponse) raiseForStatus() error {
	if r.isSuccess() {
		return nil
	}
	errorType := map[int]string{1: "Informational response", 3: "Redirect response", 4: "Client error", 5: "Server error"}[r.status/100]
	if errorType == "" {
		errorType = "Invalid status code"
	}
	msg := fmt.Sprintf("%s '%d %s' for url '%s'\nFor more information check: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/%d",
		errorType, r.status, r.reason, r.url, r.status)
	if r.status/100 == 3 && r.location != "" {
		msg += fmt.Sprintf("\nRedirect location: '%s'", r.location)
	}
	return &statusError{status: r.status, msg: msg}
}

func (r *pyResponse) text() string {
	charset := ""
	if ct := r.header.Get("Content-Type"); ct != "" {
		if _, params, err := mime.ParseMediaType(ct); err == nil {
			charset = strings.ToLower(params["charset"])
		}
	}
	switch charset {
	case "iso-8859-1", "latin-1", "latin1", "l1":
		rs := make([]rune, len(r.body))
		for i, c := range r.body {
			rs[i] = rune(c)
		}
		return string(rs)
	case "ascii", "us-ascii":
		var b strings.Builder
		for _, c := range r.body {
			if c < 0x80 {
				b.WriteByte(c)
			} else {
				b.WriteRune(0xfffd)
			}
		}
		return b.String()
	}
	return decodeReplace(r.body)
}
