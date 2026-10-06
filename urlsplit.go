package aarvion

import (
	"strings"
)

type urlParts struct {
	scheme   string
	netloc   string
	path     string
	query    string
	fragment string
}

const schemeChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-."

func urlSplit(url string) (urlParts, error) {
	var clean strings.Builder
	for i := 0; i < len(url); i++ {
		c := url[i]
		if c != '\t' && c != '\r' && c != '\n' {
			clean.WriteByte(c)
		}
	}
	u := strings.TrimLeftFunc(clean.String(), func(r rune) bool { return r <= ' ' })
	var p urlParts
	if i := strings.IndexByte(u, ':'); i > 0 && isASCIIAlpha(u[0]) {
		ok := true
		for k := 0; k < i; k++ {
			if !strings.ContainsRune(schemeChars, rune(u[k])) {
				ok = false
				break
			}
		}
		if ok {
			p.scheme = strings.ToLower(u[:i])
			u = u[i+1:]
		}
	}
	if strings.HasPrefix(u, "//") {
		delim := len(u)
		for _, c := range "/?#" {
			if w := strings.IndexRune(u[2:], c); w >= 0 && w+2 < delim {
				delim = w + 2
			}
		}
		p.netloc = u[2:delim]
		u = u[delim:]
		open := strings.Contains(p.netloc, "[")
		cls := strings.Contains(p.netloc, "]")
		if open != cls {
			return p, pyValueError("Invalid IPv6 URL")
		}
	}
	if h := strings.IndexByte(u, '#'); h >= 0 {
		p.fragment = u[h+1:]
		u = u[:h]
	}
	if q := strings.IndexByte(u, '?'); q >= 0 {
		p.query = u[q+1:]
		u = u[:q]
	}
	p.path = u
	return p, nil
}

func isASCIIAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func (p urlParts) hostname() (string, bool) {
	netloc := p.netloc
	hostinfo := netloc
	if at := strings.LastIndexByte(netloc, '@'); at >= 0 {
		hostinfo = netloc[at+1:]
	}
	var hostname string
	if br := strings.IndexByte(hostinfo, '['); br >= 0 {
		bracketed := hostinfo[br+1:]
		if end := strings.IndexByte(bracketed, ']'); end >= 0 {
			hostname = bracketed[:end]
		} else {
			hostname = bracketed
		}
	} else if colon := strings.IndexByte(hostinfo, ':'); colon >= 0 {
		hostname = hostinfo[:colon]
	} else {
		hostname = hostinfo
	}
	if hostname == "" {
		return "", false
	}
	if pct := strings.IndexByte(hostname, '%'); pct >= 0 {
		return strings.ToLower(hostname[:pct]) + hostname[pct:], true
	}
	return strings.ToLower(hostname), true
}
