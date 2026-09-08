// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Nothing decides Secure from r.TLS on its own any more.
//
// Every one of the eight places this program sets a cookie said
// `Secure: r.TLS != nil`. That is right when this process terminates TLS and
// wrong in the deployment almost everybody has: a reverse proxy speaking HTTPS
// to the browser and plain HTTP to this. The session cookie carries the API
// token, so without Secure a browser will send a working credential over a
// plain-HTTP request to the same host.
//
// A source walk rather than eight response assertions, because the defect was
// that the decision was made in eight places. One place can be reasoned about;
// eight will diverge, and the ninth cookie added will copy whichever line was
// nearest.
func TestNoCookieDecidesSecureByItself(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Skip("no working directory")
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Skip("no sources")
	}
	// r.TLS on its own is the defect; r.TLS with the proxy check beside it is
	// the fix. So this looks for the first without the second, which is also
	// why the comparison is left written out at each call site rather than
	// hidden in a method — see behindTLSProxy.
	bare := regexp.MustCompile(`Secure:\s*r\.TLS[^|\n]*$`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, rerr := os.ReadFile(f)
		if rerr != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			trimmed := strings.TrimSpace(line)
			// Prose about the rule is not a breach of it. settings.go
			// explains why the comparison stays at the call site, and quoting
			// the wrong form in order to explain it is not the wrong form.
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			if !bare.MatchString(strings.TrimRight(line, " ,")) {
				continue
			}
			t.Errorf("%s decides Secure from r.TLS alone: %q. That is false "+
				"behind a TLS-terminating proxy — it needs "+
				"|| s.behindTLSProxy() beside it",
				filepath.Base(f), strings.TrimSpace(line))
		}
	}
}

// Over TLS the cookie is Secure without any configuration.
func TestSecureOverDirectTLS(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest(http.MethodGet, "https://x.test/", nil)
	r.TLS = &tls.ConnectionState{}
	if !s.secureCookie(r) {
		t.Error("a request that arrived over TLS should get a Secure cookie")
	}
}

// On plain HTTP with nothing configured it is not, because a Secure cookie
// over plain HTTP is dropped by the browser and sign-in would stop working.
// The admin is on loopback by default, which is that case.
func TestNotSecureOnPlainHTTPByDefault(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/", nil)
	if s.secureCookie(r) {
		t.Error("a plain-HTTP request got a Secure cookie, which the browser " +
			"will drop — that breaks sign-in rather than protecting it")
	}
}

// An unwritable or absent configuration is not a reason to mark a cookie
// Secure, and not a reason to fail the request either.
func TestSecureCookieToleratesNoSettings(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest(http.MethodGet, "http://x.test/", nil)
	if s.secureCookie(r) {
		t.Error("with no Settings wired the answer should be no")
	}
}
