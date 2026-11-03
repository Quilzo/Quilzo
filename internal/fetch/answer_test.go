// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package fetch

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// -- answers from a real server ------------------------------------------------
//
// The tests below talk to a server over TLS through the production
// transport, which trusts the system's roots and nothing else. A stand-in for
// the transport is what let the bug the first of them is about through: every
// caller's test fabricated a 200, and the real client reported 0.
//
// Go reads the system's roots from SSL_CERT_FILE on Linux and the BSDs, so
// TestMain makes an authority of its own and names it there before anything
// is verified. macOS and Windows verify through the platform and do not read
// it, so those tests skip there; CI runs Linux.

// servedTLS is the certificate the test servers present, for the made-up
// hosts the tests ask for.
var servedTLS *tls.Config

func TestMain(m *testing.M) {
	dir, err := trustOwnAuthority()
	if err != nil {
		panic("fetch: cannot make the test authority: " + err.Error())
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func trustOwnAuthority() (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "quilzo fetch tests"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"answer.test", "inbox.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pair, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp("", "fetch-test-ca-")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), certPEM, 0o600); err != nil {
		return dir, err
	}
	os.Setenv("SSL_CERT_FILE", filepath.Join(dir, "ca.pem"))
	servedTLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	return dir, nil
}

// serve starts a TLS server the production transport trusts, and returns
// its port.
func serve(t *testing.T, h http.Handler) string {
	t.Helper()
	switch runtime.GOOS {
	case "darwin", "ios", "windows":
		t.Skip("this platform verifies certificates itself and does not read SSL_CERT_FILE")
	}
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = servedTLS
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// toServer is the client For builds, with the one difference that lets it
// reach the test server: every name is this machine, and this machine is
// allowed. The transport, the redirects and the limits are production's.
func toServer(purpose string) *Client {
	c := For(purpose)
	c.Reach = Anywhere
	c.Resolver = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	return c
}

// Every method reports the status that came back.
//
// Get and the methods built on it, PostForm and PostWithHeaders built their
// Result by hand and left the status out, so a 200 was reported as 0 and a
// caller that checked for 200 refused every answer that succeeded: a site
// imported by its address read no page, a replica pulling over HTTP read no
// ref, a calendar or SAML metadata by address was never read, and a staff
// notice that reached Slack was recorded as failed. Each caller's test stood
// in for the client with a 200 of its own, which is why nothing failed.
func TestEveryMethodReportsTheStatusThatCameBack(t *testing.T) {
	port := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Answer", "here")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	u := "https://answer.test:" + port + "/doc"
	c := toServer("import")
	ctx := context.Background()
	for _, k := range []struct {
		name string
		do   func() (*Result, error)
	}{
		{"Get", func() (*Result, error) { return c.Get(ctx, u) }},
		{"GetAccepting", func() (*Result, error) { return c.GetAccepting(ctx, u, "application/json") }},
		{"GetWithToken", func() (*Result, error) { return c.GetWithToken(ctx, u, "a-token") }},
		{"GetSigned", func() (*Result, error) { return c.GetSigned(ctx, u, "application/json", nil) }},
		{"Post", func() (*Result, error) { return c.Post(ctx, u, []byte("{}"), "application/json") }},
		{"PostWithHeaders", func() (*Result, error) { return c.PostWithHeaders(ctx, u, []byte("{}"), nil) }},
		{"PostForm", func() (*Result, error) { return c.PostForm(ctx, u, url.Values{"a": {"b"}}, "", "") }},
		{"Do", func() (*Result, error) { return c.Do(ctx, http.MethodGet, u, nil, nil) }},
		{"PostSigned", func() (*Result, error) { return c.PostSigned(ctx, u, []byte("{}"), nil) }},
	} {
		res, err := k.do()
		if err != nil {
			t.Errorf("%s: %v", k.name, err)
			continue
		}
		if res.Status != http.StatusOK {
			t.Errorf("%s: the server answered 200 and the result says %d", k.name, res.Status)
		}
		if res.Header.Get("X-Answer") != "here" {
			t.Errorf("%s: the answer's headers are not in the result", k.name)
		}
		if res.ContentType != "application/json" {
			t.Errorf("%s: the content type is %q", k.name, res.ContentType)
		}
	}
}

// A POST that succeeds with no body to send back says 204, which is how
// Discord answers a webhook, or 202, which is how a queue answers. Both are
// success, and Post refused both as if the receiver had said no: a staff
// notice to Discord failed every time it was delivered. Anything outside 2xx
// is still an error that carries what the receiver said.
func TestAPostIsAnsweredByAnySuccess(t *testing.T) {
	port := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/204":
			w.WriteHeader(http.StatusNoContent)
		case "/202":
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "the payload has no text")
		}
	}))
	c := toServer("webhook")
	ctx := context.Background()
	for _, code := range []int{http.StatusNoContent, http.StatusAccepted} {
		res, err := c.Post(ctx, "https://answer.test:"+port+"/"+strconv.Itoa(code), []byte("{}"), "application/json")
		if err != nil {
			t.Errorf("%d: %v", code, err)
			continue
		}
		if res.Status != code {
			t.Errorf("%d was reported as %d", code, res.Status)
		}
	}
	_, err := c.Post(ctx, "https://answer.test:"+port+"/400", []byte("{}"), "application/json")
	if err == nil || !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), "the payload has no text") {
		t.Errorf("a refusal: %v", err)
	}
}
