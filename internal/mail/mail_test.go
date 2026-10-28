// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package mail

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"mime"
	"mime/multipart"
	"net"
	netmail "net/mail"
	"strings"
	"sync"
	"testing"
	"time"
)

// A scripted SMTP server, so the STARTTLS refusal is tested against a real
// dialogue rather than against a mock of one. The behaviour under test is
// what this program does when a server does not offer encryption, and a fake
// that was told to say no proves nothing about the code that asks.
type fakeSMTP struct {
	ln        net.Listener
	tlsConf   *tls.Config
	offerTLS  bool
	mu        sync.Mutex
	delivered []string
	rcpts     []string
	sawAuth   bool
	overTLS   bool
}

func certFor(t *testing.T, host string) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{host},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k,
		Leaf: mustParse(t, der)}
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newFakeSMTP(t *testing.T, offerTLS bool) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cert := certFor(t, "localhost")
	f := &fakeSMTP{ln: ln, offerTLS: offerTLS,
		tlsConf: &tls.Config{Certificates: []tls.Certificate{cert},
			MinVersion: tls.VersionTLS12}}
	go f.serve()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeSMTP) addr() string { return f.ln.Addr().String() }

func (f *fakeSMTP) roots(t *testing.T) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(f.tlsConf.Certificates[0].Leaf)
	return pool
}

func (f *fakeSMTP) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

func (f *fakeSMTP) handle(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	say := func(s string) { fmt.Fprintf(conn, "%s\r\n", s) }
	say("220 fake ESMTP")

	var inData bool
	var body strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if inData {
			if line == "." {
				inData = false
				f.mu.Lock()
				f.delivered = append(f.delivered, body.String())
				f.mu.Unlock()
				body.Reset()
				say("250 Ok")
				continue
			}
			body.WriteString(line + "\n")
			continue
		}
		verb, rest, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO", "HELO":
			if f.offerTLS {
				say("250-fake")
				say("250-STARTTLS")
				say("250 AUTH PLAIN")
				continue
			}
			say("250-fake")
			say("250 AUTH PLAIN")
		case "STARTTLS":
			if !f.offerTLS {
				say("502 not implemented")
				continue
			}
			say("220 Ready")
			tconn := tls.Server(conn, f.tlsConf)
			if err := tconn.Handshake(); err != nil {
				return
			}
			f.mu.Lock()
			f.overTLS = true
			f.mu.Unlock()
			conn = tconn
			r = bufio.NewReader(conn)
			say = func(s string) { fmt.Fprintf(conn, "%s\r\n", s) }
		case "AUTH":
			f.mu.Lock()
			f.sawAuth = true
			f.mu.Unlock()
			say("235 Ok")
		case "MAIL":
			say("250 Ok")
		case "RCPT":
			_, addr, _ := strings.Cut(rest, ":")
			f.mu.Lock()
			f.rcpts = append(f.rcpts, strings.Trim(addr, "<>"))
			f.mu.Unlock()
			say("250 Ok")
		case "DATA":
			inData = true
			say("354 End with .")
		case "QUIT":
			say("221 Bye")
			return
		default:
			say("250 Ok")
		}
	}
}

func mailerFor(t *testing.T, f *fakeSMTP) Mailer {
	t.Helper()
	return Mailer{
		Host: f.addr(), From: "security@example.test",
		Username: "u", Password: "p",
		At: func() time.Time { return time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC) },
		TLS: &tls.Config{ServerName: "localhost", RootCAs: f.roots(t),
			MinVersion: tls.VersionTLS12},
	}
}

// The line most mail libraries make a warning.
func TestMailIsNotSentToAServerThatWillNotEncrypt(t *testing.T) {
	f := newFakeSMTP(t, false)
	m := mailerFor(t, f)
	err := m.Send("someone@example.test", "An account was taken over", "body")
	if err == nil {
		t.Fatal("a message was sent over a plaintext connection")
	}
	if !strings.Contains(err.Error(), "STARTTLS") || !strings.Contains(err.Error(), "no flag to permit that") {
		t.Errorf("the refusal does not say what is wrong, or invites a search for the flag: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.delivered) != 0 {
		t.Fatal("something was delivered anyway")
	}
	if f.sawAuth {
		t.Fatal("credentials were sent over a plaintext connection")
	}
}

func TestMailGoesOverTLSToExactlyOneRecipient(t *testing.T) {
	f := newFakeSMTP(t, true)
	m := mailerFor(t, f)
	if err := m.Send("someone@example.test", "Quilzo: a sign-in was stepped up", "body"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.overTLS {
		t.Fatal("the message crossed the network unencrypted")
	}
	if !f.sawAuth {
		t.Error("the credentials were never offered")
	}
	if len(f.rcpts) != 1 || f.rcpts[0] != "someone@example.test" {
		t.Fatalf("recipients were %v", f.rcpts)
	}
	if len(f.delivered) != 1 {
		t.Fatalf("%d messages delivered", len(f.delivered))
	}
	got := f.delivered[0]
	for _, forbidden := range []string{"Bcc:", "Cc:", "List-Unsubscribe:"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("the message carries a %s header", forbidden)
		}
	}
	if !strings.Contains(got, "Auto-Submitted: auto-generated") {
		t.Error("no Auto-Submitted header, so vacation responders will reply")
	}
}

func TestTheBodySurvivesBeingAnyLanguage(t *testing.T) {
	body := strings.Repeat("Ihre Daten waren betroffen. 日本語もです。\n", 8)
	m := Message{From: "security@example.test", To: "one@example.test",
		Subject: "Zugriff auf Sicherungsspeicher — Maßnahmen", Body: body,
		Date: time.Now(), ID: "x@example.test"}
	raw, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	_, encoded, found := strings.Cut(text, "\r\n\r\n")
	if !found {
		t.Fatal("no body")
	}
	decoded, err := base64.StdEncoding.DecodeString(
		strings.ReplaceAll(strings.TrimSpace(encoded), "\r\n", ""))
	if err != nil {
		t.Fatalf("the body does not decode: %v", err)
	}
	if string(decoded) != body {
		t.Error("the body did not survive the round trip")
	}
	if strings.Contains(text, "Subject: Zugriff") {
		t.Error("the subject is not header-encoded")
	}
}

// A subject and an address pass the header checks before anything is
// dialled.
func TestAMessageCannotInjectAHeader(t *testing.T) {
	dialled := false
	m := Mailer{Host: "relay.example.com:587", From: "security@acme.com",
		Dial: func(string, string) (net.Conn, error) {
			dialled = true
			return nil, fmt.Errorf("no network in this test")
		}}
	for _, c := range []struct{ to, subject string }{
		{"sam@acme.com", "Tasks\r\nBcc: everyone@acme.com"},
		{"sam@acme.com\r\nBcc: everyone@acme.com", "Tasks"},
		{"", "Tasks"},
	} {
		if err := m.Send(c.to, c.subject, "body"); err == nil {
			t.Errorf("%q / %q was sent", c.to, c.subject)
		}
	}
	if dialled {
		t.Error("the relay was dialled for a message that should have been refused")
	}
}

// An issue of a newsletter: the sender's name, the list it is from, the
// one-click unsubscribe of RFC 8058, and the same words as a page.
func TestANewsletterCarriesItsListAndItsWayOut(t *testing.T) {
	m := Message{From: "news@crumb.example", To: "ann@example.test", FromName: "Crumb, the bakery",
		Subject: "October", Body: "Rye is back.", HTML: "<p>Rye is back.</p>",
		ListID: "Crumb <newsletter.crumb.example>", Unsubscribe: "https://crumb.example/newsletter/leave?s=a&t=b",
		Date: time.Now(), ID: "x@crumb.example"}
	raw, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := netmail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	h := msg.Header
	from, err := netmail.ParseAddress(h.Get("From"))
	if err != nil || from.Name != "Crumb, the bakery" || from.Address != "news@crumb.example" {
		t.Errorf("From: %q %v", h.Get("From"), err)
	}
	if h.Get("List-Unsubscribe") != "<https://crumb.example/newsletter/leave?s=a&t=b>" ||
		h.Get("List-Unsubscribe-Post") != "List-Unsubscribe=One-Click" || h.Get("List-Id") != m.ListID {
		t.Errorf("list headers: %v", h)
	}
	mt, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil || mt != "multipart/alternative" {
		t.Fatalf("content type %q: %v", h.Get("Content-Type"), err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	var kinds, bodies []string
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		b, _ := io.ReadAll(base64.NewDecoder(base64.StdEncoding, p))
		kinds = append(kinds, p.Header.Get("Content-Type"))
		bodies = append(bodies, string(b))
	}
	if len(kinds) != 2 || !strings.HasPrefix(kinds[0], "text/plain") || !strings.HasPrefix(kinds[1], "text/html") ||
		bodies[0] != m.Body || bodies[1] != m.HTML {
		t.Fatalf("parts: %v %q", kinds, bodies)
	}
	m.Unsubscribe = "http://crumb.example/leave"
	if _, err := m.Bytes(); err == nil {
		t.Error("a one-click unsubscribe over plain http was accepted; RFC 8058 requires https")
	}
	for _, bad := range []Message{
		{From: "a@b.example", To: "c@d.example", FromName: "Crumb\r\nBcc: everyone@example.test"},
		{From: "a@b.example", To: "c@d.example", ListID: "x\nBcc: y@example.test"},
		{From: "a@b.example", To: "c@d.example", Unsubscribe: "https://x.example/\r\nBcc: y@example.test"},
	} {
		if _, err := bad.Bytes(); err == nil {
			t.Errorf("a header was injected through %+v", bad)
		}
	}
}
