// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package notify

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
	"math/big"
	"net"
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
		At: func() time.Time { return now },
		TLS: &tls.Config{ServerName: "localhost", RootCAs: f.roots(t),
			MinVersion: tls.VersionTLS12},
	}
}

// The line most mail libraries make a warning.
func TestABreachNoticeIsNotSentToAServerThatWillNotEncrypt(t *testing.T) {
	f := newFakeSMTP(t, false)
	m := mailerFor(t, f)
	err := m.Send(breach(), Delivery{Channel: Email,
		Address: "someone@example.test", Key: "k"})
	if err == nil {
		t.Fatal("a breach notice was sent over a plaintext connection")
	}
	if !strings.Contains(err.Error(), "STARTTLS") {
		t.Errorf("the refusal does not say what is wrong: %v", err)
	}
	if !strings.Contains(err.Error(), "no flag to permit that") {
		t.Errorf("the refusal invites somebody to look for the flag: %v", err)
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
	if err := m.Send(breach(), Delivery{Channel: Email,
		Address: "someone@example.test", Key: "k"}); err != nil {
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
	for _, forbidden := range []string{"Bcc:", "Cc:"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("the message carries a %s header", forbidden)
		}
	}
	if !strings.Contains(got, "Auto-Submitted: auto-generated") {
		t.Error("no Auto-Submitted header, so vacation responders will reply")
	}
}

// An unsubscribe link on an Article 34 notice offers a choice the law does
// not give, in the one message where the offer is most likely to be taken.
func TestOnlyADeclinableNoticeCarriesAnUnsubscribeHeader(t *testing.T) {
	f := newFakeSMTP(t, true)
	m := mailerFor(t, f)
	m.Unsubscribe = "mailto:unsubscribe@example.test"

	if err := m.Send(breach(), Delivery{Channel: Email,
		Address: "a@example.test", Key: "k1"}); err != nil {
		t.Fatal(err)
	}
	change := breach()
	change.Kind = Change
	change.Mitigated, change.Public = "", ""
	change.Affected = nil
	change.ID = Ident(change.Kind, change.Subject, change.Aware)
	if err := m.Send(change, Delivery{Channel: Email,
		Address: "b@example.test", Key: "k2"}); err != nil {
		t.Fatal(err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.delivered) != 2 {
		t.Fatalf("%d messages", len(f.delivered))
	}
	if strings.Contains(f.delivered[0], "List-Unsubscribe") {
		t.Error("the breach notice offers an unsubscribe link")
	}
	if !strings.Contains(f.delivered[1], "List-Unsubscribe") {
		t.Error("the product change does not offer one")
	}
}

func TestALineBreakInASubjectCannotAddAHeader(t *testing.T) {
	n := breach()
	n.Subject = "Breach\r\nBcc: everyone@example.test"
	m, err := NewMessage(n, "security@example.test", "one@example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Bytes(); err == nil {
		t.Fatal("a subject containing a line break rendered a message")
	}
}

func TestTheBodySurvivesBeingAnyLanguage(t *testing.T) {
	n := breach()
	n.Subject = "Zugriff auf Sicherungsspeicher — Maßnahmen"
	n.Body = strings.Repeat("Ihre Daten waren betroffen. 日本語もです。\n", 8)
	m, err := NewMessage(n, "security@example.test", "one@example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "Content-Transfer-Encoding: base64") {
		t.Fatal("the body is not encoded")
	}
	_, encoded, found := strings.Cut(text, "\r\n\r\n")
	if !found {
		t.Fatal("no body")
	}
	decoded, err := base64.StdEncoding.DecodeString(
		strings.ReplaceAll(strings.TrimSpace(encoded), "\r\n", ""))
	if err != nil {
		t.Fatalf("the body does not decode: %v", err)
	}
	if string(decoded) != n.Body {
		t.Error("the body did not survive the round trip")
	}
	if strings.Contains(text, "Subject: Zugriff") {
		t.Error("the subject is not header-encoded, so it will arrive as " +
			"mojibake in the one message somebody has to read carefully")
	}
}

func TestAMessageNeedsSomewhereToComeFromAndSomewhereToGo(t *testing.T) {
	if _, err := NewMessage(breach(), "", "a@example.test", now); err == nil {
		t.Error("a message with no sender was rendered")
	}
	if _, err := NewMessage(breach(), "a@example.test", "", now); err == nil {
		t.Error("a message with no recipient was rendered")
	}
}

// A channel with no sender is a person who was not told. Quietly falling
// back to another channel records them as told, and the record is what the
// retry consults — so they are never told afterwards either.
func TestAChannelWithNoSenderIsAnErrorAndNotAFallback(t *testing.T) {
	var reached bool
	b := ByChannel{InApp: senderFunc(func(Notice, Delivery) error {
		reached = true
		return nil
	})}
	err := b.Send(breach(), Delivery{Channel: Email,
		Address: "a@example.test", To: who(1), Key: "k"})
	if err == nil {
		t.Fatal("an email delivery was accepted with no mailer configured")
	}
	if reached {
		t.Fatal("it was quietly delivered in the app instead")
	}
	if !strings.Contains(err.Error(), "have not been told") {
		t.Errorf("the error does not say what the consequence is: %v", err)
	}
}

type senderFunc func(Notice, Delivery) error

func (f senderFunc) Send(n Notice, d Delivery) error { return f(n, d) }
