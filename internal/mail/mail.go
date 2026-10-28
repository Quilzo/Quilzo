// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package mail sends one plain message to one person over SMTP: the
// security contact told that the shield acted or a sign-in was stepped up,
// an agent's sponsor told it is about to stop.
//
// # No option to send it in the clear
//
// STARTTLS is required and there is no flag to disable it. Opportunistic
// STARTTLS — try it, carry on without it if the server does not offer it —
// is the default in most mail libraries, and it is how a message saying
// which account was taken over gets read by whoever runs a relay in the
// middle. Credentials are sent only after the connection is encrypted,
// which is the other half of the same rule.
//
// # One recipient, and headers that cannot be added to
//
// A Message has one To and no Cc or Bcc field to fill in. Every header
// value is refused if it holds a line break, because a newline in a
// subject ends that header and starts another, and the one an attacker
// picks is Bcc.
//
// # A newsletter is still one message to one person
//
// An issue of a site's newsletter is sent the same way: one message to each
// address, never a list in Bcc. What it adds are fields, not headers: the
// sender's name, an HTML alternative to the text, the list it belongs to
// (RFC 2919), and the address that ends a subscription in one step (RFC
// 8058), each checked like every other value.
//
// # Accepted is not delivered
//
// An SMTP server accepting a message means it took responsibility for it,
// not that anybody read it. What is recorded is what was accepted.
package mail

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"mime"
	"net"
	netmail "net/mail"
	"net/smtp"
	"strings"
	"time"
)

// Message is one message to exactly one person.
type Message struct {
	From    string
	To      string
	Subject string
	Body    string
	Date    time.Time
	// ID is the Message-ID, without angle brackets.
	ID string
	// FromName is the sender's name, shown beside its address.
	FromName string
	// HTML is the same message as a page, sent as the alternative to Body,
	// which every reader can show.
	HTML string
	// ListID names the list a message was sent to (RFC 2919), such as
	// "Bakery news <news.bakery.example>", so a reader can file and filter it.
	ListID string
	// Unsubscribe is the https address that ends the subscription with one
	// POST (RFC 8058): List-Unsubscribe and List-Unsubscribe-Post.
	Unsubscribe string
}

// headerSafe refuses a value that could inject a header.
func headerSafe(name, value string) error {
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf(
			"the %s contains a line break. In a mail header that ends this "+
				"header and starts another one, and the one an attacker "+
				"picks is Bcc", name)
	}
	return nil
}

// Bytes renders the message as RFC 5322.
func (m Message) Bytes() ([]byte, error) {
	for _, f := range []struct{ name, value string }{
		{"From address", m.From}, {"To address", m.To},
		{"subject", m.Subject}, {"Message-ID", m.ID},
		{"sender's name", m.FromName}, {"List-Id", m.ListID},
		{"unsubscribe address", m.Unsubscribe},
	} {
		if err := headerSafe(f.name, f.value); err != nil {
			return nil, err
		}
	}
	var b strings.Builder
	write := func(k, v string) { fmt.Fprintf(&b, "%s: %s\r\n", k, v) }
	from := m.From
	if m.FromName != "" {
		// Quoted and encoded as the name needs: a comma or a non-ASCII
		// letter in a business's name must not change what the header says.
		from = (&netmail.Address{Name: m.FromName, Address: m.From}).String()
	}
	write("From", from)
	write("To", m.To)
	// Encoded, so a subject with a name or a currency symbol in it does not
	// arrive as mojibake.
	write("Subject", mime.QEncoding.Encode("utf-8", m.Subject))
	write("Date", m.Date.Format(time.RFC1123Z))
	write("Message-ID", "<"+m.ID+">")
	// RFC 3834: machine-generated, so a vacation responder does not reply.
	write("Auto-Submitted", "auto-generated")
	if m.ListID != "" {
		write("List-Id", m.ListID)
	}
	if m.Unsubscribe != "" {
		if !strings.HasPrefix(m.Unsubscribe, "https://") {
			return nil, fmt.Errorf("the unsubscribe address must be https (RFC 8058), not %q", m.Unsubscribe)
		}
		write("List-Unsubscribe", "<"+m.Unsubscribe+">")
		// One click: a mail reader POSTs this to the address above, and
		// the subscription ends without a page to find or a form to fill.
		write("List-Unsubscribe-Post", "List-Unsubscribe=One-Click")
	}
	write("MIME-Version", "1.0")
	if m.HTML == "" {
		write("Content-Type", "text/plain; charset=utf-8")
		// Base64 rather than quoted-printable: the body is prose in any
		// language, and a transfer encoding that mangles one is not worth
		// the saved bytes.
		write("Content-Transfer-Encoding", "base64")
		b.WriteString("\r\n")
		writeBase64(&b, m.Body)
		return []byte(b.String()), nil
	}
	// Text first and the page last: a reader shows the last part it can.
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	boundary := "quilzo-" + hex.EncodeToString(raw)
	write("Content-Type", `multipart/alternative; boundary="`+boundary+`"`)
	b.WriteString("\r\n")
	for _, part := range []struct{ kind, body string }{
		{"text/plain", m.Body}, {"text/html", m.HTML},
	} {
		b.WriteString("--" + boundary + "\r\n")
		write("Content-Type", part.kind+"; charset=utf-8")
		write("Content-Transfer-Encoding", "base64")
		b.WriteString("\r\n")
		writeBase64(&b, part.body)
	}
	b.WriteString("--" + boundary + "--\r\n")
	return []byte(b.String()), nil
}

// writeBase64 writes a body encoded, in lines of 76.
func writeBase64(b *strings.Builder, body string) {
	enc := base64.StdEncoding.EncodeToString([]byte(body))
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
}

// Mailer sends over SMTP.
type Mailer struct {
	// Host is host:port. Port 465 is treated as implicit TLS; anything else
	// requires STARTTLS.
	Host string
	// From is the envelope and header sender.
	From string
	// Username and Password are optional, and are only ever sent over an
	// encrypted connection.
	Username string
	Password string
	// At is the clock, injectable for tests.
	At func() time.Time
	// Dial is injectable for tests. Nil means net.Dial.
	Dial func(network, address string) (net.Conn, error)
	// TLS is the configuration for the encrypted connection. Nil means a
	// verified connection to Host's name, which is what it should be.
	TLS *tls.Config
}

func (m Mailer) now() time.Time {
	if m.At != nil {
		return m.At()
	}
	return time.Now().UTC()
}

// Send delivers one message to one address: TLS required, credentials only
// after it, exactly one recipient, headers checked for injection before
// anything is dialled.
func (m Mailer) Send(to, subject, body string) error {
	return m.Deliver(Message{To: to, Subject: subject, Body: body})
}

// Deliver sends a message composed by the caller, from this relay's
// address, dated and identified here: the same rules as Send, for a
// message with a sender's name, an HTML part or a list's headers.
func (m Mailer) Deliver(msg Message) error {
	if strings.TrimSpace(m.From) == "" || strings.TrimSpace(msg.To) == "" {
		return fmt.Errorf("mail needs a From and a To address")
	}
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	domain := "localhost"
	if _, d, ok := strings.Cut(m.From, "@"); ok && d != "" {
		domain = d
	}
	msg.From, msg.Date, msg.ID = m.From, m.now(), hex.EncodeToString(raw)+"@"+domain
	b, err := msg.Bytes()
	if err != nil {
		return err
	}
	return m.deliver(msg.To, b)
}

func (m Mailer) deliver(to string, body []byte) error {
	host, port, err := net.SplitHostPort(m.Host)
	if err != nil {
		return fmt.Errorf("%q is not host:port: %w", m.Host, err)
	}
	dial := m.Dial
	if dial == nil {
		dial = net.Dial
	}
	conf := m.TLS
	if conf == nil {
		conf = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	}

	conn, err := dial("tcp", m.Host)
	if err != nil {
		return err
	}
	if port == "465" {
		// Implicit TLS, the submission port that never speaks plaintext.
		conn = tls.Client(conn, conf)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()

	if port != "465" {
		ok, _ := c.Extension("STARTTLS")
		if !ok {
			// Refused rather than carried on with. This is the line that
			// most mail libraries make a warning.
			return fmt.Errorf(
				"%s does not offer STARTTLS, so this message would cross the "+
					"network in the clear. There is no flag to permit that", m.Host)
		}
		if err := c.StartTLS(conf); err != nil {
			return err
		}
	}
	if m.Username != "" {
		// After TLS, never before.
		if err := c.Auth(smtp.PlainAuth("", m.Username, m.Password, host)); err != nil {
			return err
		}
	}
	if err := c.Mail(m.From); err != nil {
		return err
	}
	// Exactly one. There is no loop here and no list parameter to pass one.
	if err := c.Rcpt(to); err != nil {
		return err
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write(body); err != nil {
		wc.Close()
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return c.Quit()
}
