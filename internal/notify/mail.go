// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package notify

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// Mail, because a notice that only reaches people who are signed in does not
// discharge Article 34.
//
// The in-app channel is the better one in every way that is under this
// program's control: it cannot be read in transit, it cannot go to a mailbox
// somebody abandoned, and delivery is a fact rather than a hope. It also only
// reaches somebody who signs in, and a customer who stopped signing in six
// months ago is exactly the person whose stale credentials are in the breach.
//
// # No option to send this in the clear
//
// STARTTLS is required and there is no flag to disable it. Opportunistic
// STARTTLS — try it, carry on without it if the server does not offer it — is
// the default in most mail libraries and it is how a breach notice naming
// what leaked gets read by whoever runs a relay in the middle. A flag to turn
// it off is a flag that ends up on in production because somebody was
// debugging against a local relay at four in the afternoon.
//
// Credentials are sent only after the connection is encrypted, which is the
// other half of the same rule.
//
// # Accepted is not delivered
//
// An SMTP server accepting a message means it took responsibility for it, not
// that anybody read it. The outbox records what was accepted, because that is
// the true fact available; a bounce arriving an hour later is not visible
// here and a system claiming otherwise would be claiming somebody was told
// when they were not. Where a deployment wants both records, the same person
// is held as two contacts under two issuers — one on the in-app channel and
// one on email — and two independent records of the same notice are worth
// more than either.
//
// # What is deliberately not in the headers
//
// A declinable notice carries List-Unsubscribe. A breach notice does not, and
// not as an oversight: RFC 8058 one-click unsubscribe on an Article 34 notice
// would be offering somebody a choice the law does not give them, in the one
// message where the offer is most likely to be taken.

// Message is one notice rendered as mail to exactly one person.
//
// One To, and no Cc or Bcc field exists to be filled in. The single
// commonest personal data breach caused by breach notification is the
// notification: two hundred affected customers in one Cc line, each of them
// now knowing who the others are and that they were affected.
type Message struct {
	From    string
	To      string
	Subject string
	Body    string
	Date    time.Time
	// ID is the Message-ID, without angle brackets.
	ID string
	// Unsubscribe is the List-Unsubscribe value, empty for a notice that
	// cannot be declined.
	Unsubscribe string
}

// NewMessage renders a notice for one recipient.
func NewMessage(n Notice, from, to string, at time.Time) (Message, error) {
	if strings.TrimSpace(from) == "" {
		return Message{}, fmt.Errorf("mail needs a From address")
	}
	if strings.TrimSpace(to) == "" {
		return Message{}, fmt.Errorf("%s has nobody to go to", n.ID)
	}
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return Message{}, err
	}
	domain := "localhost"
	if _, d, ok := strings.Cut(from, "@"); ok && d != "" {
		domain = d
	}
	return Message{
		From: from, To: to, Subject: n.Subject, Body: n.Body, Date: at,
		ID: hex.EncodeToString(raw) + "@" + domain,
	}, nil
}

// headerSafe refuses a value that could inject a header.
//
// The subject comes from whatever somebody typed into `notify draft`. A
// newline in it ends the Subject header and starts another one, and the
// header an attacker would choose is Bcc.
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
		{"unsubscribe address", m.Unsubscribe},
	} {
		if err := headerSafe(f.name, f.value); err != nil {
			return nil, err
		}
	}
	var b strings.Builder
	write := func(k, v string) { fmt.Fprintf(&b, "%s: %s\r\n", k, v) }
	write("From", m.From)
	write("To", m.To)
	// Encoded, so a subject with a name or a currency symbol in it does not
	// arrive as mojibake in the one message somebody has to read carefully.
	write("Subject", mime.QEncoding.Encode("utf-8", m.Subject))
	write("Date", m.Date.Format(time.RFC1123Z))
	write("Message-ID", "<"+m.ID+">")
	// RFC 3834: this is machine-generated, so a vacation responder should not
	// reply to it. Without this a breach notice to four thousand people
	// produces four hundred out-of-office replies into the incident inbox on
	// the day it is least useful.
	write("Auto-Submitted", "auto-generated")
	if m.Unsubscribe != "" {
		write("List-Unsubscribe", "<"+m.Unsubscribe+">")
	}
	write("MIME-Version", "1.0")
	write("Content-Type", "text/plain; charset=utf-8")
	// Base64 rather than quoted-printable: the body is prose that may be in
	// any language, and a transfer encoding that mangles one of them in the
	// message somebody has to act on is not worth the saved bytes.
	write("Content-Transfer-Encoding", "base64")
	b.WriteString("\r\n")

	enc := base64.StdEncoding.EncodeToString([]byte(m.Body))
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
	return []byte(b.String()), nil
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
	// Unsubscribe is the address or URL offered on declinable notices only.
	Unsubscribe string
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

// Send delivers one notice to one address.
func (m Mailer) Send(n Notice, d Delivery) error {
	if d.Channel != Email {
		return fmt.Errorf("%s is not an email delivery", d.Key)
	}
	msg, err := NewMessage(n, m.From, d.Address, m.now())
	if err != nil {
		return err
	}
	if n.Kind.Objectable() && m.Unsubscribe != "" {
		// Only where there is something to unsubscribe from. See the file
		// comment: an unsubscribe link on an Article 34 notice offers a
		// choice the law does not give.
		msg.Unsubscribe = m.Unsubscribe
	}
	body, err := msg.Bytes()
	if err != nil {
		return err
	}
	return m.deliver(d.Address, body)
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
				"%s does not offer STARTTLS, so this notice would cross the "+
					"network in the clear. There is no flag to permit that: "+
					"a breach notice naming what leaked is the last message "+
					"to send unencrypted", m.Host)
		}
		if err := c.StartTLS(conf); err != nil {
			return err
		}
	}
	if m.Username != "" {
		// After TLS, never before.
		if err := c.Auth(smtp.PlainAuth("", m.Username, m.Password,
			host)); err != nil {
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
