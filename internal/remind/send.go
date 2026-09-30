// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package remind

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Render writes one person's reminder. Plain words, what to do and where,
// who it is from, and nothing to click that is not the tool itself.
func Render(p Person, c Config, ch Channel) (subject, body string) {
	subject = "Security tasks waiting for you"
	if len(p.Items) == 1 {
		subject = "A security task waiting for you"
	}
	var b strings.Builder
	first := strings.Fields(p.Name)
	hello := "Hello"
	if len(first) > 0 && !strings.Contains(first[0], "@") {
		hello += " " + first[0]
	}
	b.WriteString(hello + ",\n\n")
	if len(p.Items) == 1 {
		b.WriteString("There is one thing still to do:\n\n")
	} else {
		fmt.Fprintf(&b, "There are %d things still to do:\n\n", len(p.Items))
	}
	for _, it := range p.Items {
		line := "- " + it.Text + " (in " + toolName(it.Tool) + ")"
		if it.Link != "" {
			line += "\n  " + it.Link
		}
		b.WriteString(line + "\n")
	}
	b.WriteString("\nIf you open these tools another way, that is fine: " +
		"nothing here needs you to sign in to anything new, and a message " +
		"asking for your password is not from us.\n\n")
	b.WriteString(c.Signature + "\n")
	body = b.String()
	if ch == Slack {
		body = slackEscape(body)
	}
	return subject, body
}

// RenderManager writes the one message a manager gets about somebody who
// has not done what they have been reminded of. Never phishing results.
func RenderManager(p Person, stuck []Item, c Config) (subject, body string) {
	subject = "Security tasks outstanding for " + p.Name
	var b strings.Builder
	fmt.Fprintf(&b, "Hello,\n\n%s has been reminded about these for %d days "+
		"or more, and they are still open:\n\n", p.Name, c.EscalateDays)
	for _, it := range stuck {
		b.WriteString("- " + it.Text + " (in " + toolName(it.Tool) + ")\n")
	}
	b.WriteString("\nYou are receiving this as their manager, as recorded " +
		"in the training platform. A word from you usually settles it.\n\n")
	b.WriteString(c.Signature + "\n")
	return subject, b.String()
}

var toolNames = map[string]string{
	"knowbe4": "KnowBe4", "vanta": "Vanta", "mdmplus": "MDM Plus",
	"endpointcentral": "Endpoint Central",
}

func toolName(t string) string {
	if n, ok := toolNames[t]; ok {
		return n
	}
	return t
}

// slackEscape makes text inert in Slack: its markup is < > and &, and a
// device name typed into a tool as <!channel> would otherwise notify a
// whole workspace, and <https://evil|your laptop> would be a link.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").
		Replace(s)
}

// Sender sends one message.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// MailFunc sends one message as mail; the caller wires it to the SMTP relay
// notify already uses, which requires TLS and takes exactly one recipient.
type MailFunc func(to, subject, body string) error

// EmailSender sends by mail.
type EmailSender struct{ Mail MailFunc }

// Send implements Sender.
func (e EmailSender) Send(_ context.Context, m Message) error {
	if m.Channel != Email {
		return fmt.Errorf("%s is not a mail message", m.Channel)
	}
	if e.Mail == nil {
		return fmt.Errorf("mail is not configured (notify/mail.json)")
	}
	return e.Mail(m.To, m.Subject, m.Body)
}

// Doer is the HTTP client, egress's in use and a test server's in tests.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// SlackHost is the only host the Slack sender talks to.
const SlackHost = "slack.com"

// SlackSender sends a direct message from a Slack app to a person found by
// their address. Outbound only: nothing here listens for Slack, and the
// app needs three scopes — users:read, users:read.email and chat:write —
// none of which reads a message anybody wrote.
type SlackSender struct {
	Token  string
	Client Doer
	// Base replaces https://slack.com in tests.
	Base string
	// Sleep waits between requests; Slack allows about one message a
	// second to a conversation.
	Sleep func(time.Duration)
}

var reSlackID = regexp.MustCompile(`^[UW][A-Z0-9]{2,30}$`)

func (s SlackSender) base() string {
	if s.Base != "" {
		return s.Base
	}
	return "https://" + SlackHost
}

// call makes one Web API request and reads Slack's {"ok": …} answer, which
// arrives with 200 whether or not it worked.
func (s SlackSender) call(ctx context.Context, method, path string,
	body []byte, into any) error {

	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.base()+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	res, err := s.Client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	if res.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("Slack is limiting requests; the rest go on the " +
			"next run")
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("Slack answered %d", res.StatusCode)
	}
	var ok struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &ok); err != nil {
		return fmt.Errorf("Slack's answer was not JSON")
	}
	if !ok.OK {
		code := ok.Error
		if len(code) > 60 || strings.ContainsAny(code, " \n") {
			code = "an error"
		}
		return fmt.Errorf("Slack refused it: %s", code)
	}
	if into != nil {
		return json.Unmarshal(raw, into)
	}
	return nil
}

// Send implements Sender.
func (s SlackSender) Send(ctx context.Context, m Message) error {
	if m.Channel != Slack {
		return fmt.Errorf("%s is not a Slack message", m.Channel)
	}
	if m.Manager {
		return fmt.Errorf("a manager is told by mail, not in Slack")
	}
	var found struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	q := url.Values{"email": {m.To}}
	if err := s.call(ctx, http.MethodGet, "/api/users.lookupByEmail?"+
		q.Encode(), nil, &found); err != nil {
		return err
	}
	if !reSlackID.MatchString(found.User.ID) {
		return fmt.Errorf("Slack gave back no usable user for that address")
	}
	if s.Sleep != nil {
		s.Sleep(time.Second)
	}
	payload, err := json.Marshal(map[string]any{
		"channel": found.User.ID, "text": "*" + slackEscape(m.Subject) +
			"*\n\n" + m.Body,
		// No previews: a preview is Slack fetching a link on the reader's
		// behalf, and nothing in a reminder needs one.
		"unfurl_links": false, "unfurl_media": false,
	})
	if err != nil {
		return err
	}
	return s.call(ctx, http.MethodPost, "/api/chat.postMessage", payload, nil)
}
