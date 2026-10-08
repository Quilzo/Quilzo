// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package remind

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/estate"
)

// Wednesday, mid-morning in London.
var now = time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)

func ago(d int) string { return now.AddDate(0, 0, -d).Format(time.RFC3339) }

func line(src, ep string, k estate.Kind, fields map[string]string) estate.Line {
	l := estate.Line{"_source": src, "_endpoint": ep, "_produces": string(k)}
	for key, v := range fields {
		l[key] = v
	}
	return l
}

func build(people, devices, training, phishing []estate.Line) *estate.Estate {
	snap := estate.Snapshot{Source: "vanta", At: now,
		Endpoints: map[string]estate.EndpointInfo{
			"people":    {Produces: estate.KindPerson, Complete: true},
			"computers": {Produces: estate.KindDevice, Complete: true}}}
	snap.Lines = append(append(snap.Lines, people...), devices...)
	kb := estate.Snapshot{Source: "knowbe4", At: now,
		Endpoints: map[string]estate.EndpointInfo{
			"enrollments": {Produces: estate.KindTraining, Complete: true},
			"results":     {Produces: estate.KindPhishing, Complete: true}}}
	kb.Lines = append(append(kb.Lines, training...), phishing...)
	return estate.Build([]estate.Snapshot{snap, kb}, nil, now)
}

func sam(fields map[string]string) estate.Line {
	f := map[string]string{"id": "v1", "email": "sam@acme.com",
		"name": "Sam Okafor", "employment": "CURRENT",
		"manager_email": "boss@acme.com"}
	for k, v := range fields {
		f[k] = v
	}
	return line("vanta", "people", estate.KindPerson, f)
}

func all() Config {
	c := Default()
	c.Enabled = true
	c.Campaigns[Phishing] = true
	return c
}

func TestWhatSomebodyStillHasToDoIsListedOnce(t *testing.T) {
	e := build(
		[]estate.Line{sam(map[string]string{"training": "OVERDUE",
			"policies": "OVERDUE"})},
		[]estate.Line{line("vanta", "computers", estate.KindDevice,
			map[string]string{"id": "c1", "serial": "SAMLAPTOP1",
				"name": "Sam's Mac", "owner_email": "sam@acme.com",
				"seen": ago(1), "encryption": "FAIL", "screenlock": "PASS"})},
		[]estate.Line{line("knowbe4", "enrollments", estate.KindTraining,
			map[string]string{"id": "e1", "email": "sam@acme.com",
				"kind": "Training Module", "status": "Past Due"})},
		[]estate.Line{line("knowbe4", "results", estate.KindPhishing,
			map[string]string{"id": "r1", "email": "sam@acme.com",
				"clicked": ago(5)})})
	due := Due(e, now, all())
	if len(due) != 1 {
		t.Fatalf("%d people", len(due))
	}
	var keys []string
	for _, it := range due[0].Items {
		keys = append(keys, it.Key)
	}
	got := strings.Join(keys, " ")
	for _, want := range []string{"training", "policies",
		"device:encryption:serial:SAMLAPTOP1", "phishing:r1"} {
		if !strings.Contains(got, want) {
			t.Errorf("%s missing from %s", want, got)
		}
	}
	if strings.Count(got, "training") != 1 {
		t.Errorf("training overdue in two tools is one thing to do: %s", got)
	}
	if strings.Contains(got, "screenlock") {
		t.Error("a screen lock that passes was listed")
	}
	// Phishing follow-up is off unless somebody turns it on.
	for _, it := range Due(e, now, Default())[0].Items {
		if it.Campaign == Phishing {
			t.Error("the phishing follow-up was sent with the default settings")
		}
	}
}

func TestNobodyWithNothingToDoOrWhoHasLeftIsReminded(t *testing.T) {
	e := build([]estate.Line{
		sam(map[string]string{"training": "COMPLETE"}),
		line("vanta", "people", estate.KindPerson, map[string]string{
			"id": "v2", "email": "old@acme.com", "employment": "FORMER",
			"training": "OVERDUE"}),
	}, nil, nil, nil)
	if due := Due(e, now, all()); len(due) != 0 {
		t.Errorf("reminded %v", due)
	}
}

func TestAPersonIsRemindedNoMoreOftenThanAllowed(t *testing.T) {
	c := all()
	people := []Person{{Key: "k", Name: "Sam", Email: "sam@acme.com",
		Items: []Item{{Key: "training", Campaign: Training, Text: "x",
			Tool: "vanta"}}}}
	msgs, _ := Plan(people, []Sent{{At: now.AddDate(0, 0, -3), Person: "k",
		Channel: Email, Items: []string{"training"}, OK: true}}, c, now)
	if len(msgs) != 0 {
		t.Error("reminded three days after the last one, with a week between")
	}
	msgs, _ = Plan(people, []Sent{{At: now.AddDate(0, 0, -3), Person: "k",
		Channel: Email, Items: []string{"training"}, OK: false}}, c, now)
	if len(msgs) != 1 {
		t.Error("a reminder that failed to send held the next one back")
	}
	msgs, _ = Plan(people, []Sent{{At: now.AddDate(0, 0, -8), Person: "k",
		Channel: Email, Items: []string{"training"}, OK: true}}, c, now)
	if len(msgs) != 1 {
		t.Error("not reminded after the week had passed")
	}
}

func TestAManagerIsToldOnlyAfterRemindersOverWeeks(t *testing.T) {
	c := all()
	c.Channels = []Channel{Email, Slack}
	people := []Person{{Key: "k", Name: "Sam", Email: "sam@acme.com",
		ManagerEmail: "boss@acme.com", Items: []Item{
			{Key: "training", Campaign: Training, Text: "Finish training",
				Tool: "knowbe4"},
			{Key: "phishing:r1", Campaign: Phishing, Text: "Refresher",
				Tool: "knowbe4"}}}}
	sent := func(days ...int) []Sent {
		var out []Sent
		for _, d := range days {
			for _, ch := range c.Channels {
				out = append(out, Sent{At: now.AddDate(0, 0, -d), Person: "k",
					Channel: ch, Items: []string{"training", "phishing:r1"},
					OK: true})
			}
		}
		return out
	}
	manager := func(msgs []Message) *Message {
		for i := range msgs {
			if msgs[i].Manager {
				return &msgs[i]
			}
		}
		return nil
	}
	// Two reminders, even on two channels each, are not three.
	if m := manager(first(Plan(people, sent(15, 8), c, now))); m != nil {
		t.Error("escalated after two reminders counted per channel")
	}
	// Three reminders, but within ten days.
	short := []Sent{}
	for _, d := range []int{9, 8, 7} {
		short = append(short, Sent{At: now.AddDate(0, 0, -d), Person: "k",
			Channel: Email, Items: []string{"training"}, OK: true})
	}
	c2 := c
	c2.EveryDays = 1
	if m := manager(first(Plan(people, short, c2, now))); m != nil {
		t.Error("escalated after three reminders in three days")
	}
	m := manager(first(Plan(people, sent(22, 15, 8), c, now)))
	if m == nil {
		t.Fatal("not escalated after three reminders over three weeks")
	}
	if m.To != "boss@acme.com" || m.Channel != Email {
		t.Errorf("escalation went to %s by %s", m.To, m.Channel)
	}
	if strings.Contains(m.Body, "Refresher") ||
		strings.Contains(strings.Join(m.Items, " "), "phishing") {
		t.Error("a phishing result was sent to a manager")
	}
	// And not again the next week.
	withEscalation := append(sent(22, 15, 8), Sent{At: now.AddDate(0, 0, -1),
		Person: "k", Channel: Email, Manager: true, OK: true})
	if m := manager(first(Plan(people, withEscalation, c, now.AddDate(0, 0, 7)))); m != nil {
		t.Error("the manager was told again a week later")
	}
}

func first(m []Message, _ []Held) []Message { return m }

func TestNothingIsSentOutsideTheWindow(t *testing.T) {
	c := Default()
	c.Zone = "Europe/London"
	for _, tc := range []struct {
		at   time.Time
		want bool
	}{
		{time.Date(2026, 9, 30, 8, 30, 0, 0, time.UTC), true},   // 09:30 BST
		{time.Date(2026, 9, 30, 7, 30, 0, 0, time.UTC), false},  // 08:30 BST
		{time.Date(2026, 9, 30, 16, 30, 0, 0, time.UTC), false}, // 17:30 BST
		{time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC), false},  // Saturday
	} {
		if got := c.InHours(tc.at); got != tc.want {
			t.Errorf("%s: %v", tc.at, got)
		}
	}
}

func TestAConfigurationThatCouldSendMoreOrElsewhereIsRefused(t *testing.T) {
	for name, spoil := range map[string]func(*Config){
		"daily and more":       func(c *Config) { c.EveryDays = 0 },
		"escalating in days":   func(c *Config) { c.EscalateDays = 2 },
		"a plain http link":    func(c *Config) { c.Links = map[string]string{"knowbe4": "http://training.knowbe4.com"} },
		"a link with a login":  func(c *Config) { c.Links = map[string]string{"knowbe4": "https://me:pw@training.knowbe4.com"} },
		"a quoted link":        func(c *Config) { c.Links = map[string]string{"knowbe4": `https://x.com/"><script>`} },
		"no channel":           func(c *Config) { c.Channels = nil },
		"a made-up channel":    func(c *Config) { c.Channels = []Channel{"sms"} },
		"a two-line signature": func(c *Config) { c.Signature = "Security\r\nBcc: all@acme.com" },
		"no zone":              func(c *Config) { c.Zone = "Mars/Olympus" },
	} {
		c := Default()
		spoil(&c)
		if c.Validate() == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if err := Default().Validate(); err != nil {
		t.Errorf("the default: %v", err)
	}
}

func TestAReminderAsksForNothingAndLinksOnlyToTheTool(t *testing.T) {
	c := all()
	c.Links = map[string]string{"knowbe4": "https://training.knowbe4.com"}
	p := Person{Name: "Sam Okafor", Items: []Item{
		{Key: "training", Text: "Finish your security awareness training",
			Tool: "knowbe4", Link: c.Links["knowbe4"]},
		{Key: "device", Text: "Turn on disk encryption on Sam's Mac",
			Tool: "vanta"}}}
	subject, body := Render(p, c, Email)
	if subject != "Security tasks waiting for you" ||
		!strings.HasPrefix(body, "Hello Sam,") ||
		!strings.Contains(body, "https://training.knowbe4.com") {
		t.Errorf("%s\n%s", subject, body)
	}
	if strings.Count(body, "https://") != 1 {
		t.Error("the reminder links somewhere besides the configured tool")
	}
	if !strings.Contains(body, "not from us") {
		t.Error("the reminder does not say it will never ask for a password")
	}
}

func TestSlackMarkupInAToolsWordsIsInert(t *testing.T) {
	p := Person{Name: "Sam", Items: []Item{{Key: "d", Tool: "vanta",
		Text: "Turn on disk encryption on <!channel> <https://evil.example|your laptop> & more"}}}
	_, body := Render(p, all(), Slack)
	for _, bad := range []string{"<!channel>", "<https://evil"} {
		if strings.Contains(body, bad) {
			t.Errorf("%q reached Slack as markup", bad)
		}
	}
	if !strings.Contains(body, "&lt;!channel&gt;") {
		t.Error("the text was dropped rather than escaped")
	}
}

type fakeSlack struct {
	looked, posted int
	lookupReply    string
	postReply      string
	postStatus     int
	body           map[string]any
	auth           string
}

func (f *fakeSlack) server(t *testing.T) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,
		r *http.Request) {
		f.auth = r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/api/users.lookupByEmail":
			f.looked++
			if r.URL.Query().Get("email") != "sam@acme.com" {
				t.Errorf("looked up %q", r.URL.Query().Get("email"))
			}
			io.WriteString(w, f.lookupReply)
		case "/api/chat.postMessage":
			f.posted++
			json.NewDecoder(r.Body).Decode(&f.body)
			if f.postStatus != 0 {
				w.WriteHeader(f.postStatus)
			}
			io.WriteString(w, f.postReply)
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func TestASlackReminderIsADirectMessageWithNoPreviews(t *testing.T) {
	f := &fakeSlack{lookupReply: `{"ok":true,"user":{"id":"U024BE7LH"}}`,
		postReply: `{"ok":true}`}
	srv := f.server(t)
	s := SlackSender{Token: "xoxb-test", Client: srv.Client(), Base: srv.URL}
	err := s.Send(context.Background(), Message{Channel: Slack,
		To: "sam@acme.com", Subject: "Security tasks", Body: "Hello"})
	if err != nil {
		t.Fatal(err)
	}
	if f.body["channel"] != "U024BE7LH" || f.body["unfurl_links"] != false ||
		f.body["unfurl_media"] != false {
		t.Errorf("posted %v", f.body)
	}
	if f.auth != "Bearer xoxb-test" {
		t.Errorf("authorised as %q", f.auth)
	}
}

func TestSlacksRefusalsAreRefusals(t *testing.T) {
	for name, f := range map[string]*fakeSlack{
		"no such user":  {lookupReply: `{"ok":false,"error":"users_not_found"}`},
		"a bad user id": {lookupReply: `{"ok":true,"user":{"id":"../../x"}}`},
		"not allowed": {lookupReply: `{"ok":true,"user":{"id":"U1ABC"}}`,
			postReply: `{"ok":false,"error":"not_allowed_token_type"}`},
		"limited": {lookupReply: `{"ok":true,"user":{"id":"U1ABC"}}`,
			postStatus: 429, postReply: `{"ok":false}`},
	} {
		srv := f.server(t)
		s := SlackSender{Token: "xoxb-test", Client: srv.Client(), Base: srv.URL}
		if err := s.Send(context.Background(), Message{Channel: Slack,
			To: "sam@acme.com", Subject: "s", Body: "b"}); err == nil {
			t.Errorf("%s: reported as sent", name)
		}
	}
	// A server that would accept it, so only the rule can refuse it.
	f := &fakeSlack{lookupReply: `{"ok":true,"user":{"id":"U1ABC"}}`,
		postReply: `{"ok":true}`}
	srv := f.server(t)
	s := SlackSender{Token: "t", Client: srv.Client(), Base: srv.URL}
	if s.Send(context.Background(), Message{Channel: Slack, Manager: true,
		To: "sam@acme.com"}) == nil || f.posted != 0 {
		t.Error("a manager's escalation went to Slack")
	}
}
