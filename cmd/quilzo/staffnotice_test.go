// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/event"
)

func setStaff(t *testing.T, root, staff string) {
	t.Helper()
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set("notify.staff", staff, "", "test"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
}

// A notice says what visitors are waiting on, visitors first, in a
// person's words, and never who they are or what they wrote.
func TestANoticeSaysWhatVisitorsAreWaitingOn(t *testing.T) {
	events := []event.Event{
		{Type: event.FormSubmitted, Subject: "enquiries"},
		{Type: event.HandoffRequested, Subject: "help"},
		{Type: event.HandoffRequested, Subject: "help"},
		{Type: event.ChatbotUnanswered, Subject: "help"},
	}
	subject, body := staffNotice(events, 4, "https://admin.example.com")
	if subject != "Quilzo: 2 visitors asked the chatbot “help” for a person. They are waiting in the Inbox." {
		t.Fatalf("%q", subject)
	}
	for _, want := range []string{"A form was sent through the form “enquiries”. They are under Forms.",
		"The chatbot “help” could not answer a question.", "And 4 more earlier this hour",
		"Open the admin: https://admin.example.com", "never who or what they wrote"} {
		if !strings.Contains(body, want) {
			t.Errorf("the notice does not say %q:\n%s", want, body)
		}
	}
	if strings.Index(body, "visitors asked") > strings.Index(body, "form was sent") {
		t.Error("visitors waiting are not said first")
	}
}

// A visitor asking a chatbot for a person reaches the team's channel
// within the dispatcher's pass, through the sealed address, and the
// record says it went and where, by the credential's name.
func TestAVisitorAskingForAPersonReachesTheTeam(t *testing.T) {
	root := triggeredStore(t)
	setStaff(t, root, "secret:team-hook")
	t.Setenv("QUILZO_SECRET_TEAM_HOOK", "https://hooks.example.com/services/T000/B000/SECRETPART")
	got := make(chan string, 4)
	old := postNotice
	postNotice = func(_ context.Context, addr string, payload []byte) (int, error) {
		var p map[string]string
		if err := json.Unmarshal(payload, &p); err != nil {
			t.Error(err)
		}
		if addr != "https://hooks.example.com/services/T000/B000/SECRETPART" || p["text"] != p["content"] {
			t.Errorf("%s %v", addr, p)
		}
		got <- p["text"]
		return 200, nil
	}
	t.Cleanup(func() { postNotice = old })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runTriggers(ctx, root, dispatcher{
			poll: 20 * time.Millisecond, runner: func() *Caller { return asAdmin("dana") },
			noticeTypes: func() map[event.Type]bool { return noticeTypes(root) },
			notify: func(events []event.Event, held int) {
				if err := sendStaffNotice(root, events, held); err != nil {
					t.Error(err)
				}
			},
		})
	}()
	defer func() { cancel(); <-done }()

	if _, err := siteEvents(root).Append(event.Event{Type: event.HandoffRequested, Subject: "help"}); err != nil {
		t.Fatal(err)
	}
	// Not told about: a page going live is not in notify.events.
	fireWebhooks(root, "published", strings.Repeat("f", 64), []string{"about"})
	select {
	case text := <-got:
		if !strings.Contains(text, "A visitor asked the chatbot “help” for a person.") ||
			strings.Contains(text, "go live") {
			t.Fatalf("%q", text)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the team was not told")
	}
	cancel()
	<-done
	evs, _ := audit.Read(auditPath(root))
	var rec *audit.Event
	for i := range evs {
		if evs[i].Action == "notify.staff" {
			rec = &evs[i]
		}
	}
	if rec == nil || rec.Outcome != audit.Success || rec.Detail["sent"] != "secret:team-hook" ||
		rec.Detail["events"] != "handoff.requested 1" {
		t.Fatalf("%+v", rec)
	}
	for _, v := range rec.Detail {
		if strings.Contains(v, "SECRETPART") {
			t.Fatal("the webhook's address is in the audit log")
		}
	}
}

// Thirty notices an hour at most; the rest are counted and said in the
// next hour's first.
func TestNoticesDoNotFlood(t *testing.T) {
	root := triggeredStore(t)
	setStaff(t, root, "mailto:team@example.com")
	types := noticeTypes(root)
	now := time.Now()
	sent := 0
	for i := 0; i < noticesPerHour+5; i++ {
		siteEvents(root).Append(event.Event{Type: event.FormSubmitted, Subject: "enquiries"})
		w, err := dueWork(root, now, never, nil, types)
		if err != nil {
			t.Fatal(err)
		}
		if len(w.notices) > 0 {
			sent++
		}
	}
	if sent != noticesPerHour {
		t.Fatalf("%d notices in an hour", sent)
	}
	siteEvents(root).Append(event.Event{Type: event.FormSubmitted, Subject: "enquiries"})
	w, err := dueWork(root, now.Add(time.Hour), never, nil, types)
	if err != nil || len(w.notices) != 1 || w.held != 5 {
		t.Fatalf("the next hour: %+v %v", w, err)
	}
	// Nobody to tell: nothing is gathered or counted.
	setStaff(t, root, "")
	if noticeTypes(root) != nil {
		t.Fatal("notices gathered with nobody to tell")
	}
}

// A webhook's address is a credential: it is not accepted in the settings,
// only a sealed credential's name. And the webhook client will not post to
// this machine, nor repeat the address when it refuses.
func TestAWebhooksAddressStaysSealed(t *testing.T) {
	root := triggeredStore(t)
	cfg, _ := loadConfig(root)
	for _, bad := range []string{"https://hooks.example.com/services/T/B/X", "team@example.com", "secret:../x", "sms:+441234"} {
		if err := cfg.Set("notify.staff", bad, "", "test"); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	if err := cfg.Set("notify.staff", "mailto:team@example.com,secret:team-hook", "", "test"); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set("notify.events", "handoff.requested,page.deleted", "", "test"); err == nil {
		t.Error("an event that does not exist was accepted")
	}
	t.Setenv("QUILZO_SECRET_INSIDE", "https://127.0.0.1:9/hooks/SECRETPART")
	err := hookNotice(root, "inside", "x")
	if err == nil || strings.Contains(err.Error(), "SECRETPART") {
		t.Fatalf("posted to this machine, or said its address: %v", err)
	}
	t.Setenv("QUILZO_SECRET_PLAIN", "http://hooks.example.com/x")
	if err := hookNotice(root, "plain", "x"); err == nil {
		t.Fatal("posted over plain http")
	}
}

// A notice's subject is cut where a character starts, and still comes to 120
// bytes with its mark. It names the form or the chatbot as its owner named
// it, and a mail client shows a subject ending in half a character as a
// replacement mark, or refuses the header.
func TestALongSubjectIsCutBetweenCharacters(t *testing.T) {
	// The lengths take the cut across every byte of the first characters.
	for n := 66; n < 78; n++ {
		events := []event.Event{{Type: event.FormSubmitted, Subject: strings.Repeat("a", n) + strings.Repeat("中", 30)}}
		subject, _ := staffNotice(events, 0, "")
		if !utf8.ValidString(subject) || len(subject) > 120 || !strings.HasSuffix(subject, "...") {
			t.Errorf("%d bytes, ending %q", len(subject), subject[max(0, len(subject)-6):])
		}
	}
}
