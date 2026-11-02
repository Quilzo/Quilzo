// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/event"
	"github.com/quilzo/quilzo/internal/fetch"
)

// Telling staff what visitors are waiting on.
//
// A visitor who asked a chatbot for a person and was never answered is the
// commonest way a chatbot fails, and nothing told anybody: the Inbox
// waited to be opened, and a form sat under Forms. The dispatcher that
// starts agents (agenttriggers.go) reads the same events, and for the ones
// in notify.events it tells notify.staff: by mail, or through an incoming
// webhook into Slack, Teams or Discord, whose address is kept sealed.
//
// A notice says which chatbot or form and how many, never who or what
// they wrote: it goes to a mailbox or a channel, which keeps it longer and
// shows it to more people than the admin would. Notices are gathered a pass
// at a time and at most noticesPerHour go in an hour; the rest are counted
// and said in the next one.

// noticesPerHour bounds how many notices go in an hour.
const noticesPerHour = 30

// noticeState is this hour's notices: how many went and how many were held.
type noticeState struct {
	Hour string `json:"hour"`
	Sent int    `json:"sent"`
	Held int    `json:"held"`
}

// staffTargets is notify.staff.
func staffTargets(root string) []string {
	cfg, err := loadConfig(root)
	if err != nil || cfg == nil {
		return nil
	}
	return splitList(cfg.Raw("notify.staff"))
}

// noticeTypes is notify.events, when there is anybody to tell.
func noticeTypes(root string) map[event.Type]bool {
	if len(staffTargets(root)) == 0 {
		return nil
	}
	out := map[event.Type]bool{}
	for _, t := range mustConfig(root).Strings("notify.events") {
		out[event.Type(strings.TrimSpace(t))] = true
	}
	return out
}

// staffNotice is what a batch of events says, in a person's words.
func staffNotice(events []event.Event, held int, admin string) (subject, body string) {
	type key struct {
		t       event.Type
		subject string
	}
	count := map[key]int{}
	var order []key
	for _, e := range events {
		k := key{e.Type, e.Subject}
		if count[k] == 0 {
			order = append(order, k)
		}
		count[k]++
	}
	// Visitors waiting first: they are why this is sent.
	rank := func(t event.Type) int {
		switch t {
		case event.HandoffRequested:
			return 0
		case event.FormSubmitted:
			return 1
		}
		return 2
	}
	sort.SliceStable(order, func(i, j int) bool { return rank(order[i].t) < rank(order[j].t) })

	var lines []string
	for _, k := range order {
		n, about := count[k], strconvQuote(k.subject)
		switch k.t {
		case event.HandoffRequested:
			lines = append(lines, fmt.Sprintf("%s asked the chatbot %s for a person. They are waiting in the Inbox.",
				plural2(n, "A visitor", "visitors"), about))
		case event.FormSubmitted:
			lines = append(lines, fmt.Sprintf("%s sent through the form %s. They are under Forms.",
				plural2(n, "A form was", "forms were"), about))
		case event.ChatbotUnanswered:
			lines = append(lines, fmt.Sprintf("The chatbot %s could not answer %s.", about,
				plural2(n, "a question", "questions")))
		case event.BookingMade:
			lines = append(lines, fmt.Sprintf("%s for %s.", plural2(n, "A booking was made", "bookings were made"), about))
		case event.BookingCancelled:
			lines = append(lines, fmt.Sprintf("%s for %s.", plural2(n, "A booking was cancelled", "bookings were cancelled"), about))
		case event.ApprovalWaiting:
			// Which agent, never what it would do: a notice goes to a
			// channel, and deciding is done signed in, under Approvals.
			lines = append(lines, fmt.Sprintf("The agent %s is waiting for a person (%s). Decide under Approvals.",
				about, plural2(n, "once", "times")))
		default:
			line := fmt.Sprintf("%s: %s", strings.ToUpper(event.Describe(k.t)[:1])+event.Describe(k.t)[1:],
				plural2(n, "once", "times"))
			if k.subject != "" {
				line += " (" + about + ")"
			}
			lines = append(lines, line)
		}
	}
	if held > 0 {
		lines = append(lines, fmt.Sprintf("And %s earlier this hour, not sent one by one so as not to flood "+
			"you; they are in the admin.", plural2(held, "one more", "more")))
	}
	if admin != "" {
		lines = append(lines, "", "Open the admin: "+admin)
	}
	lines = append(lines, "", "Sent by Quilzo. It says which chatbot or form, never who or what they wrote.")
	subject = "Quilzo: " + onOneLine(lines[0])
	if len(subject) > 120 {
		subject = subject[:117] + "..."
	}
	return subject, strings.Join(lines, "\n")
}

// plural2 is "a visitor" for one and "3 visitors" for more.
func plural2(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// strconvQuote is a name in quotation marks, or "a chatbot" for none.
func strconvQuote(s string) string {
	if s == "" {
		return "(unnamed)"
	}
	return "“" + s + "”"
}

// sendStaffNotice tells everybody in notify.staff, and records that it did
// and how, never to which address.
func sendStaffNotice(root string, events []event.Event, held int) error {
	targets := staffTargets(root)
	if len(targets) == 0 || (len(events) == 0 && held == 0) {
		return nil
	}
	subject, body := staffNotice(events, held, strings.TrimRight(mustConfig(root).Raw("admin.base_url"), "/"))
	var sent, failed []string
	for _, t := range targets {
		scheme, rest, _ := strings.Cut(strings.TrimSpace(t), ":")
		switch strings.ToLower(scheme) {
		case "mailto":
			if err := mailNotice(root, rest, subject, body); err != nil {
				failed = append(failed, "mail: "+redact(err.Error(), rest))
				continue
			}
			sent = append(sent, "mail")
		case "secret":
			if err := hookNotice(root, rest, body); err != nil {
				failed = append(failed, "secret:"+rest+": "+err.Error())
				continue
			}
			sent = append(sent, "secret:"+rest)
		default:
			failed = append(failed, "an entry that is neither mailto: nor secret:")
		}
	}
	counts := map[string]int{}
	for _, e := range events {
		counts[string(e.Type)]++
	}
	var said []string
	for t, n := range counts {
		said = append(said, fmt.Sprintf("%s %d", t, n))
	}
	sort.Strings(said)
	detail := map[string]string{"events": strings.Join(said, ", "), "sent": strings.Join(sent, ", ")}
	if held > 0 {
		detail["held"] = fmt.Sprint(held)
	}
	outcome := audit.Success
	if len(failed) > 0 {
		outcome, detail["failed"] = audit.Failure, clip(strings.Join(failed, "; "), 500)
	}
	recordE(root, audit.Record{Action: "notify.staff", Resource: "/", Outcome: outcome,
		Principal: "quilzo", Kind: audit.KindService, Verified: true, Detail: detail})
	if len(failed) > 0 {
		return errors.New(strings.Join(failed, "; "))
	}
	return nil
}

func mailNotice(root, to, subject, body string) error {
	m, err := loadMailer(root)
	if err != nil {
		return err
	}
	if m == nil {
		return errors.New("no mail is set up (mail.json)")
	}
	return m.Send(to, subject, body)
}

// hookNotice posts a notice to the incoming webhook a sealed credential
// holds: https only, through the same client and address rules as the
// site's webhooks, so it cannot be pointed at this machine or its network.
// Errors never carry the address: it is the credential.
func hookNotice(root, name, body string) error {
	addr, err := readSecret(root, name)
	if err != nil {
		return errors.New("the credential is not kept here (quilzo secret set " + name + ")")
	}
	addr = strings.TrimSpace(addr)
	if !strings.HasPrefix(addr, "https://") {
		return errors.New("the credential is not an https address")
	}
	// "text" is Slack's and Teams' field, "content" Discord's; each ignores
	// the other's.
	payload, _ := json.Marshal(map[string]string{"text": body, "content": body})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	status, err := postNotice(ctx, addr, payload)
	if err != nil {
		return errors.New(redact(err.Error(), addr))
	}
	if status < 200 || status > 299 {
		return fmt.Errorf("the webhook answered %d", status)
	}
	return nil
}

// postNotice sends a notice's JSON: through the site's webhook client,
// which refuses this machine and its network and does not follow
// redirects. A variable so a test can stand in for a channel.
var postNotice = func(ctx context.Context, addr string, payload []byte) (int, error) {
	res, err := fetch.For("webhook").Post(ctx, addr, payload, "application/json")
	if err != nil {
		return 0, err
	}
	return res.Status, nil
}

// redact takes a secret out of a message that might repeat it.
func redact(msg, secret string) string {
	if secret == "" {
		return msg
	}
	return strings.ReplaceAll(msg, secret, "[the address]")
}

// sayNoticeError is how the server's log hears a notice failed.
func sayNoticeError(err error) {
	fmt.Fprintf(os.Stderr, "  %snotifying staff: %v%s\n", dim, err, reset)
}
