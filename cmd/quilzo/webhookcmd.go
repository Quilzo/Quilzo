// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/quilzo/quilzo/internal/collab"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/webhook"
)

func hooksPath(root string) string { return filepath.Join(root, "webhooks.json") }

type hookFile struct {
	Endpoints []webhook.Endpoint `json:"endpoints"`
	// Deliveries were kept here by older versions, and are kept apart now
	// (sitestate.go): loadHooks reads them from there.
	Deliveries []webhook.Delivery `json:"deliveries,omitempty"`
}

// sender routes deliveries through the SSRF-hardened client.
//
// A webhook endpoint is a URL somebody configured and this program requests it
// from inside the network — the same shape as importing from a URL, so it gets
// the same connect-time address check rather than a second one that could
// disagree with the first.
type sender struct{ c *fetch.Client }

func (s sender) Post(url string, body []byte, headers map[string]string) (int, error) {
	res, err := s.c.PostSigned(context.Background(), url, body, headers)
	if err != nil {
		return 0, err
	}
	return res.Status, nil
}

func cmdWebhook(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		return hookList(root)
	case "add":
		return hookAdd(root, args[1:])
	case "remove":
		return hookRemove(root, args[1:])
	case "test":
		return hookTest(root, args[1:])
	default:
		return fmt.Errorf("unknown webhook command %q; try list, add, remove "+
			"or test", args[0])
	}
}

func hookAdd(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	types := fs.String("types", "",
		"comma-separated event types; empty means all. "+
			strings.Join(webhook.EventTypes, ", ")+", or each one's event name (page.published)")
	note := fs.String("note", "", "what this endpoint is")
	if err := parseFlags(fs, flags, &pos, 1); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo webhook add https://receiver.example/hook")
	}
	e := webhook.Endpoint{URL: pos[0], Note: *note}
	for _, t := range strings.Split(*types, ",") {
		if t = strings.TrimSpace(t); t != "" {
			e.Types = append(e.Types, t)
		}
	}
	// The rule the Integrations screen and a feature's webhooks are held
	// to as well (webhook.Check).
	if err := webhook.Check(e.URL, e.Types); err != nil {
		return err
	}
	secret, err := webhook.NewSecret()
	if err != nil {
		return err
	}
	e.Secret = secret

	if err := updateHooks(root, func(f *hookFile) error {
		for _, existing := range f.Endpoints {
			if existing.URL == e.URL {
				return fmt.Errorf("%s is already configured", e.URL)
			}
		}
		f.Endpoints = append(f.Endpoints, e)
		return nil
	}); err != nil {
		return err
	}

	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action: "webhook.add", Resource: "/", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Model: caller.Model, Verified: caller.Verified,
		// The host and a reference, never the shared value and never the
		// whole address (webhook.LogForm): the path or query of an address
		// can be a credential of its own. The audit package refuses any
		// Detail key containing "secret", which is what stops the shared
		// value being added later by somebody being helpful.
		Detail: map[string]string{"endpoint": webhook.LogForm(e.URL), "endpoint_ref": webhook.Ref(e)},
	})

	// The endpoint and its key under --json. This wrote the key only for a
	// person, so under --json the endpoint was kept signing with a key its
	// receiver could not be given.
	if w.JSON(map[string]any{"url": e.URL, "secret": secret}) {
		return nil
	}
	w.Human("%s%s%s\n", bold, secret, reset)
	w.Human("\n  %sthis is the signing key, shown once. The receiver needs the\n"+
		"  same bytes to verify a delivery, so it is a shared value rather\n"+
		"  than something that can be hashed%s\n", yellow, reset)
	w.Human("\n  %severy delivery is signed over a timestamp and the body\n"+
		"  together. The timestamp is what stops a captured request being\n"+
		"  replayed a year later with a signature that still verifies%s\n",
		dim, reset)
	return nil
}

func hookRemove(root string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: quilzo webhook remove <url>")
	}
	var removed webhook.Endpoint
	if err := updateHooks(root, func(f *hookFile) error {
		kept := f.Endpoints[:0]
		found := false
		for _, e := range f.Endpoints {
			if e.URL == args[0] {
				found, removed = true, e
				continue
			}
			kept = append(kept, e)
		}
		if !found {
			return fmt.Errorf("no endpoint at %s", args[0])
		}
		f.Endpoints = kept
		return nil
	}); err != nil {
		return err
	}
	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action: "webhook.remove", Resource: "/", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Model: caller.Model, Verified: caller.Verified,
		// As webhook.add records it, so the two line up by endpoint_ref.
		Detail: map[string]string{"endpoint": webhook.LogForm(removed.URL), "endpoint_ref": webhook.Ref(removed)},
	})
	w.Human("removed\n")
	return nil
}

func hookList(root string) error {
	f := &hookFile{}
	if err := loadJSON(hooksPath(root), f); err != nil {
		return err
	}
	{
		redacted := make([]webhook.Endpoint, 0, len(f.Endpoints))
		for _, e := range f.Endpoints {
			redacted = append(redacted, webhook.Redact(e))
		}
		if w.JSON(map[string]any{"endpoints": redacted}) {
			return nil
		}
	}
	if len(f.Endpoints) == 0 {
		w.Human("no webhooks\n")
		w.Human("  %squilzo webhook add https://receiver.example/hook%s\n",
			dim, reset)
		return nil
	}
	for _, e := range f.Endpoints {
		state := ""
		if e.Disabled {
			state = yellow + " (disabled)" + reset
		}
		w.Human("  %s%s%s\n", bold, e.URL, reset+state)
		w.Human("    %skey %s", dim, webhook.SecretHint(e.Secret))
		if len(e.Types) > 0 {
			w.Human(" · %s", strings.Join(e.Types, ", "))
		}
		if e.Note != "" {
			w.Human(" · %s", e.Note)
		}
		w.Human("%s\n", reset)
	}
	return nil
}

// hookTest sends a delivery now, so a misconfigured receiver is found
// deliberately rather than by a publication going unnoticed.
func hookTest(root string, args []string) error {
	// It takes nothing: the test goes to every endpoint. `webhook test ID`
	// read as a test of that one, and sent to them all.
	if err := noArguments(args); err != nil {
		return err
	}
	f := &hookFile{}
	if err := loadJSON(hooksPath(root), f); err != nil {
		return err
	}
	if len(f.Endpoints) == 0 {
		return fmt.Errorf("no webhooks are configured")
	}

	id, err := webhook.NewID()
	if err != nil {
		return err
	}
	ev := webhook.Event{
		ID: id, Type: "test", At: time.Now().UTC().Format(time.RFC3339),
	}

	s := sender{fetch.For("webhook")}
	for _, e := range f.Endpoints {
		if len(args) == 1 && e.URL != args[0] {
			continue
		}
		w.Human("%s\n", e.URL)
		for _, d := range webhook.Send(s, e, ev, time.Now()) {
			if d.Succeeded {
				w.Human("  %sdelivered%s attempt %d, status %d\n",
					green, reset, d.Attempt, d.Status)
			} else {
				w.Human("  %sfailed%s attempt %d", yellow, reset, d.Attempt)
				if d.Status > 0 {
					w.Human(", status %d", d.Status)
				}
				if d.Error != "" {
					w.Human(" — %s", d.Error)
				}
				w.Human("\n")
			}
		}
	}
	return nil
}

// notify delivers an event to every endpoint that wants it.
//
// Called after a publication. Failures are reported and never block: a
// receiver being down is not a reason to stop publishing, and making it one
// hands anybody who can take a webhook endpoint offline the ability to stop the
// site being updated.
// notify delivers one event to every endpoint that asked for its type.
//
// form is the form a submission arrived through, and is empty for everything
// else. It carries the name and never the message: a submission has a retention
// period and a copy posted elsewhere has whatever period that system has, which
// is usually none.
// notifyProposed tells subscribers a change is waiting for agreement.
//
// Separate from notify because the fields differ: this one carries who
// proposed and whether a machine wrote it, and neither has a place in a
// publication event. Merging them would mean a function whose parameters are
// mostly empty at every call site, which is how a signature stops describing
// anything.
func notifyProposed(root string, prop *collab.Proposal) {
	if prop == nil {
		return
	}
	f := &hookFile{}
	if err := loadJSON(hooksPath(root), f); err != nil {
		return
	}
	id, err := webhook.NewID()
	if err != nil {
		return
	}
	ev := webhook.Event{
		ID: id, Type: "proposed", Commit: prop.Content,
		By: prop.Author, Machine: prop.AuthorKind == "ai",
		At: time.Now().UTC().Format(time.RFC3339), Site: siteName(root),
	}

	s := sender{fetch.For("webhook")}
	var sent []webhook.Delivery
	for _, e := range f.Endpoints {
		if !e.Wants("proposed") {
			continue
		}
		deliveries := webhook.Send(s, e, ev, time.Now())
		sent = append(sent, deliveries[len(deliveries)-1])
	}
	recordDeliveries(root, sent)
}

// recordDeliveries adds what was sent to the delivery history as it is
// stored now. Only the history: the endpoints are left as they are on
// disk, because sending takes seconds per endpoint, and writing back the
// list read before sending would put back an endpoint removed meanwhile,
// or a secret replaced, and keep it receiving signed events.
func recordDeliveries(root string, sent []webhook.Delivery) {
	if len(sent) == 0 {
		return
	}
	_ = keepDeliveries(root, sent)
}

var hooksMu sync.Mutex

// fireWebhooks posts an event to the configured endpoints.
//
// Named for what it does rather than the bare "notify" it used to be: since
// internal/notify exists, a function called notify in this package would be
// the one that tells machines, sitting next to the one that tells people,
// with nothing in the name to say which.
func fireWebhooks(root, eventType, commit string, pages []string,
	form ...string) {
	ev := webhook.Event{Type: eventType, Commit: commit, Pages: pages}
	if len(form) > 0 {
		ev.Form = form[0]
	}
	sendWebhookEvent(root, ev)
}

// fireBookingWebhooks tells endpoints a service was booked, or had a
// booking cancelled: the service, never when or who.
func fireBookingWebhooks(root, eventType, service string) {
	sendWebhookEvent(root, webhook.Event{Type: eventType, Service: service})
}

// sendWebhookEvent stamps an event and posts it to every endpoint that
// wants it.
func sendWebhookEvent(root string, ev webhook.Event) {
	// Every act that tells webhooks is also an event agents can start
	// from (agenttriggers.go), whether or not any webhook is configured.
	if e, ok := eventOfWebhook(ev); ok {
		emitEvent(root, e, nil)
	}
	eventType := ev.Type
	// One at a time: the admin tells from a goroutine per change, and two
	// publishes reading and rewriting the deliveries at once would lose one.
	hooksMu.Lock()
	defer hooksMu.Unlock()
	f := &hookFile{}
	if err := loadJSON(hooksPath(root), f); err != nil || len(f.Endpoints) == 0 {
		return
	}
	id, err := webhook.NewID()
	if err != nil {
		return
	}
	ev.ID, ev.At = id, time.Now().UTC().Format(time.RFC3339)

	s := sender{fetch.For("webhook")}
	var sent []webhook.Delivery
	for _, e := range f.Endpoints {
		if !e.Wants(eventType) {
			continue
		}
		deliveries := webhook.Send(s, e, ev, time.Now())
		last := deliveries[len(deliveries)-1]
		sent = append(sent, last)
		if !last.Succeeded {
			fmt.Fprintf(os.Stderr, "%swebhook to %s failed after %d attempt(s)%s\n",
				yellow, e.URL, len(deliveries), reset)
		}
	}
	recordDeliveries(root, sent)
}
