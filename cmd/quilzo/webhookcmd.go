package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/webhook"
)

func hooksPath(root string) string { return filepath.Join(root, "webhooks.json") }

type hookFile struct {
	Endpoints  []webhook.Endpoint `json:"endpoints"`
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
	types := fs.String("types", "", "comma-separated event types; empty means all")
	note := fs.String("note", "", "what this endpoint is")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo webhook add https://receiver.example/hook")
	}
	if _, err := fetch.ValidateURL(pos[0]); err != nil {
		return fmt.Errorf("that endpoint is not usable: %w", err)
	}

	secret, err := webhook.NewSecret()
	if err != nil {
		return err
	}
	e := webhook.Endpoint{URL: pos[0], Secret: secret, Note: *note}
	for _, t := range strings.Split(*types, ",") {
		if t = strings.TrimSpace(t); t != "" {
			e.Types = append(e.Types, t)
		}
	}

	f := &hookFile{}
	if err := loadJSON(hooksPath(root), f); err != nil {
		return err
	}
	for _, existing := range f.Endpoints {
		if existing.URL == e.URL {
			return fmt.Errorf("%s is already configured", e.URL)
		}
	}
	f.Endpoints = append(f.Endpoints, e)
	if err := saveJSON(hooksPath(root), f); err != nil {
		return err
	}

	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action: "webhook.add", Resource: "/", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		// The URL, never the shared value. The audit package refuses any Detail
		// key containing "secret", which is what stops this being added later
		// by somebody being helpful.
		Detail: map[string]string{"endpoint": e.URL},
	})

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
	f := &hookFile{}
	if err := loadJSON(hooksPath(root), f); err != nil {
		return err
	}
	kept := f.Endpoints[:0]
	found := false
	for _, e := range f.Endpoints {
		if e.URL == args[0] {
			found = true
			continue
		}
		kept = append(kept, e)
	}
	if !found {
		return fmt.Errorf("no endpoint at %s", args[0])
	}
	f.Endpoints = kept
	if err := saveJSON(hooksPath(root), f); err != nil {
		return err
	}
	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action: "webhook.remove", Resource: "/", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{"endpoint": args[0]},
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

	s := sender{fetch.New()}
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
func notify(root, eventType, commit string, pages []string) {
	f := &hookFile{}
	if err := loadJSON(hooksPath(root), f); err != nil || len(f.Endpoints) == 0 {
		return
	}
	id, err := webhook.NewID()
	if err != nil {
		return
	}
	ev := webhook.Event{
		ID: id, Type: eventType, Commit: commit, Pages: pages,
		At: time.Now().UTC().Format(time.RFC3339),
	}

	s := sender{fetch.New()}
	for _, e := range f.Endpoints {
		if !e.Wants(eventType) {
			continue
		}
		deliveries := webhook.Send(s, e, ev, time.Now())
		last := deliveries[len(deliveries)-1]
		f.Deliveries = append(f.Deliveries, last)
		if !last.Succeeded {
			fmt.Fprintf(os.Stderr, "%swebhook to %s failed after %d attempt(s)%s\n",
				yellow, e.URL, len(deliveries), reset)
		}
	}
	// Keep the last hundred, so a failure is visible without the file growing
	// without bound.
	if n := len(f.Deliveries); n > 100 {
		f.Deliveries = f.Deliveries[n-100:]
	}
	_ = saveJSON(hooksPath(root), f)
}
