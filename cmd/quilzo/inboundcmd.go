// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/inbound"
	"github.com/quilzo/quilzo/internal/ssf"
)

func inboundUsage() error {
	return fmt.Errorf("usage: quilzo inbound list | status NAME | add okta NAME | " +
		"add webhook NAME --mapping ISSUER/STREAM [--github] | " +
		"add ssf NAME --issuer URL --url https://YOUR-ADMIN [--alias okta] | " +
		"connect NAME --client-id ID [--token-url URL] | verify NAME | " +
		"rotate NAME | on NAME | off NAME | remove NAME | help")
}

// signalsClient reaches a transmitter: its configuration, its token
// endpoint and its stream API, under the signals purpose.
func signalsClient() *fetch.Client {
	c := fetch.New()
	c.Purpose = "signals"
	c.UserAgent = "quilzo/1 (+shared signals receiver)"
	return c
}

// cmdInbound manages the feeds other systems push events to.
func cmdInbound(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	caller := resolveCaller(root, "")
	note := func(action, name string, extra map[string]string) error {
		d := map[string]string{"feed": name}
		for k, v := range extra {
			d[k] = v
		}
		return recordE(root, caller.auditRecord(action, "/feeds/"+name, audit.Success, d))
	}
	// What a feed says reaches the automations, and some of them change
	// who can get in. Whoever could add a feed could make a signal up and
	// have it acted on, so feeds are a whole-site administrator's decision,
	// as rules that change access are.
	siteAdmin := func() error {
		if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
			return fmt.Errorf("changing a feed is for an administrator of the whole site: %w", err)
		}
		return nil
	}
	switch args[0] {
	case "help":
		return inboundHelp()
	case "list":
		feeds, err := loadFeeds(root)
		if err != nil {
			return err
		}
		status, _ := loadFeedStatus(root)
		if w.JSON(map[string]any{"feeds": feeds, "status": status}) {
			return nil
		}
		if len(feeds) == 0 {
			w.Human("  no feeds; quilzo inbound help says how to add one\n")
		}
		for _, n := range feedNames(feeds) {
			f := feeds[n]
			state := "on"
			if f.Off {
				state = "off"
			}
			st := status[n]
			last := "nothing yet"
			if st != nil && !st.LastAt.IsZero() {
				last = fmt.Sprintf("%d deliveries, last %s", st.Deliveries, st.LastAt.UTC().Format("2 Jan 15:04"))
			}
			w.Human("  %s%s%s  %s  /feeds/%s  [%s]  %s\n", bold, n, reset, f.Kind, n, state, last)
		}
		return nil
	case "status":
		if len(args) != 2 {
			return inboundUsage()
		}
		return inboundStatusOf(root, args[1])
	case "add":
		if len(args) < 3 {
			return inboundUsage()
		}
		if err := siteAdmin(); err != nil {
			return err
		}
		return inboundAdd(root, caller, args[1], args[2], args[3:], note)
	case "connect", "verify":
		if len(args) < 2 {
			return inboundUsage()
		}
		if err := siteAdmin(); err != nil {
			return err
		}
		return inboundConnect(root, args[0], args[1], args[2:], note)
	case "rotate":
		if len(args) != 2 {
			return inboundUsage()
		}
		if err := siteAdmin(); err != nil {
			return err
		}
		return inboundRotate(root, args[1], note)
	case "on", "off":
		if len(args) != 2 {
			return inboundUsage()
		}
		if err := siteAdmin(); err != nil {
			return err
		}
		if err := changeFeed(root, args[1], func(f *inbound.Feed) error { f.Off = args[0] == "off"; return nil }); err != nil {
			return err
		}
		w.Human("%s: %s\n", args[1], args[0])
		return note("inbound."+args[0], args[1], nil)
	case "remove":
		if len(args) != 2 {
			return inboundUsage()
		}
		if err := siteAdmin(); err != nil {
			return err
		}
		return inboundRemove(root, args[1], note)
	}
	return inboundUsage()
}

func inboundHelp() error {
	w.Human(`  Feeds are events other systems push here the moment they happen, at
  https://YOUR-ADMIN/feeds/NAME. Each is proved, stored with the events you
  collect, read by the rules at once, and — when it says something a rule
  can act on — put to the automations (Security, Automations: "Another
  system reports something").

  Okta event hooks
    quilzo inbound add okta okta
    Then in Okta: Workflow, Event Hooks, Create: the URL it prints, the
    Authorization header with the secret it prints, and the events to send
    (sign-ins, lifecycle, sessions, MFA, risk). Okta verifies the address
    once; this answers.

  Anything that signs webhooks (Standard Webhooks, or GitHub)
    quilzo source add billing.json --sample records.jsonl
    quilzo inbound add webhook billing --mapping billing/admin
    quilzo inbound add webhook github --mapping github/audit --github

  OpenID Shared Signals (Okta, Google, Jamf, any SSF 1.0 transmitter)
    quilzo inbound add ssf okta-signals --issuer https://acme.okta.com \
        --url https://admin.acme.example --alias okta
    QUILZO_CONNECT_SECRET=... quilzo inbound connect okta-signals --client-id 0oa...
    The client is one the transmitter issued with the ssf.manage and
    ssf.read scopes. connect asks for the stream and for a verification
    event; quilzo inbound status shows when it arrived.
`)
	return nil
}

func randomState() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func inboundAdd(root string, caller *Caller, kind, name string, rest []string,
	note func(string, string, map[string]string) error) error {

	opts := map[string]string{}
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "--github":
			opts["github"] = "yes"
		case "--mapping", "--issuer", "--url", "--alias", "--audience":
			if i+1 >= len(rest) {
				return fmt.Errorf("%s needs a value", rest[i])
			}
			opts[strings.TrimPrefix(rest[i], "--")] = rest[i+1]
			i++
		default:
			return fmt.Errorf("%q is not an option here", rest[i])
		}
	}
	if kind == "webhook" && opts["github"] != "" {
		kind = "github"
	}
	f, shown, err := makeFeed(root, kind, name, opts, caller.Name)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"feed": f, "path": "/feeds/" + name}) {
		return note("inbound.added", name, map[string]string{"kind": f.Kind})
	}
	w.Human("added %s%s%s (%s)\n  URL: https://YOUR-ADMIN/feeds/%s\n", bold, name, reset, f.Kind, name)
	if f.Kind == inbound.SSF {
		w.Human("  audience: %s\n  keys: %s\n", f.Audience, f.JWKSURI)
	}
	for _, s := range shown {
		w.Human("  %s\n", s)
	}
	return note("inbound.added", name, map[string]string{"kind": f.Kind})
}

// makeFeed adds a feed and returns what to tell its sender, once. kind is
// okta, webhook, github or ssf; opts carries mapping, issuer, url, alias and
// audience as each kind needs.
func makeFeed(root, kind, name string, opts map[string]string, by string) (inbound.Feed, []string, error) {
	if !inbound.ValidName(name) {
		return inbound.Feed{}, nil, fmt.Errorf("%q is not a feed name: 2 to 40 lowercase letters, digits and hyphens", name)
	}
	f := inbound.Feed{Name: name, Created: time.Now().UTC(), By: by}
	var shown []string
	// Secrets are stored only once the feed is known not to clash.
	var later []func() error
	switch kind {
	case "okta":
		f.Kind = inbound.Okta
		if _, err := findSource(root, "okta/system"); err != nil {
			return f, nil, err
		}
		secret, digest, err := inbound.NewSecret()
		if err != nil {
			return f, nil, err
		}
		f.TokenHash = digest
		shown = append(shown, "Authorization header value: "+secret)
	case "webhook", "github":
		f.Kind = inbound.Webhook
		if kind == "github" {
			f.Kind = inbound.GitHub
		}
		if opts["mapping"] == "" {
			return f, nil, fmt.Errorf("a webhook's records need a mapping: --mapping ISSUER/STREAM (quilzo source list)")
		}
		if _, err := findSource(root, opts["mapping"]); err != nil {
			return f, nil, err
		}
		f.Mapping = opts["mapping"]
		var secret string
		var err error
		if f.Kind == inbound.GitHub {
			secret, _, err = inbound.NewSecret()
		} else {
			secret, err = inbound.NewWebhookSecret()
		}
		if err != nil {
			return f, nil, err
		}
		f.Secret = feedSecretName(name)
		later = append(later, func() error { _, err := storeSecret(root, f.Secret, secret); return err })
		shown = append(shown, "signing secret: "+secret)
	case "ssf":
		f.Kind = inbound.SSF
		if opts["issuer"] == "" || opts["url"] == "" {
			return f, nil, fmt.Errorf("a shared signals feed needs the transmitter (--issuer) and this admin's public address (--url)")
		}
		base := strings.TrimSuffix(opts["url"], "/")
		if _, err := fetch.ValidateURL(base); err != nil {
			return f, nil, fmt.Errorf("this admin's address must be public and https: %w", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		t, err := ssf.Discover(ctx, signalsClient(), opts["issuer"])
		if err != nil {
			return f, nil, err
		}
		f.Issuer, f.JWKSURI = t.Issuer, t.JWKSURI
		f.Audience = base + "/feeds/" + name
		if opts["audience"] != "" {
			f.Audience = opts["audience"]
		}
		f.Alias = strings.ToLower(strings.TrimSpace(opts["alias"]))
		secret, digest, err := inbound.NewSecret()
		if err != nil {
			return f, nil, err
		}
		f.TokenHash = digest
		shown = append(shown, "push Authorization header, if you make the stream yourself: Bearer "+secret)
		// Kept sealed so connect can hand the same header to the transmitter.
		later = append(later, func() error { _, err := storeSecret(root, feedSecretName(name)+"-push", secret); return err })
	default:
		return f, nil, fmt.Errorf("%q is not a kind of feed: okta, webhook, github or ssf", kind)
	}
	feedsMu.Lock()
	defer feedsMu.Unlock()
	m, err := loadFeeds(root)
	if err != nil {
		return f, nil, err
	}
	if _, taken := m[name]; taken {
		return f, nil, fmt.Errorf("there is already a feed %q", name)
	}
	for _, do := range later {
		if err := do(); err != nil {
			return f, nil, err
		}
	}
	m[name] = f
	if err := saveFeeds(root, m); err != nil {
		return f, nil, err
	}
	return f, shown, nil
}

func inboundConnect(root, verb, name string, rest []string,
	note func(string, string, map[string]string) error) error {

	m, err := loadFeeds(root)
	if err != nil {
		return err
	}
	f, ok := m[name]
	if !ok || f.Kind != inbound.SSF {
		return fmt.Errorf("%q is not a shared signals feed (quilzo inbound list)", name)
	}
	clientID, tokenURL := "", ""
	for i := 0; i+1 < len(rest); i += 2 {
		switch rest[i] {
		case "--client-id":
			clientID = rest[i+1]
		case "--token-url":
			tokenURL = rest[i+1]
		default:
			return fmt.Errorf("%q is not an option here", rest[i])
		}
	}
	secrets, err := loadSecrets(root)
	if err != nil {
		return err
	}
	credName := feedSecretName(name) + "-client"
	// The client secret is read from the environment the first time and kept
	// sealed, so verify and remove can ask the transmitter again.
	if v := os.Getenv("QUILZO_CONNECT_SECRET"); v != "" && clientID != "" {
		if _, err := storeSecret(root, credName, clientID+"\n"+v); err != nil {
			return err
		}
		secrets[credName] = clientID + "\n" + v
	}
	cred := strings.SplitN(secrets[credName], "\n", 2)
	if len(cred) != 2 {
		return fmt.Errorf("no client to ask the transmitter with: give --client-id, with the secret in QUILZO_CONNECT_SECRET")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	h := signalsClient()
	t, err := ssf.Discover(ctx, h, f.Issuer)
	if err != nil {
		return err
	}
	if t.JWKSURI != f.JWKSURI {
		return fmt.Errorf("%s now publishes its keys at %s, not %s; remove and add the feed again to accept that", f.Issuer, t.JWKSURI, f.JWKSURI)
	}
	if tokenURL == "" {
		if tokenURL, err = ssf.TokenEndpoint(ctx, h, f.Issuer); err != nil {
			return err
		}
	}
	token, err := ssf.ClientCredentials(ctx, h, tokenURL, cred[0], cred[1], []string{"ssf.manage", "ssf.read"})
	if err != nil {
		return err
	}
	if verb == "connect" && f.StreamID == "" {
		push := secrets[feedSecretName(name)+"-push"]
		if push == "" {
			return fmt.Errorf("the push secret for %s is missing; remove and add the feed again", name)
		}
		s, err := t.CreateStream(ctx, h, token, f.Audience, "Bearer "+push, "Quilzo: "+name, ssf.Requested)
		if err != nil {
			return err
		}
		auds := s.Audiences()
		aud := f.Audience
		if len(auds) > 0 && !listHas(auds, f.Audience) {
			aud = auds[0]
		}
		if err := changeFeed(root, name, func(x *inbound.Feed) error {
			x.StreamID, x.Audience, x.Status = s.ID, aud, "enabled"
			return nil
		}); err != nil {
			return err
		}
		f.StreamID = s.ID
		w.Human("stream %s made; %d event types will be sent\n", s.ID, len(s.EventsDelivered))
		_ = note("inbound.stream-created", name, map[string]string{"stream": s.ID})
	}
	if f.StreamID == "" {
		return fmt.Errorf("%s has no stream yet; quilzo inbound connect %s makes one", name, name)
	}
	state := randomState()
	if err := changeFeed(root, name, func(x *inbound.Feed) error { x.State = inbound.Digest(state); return nil }); err != nil {
		return err
	}
	if err := t.RequestVerification(ctx, h, token, f.StreamID, state); err != nil {
		return err
	}
	if st, why, err := t.Status(ctx, h, token, f.StreamID); err == nil {
		_ = changeFeed(root, name, func(x *inbound.Feed) error { x.Status = st; return nil })
		if why != "" {
			st += " (" + why + ")"
		}
		w.Human("the transmitter says the stream is %s\n", st)
	}
	w.Human("verification asked for; quilzo inbound status %s shows when it arrives\n", name)
	return note("inbound.verify-requested", name, nil)
}

func listHas(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func inboundRotate(root, name string, note func(string, string, map[string]string) error) error {
	m, err := loadFeeds(root)
	if err != nil {
		return err
	}
	f, ok := m[name]
	if !ok {
		return fmt.Errorf("there is no feed %q", name)
	}
	var shown string
	switch f.Kind {
	case inbound.Okta:
		secret, digest, err := inbound.NewSecret()
		if err != nil {
			return err
		}
		if err := changeFeed(root, name, func(x *inbound.Feed) error { x.TokenHash = digest; return nil }); err != nil {
			return err
		}
		shown = "new Authorization header value (shown once; the old one stops working now): " + secret
	case inbound.Webhook, inbound.GitHub:
		var secret string
		if f.Kind == inbound.GitHub {
			secret, _, err = inbound.NewSecret()
		} else {
			secret, err = inbound.NewWebhookSecret()
		}
		if err != nil {
			return err
		}
		if _, err := storeSecret(root, f.Secret, secret); err != nil {
			return err
		}
		shown = "new signing secret (shown once; the old one stops working now): " + secret
	default:
		return fmt.Errorf("a shared signals stream's header is the transmitter's to change: remove the feed and add it again")
	}
	w.Human("%s\n", shown)
	return note("inbound.rotated", name, nil)
}

func inboundRemove(root, name string, note func(string, string, map[string]string) error) error {
	warn, err := removeFeed(root, name)
	if err != nil {
		return err
	}
	if warn != "" {
		w.Human("  %s%s%s\n", yellow, warn, reset)
	}
	w.Human("removed %s; anything sent to /feeds/%s is refused from now\n", name, name)
	return note("inbound.removed", name, nil)
}

// removeFeed forgets a feed. A stream this asked a transmitter for is asked
// to stop first, so it does not go on sending to an address that refuses
// everything; what it said if it would not is returned as a warning.
func removeFeed(root, name string) (string, error) {
	m, err := loadFeeds(root)
	if err != nil {
		return "", err
	}
	f, ok := m[name]
	if !ok {
		return "", fmt.Errorf("there is no feed %q", name)
	}
	warn := ""
	if f.Kind == inbound.SSF && f.StreamID != "" {
		warn = "the transmitter was not asked to delete the stream: no client is kept for it"
		secrets, _ := loadSecrets(root)
		if cred := strings.SplitN(secrets[feedSecretName(name)+"-client"], "\n", 2); len(cred) == 2 {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			h := signalsClient()
			warn = ""
			t, err := ssf.Discover(ctx, h, f.Issuer)
			var tokenURL, token string
			if err == nil {
				tokenURL, err = ssf.TokenEndpoint(ctx, h, f.Issuer)
			}
			if err == nil {
				token, err = ssf.ClientCredentials(ctx, h, tokenURL, cred[0], cred[1], []string{"ssf.manage"})
			}
			if err == nil {
				err = t.DeleteStream(ctx, h, token, f.StreamID)
			}
			if err != nil {
				warn = "the transmitter did not delete the stream: " + err.Error()
			}
		}
	}
	feedsMu.Lock()
	defer feedsMu.Unlock()
	m, err = loadFeeds(root)
	if err != nil {
		return warn, err
	}
	delete(m, name)
	return warn, saveFeeds(root, m)
}

func inboundStatusOf(root, name string) error {
	m, err := loadFeeds(root)
	if err != nil {
		return err
	}
	f, ok := m[name]
	if !ok {
		return fmt.Errorf("there is no feed %q", name)
	}
	status, err := loadFeedStatus(root)
	if err != nil {
		return err
	}
	st := status[name]
	if st == nil {
		st = &inboundStatus{}
	}
	if w.JSON(map[string]any{"feed": f, "status": st}) {
		return nil
	}
	w.Human("%s%s%s  %s  /feeds/%s\n", bold, f.Name, reset, f.Kind, f.Name)
	if f.Kind == inbound.SSF {
		v := "not yet"
		if !f.Verified.IsZero() {
			v = f.Verified.Format("2 Jan 2006 15:04")
		}
		w.Human("  from %s; stream %s, %s; verified %s\n", f.Issuer, firstNonEmpty(f.StreamID, "made elsewhere"), firstNonEmpty(f.Status, "status unknown"), v)
	}
	w.Human("  %d deliveries, %d records: %d stored, %d already held, %d did not map; %d signals\n",
		st.Deliveries, st.Records, st.Stored, st.Known, st.Missed, st.Signals)
	if st.Field != "" {
		w.Human("  %smost often missing: %s%s\n", yellow, st.Field, reset)
	}
	if st.Refused > 0 {
		w.Human("  %s%d refused, last %s: %s%s\n", yellow, st.Refused, st.LastRefuse.UTC().Format("2 Jan 15:04"), st.Why, reset)
	}
	if st.Error != "" {
		w.Human("  %s%s%s\n", red, st.Error, reset)
	}
	for _, r := range st.Recent {
		w.Human("  %s  %s  %s  [%s]\n", r.At.UTC().Format("2 Jan 15:04"), r.Type, r.Person, r.Severity)
	}
	return nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
