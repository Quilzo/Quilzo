// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package web performs an agent's web actions: reading an address
// (web_fetch) and searching (web_search).
//
// Reading is a GET, over https, through the program's client that refuses
// private addresses and revalidates every redirect (internal/fetch), of a
// host the declaration names or, when it says "any", any public host. A
// page is read as a person reads it, its words and its links, without its
// scripts, styles and forms (internal/webimport); text and JSON are read
// as they are; anything else is said and not read. Searching asks the
// provider the operator configured (internal/websearch).
//
// Both bring back somebody else's words, so both taint the run. Neither
// sends anything a person has not seen once the run holds something
// private: the address and the query are the model's words, and the
// breaker holds them (internal/agent, webSends).
package web

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/webimport"
	"github.com/quilzo/quilzo/internal/websearch"
)

// Bounds on what the web actions bring back.
const (
	// MaxFetched is the largest answer read.
	MaxFetched = 4 << 20
	// MaxShown is how much of what was read is given back.
	MaxShown = 48 << 10
	// MaxLinks is how many of a page's links are listed.
	MaxLinks = 40
)

// Page is what reading an address brought back.
type Page struct {
	// URL is where it was read from, after redirects.
	URL         string
	ContentType string
	Body        []byte
}

// Driver performs the web's actions for one run.
type Driver struct {
	Session *agent.Session
	// Get reads an address: the program's guarded client in a run.
	Get func(ctx context.Context, address string) (Page, error)
	// Search is the provider agents.search names, and Do how it is asked;
	// a zero Provider is none configured.
	Search websearch.Provider
	Do     websearch.Do
	// Key is the provider's key, read when a search needs it; Base is
	// agents.search_url.
	Key  func() (string, error)
	Base string
	// Plain allows http, for tests on loopback only.
	Plain bool
}

// Performs reports whether the driver performs an action.
func Performs(a agent.Action) bool { return a.Tool == "" && a.Delegate == "" && agent.IsWeb(a.Op) }

// Perform wraps a run's performer: the web's actions here, the rest passed
// on.
func (d *Driver) Perform(next func(context.Context, agent.Action) (string, error)) func(context.Context, agent.Action) (string, error) {
	return func(ctx context.Context, a agent.Action) (string, error) {
		if !Performs(a) {
			return next(ctx, a)
		}
		if err := d.Session.Check(a.Op); err != nil {
			return "", err
		}
		switch a.Op {
		case "web_fetch":
			return d.fetch(ctx, str(a, "url"))
		case "web_search":
			n, _ := a.Input["count"].(float64)
			return d.search(ctx, str(a, "query"), int(n))
		}
		return "", fmt.Errorf("%q is not one of the web's actions", a.Op)
	}
}

func str(a agent.Action, k string) string {
	v, _ := a.Input[k].(string)
	return strings.TrimSpace(v)
}

func (d *Driver) fetch(ctx context.Context, raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%q is not an address to read", raw)
	}
	if u.Scheme != "https" && !(d.Plain && u.Scheme == "http") {
		return "", fmt.Errorf("%s: an agent reads https addresses only", u.Redacted())
	}
	if u.User != nil {
		return "", errors.New("an address with a user name or password in it is not read")
	}
	host := strings.ToLower(u.Hostname())
	web := d.Session.Manifest().Web
	if !web.Reads(host) {
		return "", fmt.Errorf("%s is not a host this agent may read", host)
	}
	if d.Get == nil {
		return "", errors.New("this run cannot reach the web")
	}
	page, err := d.Get(ctx, u.String())
	if err != nil {
		return "", err
	}
	// Where it landed is held to the declaration too: a redirect is the
	// site's choice, and what it leads to is read only if this agent may.
	final, err := url.Parse(page.URL)
	if err != nil || final.Host == "" {
		final = u
	}
	if fh := strings.ToLower(final.Hostname()); !web.Reads(fh) {
		return "", fmt.Errorf("%s sent it on to %s, which is not a host this agent may read", host, fh)
	}
	d.Session.ReadWeb(strings.ToLower(final.Hostname()), final.Redacted())
	return Render(final, page.ContentType, page.Body), nil
}

// Render is what was read, as the model is given it: a page's words and
// links, text as it is, and anything else described.
func Render(u *url.URL, contentType string, body []byte) string {
	media, _, _ := mime.ParseMediaType(contentType)
	if media == "" {
		media = sniff(body)
	}
	head := fmt.Sprintf("read %s (%s, %d bytes)\n", u.Redacted(), media, len(body))
	switch {
	case media == "text/html" || media == "application/xhtml+xml":
		return head + page(webimport.Read(body, u))
	case strings.HasPrefix(media, "text/") || media == "application/json" || strings.HasSuffix(media, "+json") ||
		media == "application/xml" || strings.HasSuffix(media, "+xml") || media == "application/javascript":
		if !utf8.Valid(body) {
			return head + "it is not text in UTF-8, so it is not read"
		}
		return head + clip(string(body), MaxShown)
	}
	return head + "it is not text (a picture, a PDF or a file), so it is not read here; " +
		"a browser or a command in a workspace reads it"
}

func sniff(body []byte) string {
	b := strings.ToLower(strings.TrimSpace(string(body[:min(len(body), 512)])))
	switch {
	case strings.HasPrefix(b, "<!doctype html") || strings.HasPrefix(b, "<html"):
		return "text/html"
	case strings.HasPrefix(b, "{") || strings.HasPrefix(b, "["):
		return "application/json"
	case utf8.Valid(body):
		return "text/plain"
	}
	return "application/octet-stream"
}

// page is a page read as a person reads it.
func page(p webimport.Page) string {
	var b strings.Builder
	if p.Title != "" {
		fmt.Fprintf(&b, "# %s\n", p.Title)
	}
	if p.Description != "" {
		fmt.Fprintf(&b, "%s\n", p.Description)
	}
	b.WriteByte('\n')
	for _, bl := range p.Blocks {
		text := bl.MD
		if text == "" {
			text = bl.Text
		}
		switch {
		case bl.Kind == "img":
			if bl.Text != "" {
				fmt.Fprintf(&b, "[picture: %s]\n", bl.Text)
			}
		case len(bl.Kind) == 2 && bl.Kind[0] == 'h':
			fmt.Fprintf(&b, "\n%s %s\n", strings.Repeat("#", int(bl.Kind[1]-'0')), text)
		case bl.Kind == "li" || bl.Kind == "ol":
			fmt.Fprintf(&b, "- %s\n", text)
		case bl.Kind == "quote":
			fmt.Fprintf(&b, "> %s\n", text)
		case bl.Kind == "pre":
			fmt.Fprintf(&b, "```\n%s\n```\n", text)
		default:
			fmt.Fprintf(&b, "%s\n", text)
		}
		if b.Len() > MaxShown {
			break
		}
	}
	text := clip(b.String(), MaxShown)
	if len(p.Links) > 0 {
		var l strings.Builder
		fmt.Fprintf(&l, "\nLinks (%d", len(p.Links))
		if len(p.Links) > MaxLinks {
			fmt.Fprintf(&l, ", the first %d", MaxLinks)
		}
		l.WriteString("):\n")
		for i, u := range p.Links {
			if i == MaxLinks {
				break
			}
			fmt.Fprintf(&l, "- %s\n", u.Redacted())
		}
		text += l.String()
	}
	return text
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + fmt.Sprintf("\n… and %d bytes more, not shown", len(s)-n)
}

func (d *Driver) search(ctx context.Context, query string, count int) (string, error) {
	p := d.Search
	if p.ID == "" {
		return "", errors.New("no search provider is set up here (agents.search names one, and its key is " +
			"quilzo secret set search-NAME)")
	}
	key := ""
	if p.Key != "none" {
		if d.Key == nil {
			return "", fmt.Errorf("%s needs its key: quilzo secret set %s", p.Name, p.Secret())
		}
		k, err := d.Key()
		if err != nil {
			return "", fmt.Errorf("%s needs its key: quilzo secret set %s", p.Name, p.Secret())
		}
		key = strings.TrimSpace(k)
	}
	if d.Do == nil {
		return "", errors.New("this run cannot reach the web")
	}
	results, err := p.Search(ctx, d.Do, query, count, key, d.Base)
	if err != nil {
		return "", err
	}
	d.Session.ReadWeb(p.ID, "a search of "+p.Name)
	if len(results) == 0 {
		return fmt.Sprintf("%s found nothing for %q", p.Name, query), nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s found %d for %q:\n", p.Name, len(results), query)
	for i, r := range results {
		fmt.Fprintf(&b, "%d. %s\n   %s\n", i+1, nonEmpty(r.Title, "(untitled)"), r.URL)
		if r.Summary != "" {
			fmt.Fprintf(&b, "   %s\n", r.Summary)
		}
	}
	return b.String(), nil
}

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
