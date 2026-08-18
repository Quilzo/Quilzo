// Package agentexec carries out the actions an agent was authorised to take.
//
// # Why this is not in internal/agent
//
// That package decides what an agent may do and deliberately cannot reach the
// store or the network. Keeping the decision away from the doing is what makes
// the decision testable without either, and it means a mistake here cannot
// widen a manifest — everything below runs after Session.Authorize has already
// said yes, and calls Session.Retrieve before it reads anything.
//
// # The scope check is here rather than at the call site
//
// A retrieval agent is declared to read the live ref. The manifest says so and
// the session enforces it, but only if somebody asks — and "somebody remembers
// to ask" is how the type gate came to be checked in the CLI and not the API.
//
// So the ref is not a parameter. It is read from the manifest, every read goes
// through Retrieve first, and an action that names a different ref is refused
// rather than honoured. A support bot cannot be asked for the draft, however
// the question is phrased, because the phrasing never reaches this decision.
package agentexec

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// MaxBody bounds what one read returns to the model.
//
// A page is content somebody wrote and can be arbitrarily long; an agent that
// reads one is spending context and money on it. Truncating is honest here in
// a way it usually is not, because the alternative is a run that fails on a
// page nobody thought was large.
const MaxBody = 8 << 10

// Reader performs the read operations an agent holds.
type Reader struct {
	Store *store.Store
	// Types resolves a page's content type, for the scope check. Nil means
	// nothing is typed, which is the honest answer for a store with no types
	// and is treated as unrestricted by Session.Retrieve.
	Types func(page string) string
	// Locale resolves a page's language, for the same reason.
	Locale func(page string) string
}

// Perform is the agent.Perform for a session.
//
// It closes over the session rather than taking it per call, because the ref an
// action may read is a property of the agent and not of the request — and a
// signature that accepted a ref would be one somebody eventually passes from
// the model's input.
func (r Reader) Perform(s *agent.Session) func(context.Context, agent.Action) (string, error) {
	ref := s.Manifest().Retrieval.Ref
	if ref == "" {
		// A manifest that names no ref reads what is published. Never the
		// draft by default: an agent answering from unpublished content is a
		// disclosure with a friendly interface, and defaults are what most
		// installations run.
		ref = site.RefLive
	}

	return func(ctx context.Context, a agent.Action) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		switch a.Op {
		case "list_pages":
			return r.listPages(s, ref)
		case "read_page":
			return r.readPage(s, ref, nameFrom(a))
		case "diff":
			// Deliberately absent for now rather than approximated. A diff
			// spans two refs, and an agent scoped to one has not been granted
			// the other — answering with a diff that quietly includes the
			// draft would defeat the scope this file exists to enforce.
			return "", fmt.Errorf(
				"diff is not available to a scoped agent: it spans two refs " +
					"and this agent is scoped to one")
		default:
			// Authorized() let it through, so this is an operation the
			// manifest holds and this executor has not learned yet. Said
			// plainly rather than returning empty, which would read to the
			// model as "there is nothing there".
			return "", fmt.Errorf(
				"%q is permitted for this agent and not implemented here", a.Op)
		}
	}
}

func (r Reader) listPages(s *agent.Session, ref string) (string, error) {
	// The scope check before the read, always. Type and locale are empty for a
	// listing because a listing is not one typed thing; the per-page check
	// happens in readPage.
	if err := s.Retrieve(ref, "", ""); err != nil {
		return "", err
	}
	pages, err := site.PagesAt(r.Store, ref)
	if err != nil {
		return "", err
	}
	names := make([]string, 0, len(pages))
	for n := range pages {
		// A page the agent could not read is a page it should not be told
		// exists. Listing it is a disclosure of structure, which is how
		// somebody learns that /legal/redundancies is a page.
		if r.allowed(s, ref, n) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "no pages this agent may read", nil
	}
	return strings.Join(names, "\n"), nil
}

func (r Reader) readPage(s *agent.Session, ref, name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("no page was named")
	}
	if err := s.Retrieve(ref, r.typeOf(name), r.localeOf(name)); err != nil {
		return "", err
	}
	pages, err := site.PagesAt(r.Store, ref)
	if err != nil {
		return "", err
	}
	page, ok := pages[name]
	if !ok {
		// The same answer whether it does not exist or is out of scope.
		// Distinguishing them turns this into an oracle for what is in the
		// store, which is the disclosure the scope was drawn to prevent.
		return "", fmt.Errorf("no page %q that this agent may read", name)
	}
	return truncate(render(page)), nil
}

// allowed reports whether the scope lets this agent see a page, without
// spending anything or recording a refusal.
//
// A separate, quiet check because listing must not fill the audit record with
// a refusal per page the agent was never going to be shown.
func (r Reader) allowed(s *agent.Session, ref, name string) bool {
	m := s.Manifest()
	return within(m.Retrieval.Types, r.typeOf(name)) &&
		withinLocale(m.Retrieval.Locales, r.localeOf(name))
}

func (r Reader) typeOf(page string) string {
	if r.Types == nil {
		return ""
	}
	return r.Types(page)
}

func (r Reader) localeOf(page string) string {
	if r.Locale == nil {
		return ""
	}
	return r.Locale(page)
}

func within(list []string, v string) bool {
	if len(list) == 0 || v == "" {
		return true
	}
	for _, item := range list {
		if strings.EqualFold(item, v) {
			return true
		}
	}
	return false
}

func withinLocale(list []string, v string) bool {
	if len(list) == 0 || v == "" {
		return true
	}
	for _, item := range list {
		if strings.EqualFold(item, v) ||
			strings.HasPrefix(strings.ToLower(v), strings.ToLower(item)+"-") {
			return true
		}
	}
	return false
}

// nameFrom reads the page name an action asked for.
func nameFrom(a agent.Action) string {
	if v, ok := a.Input["page"].(string); ok {
		return v
	}
	if v, ok := a.Input["name"].(string); ok {
		return v
	}
	return ""
}

// render turns a decoded page into something a model can read.
//
// Field order is sorted rather than map order, because an agent asked the same
// question twice should get the same answer — and because a trace that differs
// between runs for no reason is a trace nobody can diff.
func render(page any) string {
	fields, ok := page.(map[string]any)
	if !ok {
		return fmt.Sprint(page)
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %v\n", k, fields[k])
	}
	return b.String()
}

func truncate(s string) string {
	if len(s) <= MaxBody {
		return s
	}
	return s[:MaxBody] + "\n…truncated at " + fmt.Sprint(MaxBody) + " bytes"
}
