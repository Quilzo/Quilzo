package agentexec

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/quilzo/quilzo/internal/collab"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// Writing, which is where an agent stops being an opinion.
//
// # Three rules, and none of them is a new mechanism
//
// A write lands on the draft ref. Never live, never a ref an action names —
// Session.Mutate refuses the live ref outright, so a manifest cannot ask for it
// and neither can a model. What the public is being served changes when a
// person says so, which is the same rule the CLI and the API already follow.
//
// A write is compare-and-swap against the commit the run started from. The
// store has had exact optimistic control since content-addressing arrived, and
// an agent is precisely the writer it was built for: something that reads,
// thinks for thirty seconds, and writes back into a store somebody else has
// been editing meanwhile. Without the base, an agent's write silently reverts
// whatever a person did during those thirty seconds.
//
// A publish does not publish. It records a proposal against the draft, authored
// by the agent and marked as machine-written, and internal/collab's existing
// rule — an author may not approve their own change, and an AI-authored change
// needs a human whatever the count says — decides the rest. Nothing here had to
// invent an approval queue, or a human-in-the-loop feature, or a special case
// for AI: the rule that stops a person rubber-stamping their own work already
// stops this, because a model is not one of the principals the policy names.
//
// # What this deliberately does not do
//
// No delete. An agent that can remove pages is one prompt injection away from
// removing them, and the argument that it needs to is much weaker than the
// argument for writing: a page emptied of content by a write is recoverable
// from the previous commit and visible in a diff, whereas somebody has to
// notice a page is missing to go looking for it. When there is a reason, it
// goes through this file and this comment gets shorter.

// MaxWrite bounds one page an agent may write.
//
// Smaller than the assistant's per-page limit on purpose. That one bounds a
// proposal a person is about to read; this one bounds a write that lands in the
// store on the agent's own say-so, and the step budget means a run can perform
// several. A model that has been talked into filling the store cannot do it one
// large page at a time.
const MaxWrite = 64 << 10

// AgentCommitPrefix marks a commit as machine-written, in the message, where
// the review queue reads it.
//
// A constant rather than a literal in two files: the writer that sets it and
// the classifier that reads it have to agree, and a string that has to match
// across a package boundary is one somebody eventually edits on one side.
const AgentCommitPrefix = collab.AgentPrefix

// Writer performs the write operations an agent holds.
//
// Constructed with the same field shape as Reader so that a caller wiring both
// is looking at one pattern, and so the scope questions are answered from the
// same two functions rather than from two different ideas of what a page's type
// is.
type Writer struct {
	Store *store.Store
	// Types and Locale resolve a page's type and language for the scope check,
	// exactly as they do for reads. Nil means nothing is typed.
	Types  func(page string) string
	Locale func(page string) string

	// Gate validates a page against the type bound to it, and is the same gate
	// every other writer passes. Nil means no types are configured, which is
	// the honest answer for a store with none — and not an excuse to skip a
	// check that exists.
	Gate func(page string, body map[string]any) error

	// Author is what the commit records. An agent's name, not a person's: a
	// commit attributed to whoever happened to start the run is a commit whose
	// history lies about who wrote it.
	Author string

	// Propose records a proposal for a commit, for the publish operation. Nil
	// means this deployment has no review queue wired in, and publish is then
	// refused rather than quietly performed — a publish that cannot be
	// reviewed is the one that most needs to be.
	Propose func(commit, message string) error
}

// Perform is the agent.Perform for a session's write operations.
//
// Composed with a Reader by the caller rather than embedding one, because a
// manifest that grants writes and not reads is legitimate — an agent that
// only appends does not need to be handed the ability to read the site.
func (wr Writer) Perform(s *agent.Session) func(context.Context, agent.Action) (string, error) {
	// The base for compare-and-swap: what the draft was when this run began.
	// Captured once, advanced by each successful write, and never re-read from
	// the ref — re-reading is what turns compare-and-swap back into last-write
	// wins, one call at a time.
	base := wr.Store.GetRef(site.RefDraft)
	if base == "" {
		base = wr.Store.GetRef(site.RefLive)
	}

	return func(ctx context.Context, a agent.Action) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		// Re-asked here, not assumed from the caller. Free and idempotent —
		// see Session.Check. An executor whose safety depends on whoever
		// constructed it having called Authorize first is an executor that is
		// safe until the second surface wires it up.
		if err := s.Check(a.Op); err != nil {
			return "", err
		}
		switch a.Op {
		case "write_page":
			out, cid, err := wr.writePage(s, base, a)
			if err != nil {
				return "", err
			}
			base = cid
			return out, nil
		case "publish":
			return wr.publish(s, base)
		default:
			return "", fmt.Errorf(
				"%q is permitted for this agent and is not a write this "+
					"executor performs", a.Op)
		}
	}
}

// writePage stores one page on the draft, returning the new commit.
func (wr Writer) writePage(s *agent.Session, base string, a agent.Action) (string, string, error) {
	name := nameFrom(a)
	if strings.TrimSpace(name) == "" {
		return "", "", fmt.Errorf("no page was named")
	}
	if !assist.ValidPageName(name) {
		// Said in terms of the name rather than of the store, because the
		// reader of this message is debugging a model's output.
		return "", "", fmt.Errorf(
			"%q is not a usable page name: letters, digits, dot, dash and "+
				"underscore, starting with a letter or digit", name)
	}

	fields, err := fieldsFrom(a)
	if err != nil {
		return "", "", err
	}

	// The scope check before anything is built, and against the type already
	// bound to the page — not against a type the action claims. A model that
	// could name its own type would be choosing which scope applies to it.
	if err := s.Mutate(site.RefDraft, wr.typeOf(name), wr.localeOf(name)); err != nil {
		return "", "", err
	}

	encoded, err := json.Marshal(fields)
	if err != nil {
		return "", "", fmt.Errorf("that page cannot be stored: %w", err)
	}
	if len(encoded) > MaxWrite {
		return "", "", fmt.Errorf(
			"that page is %d bytes and the limit for one agent write is %d",
			len(encoded), MaxWrite)
	}

	// The type gate, the same one the CLI and the API pass. An agent writing
	// content that does not satisfy the type bound to its page is how a site
	// acquires pages that render to nothing.
	if wr.Gate != nil {
		if err := wr.Gate(name, fields); err != nil {
			return "", "", err
		}
	}

	pages, err := site.PagesAt(wr.Store, site.RefDraft)
	if err != nil {
		return "", "", err
	}
	if pages == nil {
		pages = map[string]any{}
	}
	pages[name] = fields

	// The "agent:" prefix is load-bearing, not decoration.
	//
	// The review queue decides whether a change was machine-written by reading
	// the commit message, and an AI-authored proposal needs a human approver
	// whatever the numeric threshold says. A commit message that did not say
	// so would put an agent's work in front of reviewers labelled as somebody's
	// own — which is the one thing that rule exists to prevent.
	msg := fmt.Sprintf("%s%s wrote %s", AgentCommitPrefix, s.Manifest().Name, name)
	cid, err := site.SaveDraftFrom(wr.Store, pages, msg, wr.Author, base)
	if err != nil {
		// A conflict is returned as it is. The model does not get a retry
		// loop here: something else changed the draft, and an agent that
		// re-reads and writes again is an agent that overwrites a person's
		// edit on the second attempt instead of the first.
		return "", "", err
	}
	return fmt.Sprintf("wrote %s in %s", name, shortID(cid)), cid, nil
}

// publish records a proposal for the draft, and does not move the live ref.
//
// The gate has already refused if this agent may not publish, if a person has
// to approve first, or if the run read stored content — so by the time this
// runs, the only thing left is to put the change in front of the people who
// decide.
func (wr Writer) publish(s *agent.Session, commit string) (string, error) {
	if commit == "" {
		return "", fmt.Errorf("there is no draft to publish")
	}
	if wr.Propose == nil {
		return "", fmt.Errorf(
			"this deployment has no review queue wired in, so there is " +
				"nowhere for an agent's publish to be reviewed. Refused " +
				"rather than performed")
	}
	name := s.Manifest().Name
	if err := wr.Propose(commit, fmt.Sprintf(
		"%s proposes publishing %s", name, shortID(commit))); err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"proposed %s for publication. It is machine-written, so a person "+
			"approves it before anything is public", shortID(commit)), nil
}

// fieldsFrom reads the page body an action supplied.
//
// Only an object. A page that is a string or a number is not a page this store
// can bind a type to, and accepting one would put a value in the tree that
// every reader downstream has to type-assert around.
func fieldsFrom(a agent.Action) (map[string]any, error) {
	var raw any
	for _, k := range []string{"fields", "body", "content"} {
		if v, ok := a.Input[k]; ok {
			raw = v
			break
		}
	}
	if raw == nil {
		return nil, fmt.Errorf(
			"no fields were given; a write needs the page's content under " +
				"\"fields\"")
	}
	fields, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf(
			"a page's fields have to be an object, and that is a %T", raw)
	}
	// Sorted only to make the failure deterministic; the map itself is stored.
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.TrimSpace(k) == "" {
			return nil, fmt.Errorf("a field has an empty name")
		}
	}
	return fields, nil
}

func shortID(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// typeOf and localeOf mirror Reader's, resolving through the caller's hooks.
//
// Duplicated rather than shared through an embedded Reader, because embedding
// would give every Writer a working read path — and an agent granted writes
// and not reads would then be one field access away from having both.
func (wr Writer) typeOf(page string) string {
	if wr.Types == nil {
		return ""
	}
	return wr.Types(page)
}

func (wr Writer) localeOf(page string) string {
	if wr.Locale == nil {
		return ""
	}
	return wr.Locale(page)
}

// Dispatch routes each operation to the executor that performs it.
//
// Composed here rather than at each call site, because "which executor answers
// write_page" is not a question three surfaces should each have their own
// answer to — and the wrong answer is silent: a reads-only dispatch returns
// "not implemented" for a write the manifest granted, which reads to whoever
// wired it as the agent behaving correctly.
//
// Routing is by agent.IsWrite, the same classification the session gate uses.
// Two ideas of what counts as a write is how an operation ends up dispatched to
// the writer and checked as a read.
func Dispatch(read Reader, write Writer, s *agent.Session) func(context.Context, agent.Action) (string, error) {
	r := read.Perform(s)
	w := write.Perform(s)
	return func(ctx context.Context, a agent.Action) (string, error) {
		if agent.IsWrite(a.Op) {
			return w(ctx, a)
		}
		return r(ctx, a)
	}
}
