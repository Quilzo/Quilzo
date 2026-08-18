package agentexec

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// A store with one page published and a second only in the draft.
//
// The published/unpublished split is the whole point: an agent scoped to live
// must not be able to reach the draft page by any phrasing.
func testStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"index": map[string]any{"title": "Home", "body": "Welcome."},
	}, "first", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	// Now an unpublished page, live untouched.
	if _, err := site.SaveDraft(s, map[string]any{
		"index":  map[string]any{"title": "Home", "body": "Welcome."},
		"secret": map[string]any{"title": "Redundancies", "body": "Not public."},
	}, "second", "test"); err != nil {
		t.Fatal(err)
	}
	return s
}

func liveSession(t *testing.T) *agent.Session {
	t.Helper()
	m := agent.Manifest{
		Name: "support", Kind: agent.KindRetrieval,
		Purpose:      "answer from published content",
		Capabilities: []string{"read_page", "list_pages"},
		Autonomy:     agent.AutonomyPropose,
		Retrieval:    agent.Retrieval{Ref: site.RefLive},
		Budget: agent.Budget{
			Steps: 20, Tools: 5, Duration: agent.Duration(time.Hour)},
	}
	return agent.NewSession(m, nil)
}

// The published page is readable and the unpublished one is not.
//
// This is the claim a RAG bot is sold on: it cannot surface a draft. Not
// because the prompt says so — because the ref never comes from the request.
func TestALiveScopedAgentCannotReachTheDraft(t *testing.T) {
	st := testStore(t)
	s := liveSession(t)
	perform := Reader{Store: st}.Perform(s)
	ctx := context.Background()

	got, err := perform(ctx, agent.Action{
		Op: "read_page", Input: map[string]any{"page": "index"}})
	if err != nil {
		t.Fatalf("the published page was not readable: %v", err)
	}
	if !strings.Contains(got, "Welcome.") {
		t.Errorf("the page did not come back: %q", got)
	}

	if _, err := perform(ctx, agent.Action{
		Op: "read_page", Input: map[string]any{"page": "secret"}}); err == nil {
		t.Fatal("an agent scoped to live read a page that is only in the draft")
	}
}

// The ref cannot be supplied by the model.
//
// The action's input is attacker-influencable: it is whatever the model
// produced, and the model may have read a page telling it what to produce. So
// the ref is taken from the manifest and an input naming another is ignored.
func TestTheRefCannotComeFromTheAction(t *testing.T) {
	st := testStore(t)
	s := liveSession(t)
	perform := Reader{Store: st}.Perform(s)

	_, err := perform(context.Background(), agent.Action{
		Op: "read_page",
		Input: map[string]any{
			"page": "secret",
			// Everything a hopeful injection would try.
			"ref": "draft", "reference": "draft", "from": "draft",
		},
	})
	if err == nil {
		t.Fatal("naming a ref in the action reached the draft")
	}
}

// Listing shows only what this agent could actually read.
//
// A page it may not read is a page it should not be told exists: the list is
// how somebody learns that /legal/redundancies is a page.
func TestListingHidesWhatTheScopeExcludes(t *testing.T) {
	st := testStore(t)
	m := agent.Manifest{
		Name: "articles-only", Kind: agent.KindRetrieval,
		Purpose:      "answer about articles",
		Capabilities: []string{"list_pages"},
		Autonomy:     agent.AutonomyPropose,
		Retrieval: agent.Retrieval{
			Ref: site.RefLive, Types: []string{"article"}},
		Budget: agent.Budget{
			Steps: 5, Tools: 2, Duration: agent.Duration(time.Hour)},
	}
	s := agent.NewSession(m, nil)

	r := Reader{Store: st, Types: func(page string) string {
		if page == "index" {
			return "legal" // outside the scope
		}
		return "article"
	}}
	got, err := r.Perform(s)(context.Background(), agent.Action{Op: "list_pages"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "index") {
		t.Errorf("a page outside the type scope was listed: %q", got)
	}
}

// Out of scope and absent give the same answer.
//
// Distinguishing them turns the reader into an oracle for what is in the store,
// which is the disclosure the scope was drawn to prevent.
func TestMissingAndForbiddenAreIndistinguishable(t *testing.T) {
	st := testStore(t)
	s := liveSession(t)
	perform := Reader{Store: st}.Perform(s)
	ctx := context.Background()

	_, errForbidden := perform(ctx, agent.Action{
		Op: "read_page", Input: map[string]any{"page": "secret"}})
	_, errMissing := perform(ctx, agent.Action{
		Op: "read_page", Input: map[string]any{"page": "no-such-page"}})

	if errForbidden == nil || errMissing == nil {
		t.Fatal("one of the two was allowed")
	}
	// Compared with the requested name removed. Echoing back what the caller
	// asked for discloses nothing — they already know it. What must not differ
	// is the shape, because a distinct wording for "exists but forbidden" is
	// what turns this into an oracle for the contents of the store.
	shape := func(err error, name string) string {
		return strings.ReplaceAll(err.Error(), name, "NAME")
	}
	if shape(errForbidden, "secret") != shape(errMissing, "no-such-page") {
		t.Errorf("the answers differ in shape, so this is an oracle:\n  forbidden: %v\n  missing:   %v",
			errForbidden, errMissing)
	}
}

// Reading taints the run, so it cannot publish itself.
func TestReadingThroughTheExecutorTaintsTheSession(t *testing.T) {
	st := testStore(t)
	s := liveSession(t)
	perform := Reader{Store: st}.Perform(s)

	if s.Tainted() {
		t.Fatal("the session was tainted before reading anything")
	}
	if _, err := perform(context.Background(), agent.Action{
		Op: "read_page", Input: map[string]any{"page": "index"}}); err != nil {
		t.Fatal(err)
	}
	if !s.Tainted() {
		t.Error("reading the store did not taint the run")
	}
}

// A manifest naming no ref reads what is published, never the draft.
func TestTheDefaultRefIsLive(t *testing.T) {
	st := testStore(t)
	m := agent.Manifest{
		Name: "unspecified", Kind: agent.KindRetrieval, Purpose: "answer",
		Capabilities: []string{"read_page"}, Autonomy: agent.AutonomyPropose,
		Budget: agent.Budget{
			Steps: 5, Tools: 2, Duration: agent.Duration(time.Hour)},
	}
	s := agent.NewSession(m, nil)

	_, err := Reader{Store: st}.Perform(s)(context.Background(), agent.Action{
		Op: "read_page", Input: map[string]any{"page": "secret"}})
	if err == nil {
		t.Fatal("a manifest naming no ref defaulted to the draft")
	}
}

// Output is bounded.
func TestAPageIsTruncated(t *testing.T) {
	if got := truncate(strings.Repeat("x", MaxBody+500)); len(got) <= MaxBody {
		t.Errorf("truncate produced %d bytes", len(got))
	} else if !strings.Contains(got, "truncated") {
		t.Error("truncation is silent, so the model cannot tell it was cut")
	}
}

// Fields come back in a stable order.
func TestRenderIsDeterministic(t *testing.T) {
	page := map[string]any{"z": 1, "a": 2, "m": 3}
	first := render(page)
	for range 20 {
		if render(page) != first {
			t.Fatal("the same page rendered two different ways; a trace that " +
				"differs between runs for no reason cannot be diffed")
		}
	}
	if !strings.HasPrefix(first, "a: ") {
		t.Errorf("fields are not sorted: %q", first)
	}
}
