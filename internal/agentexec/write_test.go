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

// writerSession is a task agent that may write and publish.
func writerSession(t *testing.T, types []string, autonomy agent.Autonomy) *agent.Session {
	t.Helper()
	m := agent.Manifest{
		Name: "editor", Kind: agent.KindTask, Purpose: "write things",
		Capabilities: []string{"list_pages", "read_page", "write_page", "publish"},
		Autonomy:     autonomy,
		Retrieval:    agent.Retrieval{Types: types},
		Budget: agent.Budget{
			Steps: 20, Tools: 5, Duration: agent.Duration(time.Minute)},
	}
	return agent.NewSession(m, nil)
}

func write(t *testing.T, wr Writer, s *agent.Session, page string, fields map[string]any) (string, error) {
	t.Helper()
	perform := wr.Perform(s)
	return perform(context.Background(), agent.Action{
		Op: "write_page", Input: map[string]any{"page": page, "fields": fields},
	})
}

// The ordinary case, so the rest of these are about the refusals rather than
// about a write path that never worked.
func TestAnAgentWritesToTheDraft(t *testing.T) {
	s := testStore(t)
	sess := writerSession(t, nil, agent.AutonomyDraft)
	before := s.GetRef(site.RefLive)

	out, err := write(t, Writer{Store: s, Author: "agent/editor"}, sess,
		"pricing", map[string]any{"title": "Pricing", "body": "Numbers."})
	if err != nil {
		t.Fatalf("a draft-autonomy agent could not write: %v", err)
	}
	if !strings.Contains(out, "pricing") {
		t.Errorf("the result does not name what was written: %q", out)
	}

	pages, err := site.PagesAt(s, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pages["pricing"]; !ok {
		t.Error("the page is not in the draft, so the write went nowhere")
	}
	// The half that matters. A write that also moved live would have skipped
	// every review this program has.
	if s.GetRef(site.RefLive) != before {
		t.Error("writing moved the live ref. An agent's write is a draft; " +
			"what the public sees changes when a person says so")
	}
	if _, ok := site.PagesOf(s, before)["pricing"]; ok {
		t.Error("the page is published")
	}
}

// A propose-only agent does not write, whatever its capability list says.
func TestAProposeOnlyAgentCannotWrite(t *testing.T) {
	s := testStore(t)
	sess := writerSession(t, nil, agent.AutonomyPropose)

	_, err := write(t, Writer{Store: s}, sess, "pricing",
		map[string]any{"title": "Pricing"})
	if err == nil {
		t.Fatal("a propose-only agent wrote to the store")
	}
	if pages, _ := site.PagesAt(s, site.RefDraft); pages["pricing"] != nil {
		t.Error("the refusal did not prevent the write")
	}
}

// The scope binds writes, and does so asymmetrically on purpose.
func TestAScopedAgentCannotWriteOutsideItsTypes(t *testing.T) {
	s := testStore(t)
	types := func(page string) string {
		switch page {
		case "guide":
			return "article"
		case "terms":
			return "legal"
		}
		return "" // untyped
	}
	wr := Writer{Store: s, Types: types, Author: "agent/editor"}

	sess := writerSession(t, []string{"article"}, agent.AutonomyDraft)
	if _, err := write(t, wr, sess, "guide",
		map[string]any{"title": "Guide"}); err != nil {
		t.Fatalf("an article agent could not write an article: %v", err)
	}
	if _, err := write(t, wr, sess, "terms",
		map[string]any{"title": "Terms"}); err == nil {
		t.Error("an agent scoped to articles wrote a page bound to the legal " +
			"type")
	}

	// The asymmetry, and the reason it is here. Reading an untyped page inside
	// a type scope is allowed — an untyped page is not a page of some secret
	// type. Writing one is not, because otherwise "create a page nobody typed"
	// is the way around every type scope in every manifest.
	_, err := write(t, wr, sess, "brand-new", map[string]any{"title": "New"})
	if err == nil {
		t.Error("an agent scoped to articles created an untyped page, which " +
			"is the way around every type scope there is")
	}
	if err != nil && !strings.Contains(err.Error(), "no type bound") {
		t.Errorf("the refusal does not explain the asymmetry: %v", err)
	}

	// And an agent that declared no type scope is unrestricted, which is what
	// keeps this working for a store with no types at all.
	open := writerSession(t, nil, agent.AutonomyDraft)
	if _, err := write(t, wr, open, "anything",
		map[string]any{"title": "Anything"}); err != nil {
		t.Errorf("an unscoped agent was refused an untyped page: %v", err)
	}
}

// A write is compare-and-swap against what the run started from.
//
// The case this exists for is mundane and constant: an agent reads, spends
// thirty seconds in a model, and writes back into a store somebody has been
// editing meanwhile. Without a base, the agent's write silently reverts them.
func TestAWriteDoesNotOverwriteWhatChangedDuringTheRun(t *testing.T) {
	s := testStore(t)
	sess := writerSession(t, nil, agent.AutonomyDraft)
	wr := Writer{Store: s, Author: "agent/editor"}

	// The run begins: the base is captured here.
	perform := wr.Perform(sess)

	// A person edits while the agent is thinking.
	pages, err := site.PagesAt(s, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	pages["index"] = map[string]any{"title": "Home", "body": "Edited by a person."}
	if _, err := site.SaveDraft(s, pages, "human edit", "dana"); err != nil {
		t.Fatal(err)
	}

	_, err = perform(context.Background(), agent.Action{
		Op:    "write_page",
		Input: map[string]any{"page": "pricing", "fields": map[string]any{"title": "P"}},
	})
	if err == nil {
		t.Fatal("the agent wrote over an edit made during its run")
	}

	after, err := site.PagesAt(s, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := after["index"].(map[string]any)
	if body["body"] != "Edited by a person." {
		t.Errorf("the person's edit was lost: %v", after["index"])
	}
}

// Names a model produces cannot leave the page namespace.
func TestAModelCannotNameItsWayOutOfThePageNamespace(t *testing.T) {
	s := testStore(t)
	sess := writerSession(t, nil, agent.AutonomyDraft)
	wr := Writer{Store: s, Author: "agent/editor"}

	for _, name := range []string{
		"../escape", "data/records", "/etc/passwd", ".hidden", "", "a/b",
		strings.Repeat("x", 200),
	} {
		if _, err := write(t, wr, sess, name,
			map[string]any{"title": "x"}); err == nil {
			t.Errorf("a page called %q was accepted", name)
		}
	}
}

// Size is bounded, because a run has a step budget and each step could be large.
func TestOneWriteIsBounded(t *testing.T) {
	s := testStore(t)
	sess := writerSession(t, nil, agent.AutonomyDraft)

	_, err := write(t, Writer{Store: s}, sess, "big",
		map[string]any{"body": strings.Repeat("a", MaxWrite+1)})
	if err == nil {
		t.Fatal("an unbounded page was written")
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Errorf("the refusal does not say it is a limit: %v", err)
	}
}

// The type gate an agent passes is the one every other writer passes.
func TestAWriteIsCheckedAgainstTheTypeBoundToThePage(t *testing.T) {
	s := testStore(t)
	sess := writerSession(t, nil, agent.AutonomyDraft)
	called := false
	wr := Writer{
		Store: s, Author: "agent/editor",
		Gate: func(page string, body map[string]any) error {
			called = true
			if body["title"] == nil {
				return errMissingTitle
			}
			return nil
		},
	}

	if _, err := write(t, wr, sess, "typed",
		map[string]any{"body": "no title"}); err == nil {
		t.Error("content that fails the type gate was written")
	}
	if !called {
		t.Fatal("the type gate was never consulted, so an agent writes " +
			"content nothing validates")
	}
	if pages, _ := site.PagesAt(s, site.RefDraft); pages["typed"] != nil {
		t.Error("the failing page landed in the store anyway")
	}
}

var errMissingTitle = &gateError{"title is required"}

type gateError struct{ s string }

func (e *gateError) Error() string { return e.s }

// Publishing proposes and does not publish.
func TestPublishProposesRatherThanPublishing(t *testing.T) {
	s := testStore(t)
	m := agent.Manifest{
		Name: "shipper", Kind: agent.KindTask, Purpose: "ship",
		Capabilities: []string{"write_page", "publish"},
		Autonomy:     agent.AutonomyPublish,
		Budget: agent.Budget{
			Steps: 20, Tools: 5, Duration: agent.Duration(time.Minute)},
	}
	sess := agent.NewSession(m, nil)

	var proposed string
	wr := Writer{
		Store: s, Author: "agent/shipper",
		Propose: func(commit, message string) error {
			proposed = commit
			return nil
		},
	}
	perform := wr.Perform(sess)

	if _, err := perform(context.Background(), agent.Action{
		Op:    "write_page",
		Input: map[string]any{"page": "news", "fields": map[string]any{"title": "N"}},
	}); err != nil {
		t.Fatal(err)
	}
	before := s.GetRef(site.RefLive)

	if _, err := perform(context.Background(), agent.Action{Op: "publish"}); err != nil {
		t.Fatalf("a publish-autonomy agent could not propose: %v", err)
	}
	if proposed == "" {
		t.Error("nothing was put in front of a person")
	}
	if s.GetRef(site.RefLive) != before {
		t.Error("an agent moved the live ref. Publishing is the one action " +
			"with an outside observer, and it carries a person")
	}
}

// With no review queue wired in, publish is refused rather than performed.
func TestPublishIsRefusedWhenThereIsNowhereToReviewIt(t *testing.T) {
	s := testStore(t)
	m := agent.Manifest{
		Name: "shipper", Kind: agent.KindTask, Purpose: "ship",
		Capabilities: []string{"write_page", "publish"},
		Autonomy:     agent.AutonomyPublish,
		Budget: agent.Budget{
			Steps: 20, Tools: 5, Duration: agent.Duration(time.Minute)},
	}
	sess := agent.NewSession(m, nil)
	perform := Writer{Store: s, Author: "agent/shipper"}.Perform(sess)

	_, err := perform(context.Background(), agent.Action{Op: "publish"})
	if err == nil {
		t.Fatal("publish succeeded with no queue behind it")
	}
	if !strings.Contains(err.Error(), "review") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

// A run that read stored content does not publish, refused at the gate.
//
// Publishable() answered this at the end of a run, about a run that had
// already happened. The refusal has to come before the action.
func TestARunDownstreamOfStoredContentIsRefusedThePublish(t *testing.T) {
	s := testStore(t)
	m := agent.Manifest{
		Name: "shipper", Kind: agent.KindTask, Purpose: "ship",
		Capabilities: []string{"read_page", "publish"},
		Autonomy:     agent.AutonomyPublish,
		Budget: agent.Budget{
			Steps: 20, Tools: 5, Duration: agent.Duration(time.Minute)},
	}
	sess := agent.NewSession(m, nil)
	called := false
	wr := Writer{Store: s, Propose: func(string, string) error {
		called = true
		return nil
	}}
	rd := Reader{Store: s}
	perform := Dispatch(rd, wr, sess)

	// It reads a page — content anybody who can write a page may have written.
	if _, err := perform(context.Background(), agent.Action{
		Op: "read_page", Input: map[string]any{"page": "index"},
	}); err != nil {
		t.Fatalf("the read failed, so this test proves nothing: %v", err)
	}

	_, err := perform(context.Background(), agent.Action{Op: "publish"})
	if err == nil {
		t.Fatal("a run downstream of untrusted content published itself")
	}
	if !agent.IsRefusal(err) {
		t.Errorf("that is not a policy refusal, so nothing recorded it as " +
			"one in the audit trail")
	}
	if called {
		t.Error("the proposal was created anyway; the gate ran after the act")
	}
}

// Dispatch routes by the same classification the gate uses.
func TestDispatchSendsWritesToTheWriterAndReadsToTheReader(t *testing.T) {
	s := testStore(t)
	sess := writerSession(t, nil, agent.AutonomyDraft)
	perform := Dispatch(Reader{Store: s}, Writer{Store: s, Author: "a"}, sess)

	out, err := perform(context.Background(), agent.Action{Op: "list_pages"})
	if err != nil {
		t.Fatalf("a read was not routed to the reader: %v", err)
	}
	if !strings.Contains(out, "index") {
		t.Errorf("the reader did not answer: %q", out)
	}
	if _, err := perform(context.Background(), agent.Action{
		Op:    "write_page",
		Input: map[string]any{"page": "x", "fields": map[string]any{"t": "1"}},
	}); err != nil {
		t.Fatalf("a write was not routed to the writer: %v", err)
	}
}

// The commit says it was machine-written, where the review queue reads it.
func TestAnAgentsCommitSaysItWasMachineWritten(t *testing.T) {
	s := testStore(t)
	sess := writerSession(t, nil, agent.AutonomyDraft)

	if _, err := write(t, Writer{Store: s, Author: "agent/editor"}, sess,
		"news", map[string]any{"title": "N"}); err != nil {
		t.Fatal(err)
	}
	commit, err := s.GetCommit(s.GetRef(site.RefDraft))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(commit.Message, AgentCommitPrefix) {
		t.Errorf("the commit message is %q, which the review queue will read "+
			"as somebody's own work. An AI-authored change needs a human "+
			"approver, and this is where that is decided.", commit.Message)
	}
	if !strings.Contains(commit.Author, "editor") {
		t.Errorf("the commit is attributed to %q rather than to the agent",
			commit.Author)
	}
}

var _ = store.Store{}
