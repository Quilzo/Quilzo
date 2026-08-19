package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/agentexec"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// The review queue has to recognise an agent's work as machine-written.
//
// This is the join between two packages that have no compile-time relationship:
// agentexec writes a commit message, and the classifier here reads it. The rule
// riding on it is the one that matters most in the whole agent design — an
// AI-authored change needs a human approver, whatever the numeric threshold
// says — and it turns entirely on this string comparison.
//
// A prefix that stopped matching would not break a build or fail a request. It
// would put an agent's work in front of reviewers labelled as somebody's own,
// and the human-approval rule would sit there not firing.
func TestAnAgentsCommitEntersTheQueueAsMachineWritten(t *testing.T) {
	root := t.TempDir()
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}

	// A commit written exactly as the agent executor writes one.
	msg := agentexec.AgentCommitPrefix + "scribe wrote news"
	if _, err := site.SaveDraft(s, map[string]any{
		"news": map[string]any{"title": "News"},
	}, msg, "agent/scribe"); err != nil {
		t.Fatal(err)
	}

	prop, _, err := currentProposal(root, s)
	if err != nil {
		t.Fatal(err)
	}
	if prop.AuthorKind != "ai" {
		t.Errorf("a commit written by an agent entered the review queue as "+
			"%q. RequireHumanForAI turns on this field, so a wrong answer "+
			"here is the human-approval rule silently not applying.\n"+
			"  message: %q", prop.AuthorKind, msg)
	}
	if prop.Content != s.GetRef(site.RefDraft) {
		t.Error("the proposal does not name the draft it is about")
	}
}

// A person's commit is still a person's.
//
// The other direction, and the one a broadened prefix breaks: classifying
// everything as AI would demand a human approver for every change, which is
// how a control that fires constantly gets configured away.
func TestAPersonsCommitIsNotClassifiedAsMachineWritten(t *testing.T) {
	root := t.TempDir()
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"news": map[string]any{"title": "News"},
	}, "correct the pricing table", "dana"); err != nil {
		t.Fatal(err)
	}

	prop, _, err := currentProposal(root, s)
	if err != nil {
		t.Fatal(err)
	}
	if prop.AuthorKind != "human" {
		t.Errorf("a person's commit was classified %q", prop.AuthorKind)
	}
}

// The type gate an agent passes fails closed on an unreadable type store.
//
// Treating a broken types.json as "no types configured" would make corrupting
// one file the way to switch validation off for every page — which is the
// exact shape of the fail-open authorisation bug this project already shipped
// once and had to fix.
func TestTheAgentTypeGateFailsClosed(t *testing.T) {
	root := t.TempDir()
	if err := writeFile(t, root, "types.json", "{ not json"); err != nil {
		t.Fatal(err)
	}
	err := pageGate(root)("news", map[string]any{"title": "N"})
	if err == nil {
		t.Fatal("an unreadable type store let a write through unchecked")
	}
	if !strings.Contains(err.Error(), "could not be read") {
		t.Errorf("the refusal does not say the store was unreadable: %v", err)
	}
}

func writeFile(t *testing.T, dir, name, body string) error {
	t.Helper()
	return os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600)
}
