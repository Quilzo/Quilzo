// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package waiting

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/memory"
	"github.com/quilzo/quilzo/internal/newsletter"
)

// everything is one of each thing that waits, for dana to look at, with
// May answering whatever allowed says.
func everything(now time.Time, allowed map[auth.Action]bool) Sources {
	asked := agent.Pending{N: 2, Since: now.Add(-time.Hour), Action: agent.Action{Op: "read_page"}, Why: "it asks first"}
	old := agent.Pending{N: 3, Kind: agent.WaitQuestion, Since: now.Add(-agent.PendingTTL - time.Hour),
		Action: agent.Action{Op: "decide"}, Questions: []agent.Question{{Name: "city", Ask: "Which city?", Confidence: 0.5}}}
	return Sources{Name: "dana",
		May: func(act auth.Action, _ string) bool { return allowed[act] },
		Runs: func() ([]agent.Record, error) {
			return []agent.Record{
				agent.Keep("run-20261104-000000a1", "sam", "m", now, agent.Trace{Agent: "tidy", Goal: "g", Waiting: &asked}, agent.Receipt{}),
				agent.Keep("run-20261104-000000a2", "sam", "m", now, agent.Trace{Agent: "tidy", Goal: "g", Waiting: &old}, agent.Receipt{}),
			}, nil
		},
		MayDecide: func(agent.Record) bool { return allowed[auth.ActApprove] },
		Held: func() ([]Held, error) {
			return []Held{{ID: "h1", Integration: "crm", Tool: "create_contact", For: "rae", Asked: now}}, nil
		},
		Pending: func() ([]feature.Pending, error) {
			return []feature.Pending{{ID: "f1", Name: "lab", Version: "1.0.0", RequestedBy: "sam", At: now}}, nil
		},
		Review: func() (*Review, error) {
			return &Review{Policy: collab.Policy{Required: 1},
				Proposal: collab.Proposal{Content: "c1", Author: "sam", CreatedAt: now.Add(-3 * time.Hour).Unix()}}, nil
		},
		Issues: func() ([]newsletter.Issue, error) {
			return []newsletter.Issue{{Page: "index", Subject: "Autumn", State: newsletter.Proposed, Proposed: now}}, nil
		},
		Memories: func(f memory.Filter) ([]memory.Entry, error) {
			return []memory.Entry{{ID: "m1", Agent: "tidy", About: "dana", Held: true, Created: now}}, nil
		},
	}
}

func sourcesOf(items []Item) []string {
	var out []string
	for _, it := range items {
		out = append(out, it.Source)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// A read-only credential decides nothing, so it is offered nothing, even
// when the person holding it may decide everything.
func TestAReadOnlySessionIsOfferedNothingToDecide(t *testing.T) {
	now := time.Now()
	all := map[auth.Action]bool{auth.ActApprove: true, auth.ActInstall: true, auth.ActPublish: true, auth.ActGrant: true}
	src := everything(now, all)
	if items, _ := List(src, now); len(sourcesOf(items)) != 6 {
		t.Fatalf("control: an administrator is offered %v", sourcesOf(items))
	}
	src.ReadOnly = true
	if items, _ := List(src, now); len(items) != 0 {
		t.Errorf("a read-only session is offered %+v", items)
	}
}

// Each source is offered on the permission deciding it takes, asked of the
// session: the review and a newsletter issue on publish, an install on
// install, a held call on approve, and a person's own memories always.
func TestEachSourceIsOfferedOnThePermissionDecidingItTakes(t *testing.T) {
	now := time.Now()
	for act, want := range map[auth.Action][]string{
		auth.ActPublish: {"memory", "newsletter", "review"},
		auth.ActInstall: {"feature", "memory"},
		auth.ActApprove: {"gateway", "memory", "run"},
		auth.ActView:    {"memory"},
	} {
		items, err := List(everything(now, map[auth.Action]bool{act: true}), now)
		if err != nil {
			t.Fatal(err)
		}
		if got := sourcesOf(items); !slices.Equal(got, want) {
			t.Errorf("a session that may %s is offered %v, not %v", act, got, want)
		}
	}
}

// A question asked too long ago to agree to is listed and marked, and is
// never let go ahead with others; the review has waited since it was
// proposed.
func TestWhatWaitsIsMarkedAndDatedByWhatItIs(t *testing.T) {
	now := time.Now()
	items, err := List(everything(now, map[auth.Action]bool{auth.ActApprove: true, auth.ActPublish: true}), now)
	if err != nil {
		t.Fatal(err)
	}
	var question, ask, review *Item
	for i, it := range items {
		switch {
		case it.Source == "run" && it.Kind == agent.WaitQuestion:
			question = &items[i]
		case it.Source == "run":
			ask = &items[i]
		case it.Source == "review":
			review = &items[i]
		}
	}
	if question == nil || !question.Expired || question.Batch != "" || question.What != "Answer: Which city?" ||
		!strings.HasPrefix(question.Decide, "quilzo agent answer run-20261104-000000a2 3 city=") {
		t.Errorf("the expired question is listed as %+v", question)
	}
	if ask == nil || ask.Expired || ask.Batch == "" {
		t.Errorf("the fresh read is listed as %+v", ask)
	}
	if review == nil || now.Sub(review.Since) < 3*time.Hour-time.Minute || review.Why != "0 of 1 approvals; " {
		t.Errorf("the review is listed as %+v", review)
	}
}

// `quilzo approvals --json` keeps every key it printed, and an item with
// only those set prints no others.
func TestTheApprovalsJSONKeepsEveryKeyItHad(t *testing.T) {
	b, err := json.Marshal(Item{Source: "run", Agent: "tidy", What: "write_page", Why: "it asks first",
		Commits: "writes", Since: time.Now(), Decide: "quilzo agent approve r 1"})
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]any
	if err := json.Unmarshal(b, &keys); err != nil {
		t.Fatal(err)
	}
	var got []string
	for k := range keys {
		got = append(got, k)
	}
	slices.Sort(got)
	if want := []string{"agent", "commits", "decide", "since", "source", "what", "why"}; !slices.Equal(got, want) {
		t.Errorf("the JSON has the keys %v, not %v", got, want)
	}
}

// The change waiting for review is offered to the people whose approval
// counts. Asked only who may publish, the list offered it, with approvers
// named, to somebody they leave out, whose approval counted for nothing.
func TestTheReviewIsOfferedOnlyToWhoeverTheApproversNamed(t *testing.T) {
	now := time.Now()
	src := everything(now, map[auth.Action]bool{auth.ActPublish: true})
	src.Review = func() (*Review, error) {
		return &Review{Policy: collab.Policy{Required: 1, Approvers: []string{"lee"}},
			Proposal: collab.Proposal{Content: "c1", Author: "sam", CreatedAt: now.Unix()}}, nil
	}
	items, err := List(src, now)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(sourcesOf(items), "review") {
		t.Error("dana, whom the approvers do not name, is offered the review")
	}
	src.Name = "lee"
	if items, _ := List(src, now); !slices.Contains(sourcesOf(items), "review") {
		t.Error("lee, whom the approvers name, is not offered the review")
	}
}
