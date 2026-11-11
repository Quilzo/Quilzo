// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/dual"
	"github.com/quilzo/quilzo/internal/out"
)

// The approval policy is the four-eyes rule itself, so changing it is an
// administrator's act, and asking less of it is two administrators', as
// `quilzo config set review.required_approvals` already was.
//
// `quilzo review require` asked an author's edit-draft and nothing else:
// with alice and bob administrators and `review require 2` in force, carol,
// an author, ran `review require 0`, it wrote {"required":0}, and the next
// publish went live with no approvals while the same lowering through
// `config set` waited for the second administrator.

// approvalFile is approval.json as it stands, or nothing.
func approvalFile(t *testing.T, root string) string {
	t.Helper()
	b, err := os.ReadFile(approvalPolicyPath(root))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}

// appliedPolicy is the approval policy publishing is asked about.
func appliedPolicy(t *testing.T, root string) collab.Policy {
	t.Helper()
	p, err := loadApprovalPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAnAuthorCannotChangeHowManyApprovalsPublishingNeeds(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, dana, _ := twoAdmins(t)
	seedPolicy(t, root, [2]string{"carol", "author"})
	carol, _ := issueFor(t, root, "carol")
	t.Setenv("QUILZO_TOKEN", dana)
	if err := cmdReview(root, []string{"require", "2"}); err != nil {
		t.Fatal(err)
	}
	before := approvalFile(t, root)

	t.Setenv("QUILZO_TOKEN", carol)
	for _, args := range [][]string{{"require", "0"}, {"require", "1"}, {"require", "3"},
		{"require", "2", "--approvers", "carol"}} {
		// The gate in front of the command, as `quilzo review require`
		// is run.
		err := authoriseCommand(root, "review", args)
		if err == nil {
			t.Errorf("an author was let run quilzo review %s", strings.Join(args, " "))
		} else if !strings.Contains(err.Error(), "quilzo config set review.required_approvals") ||
			!strings.Contains(err.Error(), "second administrator") {
			t.Errorf("the refusal does not say how the count is changed, and by whom: %v", err)
		}
		// And the command itself, however it is reached.
		if err := cmdReview(root, args); err == nil {
			t.Errorf("quilzo review %s ran for an author", strings.Join(args, " "))
		}
		if got := approvalFile(t, root); got != before {
			t.Fatalf("an author's quilzo review %s rewrote approval.json: %s", strings.Join(args, " "), got)
		}
	}
	if p := appliedPolicy(t, root); p.Required != 2 {
		t.Fatalf("an author changed how many approvals publishing needs: %+v", p)
	}
	// Reading it, and approving (which asks publish of its own), are still
	// let through as they were, a bare `quilzo review` included.
	for _, args := range [][]string{nil, {"status"}, {"approve"}} {
		if err := authoriseCommand(root, "review", args); err != nil {
			t.Errorf("an author may no longer run quilzo review %s: %v", strings.Join(args, " "), err)
		}
	}
}

func TestLoweringTheApprovalCountWaitsForASecondAdministratorOnEveryPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, dana, lee := twoAdmins(t)
	t.Setenv("QUILZO_TOKEN", dana)

	// Raising is one administrator's, at once.
	if err := cmdReview(root, []string{"require", "2", "--humans", "2"}); err != nil {
		t.Fatal(err)
	}
	if p := appliedPolicy(t, root); p.Required != 2 || p.RequiredHumans != 2 {
		t.Fatalf("raising the count waited: %+v", p)
	}

	// Every way of asking fewer people waits, and nothing is written until
	// another administrator approves it.
	for _, args := range [][]string{{"require", "0"}, {"require", "1", "--humans", "1"},
		{"require", "2", "--humans", "1"}, {"require", "2"}} {
		before := approvalFile(t, root)
		if err := cmdReview(root, args); err != nil {
			t.Fatal(err)
		}
		if got := approvalFile(t, root); got != before {
			t.Fatalf("quilzo review %s wrote approval.json on one administrator's word: %s", strings.Join(args, " "), got)
		}
		if p := appliedPolicy(t, root); p.Required != 2 || p.RequiredHumans != 2 {
			t.Fatalf("quilzo review %s took effect on one administrator's word: %+v", strings.Join(args, " "), p)
		}
		r := waiting(t, root)
		if r.Kind != dual.Approval {
			t.Fatalf("quilzo review %s waits as a %s", strings.Join(args, " "), r.Kind)
		}
		if err := cmdPending(root, []string{"approve", r.ID}); err == nil {
			t.Fatal("dana approved her own lowering")
		}
		t.Setenv("QUILZO_TOKEN", lee)
		if err := cmdPending(root, []string{"decline", r.ID}); err != nil {
			t.Fatal(err)
		}
		t.Setenv("QUILZO_TOKEN", dana)
	}

	// Approved by the other, it is made.
	if err := cmdReview(root, []string{"require", "0"}); err != nil {
		t.Fatal(err)
	}
	r := waiting(t, root)
	t.Setenv("QUILZO_TOKEN", lee)
	if err := cmdPending(root, []string{"approve", r.ID}); err != nil {
		t.Fatal(err)
	}
	if p := appliedPolicy(t, root); p.Required != 0 || p.RequiredHumans != 0 {
		t.Fatalf("approved, and publishing still needs %+v", p)
	}
	if e := lastEvent(t, root, "review.policy"); e == nil || e.Detail["request"] != r.ID {
		t.Errorf("the approved policy was not recorded with its request: %+v", e)
	}

	// The count compared is the one that applies, not the file's: with the
	// settings at three and the file at nothing, asking for two is asking
	// fewer people.
	t.Setenv("QUILZO_TOKEN", dana)
	if err := cmdConfig(root, []string{"set", "review.required_approvals", "3"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdReview(root, []string{"require", "2"}); err != nil {
		t.Fatal(err)
	}
	if p := appliedPolicy(t, root); p.Required != 3 {
		t.Fatalf("the file lowered what the settings ask on one administrator's word: %+v", p)
	}
	r = waiting(t, root)
	if err := cmdPending(root, []string{"withdraw", r.ID}); err != nil {
		t.Fatal(err)
	}
	// And `config set`, the other path, waits as it did.
	if err := cmdConfig(root, []string{"set", "review.required_approvals", "1"}); err != nil {
		t.Fatal(err)
	}
	if mustConfig(root).Int("review.required_approvals") != 3 {
		t.Fatal("config set lowered the count on one administrator's word")
	}
	if err := cmdPending(root, []string{"withdraw", waiting(t, root).ID}); err != nil {
		t.Fatal(err)
	}

	// The only administrator lowers it alone, and the record says so; not
	// for a day after the other stopped being one.
	if err := cmdReview(root, []string{"require", "4"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAuth(root, []string{"revoke", "lee", "admin"}); err != nil {
		t.Fatal(err)
	}
	before := approvalFile(t, root)
	if err := cmdReview(root, []string{"require", "0"}); err != nil {
		t.Fatal(err)
	}
	if approvalFile(t, root) != before || appliedPolicy(t, root).Required != 4 {
		t.Fatal("the count was lowered alone a moment after the other administrator was removed")
	}
	if e := lastEvent(t, root, "dual.alone-refused"); e == nil || e.Detail["kind"] != dual.Approval {
		t.Errorf("approving alone was not refused on the record: %+v", e)
	}
	if err := cmdPending(root, []string{"withdraw", waiting(t, root).ID}); err != nil {
		t.Fatal(err)
	}
	removalAt(t, root, dual.Settle+time.Minute)
	if err := cmdReview(root, []string{"require", "0"}); err != nil {
		t.Fatal(err)
	}
	// Three, from the settings: the file asks for none.
	if p := appliedPolicy(t, root); p.Required != 3 {
		t.Fatalf("the only administrator could not lower the count once the day was over: %+v", p)
	}
	if e := lastEvent(t, root, "dual.approved"); e == nil || e.Detail["alone"] != "true" || e.Detail["kind"] != dual.Approval {
		t.Errorf("the record does not say the lowering was approved alone: %+v", e)
	}
}

// What `review require` says is the count publishing is asked about.
// With the settings at two, `review require 0` said "publishing needs no
// approvals" while two were still required.
func TestReviewRequireSaysTheCountThatApplies(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	root := configured(t, "review.required_approvals", "2")
	said, err := humanOutput(t, func() error { return cmdReview(root, []string{"require", "0"}) })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(said, "needs no approvals") || !strings.Contains(said, "2 approval") ||
		!strings.Contains(said, "review.required_approvals") {
		t.Errorf("with the settings at two it said:\n%s", said)
	}
	if p := appliedPolicy(t, root); p.Required != 2 {
		t.Fatalf("control: %+v", p)
	}

	old := w
	t.Cleanup(func() { w = old })
	var b strings.Builder
	w = &out.Writer{Mode: out.JSON, Out: &b, Err: &strings.Builder{}}
	if err := cmdReview(root, []string{"require", "0"}); err != nil {
		t.Fatal(err)
	}
	var said2 collab.Policy
	if err := json.Unmarshal([]byte(b.String()), &said2); err != nil {
		t.Fatalf("%v: %s", err, b.String())
	}
	if said2.Required != 2 {
		t.Errorf("--json says publishing needs %d approvals while 2 apply", said2.Required)
	}
}

// `review require --approvers` names whose approval counts, and it did
// not: the list was written to approval.json and never read back, so the
// command said "from: dana" and lee's approval published the change.
func TestTheApproversNamedAreTheOnesWhoseApprovalCounts(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, dana, lee := twoAdmins(t)
	t.Setenv("QUILZO_TOKEN", dana)

	// From anybody who may publish to dana alone is fewer people: one
	// administrator's, at once.
	if err := cmdReview(root, []string{"require", "1", "--approvers", "dana"}); err != nil {
		t.Fatal(err)
	}
	p := appliedPolicy(t, root)
	if strings.Join(p.Approvers, ",") != "dana" {
		t.Fatalf("the approvers named are not the policy's: %+v", p)
	}
	prop := collab.Proposal{Content: "abc", Author: "kit", AuthorKind: "human"}
	people := func(string) string { return "human" }
	byLee := prop
	if err := byLee.Approve("lee", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	if d := p.Evaluate(byLee, people, time.Now()); d.Allowed {
		t.Fatal("lee's approval counted, and only dana's should")
	}
	byDana := prop
	if err := byDana.Approve("dana", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	if d := p.Evaluate(byDana, people, time.Now()); !d.Allowed {
		t.Fatalf("dana's approval did not count: %s", d.Reason)
	}

	// Back to anybody, or to somebody the list does not name, is more
	// people whose approval counts: two administrators'.
	for _, args := range [][]string{{"require", "1"}, {"require", "1", "--approvers", "lee"},
		{"require", "1", "--approvers", "dana,lee"}} {
		if err := cmdReview(root, args); err != nil {
			t.Fatal(err)
		}
		if got := appliedPolicy(t, root); strings.Join(got.Approvers, ",") != "dana" {
			t.Fatalf("quilzo review %s widened whose approval counts on one administrator's word: %+v",
				strings.Join(args, " "), got)
		}
		r := waiting(t, root)
		t.Setenv("QUILZO_TOKEN", lee)
		if err := cmdPending(root, []string{"decline", r.ID}); err != nil {
			t.Fatal(err)
		}
		t.Setenv("QUILZO_TOKEN", dana)
	}

	// A file written with no list, as every one was before, is anybody who
	// may publish.
	if err := saveJSON(approvalPolicyPath(root), collab.Policy{Required: 1}); err != nil {
		t.Fatal(err)
	}
	if got := appliedPolicy(t, root); len(got.Approvers) != 0 {
		t.Fatalf("a file with no approvers names some: %+v", got)
	}
	if d := appliedPolicy(t, root).Evaluate(byLee, people, time.Now()); !d.Allowed {
		t.Fatalf("with no list, a publisher's approval did not count: %s", d.Reason)
	}
}

// Whoever decides a request to change whose approval counts reads whom it
// would count from. It said "to somebody the list in force does not name"
// and no more, in quilzo pending list and show as on People, so the second
// administrator let somebody's approval count without being told whose.
// The names stay out of the record of the request, which copies what it
// says in clear.
func TestWhoeverDecidesWhoseApprovalCountsReadsWhose(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, dana, lee := twoAdmins(t)
	t.Setenv("QUILZO_TOKEN", dana)
	if err := cmdReview(root, []string{"require", "1", "--approvers", "lee"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdReview(root, []string{"require", "1", "--approvers", "lee,sam"}); err != nil {
		t.Fatal(err)
	}
	r := waiting(t, root)
	t.Setenv("QUILZO_TOKEN", lee)
	for _, args := range [][]string{{"list"}, {"show", r.ID}} {
		said, err := humanOutput(t, func() error { return cmdPending(root, args) })
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(said, "lee, sam") {
			t.Errorf("quilzo pending %s does not say whose approval would count:\n%s", args[0], said)
		}
	}
	if e := lastEvent(t, root, "dual.proposed"); e == nil || strings.Contains(e.Detail["what"], "sam") {
		t.Errorf("the record of the request names the approvers in clear: %+v", e)
	}
}
