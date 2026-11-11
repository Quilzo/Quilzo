// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package collab

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

func kinds(m map[string]string) KindOf {
	return func(p string) string {
		if k, ok := m[p]; ok {
			return k
		}
		return "human"
	}
}

var people = kinds(map[string]string{
	"dana": "human", "sam": "human", "kit": "human",
	"svc-deploy": "service", "assistant": "ai",
})

// -- the property that makes approval mean something -------------------------

// Everywhere else, approval is a flag on a request: the row moves to
// "approved", somebody with edit rights changes the content, and the flag
// stays. Here an approval names a content hash, so editing invalidates it by
// construction — no rule has to notice.
func TestEditingContentInvalidatesItsApprovals(t *testing.T) {
	p := NewPolicy()
	prop := Proposal{Content: "aaa", Author: "dana", AuthorKind: "human"}

	if err := prop.Approve("sam", "looks right", now); err != nil {
		t.Fatal(err)
	}
	if err := prop.Approve("kit", "agreed", now); err != nil {
		t.Fatal(err)
	}
	if d := p.Evaluate(prop, people, now); !d.Allowed {
		t.Fatalf("two approvals were not enough: %s", d.Reason)
	}

	// Dana edits one character. Nothing detects this; the approvals simply
	// name content that is no longer proposed.
	prop.Rebase("bbb", "dana", now)

	d := p.Evaluate(prop, people, now)
	if d.Allowed {
		t.Fatal("approvals of the previous content still authorised the new " +
			"content — this is the hole every ticket-based review system has")
	}
	if d.Have != 0 {
		t.Errorf("%d approvals were counted after the content changed", d.Have)
	}

	// And the old ones are kept as history, because "who approved this before
	// it was edited" is a real question.
	if len(prop.Stale()) != 2 {
		t.Errorf("the superseded approvals were discarded; an auditor asking "+
			"who signed off the previous version gets nothing: %v", prop.Stale())
	}
}

// -- four eyes ---------------------------------------------------------------

func TestAnAuthorCannotApproveTheirOwnChange(t *testing.T) {
	prop := Proposal{Content: "aaa", Author: "dana", AuthorKind: "human"}
	if err := prop.Approve("dana", "it's fine", now); err == nil {
		t.Fatal("the author approved their own change")
	}

	// Even if one is forced into the record — a hand-edited file, a bug
	// elsewhere — evaluation must not count it.
	prop.Approvals = append(prop.Approvals, Approval{
		Content: "aaa", By: "dana", At: now.Unix()})
	d := NewPolicy().Evaluate(prop, people, now)
	if d.Allowed {
		t.Fatal("a forged self-approval was counted")
	}
	// And the refusal has to name the situation, or it reads as the system
	// being broken rather than as the rule working.
	if !strings.Contains(d.Reason, "cannot also approve") {
		t.Errorf("the refusal does not explain itself: %s", d.Reason)
	}
}

func TestOnePersonClickingTwiceIsStillOnePerson(t *testing.T) {
	prop := Proposal{Content: "aaa", Author: "dana", AuthorKind: "human"}
	if err := prop.Approve("sam", "yes", now); err != nil {
		t.Fatal(err)
	}
	if err := prop.Approve("sam", "yes again", now); err == nil {
		t.Error("the same person approved twice")
	}
	// Forced in anyway, evaluation must still count one.
	prop.Approvals = append(prop.Approvals, Approval{
		Content: "aaa", By: "sam", At: now.Unix()})
	if d := NewPolicy().Evaluate(prop, people, now); d.Have != 1 {
		t.Errorf("counted %d approvals from one person", d.Have)
	}
}

// Only the named approvers count, when a list is set. Otherwise "two approvals"
// is satisfiable by two accounts somebody created.
func TestOnlyNamedApproversCount(t *testing.T) {
	p := Policy{Required: 2, Approvers: []string{"sam", "kit"}}
	prop := Proposal{Content: "aaa", Author: "dana", AuthorKind: "human"}
	_ = prop.Approve("sam", "", now)
	_ = prop.Approve("nobody-in-particular", "", now)

	d := p.Evaluate(prop, people, now)
	if d.Allowed {
		t.Fatal("an approval from outside the list counted")
	}
	// And the interface should be able to say who is still needed.
	if len(d.Missing) == 0 || d.Missing[0] != "kit" {
		t.Errorf("the outstanding approver was not named: %v", d.Missing)
	}
}

// -- human in the loop -------------------------------------------------------

// A model's work reaching the public with a service account's approval is two
// machines agreeing with each other, which is not what anybody means by review.
func TestAnAIChangeNeedsAHumanEvenWithEnoughApprovals(t *testing.T) {
	p := Policy{Required: 1, RequireHumanForAI: true}
	prop := Proposal{Content: "aaa", Author: "assistant", AuthorKind: "ai"}
	if err := prop.Approve("svc-deploy", "automated check passed", now); err != nil {
		t.Fatal(err)
	}

	d := p.Evaluate(prop, people, now)
	if d.Allowed {
		t.Fatal("a model's change was published on a service account's approval")
	}
	if !strings.Contains(d.Reason, "person") {
		t.Errorf("the refusal does not say what is needed: %s", d.Reason)
	}

	if err := prop.Approve("dana", "read it, it's accurate", now); err != nil {
		t.Fatal(err)
	}
	if d := p.Evaluate(prop, people, now); !d.Allowed {
		t.Fatalf("a human approval did not unblock it: %s", d.Reason)
	}
}

// The rule that stops Dana rubber-stamping her own work is the same rule that
// stops a model shipping unreviewed. Asserted so that removing the general rule
// cannot quietly remove the AI protection.
func TestTheAIRuleIsTheSelfApprovalRule(t *testing.T) {
	p := Policy{Required: 1, RequireHumanForAI: false}
	prop := Proposal{Content: "aaa", Author: "assistant", AuthorKind: "ai"}
	prop.Approvals = append(prop.Approvals, Approval{
		Content: "aaa", By: "assistant", At: now.Unix()})

	if d := p.Evaluate(prop, people, now); d.Allowed {
		t.Fatal("a model approved its own change; self-approval must apply " +
			"whatever the author is")
	}
}

// -- concurrency -------------------------------------------------------------

// A conflict that touches nothing in common is a conflict only in the sense
// that the ref moved. Reporting it as a collision teaches people to retry
// blindly, which is how the real ones get retried blindly too.
func TestAConflictKnowsWhetherItActuallyCollides(t *testing.T) {
	c := Conflict{
		Expected: "aaaaaaaaaaaaaaaa", Actual: "bbbbbbbbbbbbbbbb",
		By: "sam", At: now, Pages: []string{"about", "pricing"},
	}
	if both := c.Overlaps([]string{"index", "contact"}); len(both) != 0 {
		t.Errorf("an unrelated edit was reported as colliding: %v", both)
	}
	if both := c.Overlaps([]string{"index", "pricing"}); len(both) != 1 ||
		both[0] != "pricing" {
		t.Errorf("a real collision was not identified: %v", both)
	}
}

// The message has to say who to talk to. "Conflict detected" makes somebody go
// looking; a name makes them go asking.
func TestAConflictSaysWhoMovedItAndWhen(t *testing.T) {
	c := Conflict{
		Expected: "aaaaaaaaaaaaaaaa", Actual: "bbbbbbbbbbbbbbbb",
		By: "sam", At: now, Pages: []string{"about"},
	}
	msg := c.Error()
	for _, want := range []string{"sam", "about", "aaaaaaaaaaaa", "bbbbbbbbbbbb"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message omits %q: %s", want, msg)
		}
	}

	// And with no overlap it should say the retry is safe.
	c.Pages = nil
	if !strings.Contains(c.Error(), "safe to retry") {
		t.Errorf("a non-colliding conflict does not say so: %s", c.Error())
	}
}

// -- advisory locks ----------------------------------------------------------

// A lock that outlives its holder is the failure mode of every checkout system.
func TestLocksExpireOnTheirOwn(t *testing.T) {
	var ls Locks
	ls.Claim("about", "dana", "rewriting", now)

	if _, held := ls.Holder("about", now); !held {
		t.Fatal("a fresh claim is not held")
	}
	later := now.Add(MaxLock + time.Minute)
	if _, held := ls.Holder("about", later); held {
		t.Error("the lock outlived its expiry; this is the stale lock that " +
			"makes every checkout system grow a break-lock button")
	}
	if len(ls.Active(later)) != 0 {
		t.Error("an expired lock is still listed as active")
	}
}

// Taking a lock somebody holds is permitted and reports theirs. Refusing would
// make this a real lock, a real lock needs a break-glass button, and the button
// is the problem.
func TestClaimingAHeldPageReportsWhoHasItRatherThanRefusing(t *testing.T) {
	var ls Locks
	ls.Claim("about", "dana", "rewriting the intro", now)

	mine, existing := ls.Claim("about", "sam", "fixing a typo", now)
	if mine.Holder != "sam" {
		t.Error("the second claim was refused; locks here are advisory")
	}
	if existing == nil {
		t.Fatal("the existing holder was not reported, so the interface " +
			"cannot warn anybody")
	}
	if existing.Holder != "dana" || existing.Note != "rewriting the intro" {
		t.Errorf("the existing claim was reported wrongly: %#v", existing)
	}
}

func TestOnlyTheHolderReleasesALock(t *testing.T) {
	var ls Locks
	ls.Claim("about", "dana", "", now)

	if ls.Release("about", "sam", now) {
		t.Error("somebody else released dana's claim")
	}
	if _, held := ls.Holder("about", now); !held {
		t.Error("the claim was dropped anyway")
	}
	if !ls.Release("about", "dana", now) {
		t.Error("the holder could not release their own claim")
	}
}

func TestLocksOnDifferentPagesDoNotInterfere(t *testing.T) {
	var ls Locks
	ls.Claim("about", "dana", "", now)
	ls.Claim("pricing", "sam", "", now)
	ls.Claim("index", "kit", "", now)

	if got := len(ls.Active(now)); got != 3 {
		t.Fatalf("%d locks held, expected 3", got)
	}
	ls.Release("pricing", "sam", now)
	if _, held := ls.Holder("about", now); !held {
		t.Error("releasing one page dropped another")
	}
}

// -- configuration -----------------------------------------------------------

// One person running their own site is a legitimate case, and a tool that
// cannot be used by one person is a tool that gets configured with two accounts
// belonging to the same human.
func TestDualAuthorizationCanBeTurnedOffDeliberately(t *testing.T) {
	p := Policy{Required: 0}
	prop := Proposal{Content: "aaa", Author: "dana", AuthorKind: "human"}
	d := p.Evaluate(prop, people, now)
	if !d.Allowed {
		t.Fatalf("a single-user configuration was blocked: %s", d.Reason)
	}
	if !strings.Contains(d.Reason, "not configured") {
		t.Errorf("the reason should say the control is off, not that it passed: %s",
			d.Reason)
	}
}

// The default has to be the safe one, because the default is what most
// installations run.
func TestTheDefaultIsTwoPeopleAndAHumanForAI(t *testing.T) {
	p := NewPolicy()
	if p.Required < 2 {
		t.Errorf("the default requires %d approvals", p.Required)
	}
	if !p.RequireHumanForAI {
		t.Error("by default a model's work could ship on machine approval alone")
	}
}

// Turning off the numeric threshold must not turn off the AI rule, or
// "Required: 0" becomes a way to let a model publish unreviewed.
func TestDisablingTheThresholdDoesNotDisableTheHumanRequirement(t *testing.T) {
	p := Policy{Required: 0, RequireHumanForAI: true}
	prop := Proposal{Content: "aaa", Author: "assistant", AuthorKind: "ai"}

	if d := p.Evaluate(prop, people, now); d.Allowed {
		t.Fatal("setting Required to zero let a model's change through with " +
			"no human at all")
	}
}

// Have and Need were declared on one line and shared a json tag, so Need
// serialised as "have" and one of the two was lost — an interface showing
// "2 of 2" when it was 1 of 2. Nothing but go vet would have caught it, so it
// gets a test that does not depend on running vet.
func TestTheApprovalCountSurvivesSerialisation(t *testing.T) {
	p := Policy{Required: 3}
	prop := Proposal{Content: "aaa", Author: "dana", AuthorKind: "human"}
	_ = prop.Approve("sam", "", now)

	d := p.Evaluate(prop, people, now)
	body, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var back Decision
	if err := json.Unmarshal(body, &back); err != nil {
		t.Fatal(err)
	}
	if back.Have != 1 || back.Need != 3 {
		t.Errorf("the counts did not survive: have=%d need=%d, from %s",
			back.Have, back.Need, body)
	}
}

// A change a machine made for a person is named by the machine, and the
// person reads it where only a person's reading is asked; where a count of
// approvals is set they asked for it, as they would their own work.
//
// The machine interface and the writing assistant commit under the name of
// the person they act for, and the proposal was named by that: dana was
// told she wrote what her client wrote and could not approve it, and on an
// installation run by one person it could never be published.
func TestWhatAMachineWroteForAPersonIsTheirsToRead(t *testing.T) {
	for _, message := range []string{"mcp: write index", "assist: retitle the homepage"} {
		writer, person := WrittenFor(message, "dana")
		if writer == "dana" || writer == "" || person != "dana" {
			t.Fatalf("%q under dana is written by %q for %q", message, writer, person)
		}
		m := &MachineChange{Commit: "aaa", Author: "dana", Message: message}
		if !strings.Contains(m.Describe("aaa"), "dana's") {
			t.Errorf("a refusal does not say whose machine wrote %q: %s", message, m.Describe("aaa"))
		}

		prop := Proposal{Content: "aaa", Author: m.Writer(), CreatedAt: now.Unix()}
		prop.MarkMachine(m)
		if prop.OnBehalfOf != "dana" || prop.AuthorKind != "ai" {
			t.Fatalf("a proposal for %q is %q for %q", message, prop.AuthorKind, prop.OnBehalfOf)
		}
		if err := prop.Approve("dana", "read it", now); err != nil {
			t.Fatalf("dana may not read what %s wrote for her: %v", writer, err)
		}
		only := Policy{RequireHumanForAI: true}
		if d := only.Evaluate(prop, people, now); !d.Allowed {
			t.Errorf("with only a person's reading asked, dana's reading of %q did not count: %s", message, d.Reason)
		}
		for _, counted := range []Policy{{Required: 1, RequireHumanForAI: true}, {RequiredHumans: 1, RequireHumanForAI: true}} {
			if !counted.Requested(prop, "dana") {
				t.Errorf("with %+v dana is not who asked for %q", counted, message)
			}
			d := counted.Evaluate(prop, people, now)
			if d.Allowed || !strings.Contains(d.Reason, "for dana") {
				t.Errorf("with %+v dana approved what was written for her: %+v", counted, d)
			}
		}
	}

	// An agent's own commit names the agent, and nobody it was for.
	if writer, person := WrittenFor(AgentPrefix+"tidy wrote index", "agent/tidy"); writer != "agent/tidy" || person != "" {
		t.Errorf("an agent's commit is written by %q for %q", writer, person)
	}
	// Nor is a person's own commit anybody else's.
	if writer, person := WrittenFor("fixed a typo", "dana"); writer != "dana" || person != "" {
		t.Errorf("a person's commit is written by %q for %q", writer, person)
	}
}

// The approval of the person a model wrote a change for stops counting once
// a count is set, and somebody else's approval is then enough: hers is set
// aside, not held against everybody else's.
//
// Dana read what her client wrote and approved it while no count was set,
// as the rule allows, and a count of one was set before it was published.
// Her approval was then reported as a refusal whatever anybody else said:
// sam's approval was the one the count asked for, and the change still
// could not be published until the draft itself changed. So was a proposal
// waiting when the program was upgraded, approved by dana while a person's
// later commit was all its author said.
func TestAnApprovalThatNoLongerCountsDoesNotOutvoteOneThatDoes(t *testing.T) {
	m := &MachineChange{Commit: "aaa", Author: "dana", Message: "mcp: write index"}
	prop := Proposal{Content: "aaa", Author: m.Writer(), CreatedAt: now.Unix()}
	prop.MarkMachine(m)
	if err := prop.Approve("dana", "read it", now); err != nil {
		t.Fatal(err)
	}
	counted := Policy{Required: 1, RequireHumanForAI: true}

	// Hers alone is not enough, and the refusal says why.
	d := counted.Evaluate(prop, people, now)
	if d.Allowed || !strings.Contains(d.Reason, "for dana") {
		t.Fatalf("with a count set, dana's approval of what was written for her: %+v", d)
	}

	if err := prop.Approve("sam", "read it too", now); err != nil {
		t.Fatal(err)
	}
	if d := counted.Evaluate(prop, people, now); !d.Allowed || d.Have != 1 {
		t.Fatalf("sam's approval did not count beside dana's: %+v", d)
	}

	// Where sam's is not enough either, the refusal says what is still
	// missing as well as why dana's was set aside.
	two := Policy{Required: 2, RequiredHumans: 2, RequireHumanForAI: true}
	if d := two.Evaluate(prop, people, now); d.Allowed || !strings.Contains(d.Reason, "for dana") ||
		!strings.Contains(d.Reason, "from people") {
		t.Fatalf("with two people asked for, sam's approval and dana's: %+v", d)
	}
}

// Everybody a machine wrote some of a change for asked for it where a count
// of approvals is set, and may read it where only a person's reading is
// asked; a proposal recorded with one person still reads as it did.
//
// Only the person the newest machine's change was made for was named. Dana's
// client rewrote the pricing and lee's client then wrote the about page:
// the proposal named lee, and dana's approval counted for her own client's
// prices.
func TestEverybodyAMachineWroteForAskedForTheChange(t *testing.T) {
	m := &MachineChange{Commit: "aaa", Author: "lee", Message: "mcp: write about", People: []string{"lee", "dana"}}
	prop := Proposal{Content: "aaa", Author: m.Writer(), CreatedAt: now.Unix()}
	prop.MarkMachine(m)
	prop.MarkMachine(m)
	if prop.OnBehalfOf != "lee" || strings.Join(prop.AlsoOnBehalfOf, ",") != "dana" ||
		strings.Join(prop.ForWhom(), ",") != "lee,dana" {
		t.Fatalf("marked twice, the proposal is for %q and also %q", prop.OnBehalfOf, prop.AlsoOnBehalfOf)
	}

	counted := Policy{Required: 1, RequireHumanForAI: true}
	only := Policy{RequireHumanForAI: true}
	for _, who := range []string{"lee", "dana"} {
		if !counted.Requested(prop, who) {
			t.Errorf("with a count set, %s is not who asked for a change a machine wrote for them", who)
		}
		if only.Requested(prop, who) {
			t.Errorf("with no count set, %s may not read what a machine wrote for them", who)
		}
		p := prop
		p.Approvals = nil
		if err := p.Approve(who, "read it", now); err != nil {
			t.Fatal(err)
		}
		if d := counted.Evaluate(p, people, now); d.Allowed || !strings.Contains(d.Reason, "for "+who) {
			t.Errorf("with a count set, %s's approval counted: %+v", who, d)
		}
	}
	if counted.Requested(prop, "sam") {
		t.Error("sam, whom no machine wrote for, is taken for who asked for it")
	}

	// A copy marked again, as the review screen marks one, leaves the
	// list it was copied from as it was.
	judged := prop
	judged.MarkMachine(&MachineChange{Commit: "aaa", Author: "kit", Message: "mcp: write faq", People: []string{"kit"}})
	if strings.Join(prop.ForWhom(), ",") != "lee,dana" || strings.Join(judged.ForWhom(), ",") != "lee,dana,kit" {
		t.Errorf("the copy is for %q and the proposal now %q", judged.ForWhom(), prop.ForWhom())
	}

	// A proposal recorded before the list existed names its one person,
	// and they are still who asked for it.
	var old Proposal
	if err := json.Unmarshal([]byte(`{"content":"aaa","author":"mcp-client","author_kind":"ai",`+
		`"on_behalf_of":"dana","created_at":1}`), &old); err != nil {
		t.Fatal(err)
	}
	if !counted.Requested(old, "dana") || strings.Join(old.ForWhom(), ",") != "dana" {
		t.Errorf("an old proposal for dana reads as for %q", old.ForWhom())
	}
	body, err := json.Marshal(prop)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"on_behalf_of":"lee"`) || !strings.Contains(string(body), `"also_on_behalf_of":["dana"]`) {
		t.Errorf("the proposal is kept as %s", body)
	}
}

// An agent's commit names the person who started its run, and is read back
// as the agent's, written for them; and only from a commit the agent it
// names is recorded as making.
func TestAnAgentsCommitIsWrittenForThePersonWhoStartedTheRun(t *testing.T) {
	msg := AgentMessage("tidy", "index", "dana")
	if !MachineWrote(msg) || !strings.HasPrefix(msg, AgentPrefix) {
		t.Fatalf("%q does not say a machine wrote it", msg)
	}
	if writer, person := WrittenFor(msg, "agent/tidy"); writer != "agent/tidy" || person != "dana" {
		t.Errorf("%q by agent/tidy is written by %q for %q", msg, writer, person)
	}
	// Recorded as made by anybody but the agent it names, it is not that
	// agent's, and names nobody.
	for _, author := range []string{"lee", "agent/other"} {
		if _, person := WrittenFor(msg, author); person != "" {
			t.Errorf("%q by %s is taken as written for %q", msg, author, person)
		}
	}
	// An agent's commit made before the person was named says nobody.
	if got := AgentMessage("tidy", "index", ""); got != AgentPrefix+"tidy wrote index" {
		t.Errorf("with nobody to name, the message is %q", got)
	}
	m := &MachineChange{Commit: "aaa", Author: "agent/tidy", Message: msg}
	prop := Proposal{Content: "aaa", Author: m.Writer(), CreatedAt: now.Unix()}
	prop.MarkMachine(m)
	if prop.Author != "agent/tidy" || prop.OnBehalfOf != "dana" {
		t.Fatalf("the proposal for the run's write is by %q for %q", prop.Author, prop.OnBehalfOf)
	}
	if !(Policy{Required: 1}).Requested(prop, "dana") || (Policy{RequireHumanForAI: true}).Requested(prop, "dana") {
		t.Error("dana is not who asked for her run's change with a count set, or is without one")
	}
}

// The author is the author under any spelling of their name, and so is one
// approver clicking twice: another case, spaces around it or a mailto: in
// front is the same person, refused as the author and counted once.
//
// Evaluate, Approve and Requested compared names exactly, so "dana"
// approved "Dana"'s change as the second pair of eyes, and "Sam" and "sam"
// were two approvals, where a privileged request (internal/dual) refused
// the same two names as one person.
func TestTheAuthorIsRecognisedWhateverTheCaseOfTheirName(t *testing.T) {
	one := Policy{Required: 1}
	prop := Proposal{Content: "aaa", Author: "Dana", AuthorKind: "human"}
	for _, by := range []string{"dana", " DANA ", "mailto:dana"} {
		if err := prop.Approve(by, "", now); err == nil {
			t.Fatalf("%q approved Dana's change", by)
		}
		if !one.Requested(prop, by) {
			t.Errorf("%q is not who asked for Dana's change", by)
		}
	}
	prop.Approvals = append(prop.Approvals, Approval{Content: "aaa", By: "dana", At: now.Unix()})
	if d := one.Evaluate(prop, people, now); d.Allowed {
		t.Fatalf("dana's approval of Dana's change counted: %+v", d)
	}

	two := Policy{Required: 2}
	prop = Proposal{Content: "aaa", Author: "dana", AuthorKind: "human"}
	if err := prop.Approve("Sam", "", now); err != nil {
		t.Fatal(err)
	}
	if err := prop.Approve("sam", "", now); err == nil {
		t.Error("sam approved again as somebody else")
	}
	prop.Approvals = append(prop.Approvals, Approval{Content: "aaa", By: "sam", At: now.Unix()})
	if d := two.Evaluate(prop, people, now); d.Allowed || d.Have != 1 {
		t.Fatalf("Sam and sam counted as two people: %+v", d)
	}

	// Whoever a model wrote it for, likewise.
	written := Proposal{Content: "aaa", Author: "agent/tidy", AuthorKind: "ai", OnBehalfOf: "Dana"}
	if !one.Requested(written, "dana") {
		t.Error("dana is not who asked for what a model wrote for Dana")
	}
}
