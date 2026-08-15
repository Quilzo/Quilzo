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
