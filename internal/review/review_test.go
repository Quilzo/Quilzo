// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package review

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/telemetry"
	"github.com/quilzo/quilzo/internal/workforce"
)

var now = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

// campaign covers one system, so a test about remediation is not also a
// test about scope.
func campaign() Campaign {
	return Campaign{
		ID: "q3-access", Name: "Q3 access review",
		Scope:     []string{"okta"},
		Opened:    now.Add(-20 * 24 * time.Hour),
		Due:       now.Add(-10 * 24 * time.Hour),
		Remediate: now.Add(-3 * 24 * time.Hour),
		By:        "rashik", Kind: audit.KindHuman,
	}
}

func acct(issuer, value string) telemetry.ID {
	return telemetry.ID{Issuer: issuer, Value: value}
}

func item(issuer, value string, seen int) Item {
	return Item{Campaign: "q3-access", Account: acct(issuer, value),
		Person: value, Seen: now.Add(-time.Duration(seen) * 24 * time.Hour)}
}

func decided(issuer, value string, v Verdict, took time.Duration) Decision {
	d := Decision{
		Campaign: "q3-access", Account: acct(issuer, value), Verdict: v,
		At: now.Add(-15 * 24 * time.Hour), By: "rashik",
		Kind: audit.KindHuman, Took: took,
	}
	if v == Keep {
		d.Because = "still in the team"
	}
	return d
}

func identity(issuer, value string) workforce.Identity {
	return workforce.Identity{ID: acct(issuer, value),
		Subject: workforce.APerson, Observed: now}
}

// The half of this control that fails, and the half no product measures.
func TestARevocationIsClosedByTheImportAndNotByTheReviewer(t *testing.T) {
	c := campaign()
	items := []Item{item("okta", "u-1", 5), item("okta", "u-2", 5)}
	decisions := []Decision{
		decided("okta", "u-1", Revoke, 20*time.Second),
		decided("okta", "u-2", Keep, 15*time.Second),
	}
	// A later import where u-1 is still present. The reviewer said remove
	// it three weeks ago.
	after := []workforce.Identity{identity("okta", "u-1"),
		identity("okta", "u-2")}

	out := Close(c, items, decisions, after, now)
	var unremediated int
	for _, o := range out {
		if o.Standing == Unremediated {
			unremediated++
			if o.Item.Account.Value != "u-1" {
				t.Errorf("the wrong item is unremediated: %s",
					o.Item.Account)
			}
		}
	}
	if unremediated != 1 {
		t.Fatalf("%d unremediated", unremediated)
	}

	r := Summarise(c, items, decisions, out, after, now)
	if !strings.Contains(r.Why(), "reports this campaign as complete") {
		t.Errorf("the summary is %q", r.Why())
	}
	found := Findings(c, r, out, now)
	if len(found) == 0 || found[0].Severity != telemetry.SeverityHigh {
		t.Fatalf("the top finding is %v", found)
	}
	if !strings.Contains(found[0].Title, "still there") {
		t.Errorf("the title is %q", found[0].Title)
	}

	// And once it is gone from the import, it closes.
	gone := Close(c, items, decisions,
		[]workforce.Identity{identity("okta", "u-2")}, now)
	for _, o := range gone {
		if o.Standing == Unremediated {
			t.Error("an account absent from the import is still open")
		}
	}
}

// Calling unverified and unremediated the same would accuse a team of not
// acting when nobody has looked.
func TestNoLaterImportMeansUnverifiedRatherThanUnremediated(t *testing.T) {
	c := campaign()
	items := []Item{item("okta", "u-1", 5)}
	decisions := []Decision{decided("okta", "u-1", Revoke, 20*time.Second)}

	out := Close(c, items, decisions, nil, now)
	if out[0].Standing != Committed {
		t.Fatalf("with no import the standing is %s", out[0].Standing)
	}
	r := Summarise(c, items, decisions, out, nil, now)
	if r.Verified {
		t.Error("a campaign with no later import reports as verified")
	}
	if !strings.Contains(r.Why(), "not when somebody says so") {
		t.Errorf("the summary is %q", r.Why())
	}
	found := Findings(c, r, out, now)
	var named bool
	for _, f := range found {
		if strings.Contains(f.Title, "nobody has verified") {
			named = true
		}
	}
	if !named {
		t.Error("an unverified change is not in the register")
	}
}

// Forty people approved in ninety seconds.
func TestTheShapeOfARubberStampIsReported(t *testing.T) {
	var decisions []Decision
	at := now.Add(-15 * 24 * time.Hour)
	for n := range 40 {
		d := decided("okta", fmt.Sprintf("u-%d", n), Keep, 1500*time.Millisecond)
		d.At = at.Add(time.Duration(n) * 2 * time.Second)
		decisions = append(decisions, d)
	}
	s := Measure(decisions)
	if !s.RubberStamped() {
		t.Fatalf("forty keeps at 1.5s each inside 80 seconds is not a "+
			"rubber stamp: %+v", s)
	}
	if !strings.Contains(s.Why(), "held-down key") {
		t.Errorf("the summary is %q", s.Why())
	}
	if s.Kept != 40 || s.Revoked != 0 {
		t.Errorf("shape is %+v", s)
	}

	// Any one of the three alone is defensible.
	spread := append([]Decision(nil), decisions...)
	for n := range spread {
		spread[n].At = at.Add(time.Duration(n) * 3 * time.Minute)
	}
	if Measure(spread).RubberStamped() {
		t.Error("a review spread over two hours is a rubber stamp")
	}

	thoughtful := append([]Decision(nil), decisions...)
	for n := range thoughtful {
		thoughtful[n].Took = 30 * time.Second
	}
	if Measure(thoughtful).RubberStamped() {
		t.Error("thirty seconds a row is a rubber stamp")
	}

	withChanges := append([]Decision(nil), decisions...)
	withChanges[3].Verdict = Revoke
	if Measure(withChanges).RubberStamped() {
		t.Error("a review that removed something is a rubber stamp")
	}
}

// Five decisions in a minute is five decisions in a minute.
func TestASmallCampaignHasNoShapeToJudge(t *testing.T) {
	var decisions []Decision
	at := now.Add(-15 * 24 * time.Hour)
	for n := range 5 {
		d := decided("okta", fmt.Sprintf("u-%d", n), Keep, time.Second)
		d.At = at.Add(time.Duration(n) * time.Second)
		decisions = append(decisions, d)
	}
	if Measure(decisions).RubberStamped() {
		t.Error("five decisions were judged as a pattern")
	}
}

// The commonest way a review is worthless, and the easiest to check.
func TestReviewingYourOwnAccessIsRefused(t *testing.T) {
	d := decided("okta", "rashik", Keep, 20*time.Second)
	err := d.Validate(false)
	if err == nil {
		t.Fatal("a reviewer signed off their own access")
	}
	if !strings.Contains(err.Error(), "self-certification with extra steps") {
		t.Errorf("the refusal is %v", err)
	}

	// And on the qualified form too.
	q := decided("okta", "u-1", Keep, 20*time.Second)
	q.By = "okta:u-1"
	if err := q.Validate(false); err == nil {
		t.Error("a reviewer signed off their own qualified account")
	}

	// Somebody else's is fine.
	other := decided("okta", "u-1", Keep, 20*time.Second)
	if err := other.Validate(false); err != nil {
		t.Fatalf("an ordinary decision was refused: %v", err)
	}
}

// That is the decision nobody writes down and the one an auditor samples.
func TestKeepingPrivilegedAccessNeedsAReason(t *testing.T) {
	d := decided("okta", "u-1", Keep, 20*time.Second)
	d.Because = ""
	if err := d.Validate(true); err == nil {
		t.Fatal("privileged access was kept with no reason")
	}
	// The same decision on ordinary access needs none.
	if err := d.Validate(false); err != nil {
		t.Fatalf("ordinary access needed a reason: %v", err)
	}
	// And a revocation needs none either: taking something away is not the
	// decision anybody questions.
	r := decided("okta", "u-1", Revoke, 20*time.Second)
	r.Because = ""
	if err := r.Validate(true); err != nil {
		t.Fatalf("a revocation needed a reason: %v", err)
	}
}

func TestAModelMaySortTheListAndNotDecide(t *testing.T) {
	d := decided("okta", "u-1", Keep, 20*time.Second)
	d.Kind = audit.KindAI
	err := d.Validate(false)
	if err == nil {
		t.Fatal("a model decided whether somebody still needs access")
	}
	if !strings.Contains(err.Error(), "what they do all day") {
		t.Errorf("the refusal does not say what is out of reach: %v", err)
	}
}

// A review of whatever happened to be exported is narrower than it claims.
func TestASystemInScopeWithNothingReviewedIsReported(t *testing.T) {
	c := campaign()
	c.Scope = []string{"okta", "github"}
	// Only okta identities arrived; github was in scope and nothing came.
	items := []Item{item("okta", "u-1", 5), item("okta", "u-2", 5)}
	decisions := []Decision{
		decided("okta", "u-1", Keep, 20*time.Second),
		decided("okta", "u-2", Keep, 20*time.Second),
	}
	out := Close(c, items, decisions, []workforce.Identity{}, now)
	r := Summarise(c, items, decisions, out, nil, now)

	if len(r.Missing) != 1 || r.Missing[0] != "github" {
		t.Fatalf("missing is %v", r.Missing)
	}
	if !strings.Contains(r.Why(), "narrower than it claims") {
		t.Errorf("the summary is %q", r.Why())
	}
	if !strings.Contains(r.Why(), "nothing was reviewed from github") {
		t.Errorf("the summary names the wrong noun: %q", r.Why())
	}
	found := Findings(c, r, out, now)
	var named bool
	for _, f := range found {
		if strings.Contains(f.Title, "reviewed nothing from there") {
			named = true
			if f.Severity != telemetry.SeverityHigh {
				t.Errorf("a missing system is %v", f.Severity)
			}
		}
	}
	if !named {
		t.Error("the missing system is not in the register")
	}
}

// An account nobody has touched in ninety days is a decision that makes
// itself, and putting it forty rows down is how it gets kept.
func TestDormantAndPrivilegedAccountsAreShownFirst(t *testing.T) {
	c := campaign()
	ordinary := identity("okta", "u-ordinary")
	ordinary.Seen = now.Add(-2 * 24 * time.Hour)
	privileged := identity("okta", "u-admin")
	privileged.Seen = now.Add(-time.Hour)
	privileged.Attributes = map[string]string{"privileged": "true"}
	dormant := identity("okta", "u-dormant")
	dormant.Seen = now.Add(-200 * 24 * time.Hour)
	never := identity("okta", "u-never")

	items := From(c, []workforce.Identity{ordinary, privileged, dormant,
		never}, now)
	if len(items) != 4 {
		t.Fatalf("%d items", len(items))
	}
	for _, item := range items[:2] {
		if !item.Dormant(now, 90*24*time.Hour) {
			t.Errorf("%s is not dormant and sorted first",
				item.Account.Value)
		}
	}
	if items[2].Account.Value != "u-admin" {
		t.Errorf("the privileged account is at %v", items[2].Account)
	}
	// An account nobody has a date for counts as dormant: never used and
	// never recorded are the same decision.
	var sawNever bool
	for _, item := range items {
		if item.Account.Value == "u-never" &&
			item.Dormant(now, 90*24*time.Hour) {
			sawNever = true
		}
	}
	if !sawNever {
		t.Error("an account with no last-seen date is not dormant")
	}
}

func TestOnlyAccountsInScopeAreReviewed(t *testing.T) {
	c := campaign()
	c.Scope = []string{"okta", "github"}
	items := From(c, []workforce.Identity{
		identity("okta", "u-1"),
		identity("aws", "i-nope"),
		{ID: acct("okta", "MBP-1"), Subject: workforce.ADevice,
			Observed: now},
	}, now)
	if len(items) != 1 || items[0].Account.Issuer != "okta" {
		t.Fatalf("items are %v", items)
	}
}

func TestACampaignWithOneDateMeasuresTheHalfThatDoesNotFail(t *testing.T) {
	good := campaign()
	for name, spoil := range map[string]func(*Campaign){
		"no remediation date": func(c *Campaign) {
			c.Remediate = time.Time{}
		},
		"no decision date": func(c *Campaign) { c.Due = time.Time{} },
		"no scope":         func(c *Campaign) { c.Scope = nil },
		"nobody":           func(c *Campaign) { c.By = "" },
		"due before it opened": func(c *Campaign) {
			c.Due = c.Opened.Add(-time.Hour)
		},
		"changes before decisions": func(c *Campaign) {
			c.Remediate = c.Due.Add(-time.Hour)
		},
	} {
		x := good
		spoil(&x)
		if err := x.Validate(); err == nil {
			t.Errorf("a campaign with %s was accepted", name)
		}
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("an ordinary campaign was refused: %v", err)
	}
	x := good
	x.Remediate = time.Time{}
	if err := x.Validate(); !strings.Contains(err.Error(),
		"half that does not fail") {
		t.Errorf("the refusal is %v", err)
	}
}

func TestAReducedAccountThatIsDisabledCountsAsDone(t *testing.T) {
	c := campaign()
	items := []Item{item("okta", "u-1", 5)}
	decisions := []Decision{decided("okta", "u-1", Reduce, 20*time.Second)}

	no := false
	disabled := identity("okta", "u-1")
	disabled.Active = &no
	out := Close(c, items, decisions, []workforce.Identity{disabled}, now)
	if out[0].Standing != Done {
		t.Fatalf("a disabled account after a reduce is %s", out[0].Standing)
	}

	// Still live and still there past the date is not done.
	out = Close(c, items, decisions,
		[]workforce.Identity{identity("okta", "u-1")}, now)
	if out[0].Standing != Unremediated {
		t.Errorf("a live account after a reduce is %s", out[0].Standing)
	}
}

func TestSomebodyChangingTheirMindIsNotTwoDecisions(t *testing.T) {
	first := decided("okta", "u-1", Keep, 20*time.Second)
	first.At = now.Add(-20 * 24 * time.Hour)
	second := decided("okta", "u-1", Revoke, 40*time.Second)

	got := Latest([]Decision{first, second})
	if len(got) != 1 {
		t.Fatalf("%d decisions for one item", len(got))
	}
	if got[first.Key()].Verdict != Revoke {
		t.Error("the older decision won")
	}
	if Measure([]Decision{first, second}).Decisions != 1 {
		t.Error("one item counted twice in the shape")
	}
}

func TestEveryVerdictReachesARealAuditLog(t *testing.T) {
	dir := t.TempDir()
	k, err := audit.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	log, err := audit.New(audit.Options{Path: dir + "/audit.jsonl", Key: k,
		Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range Verdicts() {
		d := decided("okta", "u-1", v, 20*time.Second)
		if verr := d.Validate(false); verr != nil {
			t.Fatalf("%s: %v", v, verr)
		}
		if _, aerr := log.Append(d.Record()); aerr != nil {
			t.Fatalf("%s: %v", v, aerr)
		}
	}
	events, err := audit.Read(dir + "/audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != len(Verdicts()) {
		t.Fatalf("%d entries for %d verdicts", len(events), len(Verdicts()))
	}
	// A revocation is a denial, so the access somebody decided to take away
	// can be searched for.
	var denied int
	for _, e := range events {
		if e.Outcome == audit.Denied {
			denied++
		}
	}
	if denied != 2 {
		t.Errorf("%d denials for a revoke and a reduce", denied)
	}
}

// A campaign where every decision was keep has nothing to verify, and
// deriving "verified" from the outcomes made it report that no import had
// been supplied when one had.
func TestACampaignWithNothingToRemoveIsNotToldToSupplyAnImport(t *testing.T) {
	c := campaign()
	var items []Item
	var decisions []Decision
	var after []workforce.Identity
	for n := range 6 {
		v := fmt.Sprintf("u-%d", n)
		items = append(items, item("okta", v, 5))
		decisions = append(decisions, decided("okta", v, Keep, 20*time.Second))
		after = append(after, identity("okta", v))
	}
	out := Close(c, items, decisions, after, now)
	r := Summarise(c, items, decisions, out, after, now)

	if !r.Verified {
		t.Fatal("an import was supplied and the report says otherwise")
	}
	if strings.Contains(r.Why(), "no later import has been supplied") {
		t.Errorf("the summary asks for something it was given: %q", r.Why())
	}
	if !strings.Contains(r.Why(), "nothing to remove") {
		t.Errorf("the summary is %q", r.Why())
	}
	// And it is not chased for an unverified change either.
	for _, f := range Findings(c, r, out, now) {
		if strings.Contains(f.Title, "nobody has verified") {
			t.Error("a campaign with no changes was chased for verification")
		}
	}
}
