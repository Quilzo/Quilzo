// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package entity

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/assurance"
	"github.com/quilzo/quilzo/internal/audit"
)

var (
	now    = time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)
	period = assurance.Period{From: now.Add(-182 * 24 * time.Hour), To: now}
)

// acme is a group: a holding company, two regions, three trading companies.
func acme(t *testing.T) *Tree {
	t.Helper()
	tree := New()
	for _, e := range []Entity{
		{ID: "acme", Name: "Acme Holdings"},
		{ID: "emea", Name: "Acme EMEA", Parent: "acme"},
		{ID: "amer", Name: "Acme Americas", Parent: "acme"},
		{ID: "acme-uk", Name: "Acme UK Ltd", Parent: "emea", Region: "GB"},
		{ID: "acme-de", Name: "Acme GmbH", Parent: "emea", Region: "DE"},
		{ID: "acme-us", Name: "Acme Inc", Parent: "amer", Region: "US"},
	} {
		if err := tree.Add(e); err != nil {
			t.Fatalf("add %s: %v", e.ID, err)
		}
	}
	if err := tree.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return tree
}

func day(n int) time.Time {
	return period.From.Add(time.Duration(n) * 24 * time.Hour)
}

func ev(control, entity string, from, to int) assurance.Evidence {
	return assurance.Evidence{
		Control: control, Entity: entity, From: day(from), To: day(to),
		Outcome: assurance.Operated, What: "an export", Source: "connector",
		Ref: "audit:1", At: day(to), By: "rashik", Kind: audit.KindHuman,
	}
}

func perEntity(id string) assurance.Control {
	return assurance.Control{ID: id, Name: id, Cadence: assurance.Continuous,
		Owner: "rashik", PerEntity: true}
}

// The failure this package exists to make visible: one connector's evidence
// reported as covering five companies.
func TestASharedControlIsAsCoveredAsItsWorstCompany(t *testing.T) {
	tree := acme(t)
	// MFA is performed by each company separately, and the German one runs
	// its own tenant that nobody ever connected.
	c := perEntity("mfa")
	var evidence []assurance.Evidence
	for _, id := range []string{"acme", "emea", "amer", "acme-uk",
		"acme-us"} {
		evidence = append(evidence, ev("mfa", id, 0, 182))
	}

	d := Across(tree, "acme", c, evidence, nil, period)
	if len(d.By) != 6 {
		t.Fatalf("%d companies measured", len(d.By))
	}
	if len(d.Silent) != 1 || d.Silent[0] != "acme-de" {
		t.Fatalf("silent is %v", d.Silent)
	}
	// The group is entitled to claim the worst of them, not the union.
	if d.Worst.Observations != 0 {
		t.Errorf("the group claims %d observations; the union of the "+
			"evidence would be green", d.Worst.Observations)
	}
	if d.Even() {
		t.Error("five green and one empty reads as even")
	}
	if !strings.Contains(d.Why(), "would be green") {
		t.Errorf("the summary does not say what a union would show: %q",
			d.Why())
	}
}

// Down the tree and never up.
func TestEvidenceFlowsDownAndNeverUp(t *testing.T) {
	tree := acme(t)
	for _, c := range []struct {
		from, to string
		want     bool
	}{
		{"acme", "acme-de", true},
		{"emea", "acme-de", true},
		{"acme-de", "acme-de", true},
		{"acme-de", "emea", false},
		{"acme-de", "acme", false},
		{"acme-de", "acme-uk", false},
		{"amer", "acme-de", false},
		{"acme-us", "acme-uk", false},
	} {
		if got := tree.Reaches(c.from, c.to); got != c.want {
			t.Errorf("%s reaches %s = %v, want %v", c.from, c.to, got,
				c.want)
		}
	}

	// And a subsidiary's export does not evidence the group's control,
	// because the group includes companies it never looked at.
	c := perEntity("mfa")
	d := Across(tree, "acme", c, []assurance.Evidence{
		ev("mfa", "acme-de", 0, 182),
	}, nil, period)
	for _, e := range d.By {
		if e.Entity == "acme" && e.Coverage.Observations > 0 {
			t.Fatal("a subsidiary's evidence covered the holding company")
		}
		if e.Entity == "acme-uk" && e.Coverage.Observations > 0 {
			t.Fatal("one subsidiary's evidence covered its sibling")
		}
	}
}

// A control operated in one place should not report five gaps for one
// connector.
func TestAGroupControlIsMeasuredOnceAgainstWhoOperatesIt(t *testing.T) {
	tree := acme(t)
	c := assurance.Control{ID: "sso", Name: "group SSO",
		Cadence: assurance.Continuous, Owner: "rashik", Entity: "acme"}
	d := Across(tree, "acme", c, []assurance.Evidence{
		ev("sso", "acme", 0, 182),
	}, nil, period)

	if len(d.By) != 1 || d.By[0].Entity != "acme" {
		t.Fatalf("measured against %v", d.By)
	}
	if !d.Worst.Complete() {
		t.Errorf("one connector for the group left gaps: %v", d.Worst.Gaps)
	}
	// And every company beneath is reported as relying on it without
	// anybody having said so.
	if len(d.Assumed) != 5 {
		t.Errorf("%d companies inherit it without a record: %v",
			len(d.Assumed), d.Assumed)
	}
	if !strings.Contains(d.Why(), "no reliance recorded") {
		t.Errorf("the summary does not mention it: %q", d.Why())
	}
}

// At audit the subsidiary has to say why the parent's control counts here.
func TestARecordedRelianceIsDifferentFromAnAssumedOne(t *testing.T) {
	tree := acme(t)
	c := perEntity("mfa")
	evidence := []assurance.Evidence{ev("mfa", "acme", 0, 182)}

	// A per-entity control is not satisfied by the parent's evidence on its
	// own: letting it would make the flag mean nothing. The companies are
	// silent, and separately reported as coverable, because the work there
	// is recording why the parent's control counts rather than standing one
	// up.
	plain := Across(tree, "emea", c, evidence, nil, period)
	if len(plain.Silent) != 3 {
		t.Fatalf("a parent's evidence quietly satisfied a per-entity "+
			"control: silent is %v", plain.Silent)
	}
	if plain.Coverable["acme-de"] != "acme" {
		t.Fatalf("coverable is %v", plain.Coverable)
	}
	if !strings.Contains(plain.Why(), "recording why that counts") {
		t.Errorf("the summary does not say what the work is: %q",
			plain.Why())
	}

	r := Reliance{Entity: "acme-de", On: "acme", Control: "mfa",
		Because: "the group tenant is in scope for our examination, per the " +
			"shared services agreement", At: now, By: "rashik",
		Kind: audit.KindHuman}
	if err := r.Validate(tree); err != nil {
		t.Fatalf("a defensible reliance was refused: %v", err)
	}
	with := Across(tree, "emea", c, evidence, []Reliance{r}, period)
	if with.Relying["acme-de"] != "acme" {
		t.Errorf("the reliance was not applied: %v", with.Relying)
	}
	for _, id := range with.Silent {
		if id == "acme-de" {
			t.Error("a company with a recorded reliance is still silent")
		}
	}
	// Its siblings are unaffected: one company's paperwork does not cover
	// another's.
	if with.Coverable["acme-uk"] != "acme" {
		t.Errorf("acme-uk was changed by acme-de's reliance: %v",
			with.Coverable)
	}
}

func TestRelyingOnSomethingThatIsNotAboveYouIsRefused(t *testing.T) {
	tree := acme(t)
	base := Reliance{Control: "mfa", Because: "they do it", At: now,
		By: "rashik", Kind: audit.KindHuman}
	for name, pair := range map[string][2]string{
		"a sibling":      {"acme-de", "acme-uk"},
		"a descendant":   {"acme", "acme-de"},
		"another branch": {"acme-de", "amer"},
	} {
		r := base
		r.Entity, r.On = pair[0], pair[1]
		err := r.Validate(tree)
		if err == nil {
			t.Errorf("%s was accepted as something to rely on", name)
			continue
		}
		if !strings.Contains(err.Error(), "never up or sideways") {
			t.Errorf("%s: the refusal does not say the rule: %v", name, err)
		}
	}
	good := base
	good.Entity, good.On = "acme-de", "emea"
	if err := good.Validate(tree); err != nil {
		t.Fatalf("relying on a parent was refused: %v", err)
	}
}

func TestARelianceNeedsAReasonAndAPerson(t *testing.T) {
	tree := acme(t)
	good := Reliance{Entity: "acme-de", On: "acme", Control: "mfa",
		Because: "in scope per the shared services agreement", At: now,
		By: "rashik", Kind: audit.KindHuman}
	for name, spoil := range map[string]func(*Reliance){
		"no reason":  func(r *Reliance) { r.Because = "" },
		"nobody":     func(r *Reliance) { r.By = "" },
		"no date":    func(r *Reliance) { r.At = time.Time{} },
		"a model":    func(r *Reliance) { r.Kind = audit.KindAI },
		"itself":     func(r *Reliance) { r.On = r.Entity },
		"no control": func(r *Reliance) { r.Control = "" },
	} {
		r := good
		spoil(&r)
		if err := r.Validate(tree); err == nil {
			t.Errorf("a reliance with %s was accepted", name)
		}
	}
	if r := good; r.Record().Action != "entity.relies" {
		t.Errorf("the audit action is %q", r.Record().Action)
	}
}

func TestAScopeIsASubtreeAndNotTheWholeGroup(t *testing.T) {
	tree := acme(t)
	emea := tree.Scope("emea")
	if len(emea) != 3 {
		t.Fatalf("EMEA covers %v", emea)
	}
	for _, id := range emea {
		if id == "acme-us" || id == "amer" {
			t.Errorf("an EMEA audit covers %s", id)
		}
	}
	if len(tree.Scope("acme")) != 6 {
		t.Errorf("the group covers %v", tree.Scope("acme"))
	}
	if len(tree.Scope("acme-de")) != 1 {
		t.Error("a leaf covers more than itself")
	}
	if tree.Scope("nowhere") != nil {
		t.Error("an unknown entity has a scope")
	}
}

func TestPathsAreTheShapeAuthAlreadyScopesOn(t *testing.T) {
	tree := acme(t)
	if got := tree.Path("acme-de"); got != "/acme/emea/acme-de" {
		t.Errorf("path is %q", got)
	}
	if got := tree.Path("acme"); got != "/acme" {
		t.Errorf("the root's path is %q", got)
	}
}

func TestATreeThatIsNotATreeIsRefused(t *testing.T) {
	// Two roots: two groups in one file, which would share a scope by
	// accident.
	two := New()
	for _, e := range []Entity{
		{ID: "acme", Name: "Acme"}, {ID: "other", Name: "Other"},
	} {
		if err := two.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	err := two.Close()
	if err == nil {
		t.Fatal("two separate trees were accepted as one group")
	}
	if !strings.Contains(err.Error(), "two separate trees") {
		t.Errorf("the refusal is %q", err)
	}

	// A parent that does not exist.
	orphan := New()
	if err := orphan.Add(Entity{ID: "a", Name: "A", Parent: "nowhere"}); err != nil {
		t.Fatal(err)
	}
	if err := orphan.Close(); err == nil {
		t.Fatal("a company hanging off nothing was accepted")
	}

	// A cycle.
	cycle := New()
	for _, e := range []Entity{
		{ID: "a", Name: "A", Parent: "b"}, {ID: "b", Name: "B", Parent: "a"},
	} {
		if err := cycle.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := cycle.Close(); err == nil {
		t.Fatal("a cycle was accepted as a group")
	}

	// And the same company twice.
	dup := New()
	if err := dup.Add(Entity{ID: "a", Name: "A"}); err != nil {
		t.Fatal(err)
	}
	if err := dup.Add(Entity{ID: "a", Name: "A again"}); err == nil {
		t.Error("the same identifier was added twice")
	}
}

func TestEntitiesAreListedInAnyOrder(t *testing.T) {
	// A file maintained by hand lists children before parents. That is not
	// an error.
	tree := New()
	for _, e := range []Entity{
		{ID: "acme-de", Name: "Acme GmbH", Parent: "emea"},
		{ID: "emea", Name: "Acme EMEA", Parent: "acme"},
		{ID: "acme", Name: "Acme Holdings"},
	} {
		if err := tree.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := tree.Close(); err != nil {
		t.Fatalf("a file in child-first order was refused: %v", err)
	}
	if tree.Root() != "acme" {
		t.Errorf("the root is %q", tree.Root())
	}
}

func TestAnEntityIdentifierThatWouldBreakAPathIsRefused(t *testing.T) {
	for _, id := range []string{"Acme", "acme de", "acme/de", "acme:de", ""} {
		if err := (Entity{ID: id, Name: "x"}).Validate(); err == nil {
			t.Errorf("%q was accepted as an identifier", id)
		}
	}
	if err := (Entity{ID: "acme-de"}).Validate(); err == nil {
		t.Error("an entity with no name was accepted")
	}
}

// The number a group-level dashboard cannot show.
func TestTheGroupReportLeadsWithWhatIsUneven(t *testing.T) {
	tree := acme(t)
	controls := []assurance.Control{
		perEntity("mfa"), perEntity("access-review"),
		{ID: "sso", Name: "group SSO", Cadence: assurance.Continuous,
			Owner: "rashik", Entity: "acme"},
	}
	var evidence []assurance.Evidence
	for _, id := range tree.Scope("acme") {
		evidence = append(evidence, ev("mfa", id, 0, 182))
		if id != "acme-de" {
			evidence = append(evidence, ev("access-review", id, 0, 182))
		}
	}
	evidence = append(evidence, ev("sso", "acme", 0, 182))

	g, divs := Assess(tree, "acme", controls, evidence, nil, period)
	if g.Companies != 6 || g.Controls != 3 {
		t.Fatalf("%d companies, %d controls", g.Companies, g.Controls)
	}
	if g.Uneven != 1 {
		t.Errorf("%d uneven, want the one missing in Germany", g.Uneven)
	}
	if !strings.Contains(g.Why(), "different state in different companies") {
		t.Errorf("the summary is %q", g.Why())
	}
	// Worst first, so the thing to do is at the top.
	if divs[0].Control != "access-review" {
		t.Errorf("the list starts with %s", divs[0].Control)
	}

	out := Findings(tree, g, divs, now)
	var named bool
	for _, f := range out {
		if strings.Contains(f.Title, "acme-de") &&
			strings.Contains(f.Title, "no evidence") {
			named = true
			if !strings.Contains(f.Evidence[0].What, "would be green") {
				t.Errorf("the evidence does not say what a union shows: %q",
					f.Evidence[0].What)
			}
		}
	}
	if !named {
		t.Error("the company with nothing is not named in the register")
	}
}

func TestEvidenceWithNoEntityBelongsToTheGroup(t *testing.T) {
	tree := acme(t)
	c := perEntity("mfa")
	// A deployment that never set up entities writes evidence with no
	// entity, and it should behave exactly as it did before: the group's.
	d := Across(tree, "acme", c, []assurance.Evidence{
		{Control: "mfa", From: day(0), To: day(182),
			Outcome: assurance.Operated, What: "x", Source: "s", Ref: "r",
			At: day(182), By: "rashik", Kind: audit.KindHuman},
	}, nil, period)

	var rootCovered bool
	for _, e := range d.By {
		if e.Entity == "acme" && e.Coverage.Complete() {
			rootCovered = true
		}
	}
	if !rootCovered {
		t.Fatal("evidence with no entity did not count for the group")
	}
	// And because mfa is per-entity, the companies beneath are silent with
	// an ancestor that does evidence it — which is a different piece of
	// work from nobody doing it anywhere.
	if len(d.Coverable) != 5 {
		t.Errorf("%d companies could rely on it: %v", len(d.Coverable),
			d.Coverable)
	}
	for _, from := range d.Coverable {
		if from != "" && from != "acme" {
			t.Errorf("the ancestor is reported as %q", from)
		}
	}
}

// One name and "have nothing" is the kind of sentence that makes a reader
// distrust everything else on the page.
func TestTheSummaryUsesAVerbThatAgrees(t *testing.T) {
	tree := acme(t)
	c := perEntity("mfa")
	var evidence []assurance.Evidence
	for _, id := range tree.Scope("acme") {
		if id != "acme-de" {
			evidence = append(evidence, ev("mfa", id, 0, 182))
		}
	}
	one := Across(tree, "acme", c, evidence, nil, period).Why()
	if !strings.Contains(one, "acme-de has nothing") {
		t.Errorf("one silent company reads as %q", one)
	}

	var none []assurance.Evidence
	for _, id := range []string{"acme", "emea", "amer", "acme-uk"} {
		none = append(none, ev("mfa", id, 0, 182))
	}
	two := Across(tree, "acme", c, none, nil, period).Why()
	if !strings.Contains(two, "have nothing") {
		t.Errorf("two silent companies read as %q", two)
	}
}

// A control operated in one place, with nothing behind it, said as a
// sentence rather than as "0 of 1 companies".
func TestAGroupControlWithNoEvidenceSaysWhoWasSupposedToOperateIt(t *testing.T) {
	tree := acme(t)
	c := assurance.Control{ID: "pentest", Name: "annual test",
		Cadence: assurance.Annual, Entity: "acme"}
	why := Across(tree, "acme", c, nil, nil, period).Why()
	if strings.Contains(why, "0 of 1") {
		t.Errorf("the summary reads as a puzzle: %q", why)
	}
	if !strings.Contains(why, "operated by acme") {
		t.Errorf("the summary does not say who should have: %q", why)
	}
	if !strings.Contains(why, "5 compan(ies) beneath") {
		t.Errorf("the summary does not say how many it was meant to "+
			"cover: %q", why)
	}
}

// Auditing one subsidiary is a real scope, and telling its report about a
// group dashboard is telling it about somebody else's problem.
func TestASingleCompanyScopeIsNotToldAboutAUnion(t *testing.T) {
	tree := acme(t)
	why := Across(tree, "acme-de", perEntity("mfa"), nil, nil, period).Why()
	if strings.Contains(why, "union") {
		t.Errorf("a one-company scope reads as %q", why)
	}
	if !strings.Contains(why, "acme-de has nothing") {
		t.Errorf("it does not say what is missing: %q", why)
	}
}
