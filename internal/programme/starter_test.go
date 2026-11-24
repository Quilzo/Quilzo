// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package programme

import (
	"bytes"
	"encoding/csv"
	"errors"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/frameworks"
	"github.com/quilzo/quilzo/internal/register"
)

// installs is the starter installed by dana and approved by lee, with the
// receipt of the one commit that put it in.
func (b *bench) installs(t testing.TB, framework string) register.Receipt {
	t.Helper()
	raised := must(b.Install(asDana(), framework))
	if !raised.Waits {
		t.Fatalf("installing %s with somebody else eligible did not wait for them: %+v", framework, raised)
	}
	return must(b.Approve(asLee(), raised.ID)).Receipt
}

// Taking a starter into the programme is one decision: one Starter record
// with the approval that made it, written in one commit with every
// requirement it brings. Until somebody other than the person who asked
// approves it, the register holds none of it.
func TestStarterInstallsAsOneDecision(t *testing.T) {
	b := newBench(t)
	raised := must(b.Install(asDana(), "iso-27001"))
	if !raised.Waits || b.Reg.Head() != "" {
		t.Fatalf("a starter raised by one of two eligible was written before the other approved it: %+v", raised)
	}
	if _, err := b.Approve(asDana(), raised.ID); !errors.Is(err, register.ErrRefused) {
		t.Errorf("dana approving the install she raised was answered %v", err)
	}
	rc := must(b.Approve(asLee(), raised.ID))
	iso, _ := StarterNamed("iso-27001")
	if len(iso.Clauses) != 93 {
		t.Errorf("the ISO/IEC 27001:2022 starter holds %d controls, and Annex A has 93", len(iso.Clauses))
	}
	if rc.Receipt.Commit == "" || len(rc.Receipt.Written) != 1+len(iso.Clauses) {
		t.Fatalf("the install wrote %d records; it is the decision and its %d requirements", len(rc.Receipt.Written), len(iso.Clauses))
	}
	decisions := 0
	for _, w := range rc.Receipt.Written {
		if w.Kind == register.KindStarter {
			decisions++
		}
	}
	if decisions != 1 {
		t.Errorf("the install made %d decisions", decisions)
	}
	commit := must(b.Reg.Store.GetCommit(rc.Receipt.Commit))
	if len(commit.Parents) != 0 {
		t.Errorf("the install is not the register's one commit: its parents are %v", commit.Parents)
	}
	e := must(b.Reg.Get(raised.ID))
	s := e.Record.(register.Starter)
	if !s.Installed || s.Approval == nil || s.Approval.Raised != dana.Subject || s.Approval.Signers[0].Subject != lee.Subject {
		t.Errorf("the decision is %+v", s)
	}
	if s.Content != iso.Content() || s.Approval.Surface != register.SurfaceOf(withApproval(s, nil)) {
		t.Error("the decision does not name what it brought, or its approval is of something else")
	}
	installed := must(Installed(b.view(t)))
	if _, ok := installed["iso-27001"]; !ok {
		t.Error("the programme does not read the starter as installed")
	}

	// The only person eligible decides alone, at once, with a review due.
	b2 := newBench(t)
	d := must(b2.Install(alone(), "iso-42001"))
	if d.Waits || !d.Alone {
		t.Fatalf("the only person eligible installing a starter was %+v", d)
	}
	got := must(b2.Reg.Get(d.ID)).Record.(register.Starter)
	if !got.Approval.Alone || got.Approval.ReviewDue == 0 {
		t.Errorf("a decision made alone is not marked so: %+v", got.Approval)
	}
	// Somebody who may not approve decides nothing alone, even where only
	// one person may: what they raise waits for that person.
	b3 := newBench(t)
	notEligible := Decider{By: lee, Eligible: 1, MayApprove: false, Proof: "lee's session"}
	if d := must(b3.Install(notEligible, "dora")); !d.Waits || b3.Reg.Head() != "" {
		t.Errorf("somebody who may not approve installed a starter alone: %+v", d)
	}
	// And a starter this program does not carry, or another edition of
	// one, is not what would be written, so it is refused.
	forged := iso.Decision(true)
	forged.Content = register.Digest("sha256:" + strings.Repeat("0", 64))
	if _, err := b2.Raise(alone(), "a forged starter", forged); !errors.Is(err, register.ErrInvalid) {
		t.Errorf("a starter whose content is not this program's was answered %v", err)
	}
}

// Taking a starter out is one decision too: the Starter record changes and
// nothing else, in one commit, and the programme reads its requirements as
// out of it while they stay in the register.
func TestStarterUninstallsAsOneDecision(t *testing.T) {
	b := newBench(t)
	b.installs(t, "iso-27001")
	scope := must(b.DecideScope(alone(), register.Scope{Name: "group", Title: "The group",
		Domains: []register.Domain{"identity"}, Frameworks: []string{"iso-27001"}}))
	if scope.Waits {
		t.Fatal("the scope waits")
	}
	before := must(StatementAt(b.view(t), b.Keep, "group"))
	if len(before.Lines) != 93 {
		t.Fatalf("the statement has %d lines with the starter installed", len(before.Lines))
	}
	raised := must(b.Uninstall(asDana(), "iso-27001"))
	if !raised.Waits {
		t.Fatal("taking a starter out did not wait for somebody else")
	}
	rc := must(b.Approve(asLee(), raised.ID))
	if rc.Receipt.Commit == "" || len(rc.Receipt.Written) != 1 || rc.Receipt.Written[0].Kind != register.KindStarter {
		t.Fatalf("taking the starter out wrote %+v", rc.Receipt.Written)
	}
	if installed := must(Installed(b.view(t))); len(installed) != 0 {
		t.Errorf("the starter is still read as installed: %v", installed)
	}
	if n := must(b.Reg.Counts())[register.KindRequirement]; n != 93 {
		t.Errorf("the register holds %d requirements; what was written stays", n)
	}
	after := must(StatementAt(b.view(t), b.Keep, "group"))
	if len(after.Lines) != 0 {
		t.Errorf("the statement lists %d requirements of a starter taken out", len(after.Lines))
	}
}

// A line of the statement of applicability is a decision: written without
// an approval it is refused, written with an approval of another line it
// is refused, and raised by one of two eligible it waits, undecided, until
// the other approves it.
func TestApplicabilityNeedsApproval(t *testing.T) {
	b := newBench(t)
	b.installs(t, "iso-27001")
	must(b.DecideScope(alone(), register.Scope{Name: "group", Title: "The group", Domains: []register.Domain{"identity"}}))
	v := b.view(t)
	rid := must(RequirementID("iso-27001", "A.7.4"))
	sid := must(register.DeriveID(register.KindScope, register.Local, "group"))
	line := register.Applicability{Requirement: rid, Scope: sid, Applicable: false, Justification: TextOf("no premises")}
	if _, err := b.Reg.Put(dana, "a line with no approval", line); !errors.Is(err, register.ErrInvalid) {
		t.Errorf("a line with no approval was answered %v", err)
	}
	other := line
	other.Applicable = true
	a := must(approvalOf(other, dana.Subject, asLee(), b.clock.now()))
	line.Approval = a
	if _, err := b.Reg.Put(dana, "a line with another's approval", line); !errors.Is(err, register.ErrInvalid) {
		t.Errorf("a line carrying the approval of another was answered %v", err)
	}

	d := must(b.DecideLine(asDana(), "group", "iso-27001", "A.7.4", false,
		"We have no premises of our own; staff work from home and the office is a shared desk."))
	if !d.Waits {
		t.Fatal("a line raised by one of two eligible was written at once")
	}
	st := must(StatementAt(b.view(t), b.Keep, "group"))
	if st.Undecided != 93 || st.Applying != 0 || st.NotApplying != 0 {
		t.Errorf("before its approval the statement counts %d undecided, %d applying, %d not", st.Undecided, st.Applying, st.NotApplying)
	}
	must(b.Approve(asLee(), d.ID))
	st = must(StatementAt(b.view(t), b.Keep, "group"))
	if st.NotApplying != 1 || st.Undecided != 92 {
		t.Errorf("after its approval the statement counts %d not applying, %d undecided", st.NotApplying, st.Undecided)
	}
	_ = v
}

// What the programme covers is a decision, refused without its approval.
func TestScopeNeedsApproval(t *testing.T) {
	b := newBench(t)
	s := register.Scope{Name: "group", Title: "The group", Domains: []register.Domain{"identity", "cloud"},
		Frameworks: []string{"nis2"}}
	if _, err := b.Reg.Put(dana, "a scope with no approval", s); !errors.Is(err, register.ErrInvalid) {
		t.Errorf("a scope with no approval was answered %v", err)
	}
	d := must(b.DecideScope(asDana(), s))
	if !d.Waits || b.Reg.Head() != "" {
		t.Fatal("a scope raised by one of two eligible was written at once")
	}
	if _, err := b.Approve(asDana(), d.ID); !errors.Is(err, register.ErrRefused) {
		t.Errorf("dana approving her own scope was answered %v", err)
	}
	must(b.Approve(asLee(), d.ID))
	got := must(b.Reg.Get(d.ID)).Record.(register.Scope)
	if got.Approval == nil || got.Approval.Signers[0].Subject != lee.Subject {
		t.Errorf("the scope's approval is %+v", got.Approval)
	}
	// Change it, and the approval is of the scope it was.
	got.Domains = append(got.Domains, "vendors")
	if _, err := b.Reg.Put(lee, "a scope widened under its old approval", got); !errors.Is(err, register.ErrInvalid) {
		t.Errorf("a widened scope carrying the old approval was answered %v", err)
	}
}

// Every mapping carries one of NIST IR 8477's relationships and why: one
// without a relation, or with a word that is not one of the five, is
// refused, and every mapping a starter brings has both.
func TestMappingCarriesIR8477Relation(t *testing.T) {
	b := newBench(t)
	b.installs(t, "iso-27001")
	ctl := register.Control{Ref: "AC-01", Title: "Second factor for every account", Domain: "identity", Owner: dana.Subject}
	b.put(t, dana, ctl)
	to := must(RequirementID("iso-27001", "A.8.5"))
	for _, rel := range []register.Relation{"", "covers", "satisfies"} {
		m := register.Mapping{From: mustID(t, ctl), To: to, Relation: rel, Rationale: TextOf("why")}
		if _, err := b.Reg.Put(dana, "a mapping", m); !errors.Is(err, register.ErrInvalid) {
			t.Errorf("a mapping related by %q was answered %v", rel, err)
		}
	}
	if _, _, err := b.MapControl(dana, "AC-01", "iso-27001", "A.8.5", "subset-of", ""); !errors.Is(err, register.ErrInvalid) {
		t.Errorf("a mapping with no rationale was answered %v", err)
	}
	must(func() (register.ID, error) {
		id, _, err := b.MapControl(dana, "AC-01", "iso-27001", "A.8.5", "subset-of",
			"Second factors are one part of signing in securely; the control says nothing of passwords or sessions.")
		return id, err
	}())
	for _, s := range Starters() {
		recs := must(s.Records())
		for _, r := range recs {
			m, ok := r.(register.Mapping)
			if !ok {
				continue
			}
			if !strings.Contains(strings.Join(register.Relation("").Values(), " "), string(m.Relation)) || m.Relation == "" {
				t.Errorf("a %s mapping is related by %q", s.Framework, m.Relation)
			}
			if words, ok := b.Keep.Words(m.Rationale); !ok || words == "" {
				t.Errorf("a %s mapping's rationale has no words", s.Framework)
			}
		}
	}
}

// The statement of applicability exports as CSV: a header, a row for each
// requirement, the state of each, the justification's words, who approved
// and whether alone, and each mapped control as evidence towards the
// requirement. A cell a spreadsheet would run as a formula is guarded, and
// nothing is called compliant.
func TestSoACSVExport(t *testing.T) {
	b := newBench(t)
	b.installs(t, "nis2")
	must(b.DecideScope(alone(), register.Scope{Name: "group", Title: "The group",
		Domains: []register.Domain{"identity"}, Frameworks: []string{"nis2"}}))
	must(b.DecideLine(alone(), "group", "nis2", "Art. 21(2)(j)", true, "=HYPERLINK(\"http://x\") we sign in with passkeys"))
	ctl := register.Control{Ref: "AC-01", Title: "Second factor for every account", Domain: "identity", Owner: dana.Subject}
	b.put(t, dana, ctl)
	must(func() (register.ID, error) {
		id, _, err := b.MapControl(dana, "AC-01", "nis2", "Art. 21(2)(j)", "subset-of", "Second factors are part of the point.")
		return id, err
	}())
	st := must(StatementAt(b.view(t), b.Keep, "group"))
	var buf bytes.Buffer
	if err := st.WriteCSV(&buf); err != nil {
		t.Fatal(err)
	}
	rows := must(csv.NewReader(&buf).ReadAll())
	if len(rows) != 11 || strings.Join(rows[0], ",") != strings.Join(CSVHeader, ",") {
		t.Fatalf("the export has %d rows, headed %v", len(rows), rows[0])
	}
	var j []string
	for _, r := range rows[1:] {
		if r[1] == "Art. 21(2)(j)" {
			j = r
		} else if r[3] != Undecided {
			t.Errorf("%s is %q and nobody decided it", r[1], r[3])
		}
	}
	if j == nil || j[3] != Applies || !strings.HasPrefix(j[4], "'=") || j[7] != "yes" || j[5] != string(dana.Subject) {
		t.Errorf("the decided line is %q", j)
	}
	if !strings.Contains(j[8], "AC-01 (subset-of): no evidence from a run") {
		t.Errorf("the evidence column says %q", j[8])
	}
	if strings.Contains(strings.ToLower(buf.String()), "compliant") {
		t.Error("the statement calls something compliant")
	}
}

// The NIS2 starter goes in as one decision, as every starter does.
func TestNIS2InstallsAsOneDecision(t *testing.T) {
	b := newBench(t)
	rc := b.installs(t, "nis2")
	nis2, _ := StarterNamed("nis2")
	if len(nis2.Clauses) != 10 {
		t.Errorf("the NIS2 starter holds %d points of Article 21(2), and there are ten", len(nis2.Clauses))
	}
	decisions, reqs, maps := 0, 0, 0
	for _, w := range rc.Written {
		switch w.Kind {
		case register.KindStarter:
			decisions++
		case register.KindRequirement:
			reqs++
		case register.KindMapping:
			maps++
		}
	}
	if decisions != 1 || reqs != 10 || maps != len(nis2.Crosswalk) || len(rc.Written) != 1+10+len(nis2.Crosswalk) {
		t.Errorf("the NIS2 install wrote %d decisions, %d requirements and %d mappings in its commit", decisions, reqs, maps)
	}
}

// NIS2's points are mapped to ISO/IEC 27001's controls, each by one of NIST
// IR 8477's relationships with why, and the statement shows each from both
// sides.
func TestNIS2MapsToISOByRelation(t *testing.T) {
	b := newBench(t)
	b.installs(t, "iso-27001")
	b.installs(t, "nis2")
	v := b.view(t)
	var maps int
	if err := v.Each(register.KindMapping, func(e register.Entry, _ map[string]any) error {
		m := e.Record.(register.Mapping)
		from := must(v.Get(m.From)).Record.(register.Requirement)
		to := must(v.Get(m.To)).Record.(register.Requirement)
		if from.Framework != "nis2" || to.Framework != "iso-27001" {
			t.Errorf("a mapping goes from %s to %s", from.Framework, to.Framework)
		}
		if m.Relation == "" || m.Relation == "equal" {
			t.Errorf("%s is mapped to %s as %q; no NIS2 point is the same as one ISO control", from.Ref, to.Ref, m.Relation)
		}
		maps++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if maps < 10 {
		t.Errorf("NIS2 is mapped to ISO by %d relations", maps)
	}
	must(b.DecideScope(alone(), register.Scope{Name: "group", Title: "The group", Domains: []register.Domain{"identity"},
		Frameworks: []string{"iso-27001", "nis2"}}))
	st := must(StatementAt(b.view(t), b.Keep, "group"))
	var fromNIS2, toISO bool
	for _, l := range st.Lines {
		for _, r := range l.Related {
			if l.Framework == "nis2" && l.Ref == "Art. 21(2)(b)" && r.Framework == "iso-27001" && r.Ref == "A.5.26" && r.Relation == "superset-of" {
				fromNIS2 = true
			}
			if l.Framework == "iso-27001" && l.Ref == "A.5.26" && r.From && r.Ref == "Art. 21(2)(b)" {
				toISO = true
			}
		}
	}
	if !fromNIS2 || !toISO {
		t.Errorf("the statement shows the incident mapping from NIS2 %v and from ISO %v", fromNIS2, toISO)
	}
	if strings.Join(st.Frameworks, ",") != "iso-27001,nis2" || len(st.Lines) != 103 {
		t.Errorf("the statement covers %v in %d lines", st.Frameworks, len(st.Lines))
	}
}

// Every starter is written in Quilzo's own words: a line for each
// requirement, and none of them a framework's own title as this program
// carries it from the published list.
func TestStartersAreInQuilzosOwnWords(t *testing.T) {
	want := map[string]int{"iso-27001": 93, "nis2": 10, "soc2": 61, "dora": 22, "nist-csf": 22, "iso-42001": 38}
	got := map[string]int{}
	for _, s := range Starters() {
		got[s.Framework] = len(s.Clauses)
		if cat, ok := s.Catalogued(); ok && cat.Name == "" {
			t.Errorf("%s is catalogued with no name", s.Framework)
		}
		for _, c := range s.Clauses {
			if strings.Contains(strings.ToLower(c.Line), "compliant") {
				t.Errorf("%s %s says compliant", s.Framework, c.Ref)
			}
		}
	}
	for f, n := range want {
		if got[f] != n {
			t.Errorf("the %s starter holds %d requirements, not %d", f, got[f], n)
		}
	}
	nis2, _ := StarterNamed("nis2")
	for _, c := range nis2.Clauses {
		if strings.EqualFold(c.Line, frameworks.Title("nis2", c.Ref)) {
			t.Errorf("NIS2 %s is the Directive's own words, not Quilzo's", c.Ref)
		}
	}
}

// A person has one pseudonym however many processes ask for it at once,
// and it is the same the next time it is asked for.
func TestAPersonHasOnePseudonym(t *testing.T) {
	dir := t.TempDir()
	ids := make(chan register.ID, 8)
	for range 8 {
		go func() {
			k := &FileKeeper{Dir: dir}
			id, err := k.Pseudonym("dana@example.org", "person")
			if err != nil {
				t.Error(err)
			}
			ids <- id
		}()
	}
	first := <-ids
	for range 7 {
		if id := <-ids; id != first {
			t.Errorf("one person was given %s and %s", first, id)
		}
	}
	if !first.Valid() {
		t.Fatalf("the pseudonym is %q", first)
	}
	k := &FileKeeper{Dir: dir}
	if again, _ := k.Pseudonym("dana@example.org", "person"); again != first {
		t.Errorf("asked again, the pseudonym is %s, not %s", again, first)
	}
	words := "We hold no premises of our own."
	text := must(k.Keep(words))
	if got, ok := k.Words(text); !ok || got != words {
		t.Errorf("the words kept read back as %q", got)
	}
	sealed := &FileKeeper{Dir: t.TempDir(), NoWords: true}
	if text := must(sealed.Keep(words)); text != TextOf(words) {
		t.Error("a keeper that keeps no words gave another digest")
	} else if _, ok := sealed.Words(text); ok {
		t.Error("a keeper that keeps no words read some back")
	}
}
