// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package vendor

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/connector"
	"github.com/quilzo/quilzo/internal/telemetry"
)

var now = time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)

func plain(id string) Vendor {
	return Vendor{
		ID: id, Name: strings.ToUpper(id[:1]) + id[1:],
		Purpose: "does a thing for us", Status: Active, Owner: "rashik",
		Reviewed: now.Add(-30 * 24 * time.Hour),
	}
}

func register(t *testing.T, in ...Vendor) *Register {
	t.Helper()
	r := NewRegister()
	for _, v := range in {
		if err := r.Add(v); err != nil {
			t.Fatalf("add %s: %v", v.ID, err)
		}
	}
	return r
}

func manifest(name, host string, endpoints ...string) connector.Manifest {
	m := connector.Manifest{
		Name: name, Tool: name, Host: host,
		Auth: connector.Auth{Kind: connector.Bearer, Secret: name + "-token"},
	}
	for _, e := range endpoints {
		m.Endpoints = append(m.Endpoints, connector.Endpoint{
			Name: e, Path: "/v1/" + e, Produces: connector.Identities,
			Reads: []string{"id"}, Map: map[string]string{"id": "id"},
		})
	}
	return m
}

// Every product in this category has one field called "access". This is the
// half of it where their breach is our breach.
func TestAVendorHoldingACredentialHereIsCriticalWhateverAnybodySaid(t *testing.T) {
	// A chat widget. Small contract, no sensitive data declared, not
	// essential — and an OAuth token in the CRM.
	drift := plain("chatwidget")
	drift.Access = []Access{{Reach: TheyRead, What: "salesforce",
		Scopes: []string{"api", "refresh_token"}}}

	tier, because := drift.Tier()
	if tier != Critical {
		t.Fatalf("a vendor with a token in the CRM is %s", tier)
	}
	if !strings.Contains(because, "not a judgement about them") {
		t.Errorf("the reason is %q", because)
	}

	// The same vendor without the token is routine, which is what an
	// inherent risk questionnaire about a chat widget would have said.
	drift.Access = nil
	if tier, _ := drift.Tier(); tier != Routine {
		t.Errorf("without the token it is %s", tier)
	}
}

func TestTheTwoDirectionsAreKeptApart(t *testing.T) {
	for reach, inbound := range map[Reach]bool{
		TheyRead: true, TheyWrite: true,
		WeRead: false, WeSend: false, TheyHost: false,
	} {
		if reach.Inbound() != inbound {
			t.Errorf("%s inbound = %v", reach, reach.Inbound())
		}
		if d := reach.Describe(); d == "" || d == string(reach) {
			t.Errorf("%s describes itself as %q", reach, d)
		}
	}

	// We hold a credential to them: elevated, not critical. If their service
	// lies to us we get bad data; that is bounded and unpleasant.
	ours := plain("kandji")
	ours.Access = []Access{{Reach: WeRead, What: "acme.api.kandji.io"}}
	if tier, _ := ours.Tier(); tier != Elevated {
		t.Errorf("holding a credential to them is %s", tier)
	}
}

func TestSensitiveDataAndEssentialnessRaiseTheTier(t *testing.T) {
	v := plain("payroll")
	v.Data = []Data{"staff records (sensitive)"}
	if tier, because := v.Tier(); tier != High ||
		!strings.Contains(because, "marked sensitive") {
		t.Errorf("tier is %s because %q", tier, because)
	}

	v = plain("cdn")
	v.Essential = true
	if tier, because := v.Tier(); tier != High ||
		!strings.Contains(because, "business stops") {
		t.Errorf("tier is %s because %q", tier, because)
	}

	// And a credential here beats both, because it is a token rather than
	// an opinion.
	v.Access = []Access{{Reach: TheyWrite, What: "the build pipeline"}}
	if tier, _ := v.Tier(); tier != Critical {
		t.Errorf("tier is %s", tier)
	}
}

// What makes a critical vendor critical is a thing that changes without
// anybody telling us.
func TestACriticalVendorIsReviewedTwiceAsOften(t *testing.T) {
	ordinary := plain("stationery")
	critical := plain("chatwidget")
	critical.Access = []Access{{Reach: TheyRead, What: "salesforce"}}
	critical.Reviewed = ordinary.Reviewed

	if !critical.Due().Before(ordinary.Due()) {
		t.Fatalf("critical is due %s and ordinary %s", critical.Due(),
			ordinary.Due())
	}
	// Seven months on: the critical one has lapsed and the other has not.
	later := now.Add(180 * 24 * time.Hour)
	if !critical.Overdue(later) {
		t.Error("a critical vendor is not yet due after seven months")
	}
	if ordinary.Overdue(later) {
		t.Error("an ordinary vendor is already due after seven months")
	}
	// A vendor nobody has ever reviewed is overdue from the start.
	never := plain("new")
	never.Reviewed = time.Time{}
	if !never.Overdue(now) {
		t.Error("a vendor nobody has reviewed is not overdue")
	}
}

// The single most useful thing this package computes.
func TestATerminatedVendorWithALiveCredentialIsCritical(t *testing.T) {
	gone := plain("chatwidget")
	gone.Status = Terminated
	gone.Access = []Access{{Reach: TheyRead, What: "salesforce"}}

	r := register(t, gone)
	rec := Reconcile(r, nil, now)
	if len(rec.Lingering) != 1 {
		t.Fatalf("lingering is %v", rec.Lingering)
	}
	if !strings.Contains(rec.Lingering[0].What, "until somebody revokes it") {
		t.Errorf("the gap does not say why: %q", rec.Lingering[0].What)
	}
	if !strings.Contains(rec.Why(), "The contract ended and the credential "+
		"did not") {
		t.Errorf("the summary is %q", rec.Why())
	}

	out := Findings(r, rec, now)
	if len(out) == 0 || out[0].Severity != telemetry.SeverityCritical {
		t.Fatalf("the top finding is %v", out)
	}
	if !strings.Contains(out[0].Title, "after the relationship ended") {
		t.Errorf("the title is %q", out[0].Title)
	}

	// And a vendor on the way out with a live connector is the same problem
	// caught earlier.
	exiting := plain("kandji")
	exiting.Status = Exiting
	rec = Reconcile(register(t, exiting),
		[]connector.Manifest{manifest("kandji", "acme.api.kandji.io", "devices")},
		now)
	if len(rec.Lingering) != 1 {
		t.Fatalf("an exiting vendor with a live connector: %v", rec)
	}
}

// A register that only knows what somebody typed into it will always be
// behind.
func TestAConnectorForAVendorNobodyRegisteredIsFound(t *testing.T) {
	r := register(t, plain("kandji"))
	rec := Reconcile(r, []connector.Manifest{
		manifest("kandji", "acme.api.kandji.io", "devices"),
		manifest("knowbe4", "eu.api.knowbe4.com", "users"),
	}, now)

	if len(rec.Unregistered) != 1 || rec.Unregistered[0].Vendor != "knowbe4" {
		t.Fatalf("unregistered is %v", rec.Unregistered)
	}
	if !strings.Contains(rec.Unregistered[0].What, "eu.api.knowbe4.com") {
		t.Errorf("the gap does not say where: %q", rec.Unregistered[0].What)
	}
	out := Findings(r, rec, now)
	var found bool
	for _, f := range out {
		if strings.Contains(f.Title, "knowbe4") &&
			strings.Contains(f.Title, "not in the register") {
			found = true
			if f.Severity != telemetry.SeverityHigh {
				t.Errorf("an unassessed processor is %v", f.Severity)
			}
		}
	}
	if !found {
		t.Error("the unregistered processor is not in the queue")
	}
}

// An access nobody wrote down is a tier that is too low.
func TestARegisteredVendorWithUndeclaredAccessIsReported(t *testing.T) {
	r := register(t, plain("kandji"))
	rec := Reconcile(r, []connector.Manifest{
		manifest("kandji", "acme.api.kandji.io", "devices"),
	}, now)
	if len(rec.Undeclared) != 1 {
		t.Fatalf("undeclared is %v", rec.Undeclared)
	}
	if !strings.Contains(rec.Undeclared[0].What, "tier that is too low") {
		t.Errorf("the gap does not say the consequence: %q",
			rec.Undeclared[0].What)
	}

	// Once the register records it, the two agree — and the vendor's tier
	// has moved.
	declared := plain("kandji")
	declared.Access = []Access{Derived(
		manifest("kandji", "acme.api.kandji.io", "devices"), now)}
	clean := Reconcile(register(t, declared), []connector.Manifest{
		manifest("kandji", "acme.api.kandji.io", "devices"),
	}, now)
	if !clean.Clean() {
		t.Fatalf("a declared access still disagrees: %v", clean)
	}
	if tier, _ := declared.Tier(); tier != Elevated {
		t.Errorf("after declaring the access the tier is %s", tier)
	}
}

// What a connector proves is that a credential exists and what it may read.
// Whether that is the whole of the relationship is a question for whoever
// owns the vendor.
func TestDerivedAccessIsOfferedRatherThanApplied(t *testing.T) {
	m := manifest("kandji", "acme.api.kandji.io", "devices", "users")
	a := Derived(m, now)
	if a.Reach != WeRead {
		t.Errorf("derived reach is %s", a.Reach)
	}
	if a.What != "acme.api.kandji.io" || a.Connector != "kandji" {
		t.Errorf("derived access is %+v", a)
	}
	if len(a.Scopes) != 2 || a.Scopes[0] != "devices" {
		t.Errorf("scopes are %v", a.Scopes)
	}
	// A register with the connector present and the access absent still
	// disagrees, which is the point: nothing absorbed it silently.
	rec := Reconcile(register(t, plain("kandji")),
		[]connector.Manifest{m}, now)
	if rec.Clean() {
		t.Error("the register silently absorbed a derived access")
	}
}

// An empty subprocessor list is not the same as a vendor with no
// subprocessors.
func TestNobodyAskingAboutSubprocessorsIsAFinding(t *testing.T) {
	v := plain("payroll")
	v.Data = []Data{"staff records (sensitive)"}
	r := register(t, v)
	out := Findings(r, Reconcile(r, nil, now), now)

	var asked bool
	for _, f := range out {
		if strings.Contains(f.Title, "who their processors are") {
			asked = true
			if !strings.Contains(f.Evidence[0].What, "700 organisations") {
				t.Errorf("the evidence does not say why: %q",
					f.Evidence[0].What)
			}
		}
	}
	if !asked {
		t.Fatal("a high-tier vendor nobody has asked about subprocessors " +
			"produced nothing")
	}

	// Having asked and been told there are none is a different state.
	v.Asked = now.Add(-30 * 24 * time.Hour)
	r = register(t, v)
	for _, f := range Findings(r, Reconcile(r, nil, now), now) {
		if strings.Contains(f.Title, "who their processors are") {
			t.Error("a vendor that was asked is still reported")
		}
	}

	// And a routine vendor is not asked at all, because a register that
	// asks everybody about everything is one nobody fills in.
	routine := plain("stationery")
	rr := register(t, routine)
	for _, f := range Findings(rr, Reconcile(rr, nil, now), now) {
		if strings.Contains(f.Title, "who their processors are") {
			t.Error("a stationery supplier was asked for a subprocessor list")
		}
	}
}

func TestAVendorNobodyCanExplainIsRefused(t *testing.T) {
	good := plain("kandji")
	for name, spoil := range map[string]func(*Vendor){
		"no purpose": func(v *Vendor) { v.Purpose = "" },
		"no name":    func(v *Vendor) { v.Name = "" },
		"no status":  func(v *Vendor) { v.Status = "" },
		"an invented status": func(v *Vendor) {
			v.Status = Status("maybe")
		},
		"an identifier a connector cannot match": func(v *Vendor) {
			v.ID = "Kandji MDM"
		},
		"access in no direction": func(v *Vendor) {
			v.Access = []Access{{What: "something"}}
		},
		"access to nothing": func(v *Vendor) {
			v.Access = []Access{{Reach: WeRead}}
		},
	} {
		v := good
		spoil(&v)
		if err := v.Validate(); err == nil {
			t.Errorf("a vendor with %s was accepted", name)
		}
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("an ordinary vendor was refused: %v", err)
	}
	// The purpose refusal says why it matters.
	v := good
	v.Purpose = ""
	if err := v.Validate(); !strings.Contains(err.Error(),
		"still holding credentials") {
		t.Errorf("the refusal is %v", err)
	}
}

func TestTheRegisterListsTheWorstFirst(t *testing.T) {
	critical := plain("chatwidget")
	critical.Access = []Access{{Reach: TheyRead, What: "salesforce"}}
	high := plain("payroll")
	high.Data = []Data{"staff records (sensitive)"}

	r := register(t, plain("stationery"), high, critical)
	all := r.All()
	if all[0].ID != "chatwidget" {
		t.Errorf("the list starts with %s", all[0].ID)
	}
	if all[len(all)-1].ID != "stationery" {
		t.Errorf("the list ends with %s", all[len(all)-1].ID)
	}
}

func TestAVendorAssessmentReachesARealAuditLog(t *testing.T) {
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
	for _, s := range Statuses() {
		v := plain("kandji")
		v.Status = s
		if verr := v.Validate(); verr != nil {
			t.Fatalf("%s: %v", s, verr)
		}
		if _, aerr := log.Append(v.Record("rashik",
			audit.KindHuman)); aerr != nil {
			t.Fatalf("%s: %v", s, aerr)
		}
	}
	events, err := audit.Read(dir + "/audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != len(Statuses()) {
		t.Fatalf("%d entries for %d statuses", len(events), len(Statuses()))
	}
	// The tier is in the record, derived, so a log read years later says
	// what this was rather than what somebody called it.
	if events[0].Detail["tier"] == "" {
		t.Error("the record does not carry the tier")
	}
}

func TestTerminatedVendorsAreNotChasedForReviews(t *testing.T) {
	gone := plain("stationery")
	gone.Status = Terminated
	gone.Reviewed = now.Add(-900 * 24 * time.Hour)
	r := register(t, gone)
	for _, f := range Findings(r, Reconcile(r, nil, now), now) {
		if strings.Contains(f.Title, "has not been reviewed") {
			t.Error("a terminated vendor is in the review queue")
		}
	}
}
