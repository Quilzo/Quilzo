// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package telemetry

import (
	"strings"
	"testing"
	"time"
)

var at = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

func signIn() Event {
	return Event{
		Time: at, Received: at.Add(2 * time.Second),
		Class: ClassAuthentication, Activity: 1,
		Severity: SeverityMedium, Disposition: DispositionBlocked,
		Source: "okta/system", Message: "sign-in denied",
		Actor:  ID{Issuer: "okta", Value: "u-1043"},
		Device: ID{Issuer: "kandji", Value: "d-77"},
		Observables: []Observable{
			{Kind: ObservableIP, Value: "203.0.113.9", Name: "client_ip"},
			{Kind: ObservableIP, Value: "198.51.100.4", Name: "gateway_ip"},
		},
		Raw: map[string]string{"factor": "push"},
	}
}

// The arithmetic OCSF gets right, and the reason it is worth borrowing.
func TestAClassKnowsItsOwnCategory(t *testing.T) {
	// Derived by division, not looked up: a table would be a second place for
	// the answer to live and therefore a place for it to drift.
	for class, want := range map[Class]Category{
		ClassAuthentication:  CategoryIAM,
		ClassAPIActivity:     CategoryApplication,
		ClassHTTPActivity:    CategoryNetwork,
		ClassProcessActivity: CategorySystem,
		ClassDetection:       CategoryFindings,
	} {
		if got := class.Category(); got != want {
			t.Errorf("class %d is in category %d, wanted %d", class, got, want)
		}
	}
}

func TestACategoryIsNotAClassInIt(t *testing.T) {
	// 3000 is "IAM" and names no class, so a source that sent it has told us
	// it does not know what it is sending.
	if Class(3000).Valid() {
		t.Error("a bare category was accepted as a class")
	}
	if !ClassAuthentication.Valid() {
		t.Error("a real class was refused")
	}
	if Class(9001).Valid() {
		t.Error("a class outside every category was accepted")
	}
}

func TestTypeUIDIsClassAndActivity(t *testing.T) {
	e := signIn()
	// OCSF's own composition, so an export needs no translation.
	if got, want := e.TypeUID(), uint32(300201); got != want {
		t.Errorf("type_uid is %d, wanted %d", got, want)
	}
}

// -- the two things OCSF gets wrong ------------------------------------------

func TestDispositionIsOnEveryEvent(t *testing.T) {
	// OCSF has no disposition on its Network, HTTP or Process classes, which
	// are exactly the classes where it decides whether an event is an attack
	// or a stopped attack.
	for _, class := range []Class{
		ClassHTTPActivity, ClassNetworkActivity, ClassProcessActivity,
	} {
		e := signIn()
		e.Class = class
		if _, ok := e.Fields()["disposition"]; !ok {
			t.Errorf("class %d carries no disposition", class)
		}
	}
}

func TestAFailureIsNotABlock(t *testing.T) {
	// Conflating them inflates every "attacks stopped" figure a report will
	// ever produce: a wrong password is not a control working.
	if DispositionFailed == DispositionBlocked {
		t.Fatal("failed and blocked are the same value")
	}
	if DispositionFailed.String() == DispositionBlocked.String() {
		t.Error("failed and blocked read the same")
	}
}

func TestAnIdentifierCarriesTheSystemThatIssuedIt(t *testing.T) {
	// The join that makes comparing a workforce across platforms possible.
	// Two directories both issue "u-1043" and they are not the same person.
	okta := ID{Issuer: "okta", Value: "u-1043"}
	mdm := ID{Issuer: "kandji", Value: "u-1043"}
	if okta.String() == mdm.String() {
		t.Fatal("two identifiers from different directories compare equal, " +
			"so a correlation would invent a relationship between two people")
	}

	e := signIn()
	f := e.Fields()
	if f["actor"] != "okta:u-1043" {
		t.Errorf("the actor reads as %q", f["actor"])
	}
	// And addressable separately, so a rule can match every identity from one
	// directory without caring which account.
	if f["actor.issuer"] != "okta" || f["actor.value"] != "u-1043" {
		t.Errorf("the parts are %q / %q", f["actor.issuer"], f["actor.value"])
	}
}

func TestAnIdentifierWithoutAnIssuerIsRefused(t *testing.T) {
	e := signIn()
	e.Actor = ID{Value: "u-1043"}
	err := e.Validate()
	if err == nil {
		t.Fatal("an identifier with no issuer was accepted; downstream it " +
			"cannot be joined against anything and the loss is not recoverable")
	}
	if !strings.Contains(err.Error(), "issuer") {
		t.Errorf("the refusal does not say what is missing: %v", err)
	}
}

// -- event time is not arrival time ------------------------------------------

func TestBothTimesAreRequired(t *testing.T) {
	// A store that kept one of them cannot tell a late delivery from a quiet
	// period, which is the question a correlation window exists to answer.
	e := signIn()
	e.Received = time.Time{}
	if err := e.Validate(); err == nil {
		t.Error("an event with no arrival time was accepted")
	}
	e = signIn()
	e.Time = time.Time{}
	if err := e.Validate(); err == nil {
		t.Error("an event with no event time was accepted")
	}
}

func TestLatenessIsReportedAndNotClamped(t *testing.T) {
	e := signIn()
	if got := e.Lateness(); got != 2*time.Second {
		t.Errorf("lateness is %s", got)
	}
	// A source whose clock runs ahead is ordinary and is not an error. Clamping
	// it to zero would hide a fleet that is minutes off, which is a thing a
	// health check very much wants to know.
	ahead := signIn()
	ahead.Received = ahead.Time.Add(-90 * time.Second)
	if got := ahead.Lateness(); got >= 0 {
		t.Errorf("a source ahead of us reports lateness %s; the sign is the "+
			"finding", got)
	}
}

// -- the surface a rule addresses --------------------------------------------

func TestARuleCanAskForEveryAddressWithoutKnowingTheField(t *testing.T) {
	e := signIn()
	ips := e.Of(ObservableIP)
	if len(ips) != 2 {
		t.Fatalf("%d address(es) found: %v", len(ips), ips)
	}
	// And through the field surface too, since that is what a predicate reads.
	if got := e.Fields()["ip"]; !strings.Contains(got, "203.0.113.9") ||
		!strings.Contains(got, "198.51.100.4") {
		t.Errorf("the ip field is %q and should carry both", got)
	}
}

func TestASourceCannotShadowAFieldARuleReliesOn(t *testing.T) {
	// Raw is attacker-adjacent: whoever writes the log chooses the attribute
	// names. Without the prefix a source could name one of its own attributes
	// "severity" and quietly change what every rule reading severity matches.
	e := signIn()
	e.Raw = map[string]string{"severity": "0", "disposition": "allowed"}
	f := e.Fields()
	if f["severity"] != "3" {
		t.Errorf("severity reads as %q; the source overwrote it", f["severity"])
	}
	if f["disposition"] != "blocked" {
		t.Errorf("disposition reads as %q; the source overwrote it",
			f["disposition"])
	}
	if f["raw.severity"] != "0" {
		t.Errorf("the source's own value was lost: %q", f["raw.severity"])
	}
}

func TestAnEventWithNoSourceIsRefused(t *testing.T) {
	e := signIn()
	e.Source = ""
	if err := e.Validate(); err == nil {
		t.Error("an anonymous event was accepted; no detection can match it " +
			"and nobody reading it later can attribute it")
	}
}

func TestFieldNamesAreStable(t *testing.T) {
	// Sorted, because this is what an author is shown when they ask what a
	// rule may refer to, and a list that reorders between runs is one nobody
	// can diff.
	e := signIn()
	first := strings.Join(e.FieldNames(), ",")
	for range 20 {
		if got := strings.Join(e.FieldNames(), ","); got != first {
			t.Fatalf("the field list reordered:\n  %s\n  %s", first, got)
		}
	}
}

func TestAWellFormedEventValidates(t *testing.T) {
	if err := signIn().Validate(); err != nil {
		t.Fatalf("a well-formed event was refused: %v", err)
	}
}
