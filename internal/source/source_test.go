// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package source

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/telemetry"
)

var t0 = time.Date(2026, 9, 26, 9, 0, 0, 0, time.UTC)

func doc(t *testing.T, src string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(src), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// A CloudTrail record in the shape AWS documents.
const trailRecord = `{
  "eventTime": "2026-09-26T09:14:02Z",
  "eventName": "PutBucketPolicy",
  "eventSource": "s3.amazonaws.com",
  "awsRegion": "eu-west-1",
  "recipientAccountId": "123456789012",
  "sourceIPAddress": "203.0.113.9",
  "userAgent": "aws-cli/2.15.0",
  "readOnly": false,
  "userIdentity": {
    "type": "IAMUser",
    "arn": "arn:aws:iam::123456789012:user/deploy"
  }
}`

func TestEveryBuiltInMappingValidates(t *testing.T) {
	for _, s := range Known() {
		if err := s.Validate(); err != nil {
			t.Errorf("%s/%s: %v", s.Issuer, s.Stream, err)
		}
	}
	if len(Issuers()) < 4 {
		t.Fatalf("issuers = %v", Issuers())
	}
	for _, i := range Issuers() {
		if i != strings.ToLower(i) {
			t.Fatalf("the issuer %q is not lowercase", i)
		}
	}
}

func TestMapsARealRecord(t *testing.T) {
	s, ok := Find("aws", "cloudtrail")
	if !ok {
		t.Fatal("no cloudtrail source")
	}
	e, missed := s.Map(doc(t, trailRecord))
	if len(missed) != 0 {
		t.Fatalf("missed %+v", missed)
	}
	if e.Source != "aws/cloudtrail" {
		t.Fatalf("source = %q", e.Source)
	}
	if e.Class != telemetry.ClassAPIActivity {
		t.Fatalf("class = %v", e.Class)
	}
	if !e.Time.Equal(time.Date(2026, 9, 26, 9, 14, 2, 0, time.UTC)) {
		t.Fatalf("time = %s", e.Time)
	}
	// The identity is the ARN under the issuer, which is what a join
	// hangs off.
	if e.Actor.Issuer != "aws" ||
		!strings.HasSuffix(e.Actor.Value, "user/deploy") {
		t.Fatalf("actor = %+v", e.Actor)
	}
	var sawIP bool
	for _, o := range e.Observables {
		if o.Kind == telemetry.ObservableIP && o.Value == "203.0.113.9" {
			sawIP = true
		}
	}
	if !sawIP {
		t.Fatalf("observables = %+v", e.Observables)
	}
	if e.Raw["awsRegion"] != "eu-west-1" {
		t.Fatalf("raw = %v", e.Raw)
	}
	// A record with no error code is a success.
	if e.Disposition != telemetry.DispositionAllowed {
		t.Fatalf("disposition = %v", e.Disposition)
	}
}

// TestAChangedSourceProducesAMissNotAHole is the whole point.
func TestAChangedSourceProducesAMissNotAHole(t *testing.T) {
	s, _ := Find("aws", "cloudtrail")
	// The vendor moved the identity. Every other field is still there.
	moved := strings.Replace(trailRecord, `"arn"`, `"principalArn"`, 1)
	e, missed := s.Map(doc(t, moved))
	if len(missed) != 1 {
		t.Fatalf("missed %+v", missed)
	}
	if missed[0].Path != "userIdentity.arn" {
		t.Fatalf("missed %q", missed[0].Path)
	}
	// And crucially, no event at all rather than one with an empty actor.
	if e.Source != "" || !e.Actor.Zero() {
		t.Fatalf("an event was produced anyway: %+v", e)
	}
}

// TestATimeThatDoesNotParseFailsRatherThanMovingEverythingToTheEpoch.
func TestATimeThatDoesNotParseFailsRatherThanMovingEverything(t *testing.T) {
	s, _ := Find("aws", "cloudtrail")
	odd := strings.Replace(trailRecord, `"2026-09-26T09:14:02Z"`,
		`"26/09/2026 09:14:02"`, 1)
	_, missed := s.Map(doc(t, odd))
	if len(missed) != 1 || missed[0].Path != "eventTime" {
		t.Fatalf("missed %+v", missed)
	}
	if !strings.Contains(missed[0].Why, "silently moves every event") {
		t.Fatalf("why = %q", missed[0].Why)
	}
}

// TestFailureIsReadFromEachSourcesOwnConvention.
func TestFailureIsReadFromEachSourcesOwnConvention(t *testing.T) {
	// CloudTrail: the presence of an error code at all.
	trail, _ := Find("aws", "cloudtrail")
	failed := strings.Replace(trailRecord, `"readOnly": false`,
		`"errorCode": "AccessDenied"`, 1)
	e, missed := trail.Map(doc(t, failed))
	if len(missed) != 0 {
		t.Fatalf("missed %+v", missed)
	}
	if e.Disposition != telemetry.DispositionFailed {
		t.Fatalf("an error code did not read as a failure: %v",
			e.Disposition)
	}
	if e.Severity != telemetry.SeverityMedium {
		t.Fatalf("a refused action is not raised above a completed one: %v",
			e.Severity)
	}

	// Okta: a named result value.
	okta, _ := Find("okta", "system")
	rec := doc(t, `{"published":"2026-09-26T09:00:00Z",
		"eventType":"user.session.start","displayMessage":"sign in",
		"actor":{"id":"00u1","alternateId":"ada@example.invalid"},
		"outcome":{"result":"FAILURE","reason":"INVALID_CREDENTIALS"},
		"client":{"ipAddress":"203.0.113.9"}}`)
	oe, missed := okta.Map(rec)
	if len(missed) != 0 {
		t.Fatalf("missed %+v", missed)
	}
	if oe.Disposition != telemetry.DispositionFailed {
		t.Fatalf("disposition = %v", oe.Disposition)
	}
	if oe.Raw["reason"] != "INVALID_CREDENTIALS" {
		t.Fatalf("raw = %v", oe.Raw)
	}
}

// TestWorkspaceSelectsItsActivityFromTheEventName.
func TestWorkspaceSelectsItsActivityFromTheEventName(t *testing.T) {
	ws, _ := Find("workspace", "login")
	for _, c := range []struct {
		name string
		want uint8
		fail bool
	}{
		{"login_success", 1, false},
		{"logout", 2, false},
		{"login_failure", 1, true},
	} {
		rec := doc(t, fmt.Sprintf(`{"id":{"time":"2026-09-26T09:00:00Z",
			"applicationName":"login"},
			"actor":{"profileId":"1234","email":"ada@example.invalid"},
			"ipAddress":"203.0.113.9","events":{"name":%q,"type":"login"}}`,
			c.name))
		e, missed := ws.Map(rec)
		if len(missed) != 0 {
			t.Fatalf("%s: missed %+v", c.name, missed)
		}
		if e.Activity != c.want {
			t.Errorf("%s: activity = %d, want %d", c.name, e.Activity,
				c.want)
		}
		failed := e.Disposition == telemetry.DispositionFailed
		if failed != c.fail {
			t.Errorf("%s: failed = %v", c.name, failed)
		}
	}
}

// TestDriftIsReportedWithTheFieldThatMoved.
func TestDriftIsReportedWithTheFieldThatMoved(t *testing.T) {
	s, _ := Find("aws", "cloudtrail")
	var docs []any
	for i := range 100 {
		src := trailRecord
		if i < 40 {
			src = strings.Replace(src, `"arn"`, `"principalArn"`, 1)
		}
		docs = append(docs, doc(t, src))
	}
	b := Map(s, docs, t0)
	if !b.Balances() {
		t.Fatalf("%d + %d != %d", b.Mapped, b.Missed, b.Records)
	}
	if b.Mapped != 60 || b.Missed != 40 {
		t.Fatalf("mapped %d, missed %d", b.Mapped, b.Missed)
	}
	why, drifted := b.Drifted()
	if !drifted {
		t.Fatal("40% of a page failing on one field is not drift?")
	}
	for _, want := range []string{"userIdentity.arn", "changed shape",
		"quietly not firing"} {
		if !strings.Contains(why, want) {
			t.Fatalf("why does not mention %q: %s", want, why)
		}
	}

	// A couple of odd records is not drift, because treating it as one is
	// how a real alert gets muted.
	var few []any
	for i := range 100 {
		src := trailRecord
		if i < 2 {
			src = strings.Replace(src, `"arn"`, `"principalArn"`, 1)
		}
		few = append(few, doc(t, src))
	}
	if _, drifted := Map(s, few, t0).Drifted(); drifted {
		t.Fatal("two odd records in a hundred was reported as a schema " +
			"change")
	}
}

// TestAcrossTellsOnePageApartFromEveryPage.
func TestAcrossTellsOnePageApartFromEveryPage(t *testing.T) {
	s, _ := Find("aws", "cloudtrail")
	page := func(bad int) Batch {
		var docs []any
		for i := range 50 {
			src := trailRecord
			if i < bad {
				src = strings.Replace(src, `"arn"`, `"principalArn"`, 1)
			}
			docs = append(docs, doc(t, src))
		}
		return Map(s, docs, t0)
	}
	// One bad page among four good ones: not drift.
	noisy := Across([]Batch{page(0), page(30), page(0), page(0)})
	if noisy.Drifted {
		t.Fatalf("one bad page was called drift: %s", noisy.Why)
	}
	// Every page failing the same way: drift.
	broken := Across([]Batch{page(30), page(30), page(30)})
	if !broken.Drifted {
		t.Fatal("every page failing on one field is not drift?")
	}
	if !strings.Contains(broken.Why, "userIdentity.arn") {
		t.Fatalf("why = %q", broken.Why)
	}

	// A source sending nothing is its own state.
	quiet := Across([]Batch{{Source: "aws/cloudtrail"}})
	if !quiet.Quiet || quiet.Drifted {
		t.Fatalf("%+v", quiet)
	}
	if !strings.Contains(quiet.Why, "connector that has stopped") {
		t.Fatalf("why = %q", quiet.Why)
	}
}

// TestValidationRefusesAMappingThatCannotBreak.
func TestValidationRefusesAMappingThatCannotBreak(t *testing.T) {
	good, _ := Find("okta", "system")
	for _, c := range []struct {
		name string
		edit func(*Source)
		says string
	}{
		{"no requirements", func(s *Source) { s.Require = nil },
			"a record of any shape maps to an event"},
		{"no time path", func(s *Source) { s.Time = "" }, "where the record's time is"},
		{"no layout", func(s *Source) { s.Layout = "" },
			"how the source writes its time"},
		{"no lateness", func(s *Source) { s.Lateness = 0 },
			"how far behind it runs"},
		{"too late", func(s *Source) { s.Lateness = 3 * time.Hour },
			"batch import rather than a stream"},
		{"mixed-case issuer", func(s *Source) { s.Issuer = "Okta" },
			"break every join"},
		{"time not required", func(s *Source) {
			s.Require = []string{"actor.id"}
		}, "does not require its own time path"},
		{"requires what it never reads", func(s *Source) {
			s.Require = append(s.Require, "some.unused.path")
		}, "fails records for no reason"},
		{"activity from nothing", func(s *Source) {
			s.From = "eventType"
			s.Activities = nil
		}, "lists none"},
	} {
		s := good
		s.Require = append([]string(nil), good.Require...)
		c.edit(&s)
		err := s.Validate()
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// TestAMappingAndItsConnectorMustAgreeOnTheIssuer.
func TestAMappingAndItsConnectorMustAgreeOnTheIssuer(t *testing.T) {
	s, _ := Find("entra", "signin")
	if err := s.AgreesWith("entra"); err != nil {
		t.Fatal(err)
	}
	err := s.AgreesWith("azure-ad")
	if err == nil {
		t.Fatal("a mapping and its connector disagreed and nothing said so")
	}
	if !strings.Contains(err.Error(), "will match nothing") {
		t.Fatalf("%v", err)
	}
}

// TestACorrelationWaitsForTheSlowestSource.
func TestACorrelationWaitsForTheSlowestSource(t *testing.T) {
	okta, _ := Find("okta", "system")
	ws, _ := Find("workspace", "login")
	worst, at := Slowest([]Source{okta, ws})
	if worst.Issuer != "workspace" || at != 30*time.Minute {
		t.Fatalf("slowest = %s at %s", worst.Issuer, at)
	}
	advice := Advice([]Source{okta, ws})
	if !strings.Contains(advice, "workspace/login") ||
		!strings.Contains(advice, "never sees it") {
		t.Fatalf("advice = %q", advice)
	}
	if Advice(nil) != "" {
		t.Fatal("advice about no sources")
	}
}

// TestCheckRefusesToValidateAgainstNothing.
func TestCheckRefusesToValidateAgainstNothing(t *testing.T) {
	s, _ := Find("aws", "cloudtrail")
	if _, err := Check(s, nil); err == nil {
		t.Fatal("a mapping was checked against no records")
	}
	b, err := Check(s, []any{doc(t, trailRecord)})
	if err != nil {
		t.Fatal(err)
	}
	if b.Mapped != 1 || len(b.Events) != 0 {
		t.Fatalf("check produced %d event(s)", len(b.Events))
	}
}

// TestTheBreadthIsRealAndConsistent.
//
// Sixteen sources across cloud control planes, identity, endpoint, device
// management, source control, orchestration, network, business
// applications and a machine with no API at all. What is checked here is
// not that the field names are right — a deployment verifies those against
// its own tenant — but that nothing in the set contradicts anything else.
func TestTheBreadthIsRealAndConsistent(t *testing.T) {
	all := Known()
	if len(all) < 16 {
		t.Fatalf("%d source(s); the point is breadth", len(all))
	}
	seen := map[string]bool{}
	classes := map[telemetry.Class]int{}
	for _, s := range all {
		if err := s.Validate(); err != nil {
			t.Errorf("%s/%s: %v", s.Issuer, s.Stream, err)
			continue
		}
		key := s.Issuer + "/" + s.Stream
		if seen[key] {
			t.Errorf("%s appears twice", key)
		}
		seen[key] = true
		classes[s.Class]++
		if s.Tool == "" {
			t.Errorf("%s has no name a person would use", key)
		}
	}
	// Several classes, because a set that mapped everything to one class
	// would have decided nothing.
	if len(classes) < 4 {
		t.Fatalf("every source lands in %d class(es)", len(classes))
	}
	// An endpoint product's stream is a detection rather than an
	// activity: it has already decided something is wrong, which is a
	// different claim from a log line.
	cs, ok := Find("crowdstrike", "detections")
	if !ok || cs.Class != telemetry.ClassDetection {
		t.Fatalf("crowdstrike is %v", cs.Class)
	}
}

// TestEachSourceStatesItsOutcomeConvention.
//
// Three exist in the wild and guessing wrong inverts every disposition in
// the stream with no error anywhere.
func TestEachSourceStatesItsOutcomeConvention(t *testing.T) {
	for _, s := range Known() {
		if s.Outcome == "" {
			continue
		}
		if len(s.Failed) > 0 && len(s.Succeeded) > 0 {
			t.Errorf("%s/%s says both", s.Issuer, s.Stream)
		}
	}
	// Presence is failure: CloudTrail omits errorCode when it worked.
	trail, _ := Find("aws", "cloudtrail")
	if len(trail.Failed) != 0 || len(trail.Succeeded) != 0 {
		t.Fatal("cloudtrail should use the presence convention")
	}
	// A named success value, because the failures number in the hundreds.
	entra, _ := Find("entra", "signin")
	if len(entra.Succeeded) != 1 || entra.Succeeded[0] != "0" {
		t.Fatalf("entra = %v", entra.Succeeded)
	}
	e, missed := entra.Map(doc(t, `{"createdDateTime":"2026-09-26T09:00:00Z",
		"userId":"11111111-2222-3333-4444-555555555555",
		"appDisplayName":"Office 365","ipAddress":"203.0.113.9",
		"status":{"errorCode":50126,"failureReason":"Invalid password"}}`))
	if len(missed) != 0 {
		t.Fatalf("missed %+v", missed)
	}
	if e.Disposition != telemetry.DispositionFailed {
		t.Fatalf("a non-zero error code read as %v", e.Disposition)
	}
	ok, _ := entra.Map(doc(t, `{"createdDateTime":"2026-09-26T09:00:00Z",
		"userId":"11111111-2222-3333-4444-555555555555",
		"status":{"errorCode":0}}`))
	if ok.Disposition != telemetry.DispositionAllowed {
		t.Fatalf("a zero error code read as %v", ok.Disposition)
	}
}

// TestSourcesThatWriteANumberForTheTime.
//
// GitHub writes milliseconds and Slack writes seconds. A mapping that said
// nothing about that would produce 1970 for every event and no error.
func TestSourcesThatWriteANumberForTheTime(t *testing.T) {
	gh, _ := Find("github", "audit")
	e, missed := gh.Map(doc(t, `{"@timestamp":1790000000000,
		"actor":"ada","action":"repo.destroy","repo":"acme/api",
		"actor_ip":"203.0.113.9"}`))
	if len(missed) != 0 {
		t.Fatalf("missed %+v", missed)
	}
	if e.Time.Year() != 2026 {
		t.Fatalf("milliseconds parsed as %s", e.Time)
	}
	sl, _ := Find("slack", "audit")
	se, missed := sl.Map(doc(t, `{"date_create":1790000000,
		"action":"user_channel_join","actor":{"user":{"id":"U1",
		"email":"ada@example.invalid"}},"entity":{"type":"channel"}}`))
	if len(missed) != 0 {
		t.Fatalf("missed %+v", missed)
	}
	if se.Time.Year() != 2026 {
		t.Fatalf("seconds parsed as %s", se.Time)
	}
	// And something that is not a number fails rather than becoming 1970.
	_, bad := gh.Map(doc(t, `{"@timestamp":"yesterday","actor":"a",
		"action":"b"}`))
	if len(bad) != 1 {
		t.Fatalf("a non-numeric epoch produced %d miss(es)", len(bad))
	}
}

// TestEveryIssuerIsDistinctAndLowercase.
//
// The issuer is the namespace a join hangs off. Two spellings of one
// platform breaks every join in the estate and produces no error anywhere,
// which is why it is checked rather than trusted.
func TestEveryIssuerIsDistinctAndLowercase(t *testing.T) {
	byIssuer := map[string][]string{}
	for _, s := range Known() {
		byIssuer[s.Issuer] = append(byIssuer[s.Issuer], s.Stream)
		if s.Issuer != strings.ToLower(s.Issuer) {
			t.Errorf("%q is not lowercase", s.Issuer)
		}
		if strings.ContainsAny(s.Issuer, " /_") {
			t.Errorf("%q has a separator in it, so it will not join "+
				"cleanly", s.Issuer)
		}
	}
	// Nothing that is plainly the same platform under two names.
	for _, pair := range [][2]string{
		{"entra", "azure-ad"}, {"entra", "aad"}, {"gcp", "google"},
		{"workspace", "gsuite"}, {"kubernetes", "k8s"},
	} {
		if byIssuer[pair[0]] != nil && byIssuer[pair[1]] != nil {
			t.Errorf("%q and %q are the same platform under two issuers",
				pair[0], pair[1])
		}
	}
}

// TestTheSlowestSourceDecidesTheWindow across the whole set.
func TestTheSlowestSourceDecidesTheWindow(t *testing.T) {
	worst, at := Slowest(Known())
	if at == 0 {
		t.Fatal("no source declares any lateness")
	}
	if at > MaxLateness {
		t.Fatalf("%s/%s declares %s, above the cap", worst.Issuer,
			worst.Stream, at)
	}
	// The on-premise one is the fastest, because nothing batches it.
	fast, _ := Find("auditd", "events")
	for _, s := range Known() {
		if s.Lateness < fast.Lateness {
			t.Fatalf("%s/%s is faster than a local agent", s.Issuer,
				s.Stream)
		}
	}
}
