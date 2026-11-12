// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agentwatch

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
)

var now = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

func ev(seq int64, principal, action, resource string, outcome audit.Outcome,
	ago time.Duration, detail map[string]string) audit.Event {

	return audit.Event{
		Seq: seq, At: now.Add(-ago).Format(time.RFC3339),
		Action: action, Resource: resource, Outcome: outcome,
		Principal: principal, Kind: audit.KindAI, Model: "claude",
		Verified: true, Detail: detail,
	}
}

// The distinction this exists to make. An agent that attempts something, is
// told it needs approval, and stops has behaved correctly — it asked. Counting
// that quarantines the well-behaved agents fastest, because they are the ones
// that try things and accept the answer.
func TestBeingToldToGetApprovalIsNotAStrike(t *testing.T) {
	var events []audit.Event
	for i := range 10 {
		events = append(events, ev(int64(i+1), "assistant", "publish", "/",
			audit.Denied, time.Hour, map[string]string{
				"reason": "dual-authorization",
			}))
	}

	reports := Look(events, now)
	if len(reports) != 1 {
		t.Fatalf("got %d reports", len(reports))
	}
	if len(reports[0].Strikes) != 0 {
		t.Errorf("an agent that asked ten times and accepted the answer "+
			"collected %d strikes", len(reports[0].Strikes))
	}
	if reports[0].Flagged {
		t.Error("a well-behaved agent was flagged")
	}
}

// The shape being detected is not "was refused" but "keeps trying".
func TestRetryingTheSameRefusalIsAStrike(t *testing.T) {
	var events []audit.Event
	for i := range 6 {
		events = append(events, ev(int64(i+1), "assistant", "publish", "/legal",
			audit.Denied, time.Hour, map[string]string{
				"reason": "authorisation",
			}))
	}

	r := Look(events, now)[0]
	// The first refusal is an agent exploring, so it is not a strike for
	// repetition — but it is one for escalation.
	if len(r.Strikes) < 5 {
		t.Fatalf("six identical refusals produced %d strikes", len(r.Strikes))
	}
	if !r.Flagged {
		t.Error("an agent that ignored five refusals was not flagged")
	}
	if r.Counts[RepeatedRefusal] == 0 {
		t.Errorf("the repetition was not identified: %v", r.Counts)
	}
}

// A single refusal is an agent finding out what it may do.
func TestOneRefusalIsNotEnoughToFlag(t *testing.T) {
	events := []audit.Event{
		ev(1, "assistant", "publish", "/", audit.Denied, time.Hour,
			map[string]string{"reason": "authorisation"}),
		ev(2, "assistant", "mcp.write_page", "/news", audit.Success, time.Hour, nil),
	}
	r := Look(events, now)[0]
	if r.Flagged {
		t.Error("an agent refused once was flagged")
	}
}

// Reaching above the role it holds is its own pattern, and naming it separately
// is what lets somebody tell "confused" from "probing".
func TestEscalationIsNamedSeparately(t *testing.T) {
	events := []audit.Event{
		ev(1, "assistant", "auth.grant", "/", audit.Denied, time.Hour,
			map[string]string{"reason": "authorisation: needs role admin"}),
	}
	r := Look(events, now)[0]
	if r.Counts[Escalation] != 1 {
		t.Errorf("an escalation attempt was classified as %v", r.Counts)
	}
}

func TestGateFailuresAreNamedSeparately(t *testing.T) {
	events := []audit.Event{
		ev(1, "assistant", "publish", "/", audit.Denied, time.Hour,
			map[string]string{"reason": "accessibility"}),
	}
	r := Look(events, now)[0]
	if r.Counts[GateFailure] != 1 {
		t.Errorf("a gate failure was classified as %v", r.Counts)
	}
}

// Six strikes in six actions is a different agent from six in six thousand,
// and a report that cannot tell them apart flags the busy one and misses the
// bad one.
func TestTheReportCarriesTheRateNotJustTheCount(t *testing.T) {
	var events []audit.Event
	var seq int64
	for range 6 {
		seq++
		events = append(events, ev(seq, "assistant", "publish", "/x",
			audit.Denied, time.Hour, map[string]string{"reason": "authorisation"}))
	}
	for range 500 {
		seq++
		events = append(events, ev(seq, "assistant", "mcp.write_page", "/news",
			audit.Success, time.Hour, nil))
	}

	r := Look(events, now)[0]
	if r.Actions != 506 {
		t.Errorf("the report counts %d actions", r.Actions)
	}
	if !contains(r.Summary, "506") {
		t.Errorf("the summary does not give the denominator: %q", r.Summary)
	}
}

// Something from last month should not still count against an agent that has
// behaved since.
func TestOldBehaviourAgesOut(t *testing.T) {
	var events []audit.Event
	for i := range 10 {
		events = append(events, ev(int64(i+1), "assistant", "publish", "/",
			audit.Denied, 30*24*time.Hour, map[string]string{
				"reason": "authorisation"}))
	}
	reports := Look(events, now)
	if len(reports) != 0 {
		t.Errorf("month-old behaviour still produced a report: %#v", reports)
	}
}

// Only models are watched. A person being refused repeatedly is a
// conversation, not a detection.
func TestOnlyModelsAreWatched(t *testing.T) {
	var events []audit.Event
	for i := range 10 {
		e := ev(int64(i+1), "dana", "publish", "/", audit.Denied, time.Hour,
			map[string]string{"reason": "authorisation"})
		e.Kind = audit.KindHuman
		events = append(events, e)
	}
	if reports := Look(events, now); len(reports) != 0 {
		t.Errorf("a person was reported as an agent: %#v", reports)
	}
}

// A single misconfiguration producing thousands of unverified actions would
// otherwise bury every other signal.
func TestUnattributedActionsAreCountedOncePerAgent(t *testing.T) {
	var events []audit.Event
	for i := range 200 {
		e := ev(int64(i+1), "assistant", "mcp.write_page", "/news",
			audit.Success, time.Hour, nil)
		e.Verified = false
		events = append(events, e)
	}
	r := Look(events, now)[0]
	if r.Counts[Unattributed] != 1 {
		t.Errorf("200 unverified actions produced %d strikes; that buries "+
			"everything else", r.Counts[Unattributed])
	}
	if !contains(r.Strikes[len(r.Strikes)-1].Why, "200") {
		t.Errorf("the count was lost: %q", r.Strikes[len(r.Strikes)-1].Why)
	}
}

// Every strike points at an audit entry, so it is checkable against the record
// rather than being this package's opinion.
func TestEveryStrikePointsAtTheRecord(t *testing.T) {
	var events []audit.Event
	for i := range 6 {
		events = append(events, ev(int64(i+1), "assistant", "publish", "/x",
			audit.Denied, time.Hour, map[string]string{"reason": "authorisation"}))
	}
	for _, s := range Look(events, now)[0].Strikes {
		if s.Kind == Unattributed {
			continue // aggregate, has no single entry
		}
		if s.Seq == 0 || s.At == "" {
			t.Errorf("a strike with no entry behind it: %#v", s)
		}
		if s.Why == "" {
			t.Errorf("a strike with no explanation: %#v", s)
		}
	}
}

// Two agents must be reported separately, or one badly behaved agent makes
// every other one look guilty.
func TestAgentsAreReportedSeparately(t *testing.T) {
	var events []audit.Event
	for i := range 6 {
		events = append(events, ev(int64(i+1), "bad-agent", "publish", "/x",
			audit.Denied, time.Hour, map[string]string{"reason": "authorisation"}))
	}
	events = append(events, ev(99, "good-agent", "mcp.write_page", "/news",
		audit.Success, time.Hour, nil))

	reports := Look(events, now)
	if len(reports) != 2 {
		t.Fatalf("got %d reports", len(reports))
	}
	// The worst first, so a list can be read from the top.
	if reports[0].Principal != "bad-agent" {
		t.Errorf("reports are not ordered by severity: %s", reports[0].Principal)
	}
	for _, r := range reports {
		if r.Principal == "good-agent" && r.Flagged {
			t.Error("a well-behaved agent was flagged alongside a bad one")
		}
	}
	if len(Flagged(reports)) != 1 {
		t.Errorf("%d agents flagged", len(Flagged(reports)))
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub ||
		len(s) > 0 && func() bool {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}

// A report names what a person can act on: the declared agent a run was
// of, or the app at the agent interface, whose refusals are recorded as
// the error it was told.
func TestAReportNamesTheAgentOrAppAndReadsTheInterfacesRefusals(t *testing.T) {
	var events []audit.Event
	for i := range 6 {
		events = append(events, ev(int64(i+1), "p_run", "agent.action", "/legal",
			audit.Denied, time.Hour, map[string]string{"reason": "authorisation", "agent": "triage"}))
	}
	for i := range 6 {
		e := ev(int64(i+10), "p_app", "mcp.call", "/mcp", audit.Denied, time.Hour,
			map[string]string{"error": "needs approval: a second person approves a publish"})
		e.Model = "https://app.example.com/meta"
		events = append(events, e)
	}
	for i := range 6 {
		e := ev(int64(i+20), "p_rogue", "mcp.call", "/mcp", audit.Denied, time.Hour,
			map[string]string{"error": "the access policy refuses delete_page"})
		e.Model = "https://rogue.example.com/meta"
		events = append(events, e)
	}
	by := map[string]Report{}
	for _, r := range Look(events, now) {
		by[r.Principal] = r
	}
	if r := by["p_run"]; r.Subject() != "agent:triage" || !r.Flagged || r.Latest() != 6 {
		t.Errorf("the agent's run: subject %q flagged %v latest %d", r.Subject(), r.Flagged, r.Latest())
	}
	if r := by["p_app"]; r.Subject() != "app:https://app.example.com/meta" || len(r.Strikes) != 0 {
		t.Errorf("an app told to get approval: subject %q, %d strikes", r.Subject(), len(r.Strikes))
	}
	if r := by["p_rogue"]; !r.Flagged || r.Subject() != "app:https://rogue.example.com/meta" || r.Latest() != 25 {
		t.Errorf("an app that kept trying: %+v", r)
	}
	// An unattributed strike has no place in the log, and comes last.
	if n := (Report{Strikes: []Strike{{Seq: 9}, {Seq: 4}, {Kind: Unattributed}}}).Latest(); n != 9 {
		t.Errorf("latest %d", n)
	}
	if (Report{Principal: "p_x"}).Subject() != "p_x" {
		t.Error("a report with neither names the handle")
	}
}

// A run's step records its refusal as why; reaching above its role there
// is an escalation, as it is anywhere else.
func TestARunsRefusalIsReadWhereTheRunRecordsIt(t *testing.T) {
	var events []audit.Event
	for i := range 2 {
		events = append(events, ev(int64(i+1), "p_run", "agent.action", fmt.Sprintf("/legal/%d", i), audit.Denied, time.Hour,
			map[string]string{"why": "the access policy refuses this: it needs the publisher role", "agent": "triage"}))
	}
	r := Look(events, now)
	if len(r) != 1 || r[0].Counts[Escalation] != 2 {
		t.Fatalf("%+v", r)
	}
}

// Every call at the agent interface is one action, mcp.call on /mcp, and
// the request is the operation it named. Keyed on the action and resource
// alone, a client that tried six different operations once each was told
// "the same request has now been refused 6 times", and the first of them,
// "is author on /; grant needs admin", was not seen as reaching above its
// role because the refusal said "needs admin" rather than "role".
func TestDifferentOperationsAtTheInterfaceAreDifferentRequests(t *testing.T) {
	var events []audit.Event
	for i, op := range []string{"verify_store", "inventory", "policy_status", "agent_activity", "scan_content", "site_report"} {
		events = append(events, ev(int64(i+1), "p_dana", "mcp.call", "/mcp", audit.Denied, time.Hour,
			map[string]string{"tool": "quilzo_read", "operation": op, "on_behalf_of": "p_dana",
				"error": "p_dana is author on /; grant needs admin"}))
	}
	r := Look(events, now)[0]
	if r.Counts[RepeatedRefusal] != 0 || r.Counts[Escalation] != 6 {
		t.Fatalf("six different operations, each refused once: %v", r.Counts)
	}
	// The same operation again is the same request.
	events = append(events, ev(7, "p_dana", "mcp.call", "/mcp", audit.Denied, time.Hour,
		map[string]string{"tool": "quilzo_read", "operation": "inventory", "on_behalf_of": "p_dana",
			"error": "p_dana is author on /; grant needs admin"}))
	if r := Look(events, now)[0]; r.Counts[RepeatedRefusal] != 1 {
		t.Fatalf("the same operation refused twice: %v", r.Counts)
	}
	// A credential, or an app's consent, too small for an operation is
	// reaching above it too.
	for i, why := range []string{"this credential carries reader and edit-draft needs author",
		"this app was given reader access, and this needs author"} {
		esc := []audit.Event{ev(int64(i+1), "p_client", "mcp.call", "/mcp", audit.Denied, time.Hour,
			map[string]string{"tool": "quilzo_write", "operation": "write_page", "error": why})}
		if r := Look(esc, now)[0]; r.Counts[Escalation] != 1 {
			t.Errorf("%q: %v", why, r.Counts)
		}
	}
	// A refusal naming only what is needed is not about the role held: a
	// bearer token too long-lived for a publish from another machine.
	proof := []audit.Event{ev(1, "p_client", "mcp.call", "/mcp", audit.Denied, time.Hour,
		map[string]string{"tool": "quilzo_publish", "operation": "publish",
			"error": "this needs publisher, and from another machine that takes a token bound to the program's key"})}
	if r := Look(proof, now)[0]; r.Counts[Escalation] != 0 {
		t.Errorf("a token too long-lived was read as reaching above its role: %v", r.Counts)
	}
}

// An app many people connected asks for each of them: the same operation
// refused to two people is not one request asked twice.
func TestTheSameOperationForTwoPeopleIsTwoRequests(t *testing.T) {
	var events []audit.Event
	for i, who := range []string{"p_dana", "p_lee", "p_sam", "p_ana", "p_kai", "p_bo"} {
		e := ev(int64(i+1), "p_app", "mcp.call", "/mcp", audit.Denied, time.Hour,
			map[string]string{"tool": "quilzo_read", "operation": "inventory", "on_behalf_of": who,
				"error": "not now"})
		e.Model = "https://app.example.com/meta"
		events = append(events, e)
	}
	for _, s := range Look(events, now)[0].Strikes {
		if strings.Contains(s.Why, "the same request") {
			t.Fatalf("an operation refused once for each of six people was read as one asked again: %s", s.Why)
		}
	}
}

// A report on a client holding a person's own token names the client and
// the person it acted for, so the case the shield opens says whose client
// it was: the log's handle alone means nothing to whoever reads the case.
func TestAReportSaysWhoAClientActedFor(t *testing.T) {
	e := ev(1, "p_dana", "mcp.call", "/mcp", audit.Success, time.Hour,
		map[string]string{"tool": "quilzo_read", "operation": "list_pages", "on_behalf_of": "p_dana"})
	e.Model = "mcp-client"
	if s := Look([]audit.Event{e}, now)[0].Subject(); s != "mcp-client for p_dana" {
		t.Fatalf("subject %q", s)
	}
	// An app is named as before, by what an administrator disconnects, on
	// a call through the gateway as on one at the interface.
	g := ev(1, "p_app", "mcp.gateway", "/integrations/crm", audit.Success, time.Hour,
		map[string]string{"tool": "lookup", "on_behalf_of": "p_dana"})
	g.Model = "https://app.example.com/meta"
	if s := Look([]audit.Event{g}, now)[0].Subject(); s != "app:https://app.example.com/meta" {
		t.Errorf("an app through the gateway: %q", s)
	}
}
