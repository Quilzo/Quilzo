package agentwatch

import (
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
