// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agent

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func subtreeAgent(path string) Manifest {
	return Manifest{
		Name: "helpdesk", Kind: KindRetrieval,
		Purpose:      "answer from the help pages",
		Capabilities: []string{"read_page", "list_pages"},
		Autonomy:     AutonomyPropose,
		Retrieval:    Retrieval{Ref: "live", Path: path},
		Budget: Budget{
			Steps: 20, Tools: 0, Duration: Duration(time.Hour)},
	}
}

// The third field of a struct whose other two were already found to be
// decoration. Retrieval.Path is documented as "limits it to a subtree", and it
// appeared in exactly one place in the whole program — inside Narrow, where it
// was carefully intersected and then consulted by nothing.
func TestAPageOutsideTheSubtreeIsRefused(t *testing.T) {
	s := NewSession(subtreeAgent("/help"), nil)

	if err := s.Retrieve("live", "help/billing", "", ""); err != nil {
		t.Fatalf("a page inside the subtree was refused: %v", err)
	}
	err := s.Retrieve("live", "legal/redundancies", "", "")
	if err == nil {
		t.Fatal("a page outside the subtree was read")
	}
	if !strings.Contains(err.Error(), "legal/redundancies") ||
		!strings.Contains(err.Error(), "help") {
		t.Errorf("the refusal names neither side: %v", err)
	}
}

// And writing, which is the half that matters more.
func TestAWriteOutsideTheSubtreeIsRefused(t *testing.T) {
	m := subtreeAgent("/help")
	m.Kind = KindTask
	m.Capabilities = []string{"read_page", "write_page"}
	m.Autonomy = AutonomyDraft
	s := NewSession(m, nil)

	if err := s.Mutate("draft", "help/billing", "", ""); err != nil {
		t.Fatalf("a write inside the subtree was refused: %v", err)
	}
	if err := s.Mutate("draft", "legal/redundancies", "", ""); err == nil {
		t.Fatal("a write outside the subtree was allowed")
	}
}

// Segments, not a string prefix. A prefix test says "helpdesk" is inside
// "help", which is a scope that leaks to whoever names the next page.
func TestASubtreeIsMatchedOnSegments(t *testing.T) {
	for _, tc := range []struct {
		declared, page string
		want           bool
	}{
		{"/help", "help", true},
		{"/help", "help/billing", true},
		{"/help", "help/billing/vat", true},
		{"/help", "helpdesk", false},
		{"/help", "helpdesk/tickets", false},
		{"/help", "legal", false},
		{"help", "help/one", true},
		{"help/", "help/one", true},
		{"/help/", "/help/one", true},
		{"/HELP", "help/one", true},
		{"/help", "HELP/one", true},
		// No declaration permits everything, as an unset field does
		// everywhere else in this struct.
		{"", "anything", true},
		{"", "", true},
		// A declared scope with no page to judge refuses: a caller that
		// cannot say what it is reading has not shown it is inside.
		{"/help", "", false},
		// The sentinel Narrow produces for two subtrees with nothing in
		// common permits nothing, because that is what it means.
		{pathNothing, "help", false},
		{pathNothing, "", false},
	} {
		if got := within(tc.declared, tc.page); got != tc.want {
			t.Errorf("within(%q, %q) = %v, wanted %v",
				tc.declared, tc.page, got, tc.want)
		}
	}
}

// Inside is the quiet half, for a listing: a page the agent could not read is
// a page it should not be told exists, so a listing narrows rather than
// refusing — and narrowing must not record a refusal per page.
func TestInsideCostsNothingAndRecordsNothing(t *testing.T) {
	s := NewSession(subtreeAgent("/help"), nil)
	for i := 0; i < 20; i++ {
		s.Inside("legal/redundancies")
	}
	if n := len(s.Refusals()); n != 0 {
		t.Errorf("checking a listing recorded %d refusal(s)", n)
	}
	if !s.Inside("help/billing") || s.Inside("legal/x") {
		t.Error("Inside disagrees with the check Retrieve makes")
	}
}

// Every field of Retrieval must be enforced somewhere.
//
// Types and Locales were decoration until the executor was given resolvers.
// Path was decoration until now, and it was left out of that repair because
// nothing made the omission visible. This makes the next one visible: a field
// added to Retrieval fails here until it is named as enforced or named as
// deliberately not.
func TestEveryRetrievalFieldIsAccountedFor(t *testing.T) {
	enforced := map[string]string{
		"Ref":     "Session.Retrieve and Session.Mutate, which refuses live outright",
		"Types":   "Session.Retrieve, Session.Mutate and agentexec's corpus filter",
		"Locales": "Session.Retrieve, Session.Mutate and agentexec's corpus filter",
		"Path":    "Session.Retrieve, Session.Mutate and Session.Inside",
	}
	rt := reflect.TypeOf(Retrieval{})
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		if enforced[name] == "" {
			t.Errorf("Retrieval.%s is declared and this test does not say "+
				"what enforces it. A field in this struct that nothing "+
				"consults is a scope an operator believes they have — which "+
				"has now happened to three of the four.", name)
		}
	}
	if len(enforced) != rt.NumField() {
		t.Errorf("this test accounts for %d fields and Retrieval has %d",
			len(enforced), rt.NumField())
	}
}

// The card has to say what is enforced. Advertising a boundary nothing applies
// would be worse than the silence it replaces; not advertising one that is
// enforced leaves a delegating caller reading an agent with the run of the
// site.
func TestTheSubtreeIsOnTheWire(t *testing.T) {
	m := subtreeAgent("/help")
	b, err := json.Marshal(Retrieval{Path: "/help"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "/help") {
		t.Fatalf("the manifest does not serialise its path: %s", b)
	}
	if m.Retrieval.Path != "/help" {
		t.Fatal("the fixture is wrong")
	}
}

// RetrieveSet still taints and still checks the ref. What it skips is the
// per-page half, which the caller has taken on.
func TestRetrieveSetTaintsAndChecksTheRef(t *testing.T) {
	s := NewSession(subtreeAgent("/help"), nil)
	if s.Tainted() {
		t.Fatal("tainted before reading anything")
	}
	if err := s.RetrieveSet("live"); err != nil {
		t.Fatalf("a set read of the declared ref was refused: %v", err)
	}
	if !s.Tainted() {
		t.Error("a set read did not taint the run")
	}
	if err := s.RetrieveSet("draft"); err == nil {
		t.Error("a set read of another ref was allowed")
	}
}

// And it is not a way round the subtree. A caller using it takes on the
// filtering, and Retrieve still refuses a page it cannot name — which is what
// stops a forgetful caller getting through by passing nothing.
func TestRetrieveStillNeedsAPageWhenASubtreeIsDeclared(t *testing.T) {
	s := NewSession(subtreeAgent("/help"), nil)
	if err := s.Retrieve("live", "", "", ""); err == nil {
		t.Fatal("a read with no page named was allowed inside a subtree scope")
	}
	// With no subtree there is nothing to judge, so it is allowed — this is
	// what every existing caller relies on.
	open := NewSession(subtreeAgent(""), nil)
	if err := open.Retrieve("live", "", "", ""); err != nil {
		t.Errorf("an unscoped read with no page was refused: %v", err)
	}
}
