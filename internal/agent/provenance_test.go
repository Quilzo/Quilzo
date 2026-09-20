// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agent

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func reader() Manifest {
	return Manifest{
		Name: "support", Kind: KindRetrieval, Purpose: "answer",
		Capabilities: []string{"read_page", "list_pages"},
		Autonomy:     AutonomyPublish,
		Tools: []Tool{
			{Name: "crm", Host: "api.example.com", Purpose: "lookup"},
		},
		Budget: Budget{Steps: 50, Tools: 20, Duration: Duration(time.Hour)},
	}
}

func TestAReadNamesWhatWasRead(t *testing.T) {
	// The whole point. A person asked to approve a tainted run was told that
	// it had read something and not what, and the honest review of that is to
	// re-read the site — which nobody does, so the approval became a
	// formality.
	s := NewSession(reader(), nil)
	if err := s.Retrieve("live", "pricing", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Retrieve("live", "faq", "", ""); err != nil {
		t.Fatal(err)
	}
	got := s.Sources()
	if len(got) != 2 {
		t.Fatalf("two pages read and %d source(s) recorded: %v", len(got), got)
	}
	if got[0].Name != "faq" || got[1].Name != "pricing" {
		t.Fatalf("sorted order is %v", got)
	}
	for _, src := range got {
		if src.Kind != FromPage {
			t.Errorf("%s was recorded as a %s", src.Name, src.Kind)
		}
	}
}

func TestThreeKindsOfSourceAreToldApart(t *testing.T) {
	s := NewSession(reader(), nil)
	_ = s.Retrieve("live", "pricing", "", "")
	_ = s.RetrieveSet("live")
	if err := s.MayCallTool("crm", ""); err != nil {
		t.Fatal(err)
	}
	line := Provenance(s.Sources(), s.Omitted())
	for _, want := range []string{
		"pricing",                // a page, by name
		"a listing of live",      // a set, by ref
		"crm at api.example.com", // a tool, by name and host
	} {
		if !strings.Contains(line, want) {
			t.Errorf("the provenance line does not say %q: %s", want, line)
		}
	}
}

func TestAToolIsNamedRatherThanOnlyItsHost(t *testing.T) {
	// MayReach is handed a host and never the tool behind it, so a record
	// saying "reached api.example.com" is one nobody can act on without the
	// manifest open beside it.
	s := NewSession(reader(), nil)
	if err := s.MayCallTool("crm", ""); err != nil {
		t.Fatal(err)
	}
	got := s.Sources()
	if len(got) != 1 {
		t.Fatalf("%d source(s): %v", len(got), got)
	}
	if got[0].Kind != FromTool || got[0].Name != "crm" ||
		got[0].Where != "api.example.com" {
		t.Fatalf("the tool call was recorded as %+v", got[0])
	}
}

func TestARefusedToolCallIsNotASource(t *testing.T) {
	// A refusal is not a read. Recording it would send a reviewer to look at
	// content that never arrived.
	s := NewSession(reader(), nil)
	if err := s.MayCallTool("crm", "evil.example.com"); err == nil {
		t.Fatal("a redirected tool call was permitted")
	}
	if got := s.Sources(); len(got) != 0 {
		t.Fatalf("a refused call was recorded as a source: %v", got)
	}
}

func TestTheSamePageReadTwiceIsOneSource(t *testing.T) {
	// And the bug that made this worth separating: reads counted events, so a
	// run that touched three things repeatedly reported "and 6 more" and sent
	// a reviewer looking for six pages that do not exist.
	s := NewSession(reader(), nil)
	for range 4 {
		_ = s.Retrieve("live", "pricing", "", "")
	}
	if got := s.Sources(); len(got) != 1 {
		t.Fatalf("one page read four times gave %d source(s): %v", len(got), got)
	}
	if s.Reads() != 4 {
		t.Errorf("four reads were counted as %d", s.Reads())
	}
	if s.Omitted() != 0 {
		t.Errorf("%d source(s) reported as omitted when none were", s.Omitted())
	}
	if line := Provenance(s.Sources(), s.Omitted()); strings.Contains(line, "more") {
		t.Errorf("the line claims there is more to look at: %s", line)
	}
}

func TestPastTheBoundSourcesAreCountedAndNotNamed(t *testing.T) {
	// A run that read four hundred pages has a provenance list nobody reads,
	// and putting it in an audit detail turns a record into a document.
	s := NewSession(reader(), nil)
	for i := range MaxSources + 10 {
		_ = s.Retrieve("live", fmt.Sprintf("page-%03d", i), "", "")
	}
	got := s.Sources()
	if len(got) != MaxSources {
		t.Fatalf("%d source(s) named against a bound of %d", len(got), MaxSources)
	}
	if s.Omitted() != 10 {
		t.Fatalf("%d omitted; ten did not fit", s.Omitted())
	}
	line := Provenance(got, s.Omitted())
	if !strings.HasSuffix(line, "and 10 more") {
		t.Errorf("the line does not say what was left out: …%s",
			line[max(0, len(line)-40):])
	}
}

func TestACleanRunHasNoProvenanceLine(t *testing.T) {
	// An empty line in the record would read as a run whose provenance was
	// lost rather than one that read nothing.
	s := NewSession(reader(), nil)
	if line := Provenance(s.Sources(), s.Omitted()); line != "" {
		t.Fatalf("a run that read nothing produced %q", line)
	}
}

func TestTheRefusalToPublishSaysWhatToCheck(t *testing.T) {
	m := reader()
	m.HumanApproval = false
	s := NewSession(m, nil)
	if ok, _ := s.Publishable(); !ok {
		t.Skip("this manifest cannot publish for an unrelated reason")
	}
	_ = s.Retrieve("live", "pricing", "", "")
	ok, why := s.Publishable()
	if ok {
		t.Fatal("a tainted run was publishable")
	}
	if !strings.Contains(why, "pricing") {
		t.Errorf("the reason does not name what to check: %s", why)
	}
}

func TestADelegatesSourcesComeBackNamed(t *testing.T) {
	// A supervisor whose receipt said "tainted" without saying what the
	// delegate read would hand a reviewer strictly less than the delegate's
	// own receipt already has.
	parent := NewSession(supervisor(), nil)
	child := NewSession(Manifest{
		Name: "researcher", Kind: KindRetrieval, Purpose: "find",
		Capabilities: []string{"read_page"}, Autonomy: AutonomyPropose,
		Budget: Budget{Steps: 5, Tools: 2, Duration: Duration(time.Hour)},
	}, nil)
	_ = child.Retrieve("live", "pricing", "", "")
	parent.Fold(child)

	line := Provenance(parent.Sources(), parent.Omitted())
	if !strings.Contains(line, "pricing") {
		t.Errorf("the supervisor cannot say what its delegate read: %s", line)
	}
	if !strings.Contains(line, "researcher") {
		t.Errorf("the supervisor does not say which delegate read it: %s", line)
	}
}
