// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package notify

import (
	"fmt"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/telemetry"
)

// A page saying "the following customers had their data exposed" is a second
// breach, committed while notifying people about the first.
func TestThePublicPageNeverNamesAnybodyAffected(t *testing.T) {
	n := breach()
	page, err := n.Page(now)
	if err != nil {
		t.Fatal(err)
	}
	rendered := fmt.Sprint(page)
	for _, id := range n.Affected {
		if strings.Contains(rendered, id.Value) {
			t.Errorf("the page names %s", id)
		}
	}
	// And the field is not reachable: a template that asked for it would
	// find nothing, because it is not on the page at all.
	if _, ok := page["affected"]; ok {
		t.Error("the page carries an affected field")
	}
	allowed := map[string]bool{}
	for _, f := range PageFields() {
		allowed[f] = true
	}
	for k := range page {
		if !allowed[k] {
			t.Errorf("the page carries %q, which is not a declared field", k)
		}
	}
}

// The way this goes wrong is somebody pasting a list into the body at two in
// the morning, not the program rendering the wrong field.
func TestAnIdentifierPastedIntoTheProseIsRefused(t *testing.T) {
	for _, where := range []struct {
		field string
		put   func(*Notice, string)
	}{
		{"body", func(n *Notice, s string) { n.Body += "\n\nAffected: " + s }},
		{"nature", func(n *Notice, s string) { n.Nature += " (" + s + ")" }},
		{"measures", func(n *Notice, s string) { n.Measures += " for " + s }},
		{"subject", func(n *Notice, s string) { n.Subject += " — " + s }},
	} {
		n := breach()
		where.put(&n, n.Affected[0].Value)
		if leak := n.Leaks(); leak == "" {
			t.Errorf("an identifier in the %s was not noticed", where.field)
		}
		if _, err := n.Page(now); err == nil {
			t.Errorf("a page was built with an identifier in the %s",
				where.field)
		} else if !strings.Contains(err.Error(), "second breach") {
			t.Errorf("the refusal does not say why: %v", err)
		}
	}

	// And the issuer-qualified form too, which is the other thing somebody
	// pastes.
	n := breach()
	n.Body += "\n" + n.Affected[1].String()
	if n.Leaks() == "" {
		t.Error("the qualified form of an identifier was not noticed")
	}
}

func TestAShortIdentifierDoesNotRefuseEveryNotice(t *testing.T) {
	n := breach()
	// A customer whose identifier is an ordinary word fragment. A check that
	// refuses every notice is one somebody turns off.
	n.Affected = []telemetry.ID{{Issuer: "crm", Value: "ops"}}
	n.Body = "Access to the backup bucket was revoked by the ops team."
	if leak := n.Leaks(); leak != "" {
		t.Errorf("a three-character identifier matched ordinary prose: %s",
			leak)
	}
	if _, err := n.Page(now); err != nil {
		t.Errorf("the notice was refused: %v", err)
	}
}

func TestThePageCarriesWhatArticleThirtyFourAsksFor(t *testing.T) {
	n := breach()
	n.Affected = nil
	n.Public = "the affected accounts cannot be identified from the logs " +
		"that survive"
	page, err := n.Page(now)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"nature", "consequences", "measures",
		"contact", "occurred", "aware", "published", "summary"} {
		if page[want] == nil || page[want] == "" {
			t.Errorf("the page has no %s", want)
		}
	}
	if !strings.Contains(fmt.Sprint(page["summary"]), "34(3)(c)") {
		t.Errorf("the page does not say what it is: %q", page["summary"])
	}
	// The dates are dates. A breach page carrying a nanosecond timestamp is
	// one written by a machine for machines, and this one is read by the
	// public.
	for _, f := range []string{"occurred", "aware", "published"} {
		if len(fmt.Sprint(page[f])) != len("2026-09-25") {
			t.Errorf("%s reads %q", f, page[f])
		}
	}
}

func TestAProductChangePageCarriesNoBreachFraming(t *testing.T) {
	n := breach()
	n.Kind = Change
	n.Affected, n.Public, n.Mitigated = nil, "", ""
	page, err := n.Page(now)
	if err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{"summary", "nature", "consequences",
		"measures", "contact"} {
		if _, ok := page[unwanted]; ok {
			t.Errorf("a product change page carries %q, which tells a "+
				"reader this is a breach", unwanted)
		}
	}
	if page["title"] == nil {
		t.Error("the page has no title")
	}
}

// A subject gets reworded as an incident develops. A public notice whose
// address changed halfway through is one that every link to it now misses —
// including the one in the individual notices already sent.
func TestThePageNameDoesNotMoveWhenTheWordingDoes(t *testing.T) {
	n := breach()
	first := n.PageName()
	n.Subject = "Update: unauthorised access to backup storage"
	if n.PageName() != first {
		t.Errorf("rewording moved the page from %s to %s", first,
			n.PageName())
	}
	if !strings.HasPrefix(first, "notice-") {
		t.Errorf("the page name is %q", first)
	}
}

func TestAnEmptyFieldIsAbsentRatherThanBlank(t *testing.T) {
	n := breach()
	n.Affected = nil
	n.Public = "reason"
	n.Body = "   "
	page, err := n.Page(now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := page["body"]; ok {
		t.Error("a blank body is on the page, which renders as an empty " +
			"heading with nothing under it")
	}
}
