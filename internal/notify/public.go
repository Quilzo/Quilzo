// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package notify

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Article 34(3)(c): the public communication, when telling people one at a
// time is not possible.
//
// # Why this belongs in a CMS and nowhere else
//
// Every incident-communication product builds a status page. This one already
// publishes pages: content-addressed, hash-chained, with an accessibility
// gate, a provenance gate and a two-person approval path in front of them.
// The public communication is a page, and it goes through all of that.
//
// That is not a shortcut avoided. Article 34(3)(c) permits a public
// communication only where the data subjects are informed "in an equally
// effective manner", and a notice page that fails an accessibility check is
// not equally effective for somebody reading it with a screen reader. Routing
// it through the ordinary publish path is how the legal test is met, so
// `notify publish` writes a draft and stops, and `quilzo publish` does what
// it does for every other page.
//
// # What a public notice must never contain
//
// The individual notices name who was affected. The public one cannot: a page
// saying "the following customers had their data exposed" is a second breach,
// committed while notifying people about the first. Page() builds from a
// fixed set of fields and Affected is not one of them — and Leaks() checks
// the prose as well, because the way this goes wrong is somebody pasting a
// list into the body at two in the morning.
//
// # A public communication that is taken down was not one
//
// If it is the only way somebody was told, then removing it three weeks later
// unmakes the notification. Nothing here stops a page being unpublished —
// that is the operator's store and their decision — but `notify list` reads
// the live ref and says when the page a notice relies on is no longer there,
// because the alternative is finding out from a regulator.

// PageFields are the fields a public notice page carries, in reading order.
//
// A closed list. Anything that is not here does not reach the page, which is
// what makes "Affected is not on the page" a property of the code rather than
// a habit of whoever wrote it.
func PageFields() []string {
	return []string{"title", "kind", "summary", "body", "nature",
		"consequences", "measures", "contact", "occurred", "aware",
		"published"}
}

// Page renders a notice as a page for the content store.
func (n Notice) Page(at time.Time) (map[string]any, error) {
	if leaked := n.Leaks(); leaked != "" {
		return nil, fmt.Errorf(
			"the wording of %s contains %s, which identifies somebody "+
				"affected. A public notice naming who was affected is a "+
				"second breach, committed while notifying people about the "+
				"first", n.ID, leaked)
	}
	page := map[string]any{
		"title":     n.Subject,
		"kind":      string(n.Kind),
		"body":      n.Body,
		"occurred":  n.Occurred.UTC().Format("2006-01-02"),
		"aware":     n.Aware.UTC().Format("2006-01-02"),
		"published": at.UTC().Format("2006-01-02"),
	}
	if n.Kind == Breach {
		page["summary"] = "This is a notification of a personal data " +
			"breach, published under Article 34(3)(c) of the UK GDPR " +
			"because individual notification would involve disproportionate " +
			"effort."
		page["nature"] = n.Nature
		page["consequences"] = n.Consequences
		page["measures"] = n.Measures
		page["contact"] = n.Contact
	}
	for k := range page {
		if v, ok := page[k].(string); ok && strings.TrimSpace(v) == "" {
			delete(page, k)
		}
	}
	return page, nil
}

// Leaks reports the first identifier of an affected person found in the
// notice's own prose, or empty.
//
// Checked across every field that reaches the page, and against both halves
// of an identifier: a body mentioning "cust-1043" is as identifying as one
// mentioning the whole issuer-qualified form, and the half is what somebody
// pastes.
func (n Notice) Leaks() string {
	if len(n.Affected) == 0 {
		return ""
	}
	prose := strings.ToLower(strings.Join([]string{
		n.Subject, n.Body, n.Nature, n.Consequences, n.Measures, n.Public,
		n.Mitigated,
	}, "\n"))
	var found []string
	for _, id := range n.Affected {
		for _, needle := range []string{id.String(), id.Value} {
			needle = strings.ToLower(strings.TrimSpace(needle))
			// Short values are skipped: an identifier of three characters
			// matches ordinary words, and a check that refuses every notice
			// is one somebody turns off.
			if len(needle) < 4 || !strings.Contains(prose, needle) {
				continue
			}
			found = append(found, id.String())
			break
		}
	}
	if len(found) == 0 {
		return ""
	}
	sort.Strings(found)
	if len(found) > 3 {
		return fmt.Sprintf("%s and %d others", strings.Join(found[:3], ", "),
			len(found)-3)
	}
	return strings.Join(found, ", ")
}

// PageName is the slug a notice's page is stored under.
//
// Derived from the id rather than the subject. A subject gets reworded as an
// incident develops, and a public notice whose address changed halfway
// through is one that every link to it now misses — including the one in the
// individual notices already sent.
func (n Notice) PageName() string { return "notice-" + n.ID }
