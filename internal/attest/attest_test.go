// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/a11y"
)

var today = time.Date(2027, 3, 10, 12, 0, 0, 0, time.UTC)

func held() *File {
	return &File{Format: 1, Organisation: "Fernhollow Ltd",
		Attestations: []Attestation{
			{ID: "soc2-2026", Kind: Report, Title: "SOC 2 Type II report", Framework: "SOC 2",
				PeriodStart: "2026-01-01", PeriodEnd: "2026-12-31", Issuer: "Ashby & Rowe LLP",
				Issued: "2027-02-14", Available: "on request, under a non-disclosure agreement"},
			{ID: "iso27001", Kind: Certificate, Title: "ISO/IEC 27001:2022 certificate", Framework: "ISO/IEC 27001:2022",
				PeriodStart: "2025-06-01", PeriodEnd: "2028-05-31", Issuer: "Northgate Certification",
				Issued: "2025-06-01", Expires: "2028-05-31", Scope: "Certified for the hosting of the Fernhollow platform"},
		},
		Policies: []Policy{
			{Title: "Information security policy", Version: "4.2", Approved: "2027-01-20"},
			{Title: "Access control policy", Version: "3.0", Approved: "2026-11-02"},
		}}
}

func page(t *testing.T, f *File) string {
	t.Helper()
	body, err := Page(f, []Head{{Size: 1200, Root: strings.Repeat("ab", 32), At: today, KeyID: "adcd96236f6dff51"}}, today)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// The page shows attestations only: what is held, for which period, from
// whom, and the policies in force. The typed file has no field for a figure,
// refuses one it does not know, and refuses a percentage or a count of
// controls hidden in a description; the page carries no number but dates,
// versions, the framework's own and the head's.
func TestPublicPageHasNoOperationalMetric(t *testing.T) {
	f := held()
	if err := f.Validate(today); err != nil {
		t.Fatalf("a file of attestations does not validate: %v", err)
	}
	body := page(t, f)
	for _, want := range []string{"SOC 2 Type II report", "Ashby &amp; Rowe LLP", "1 January 2026 to 31 December 2026",
		"Information security policy", "4.2", "ISO/IEC 27001:2022"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page does not show %q", want)
		}
	}
	for _, metric := range []string{"%", "score", "passing", "failing", "controls met", "risk"} {
		if strings.Contains(strings.ToLower(textOf(body)), metric) {
			t.Errorf("the page says %q, which is an operational figure's word", metric)
		}
	}

	raw, _ := json.Marshal(f)
	var withScore map[string]any
	_ = json.Unmarshal(raw, &withScore)
	withScore["posture_score"] = 97
	sneaky, _ := json.Marshal(withScore)
	if _, err := Parse(sneaky, today); err == nil {
		t.Error("a file carrying a posture score was taken")
	}
	for _, hidden := range []string{"98% of controls passing", "142 of 150 controls tested", "12 out of 14 risks treated"} {
		g := held()
		g.Attestations[0].Scope = hidden
		if err := g.Validate(today); err == nil || !strings.Contains(err.Error(), "figure") {
			t.Errorf("an operational figure in a description was taken: %q (%v)", hidden, err)
		}
		g = held()
		g.Policies[0].Title = hidden
		if err := g.Validate(today); err == nil {
			t.Errorf("an operational figure in a policy's title was taken: %q", hidden)
		}
	}
}

// "Compliant" and "certified" are refused through internal/brand wherever
// no attestation backs them, and "certified" wherever no certificate in
// force does.
func TestBrandRefusesCompliantWithoutAttestation(t *testing.T) {
	if err := held().Validate(today); err != nil {
		t.Fatalf("a certificate's own scope saying certified was refused: %v", err)
	}
	for name, change := range map[string]func(*File){
		"a policy that says compliant":        func(f *File) { f.Policies[0].Title = "Compliant access policy" },
		"an organisation that says certified": func(f *File) { f.Organisation = "Fernhollow, certified secure" },
		"a report that says certified":        func(f *File) { f.Attestations[0].Scope = "Certified by our auditor" },
		"a certificate that has expired": func(f *File) {
			f.Attestations[1].Expires, f.Attestations[1].PeriodEnd = "2027-01-31", "2027-01-31"
		},
		"non-compliant in a policy": func(f *File) { f.Policies[1].Title = "Handling non-compliant suppliers" },
	} {
		f := held()
		change(f)
		err := f.Validate(today)
		if said := strings.ToLower(fmt.Sprint(err)); err == nil || !(strings.Contains(said, `"compliant"`) || strings.Contains(said, `"certified"`)) {
			t.Errorf("%s was taken: %v", name, err)
		}
	}
	// A report backs compliant in its own description.
	f := held()
	f.Attestations[0].Scope = "The services are compliant with the trust services criteria chosen"
	if err := f.Validate(today); err != nil {
		t.Errorf("an attestation's own description saying compliant was refused: %v", err)
	}
	// And the page's own words never say either.
	empty, err := Page(&File{Format: 1, Organisation: "Fernhollow Ltd"}, nil, today)
	if err != nil {
		t.Fatal(err)
	}
	if words := strings.ToLower(textOf(string(empty))); regexp.MustCompile(`\b(compliant|certified)\b`).MatchString(words) {
		t.Error("the page's own words say compliant or certified")
	}
}

// A file that is not one is refused whole, with what is wrong named.
func TestAFileOfAttestationsIsCheckedWhole(t *testing.T) {
	for name, change := range map[string]func(*File){
		"an unknown kind":           func(f *File) { f.Attestations[0].Kind = "badge" },
		"a period that ends first":  func(f *File) { f.Attestations[0].PeriodEnd = "2025-12-31" },
		"a date that is not one":    func(f *File) { f.Attestations[0].Issued = "14/02/2027" },
		"no issuer":                 func(f *File) { f.Attestations[0].Issuer = "" },
		"two with one id":           func(f *File) { f.Attestations[1].ID = f.Attestations[0].ID },
		"no organisation":           func(f *File) { f.Organisation = "  " },
		"a control character":       func(f *File) { f.Policies[0].Title = "Policy\u0007" },
		"a report issued in future": func(f *File) { f.Attestations[0].Issued = "2027-09-01" },
	} {
		f := held()
		change(f)
		if err := f.Validate(today); err == nil {
			t.Errorf("%s was taken", name)
		}
	}
	if _, err := Parse([]byte(strings.Repeat(" ", MaxBytes+1)), today); err == nil {
		t.Error("a file larger than the limit was read")
	}
}

// The page passes the accessibility checks the interface enforces on
// content: one h1, headings in order, tables with captions and header
// scopes, a language, and it is the same page twice.
func TestThePageIsAccessible(t *testing.T) {
	body := page(t, held())
	for _, f := range a11y.Check("/", body).Findings {
		if f.Severity == a11y.Blocking {
			t.Errorf("%s (%s): %s", f.Rule, f.Criterion, f.Detail)
		}
	}
	if strings.Count(body, "<h1") != 1 || strings.Count(body, "<caption>") != 2 || !strings.Contains(body, `scope="col"`) {
		t.Error("the page does not have one heading of the first level and captioned tables with header scopes")
	}
	if page(t, held()) != body {
		t.Error("the same file rendered twice is two different pages")
	}
	empty, err := Page(nil, nil, today)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range a11y.Check("/", string(empty)).Findings {
		if f.Severity == a11y.Blocking {
			t.Errorf("the page with nothing published: %s (%s): %s", f.Rule, f.Criterion, f.Detail)
		}
	}
	if !strings.Contains(string(empty), "Nothing has been published here yet") {
		t.Error("an instance with nothing published does not say so")
	}
}

var reTags = regexp.MustCompile(`(?s)<style.*?</style>|<[^>]+>`)

func textOf(html string) string { return reTags.ReplaceAllString(html, " ") }
