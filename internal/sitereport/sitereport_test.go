// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package sitereport

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/a11y"
)

func acrWith(failing bool) a11y.ACR {
	acr := a11y.ACR{Pages: 3, NotEvaluated: []string{"a", "b"}}
	acr.Evaluated = []a11y.Criterion{
		{Number: "1.1.1", Clause: "9.1.1.1", Checks: []string{"images have alternative text (1.1.1)"}, Result: a11y.Supports},
		{Number: "2.4.2", Clause: "9.2.4.2", Checks: []string{"the page has a title (2.4.2)"}, Result: a11y.Supports},
	}
	if failing {
		acr.Evaluated[0].Result = a11y.PartiallySupports
		acr.Evaluated[0].Remarks = "2 finding(s) on: about, home"
	}
	return acr
}

func duty(r Report, key string) Duty {
	for _, d := range r.Duties {
		if d.Key == key {
			return d
		}
	}
	return Duty{}
}

// A clean automated check is never written up as compliance: the duty is
// clear, the statement leaves the status for a person.
func TestNothingFoundIsNotCompliant(t *testing.T) {
	r := Build(Input{Site: "Acme", Organisation: "Acme Ltd", Address: "https://acme.test",
		At: time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC), ACR: acrWith(false)})
	if d := duty(r, "accessibility"); d.State != Clear || !strings.Contains(d.Says, "2 more need a person") {
		t.Fatalf("%+v", d)
	}
	md := r.Statement.Markdown()
	if !strings.Contains(md, "[fully / partially] compliant") || strings.Contains(md, "is fully compliant") {
		t.Fatalf("the draft decided the status itself:\n%s", md)
	}
	if !strings.Contains(md, "5 October 2026") || !strings.Contains(md, "https://acme.test") {
		t.Fatalf("the draft lacks what is known:\n%s", md)
	}
	if d := duty(r, "statement"); d.State != Attention {
		t.Fatalf("no statement page and the duty is %s", d.State)
	}
	if strings.Contains(md, "[") != (len(r.Statement.ToFill) > 0) {
		t.Fatalf("square brackets and the list of what to fill disagree: %v", r.Statement.ToFill)
	}
	if strings.Contains(md, "[organisation name]") || strings.Contains(md, "[the website's address]") {
		t.Fatal("asked for what was given")
	}
}

// A failure is named in the statement with its pages, criterion and clause.
func TestAFailureIsStatedWithWhereAndWhich(t *testing.T) {
	r := Build(Input{Site: "Acme", ACR: acrWith(true), StatementPage: "accessibility"})
	d := duty(r, "accessibility")
	if d.State != Attention || !strings.Contains(d.Says, "1 criterion") || !strings.Contains(d.Says, "2 pages") {
		t.Fatalf("%+v", d)
	}
	md := r.Statement.Markdown()
	for _, want := range []string{"partially compliant", "Images have alternative text: not yet on about, home (WCAG 1.1.1; EN 301 549 clause 9.1.1.1).",
		"[organisation name]"} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q in\n%s", want, md)
		}
	}
	if duty(r, "statement").State != Clear {
		t.Error("a published statement page is not noticed")
	}
}

// A check that could not run is unknown, never clear.
func TestACheckThatCouldNotRunIsUnknown(t *testing.T) {
	r := Build(Input{ACRUnread: "no layouts", FormsUnread: "bad json", PIIUnread: "x",
		HeadersUnread: "y", AIUnread: "z", MarkingUnread: "w"})
	for _, d := range r.Duties {
		if d.Key == "statement" {
			continue
		}
		if d.State != Unknown {
			t.Errorf("%s is %s", d.Key, d.State)
		}
	}
	if Worst(r.Duties) != Attention {
		t.Errorf("worst %s", Worst(r.Duties))
	}
}

func TestFormsAndPersonalData(t *testing.T) {
	r := Build(Input{Forms: []Form{{Name: "enquiry", Lawful: true}, {Name: "jobs"}, {Name: "old", Closed: true}}})
	if d := duty(r, "forms"); d.State != Attention || !strings.Contains(d.Says, "1 form of 3 does not say") || !strings.Contains(d.Says, "jobs") {
		t.Fatalf("%+v", d)
	}
	r = Build(Input{PersonalData: []Item{{Page: "contact", Detail: "the email address j…@gmail.com"}}})
	if d := duty(r, "personal-data"); d.State != Review {
		t.Fatalf("an address is %s", d.State)
	}
	r = Build(Input{PersonalData: []Item{{Page: "x", Detail: "a card number ending 6467", Blocking: true}}})
	if d := duty(r, "personal-data"); d.State != Attention || !strings.Contains(d.Fix, "revoke") {
		t.Fatalf("%+v", d)
	}
}

func TestHeadersAreGradedFromWhatWasServed(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	h.Set("Permissions-Policy", "camera=()")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Strict-Transport-Security", "max-age=31536000")
	for _, g := range GradeHeaders(h, Served{Address: "https://acme.test"}) {
		if g.Grade != Good {
			t.Errorf("%s: %s (%s)", g.Name, g.Grade, g.Why)
		}
	}

	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'")
	h.Del("Strict-Transport-Security")
	grades := map[string]Grade{}
	for _, g := range GradeHeaders(h, Served{Address: "https://acme.test", Proxied: true}) {
		grades[g.Name] = g.Grade
	}
	if grades["Content-Security-Policy"] != Weak || grades["Framing"] != Missing || grades["Strict-Transport-Security"] != Elsewhere {
		t.Fatalf("%v", grades)
	}
	r := Build(Input{Headers: GradeHeaders(h, Served{Address: "https://acme.test", Proxied: true})})
	if d := duty(r, "headers"); d.State != Attention || strings.Contains(d.Says, "Strict-Transport") {
		t.Fatalf("a header the proxy sends counted against the site: %+v", d)
	}

	h.Set("Strict-Transport-Security", "max-age=86400")
	for _, g := range GradeHeaders(h, Served{Address: "https://acme.test"}) {
		if g.Name == "Strict-Transport-Security" && g.Grade != Weak {
			t.Errorf("a day of HSTS is %s", g.Grade)
		}
	}
}

func TestHSTSDependsOnTheAddress(t *testing.T) {
	grade := func(addr string) Grade {
		for _, g := range GradeHeaders(http.Header{}, Served{Address: addr}) {
			if g.Name == "Strict-Transport-Security" {
				return g.Grade
			}
		}
		return ""
	}
	for addr, want := range map[string]Grade{
		"": Unchecked, "http://127.0.0.1:8081": Unchecked, "http://localhost": Unchecked,
		"http://acme.test": Missing, "https://acme.test": Missing,
	} {
		if got := grade(addr); got != want {
			t.Errorf("%q: %s, want %s", addr, got, want)
		}
	}
}

func TestAProtectionThatDependsOnTheAddressIsNotCountedAsSent(t *testing.T) {
	r := Build(Input{Headers: []Header{{Name: "A", Grade: Good}, {Name: "Strict-Transport-Security", Grade: Unchecked}}})
	if d := duty(r, "headers"); d.State != Clear || !strings.Contains(d.Says, "1 of 2") || !strings.Contains(d.Says, "Strict-Transport-Security depends") {
		t.Fatalf("%+v", d)
	}
	st := BuildStatement(Input{Site: "Marginalia", Organisation: "Marginalia"})
	if md := st.Markdown(); !strings.Contains(md, "Marginalia is committed to making its website accessible") {
		t.Fatalf("%s", md)
	}
}
