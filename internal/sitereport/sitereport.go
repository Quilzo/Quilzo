// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package sitereport is what the law asks of a published site, and where
// this one stands.
//
// A site run on this program owes its visitors a handful of things that are
// each somebody else's specialism: pages people can use with assistive
// technology (the European Accessibility Act), a statement saying how
// accessible they are, forms that say what they collect and why (GDPR),
// nothing personal published by accident, an automated assistant that says
// it is one and generated content that is marked (the AI Act), and the
// browser protections the rest relies on. Every one of them is checked
// somewhere in this program already. This puts them on one page, in the
// order a person answering a regulator or a buyer would be asked, each with
// the law it comes from, what was found, and what to do.
//
// Four states, and the difference between two of them is the point. Clear
// says the checks that exist found nothing, never that the duty is met: a
// report that said "compliant" about criteria nobody tested would be the
// hand-written conformance report this program exists to replace. Unknown
// says a check could not run, which is not the same as passing.
//
// The pure half lives here, so it can be tested without a site; the half
// that reads one is in cmd/quilzo.
package sitereport

import (
	"fmt"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/a11y"
)

// State is where a duty stands.
type State string

const (
	// Attention: something was found that needs fixing.
	Attention State = "attention"
	// Review: nothing that must change, and something a person should look
	// at — an email address on a page, which is right on a contact page.
	Review State = "review"
	// Clear: the checks that exist found nothing. Not a claim the duty is met.
	Clear State = "clear"
	// Unknown: a check could not run.
	Unknown State = "unknown"
)

// Duty is one thing the law asks of the site.
type Duty struct {
	Key   string `json:"key"`
	Title string `json:"title"`
	// Law is where the duty comes from, as a person would cite it.
	Law string `json:"law"`
	// Asks is the duty in one plain sentence.
	Asks  string `json:"asks"`
	State State  `json:"state"`
	// Says is what this site shows.
	Says string `json:"says"`
	// Fix is what to do, when there is something.
	Fix string `json:"fix,omitempty"`
}

// Form is a form as the report sees it.
type Form struct {
	Name          string `json:"name"`
	Label         string `json:"label,omitempty"`
	Purpose       string `json:"purpose,omitempty"`
	Basis         string `json:"basis,omitempty"`
	RetentionDays int    `json:"retention_days"`
	Closed        bool   `json:"closed,omitempty"`
	// Sensitive are the fields kept out of listings.
	Sensitive []string `json:"sensitive,omitempty"`
	Lawful    bool     `json:"lawful"`
}

// Item is one finding on a page.
type Item struct {
	Page     string `json:"page,omitempty"`
	Detail   string `json:"detail"`
	Blocking bool   `json:"blocking,omitempty"`
	Fix      string `json:"fix,omitempty"`
}

// Input is everything read from the site.
type Input struct {
	Site, Address, Organisation, Version string
	At                                   time.Time
	// Live is the published commit the report is about.
	Live string
	ACR  a11y.ACR
	// ACRUnread says why the accessibility check could not run.
	ACRUnread string
	// StatementPage is the published page that is an accessibility
	// statement, when there is one.
	StatementPage string
	Forms         []Form
	FormsUnread   string
	PersonalData  []Item
	PIIUnread     string
	Headers       []Header
	HeadersUnread string
	// Assistants is how many public assistants there are, and Undisclosed
	// what posture's ai.chatbot-undisclosed rule found about them.
	Assistants  int
	Undisclosed []Item
	AIUnread    string
	// Unmarked is what posture's provenance rules found.
	Unmarked      []Item
	MarkingUnread string
}

// Report is the whole answer.
type Report struct {
	Site          string    `json:"site"`
	Address       string    `json:"address,omitempty"`
	At            time.Time `json:"at"`
	Live          string    `json:"live"`
	Duties        []Duty    `json:"duties"`
	Accessibility a11y.ACR  `json:"accessibility"`
	Statement     Statement `json:"statement"`
	Forms         []Form    `json:"forms"`
	PersonalData  []Item    `json:"personal_data"`
	Headers       []Header  `json:"headers"`
	Caveat        string    `json:"caveat"`
}

// Caveat is what the report is not.
const Caveat = "This report is not legal advice, not an audit and not a " +
	"certificate. It says what this program can check about the published " +
	"site against each duty named, and where a person has to decide. A " +
	"duty marked clear means the checks that exist found nothing, not that " +
	"the duty is met."

// Build turns what was read into the report.
func Build(in Input) Report {
	r := Report{Site: in.Site, Address: in.Address, At: in.At, Live: in.Live,
		Accessibility: in.ACR, Forms: in.Forms, PersonalData: in.PersonalData,
		Headers: in.Headers, Caveat: Caveat}
	r.Statement = BuildStatement(in)
	r.Duties = []Duty{
		accessibility(in), statementDuty(in), forms(in), personal(in),
		disclosure(in), marking(in), headers(in),
	}
	return r
}

// Worst is the state a summary of these duties should show.
func Worst(duties []Duty) State {
	rank := map[State]int{Clear: 0, Review: 1, Unknown: 2, Attention: 3}
	worst := Clear
	for _, d := range duties {
		if rank[d.State] > rank[worst] {
			worst = d.State
		}
	}
	return worst
}

func accessibility(in Input) Duty {
	d := Duty{Key: "accessibility", Title: "Accessible pages",
		Law:  "European Accessibility Act (Directive (EU) 2019/882); EN 301 549 clause 9; WCAG 2.2 AA",
		Asks: "Pages people can perceive, operate and understand, including with assistive technology."}
	if in.ACRUnread != "" {
		d.State, d.Says = Unknown, "The accessibility check could not run: "+in.ACRUnread+"."
		d.Fix = "quilzo a11y check"
		return d
	}
	failing, pages := 0, map[string]bool{}
	for _, c := range in.ACR.Evaluated {
		if c.Result == a11y.PartiallySupports {
			failing++
			for _, p := range pagesIn(c.Remarks) {
				pages[p] = true
			}
		}
	}
	checked, person := len(in.ACR.Evaluated), len(in.ACR.NotEvaluated)
	if failing > 0 {
		d.State = Attention
		d.Says = fmt.Sprintf("%s of the %d checked automatically %s findings, on %s.",
			count(failing, "criterion", "criteria"), checked, plural(failing, "has", "have"),
			count(len(pages), "page", "pages"))
		d.Fix = "Open each page named in the table below in the editor; the accessibility panel says what to change."
		return d
	}
	d.State = Clear
	d.Says = fmt.Sprintf("Nothing found in the %d criteria checked automatically across %s. %d more need a person.",
		checked, count(in.ACR.Pages, "page", "pages"), person)
	return d
}

// pagesIn reads the page names out of a remark like "2 finding(s) on: a, b".
func pagesIn(remarks string) []string {
	_, list, ok := strings.Cut(remarks, ": ")
	if !ok {
		return nil
	}
	return strings.Split(list, ", ")
}

func statementDuty(in Input) Duty {
	d := Duty{Key: "statement", Title: "Accessibility statement",
		Law:  "European Accessibility Act, Article 13 and Annex V; for public bodies, Directive (EU) 2016/2102, Article 7",
		Asks: "A public statement of how accessible the site is, what is not, and how to report a problem."}
	if in.StatementPage != "" {
		d.State, d.Says = Clear, "Published as the page \""+in.StatementPage+"\". Compare it with the draft below when this report changes."
		return d
	}
	d.State = Attention
	d.Says = "No published page is an accessibility statement."
	d.Fix = "The draft below is written from this report. Fill in the parts in square brackets and publish it as a page called accessibility."
	return d
}

func forms(in Input) Duty {
	d := Duty{Key: "forms", Title: "What forms collect, and why",
		Law:  "GDPR Articles 5(1)(b) and (e), 6 and 13",
		Asks: "Each form tells the person what their answers are for, on what lawful basis, and how long they are kept."}
	if in.FormsUnread != "" {
		d.State, d.Says = Unknown, "The forms could not be read: "+in.FormsUnread+"."
		return d
	}
	if len(in.Forms) == 0 {
		d.State, d.Says = Clear, "This site has no forms."
		return d
	}
	var missing []string
	for _, f := range in.Forms {
		if !f.Lawful && !f.Closed {
			missing = append(missing, f.Name)
		}
	}
	if len(missing) > 0 {
		d.State = Attention
		d.Says = fmt.Sprintf("%s of %d %s not say what %s for or on what basis: %s.",
			count(len(missing), "form", "forms"), len(in.Forms), plural(len(missing), "does", "do"),
			plural(len(missing), "its answers are", "their answers are"), strings.Join(missing, ", "))
		d.Fix = "On the Forms screen, give each a purpose and a lawful basis. The form then tells the person both, with how long their answers are kept."
		return d
	}
	d.State = Clear
	d.Says = fmt.Sprintf("Every open form says what its answers are for, its lawful basis and how long they are kept (%s).",
		count(len(in.Forms), "form", "forms"))
	return d
}

func personal(in Input) Duty {
	d := Duty{Key: "personal-data", Title: "Personal data on pages",
		Law:  "GDPR Articles 5(1)(f) and 32",
		Asks: "Nothing personal is published by accident: no card numbers or credentials, and no one's contact details unless they are meant to be there."}
	if in.PIIUnread != "" {
		d.State, d.Says = Unknown, "The published pages could not be read: "+in.PIIUnread+"."
		return d
	}
	blocking := 0
	for _, it := range in.PersonalData {
		if it.Blocking {
			blocking++
		}
	}
	switch {
	case blocking > 0:
		d.State = Attention
		d.Says = fmt.Sprintf("%s on published pages %s a card number or a credential.",
			count(blocking, "field", "fields"), plural(blocking, "carries", "carry"))
		d.Fix = "Remove it and publish. If it was a credential, revoke it first: it has been public."
	case len(in.PersonalData) > 0:
		d.State = Review
		d.Says = fmt.Sprintf("%s to look at: an email address, a telephone number or a bank account. Right on a contact or donation page; not on one pasted from a customer's message.",
			count(len(in.PersonalData), "item", "items"))
	default:
		d.State, d.Says = Clear, "No card number, credential, bank account, email address or telephone number on a published page, other than this site's own."
	}
	return d
}

func disclosure(in Input) Duty {
	d := Duty{Key: "ai-disclosure", Title: "Saying an assistant is automated",
		Law:  "EU AI Act, Article 50(1)",
		Asks: "A person talking to an automated assistant, or reading an answer it wrote, is told so."}
	if in.AIUnread != "" {
		d.State, d.Says = Unknown, "The assistants could not be checked: "+in.AIUnread+"."
		return d
	}
	if len(in.Undisclosed) > 0 {
		d.State = Attention
		names := make([]string, 0, len(in.Undisclosed))
		for _, it := range in.Undisclosed {
			names = append(names, it.Page)
		}
		d.Says = fmt.Sprintf("%s %s not say %s automated: %s.", count(len(names), "page", "pages"),
			plural(len(names), "does", "do"), "it is", strings.Join(names, ", "))
		d.Fix = in.Undisclosed[0].Fix
		return d
	}
	d.State = Clear
	if in.Assistants == 0 {
		d.Says = "No public assistant. A search answer written by a model carries its own notice."
	} else {
		d.Says = fmt.Sprintf("%s, and each says it is automated.", count(in.Assistants, "public assistant", "public assistants"))
	}
	return d
}

func marking(in Input) Duty {
	d := Duty{Key: "ai-marking", Title: "Marking generated content",
		Law:  "EU AI Act, Article 50(2) and (4)",
		Asks: "Content a model generated or changed is marked as such, in a way a machine can read."}
	if in.MarkingUnread != "" {
		d.State, d.Says = Unknown, "Provenance could not be read: "+in.MarkingUnread+"."
		return d
	}
	if len(in.Unmarked) > 0 {
		d.State = Attention
		var says []string
		for _, it := range in.Unmarked {
			says = append(says, it.Detail)
		}
		d.Says = sentence(strings.Join(says, "; "))
		d.Fix = in.Unmarked[0].Fix
		return d
	}
	d.State, d.Says = Clear, "Every published page says where its content came from, and the record matches the page."
	return d
}

func headers(in Input) Duty {
	d := Duty{Key: "headers", Title: "Browser protections",
		Law:  "GDPR Article 32; NIS2 Article 21 where it applies",
		Asks: "The site tells browsers to enforce the protections its pages rely on."}
	if in.HeadersUnread != "" {
		d.State, d.Says = Unknown, "The site could not be asked for a page: "+in.HeadersUnread+"."
		return d
	}
	var weak []string
	for _, h := range in.Headers {
		if h.Grade == Weak || h.Grade == Missing {
			weak = append(weak, h.Name)
		}
	}
	if len(weak) > 0 {
		d.State = Attention
		d.Says = fmt.Sprintf("%s missing or weak: %s.", count(len(weak), "protection is", "protections are"), strings.Join(weak, ", "))
		d.Fix = "Each row below says what to set."
		return d
	}
	d.State = Clear
	var aside []string
	for _, h := range in.Headers {
		if h.Grade == Unchecked || h.Grade == Elsewhere {
			aside = append(aside, h.Name)
		}
	}
	if len(aside) == 0 {
		d.Says = fmt.Sprintf("All %d protections are sent, as this program serves the site.", len(in.Headers))
	} else {
		d.Says = fmt.Sprintf("%d of %d protections are sent, as this program serves the site; %s %s on how it is reached (see below).",
			len(in.Headers)-len(aside), len(in.Headers), strings.Join(aside, ", "), plural(len(aside), "depends", "depend"))
	}
	return d
}

func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func sentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	s = strings.ToUpper(s[:1]) + s[1:]
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}
