// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package sitereport

import (
	"fmt"
	"strings"

	"github.com/quilzo/quilzo/internal/a11y"
)

// An accessibility statement, drafted from the report.
//
// The shape is the European Commission's model statement (Implementing
// Decision (EU) 2018/1523), which public bodies must follow and which the
// European Accessibility Act's Annex V information fits as well: how
// accessible the site is, what is not, how the statement was made, how to
// report a problem, and who enforces the law.
//
// Drafted rather than finished, on purpose. What this program knows, it
// writes: the standard, the failures it found and on which pages, the date
// and the method. What only the organisation knows, it leaves in square
// brackets and lists in ToFill — a contact, a reply time, the national
// enforcement body, and the compliance status itself whenever nothing was
// found automatically, because "fully compliant" is a judgement about the
// criteria a person has to check, and a generated draft that made it would
// be the confident document the conformance report refuses to be.

// Statement is a draft accessibility statement.
type Statement struct {
	Title    string    `json:"title"`
	Sections []Section `json:"sections"`
	// ToFill names each part in square brackets a person has to write.
	ToFill []string `json:"to_fill"`
}

// Section is one heading and what is under it.
type Section struct {
	Heading    string   `json:"heading"`
	Paragraphs []string `json:"paragraphs"`
	List       []string `json:"list,omitempty"`
}

// BuildStatement drafts the statement from what was read.
func BuildStatement(in Input) Statement {
	site := in.Site
	if site == "" {
		site = "this website"
	}
	org := in.Organisation
	var fill []string
	if org == "" {
		org = "[organisation name]"
		fill = append(fill, "the organisation's name")
	}
	address := in.Address
	if address == "" {
		address = "[the website's address]"
		fill = append(fill, "the website's address (set site.base_url and it is filled in)")
	}
	date := in.At.Format("2 January 2006")

	st := Statement{Title: "Accessibility statement for " + site}
	what := site
	if strings.EqualFold(org, site) {
		what = "its website"
	}
	st.Sections = append(st.Sections, Section{Heading: "", Paragraphs: []string{
		org + " is committed to making " + what + " accessible, in accordance with the European Accessibility Act " +
			"(Directive (EU) 2019/882) and [the national law that puts it into effect].",
		"This statement applies to " + address + ".",
	}})
	fill = append(fill, "the national law that puts the European Accessibility Act into effect")

	var failing []a11y.Criterion
	for _, c := range in.ACR.Evaluated {
		if c.Result == a11y.PartiallySupports {
			failing = append(failing, c)
		}
	}
	status := Section{Heading: "Compliance status"}
	switch {
	case in.ACRUnread != "" || in.ACR.Pages == 0:
		status.Paragraphs = []string{"This website is [fully / partially / not] compliant with WCAG 2.2 level AA " +
			"and EN 301 549 V4.1.1 clause 9."}
		fill = append(fill, "the compliance status: the automated check did not run, so a person has to establish it")
	case len(failing) > 0:
		status.Paragraphs = []string{"This website is partially compliant with WCAG 2.2 level AA and EN 301 549 " +
			"V4.1.1 clause 9, because of the non-compliances listed below."}
	default:
		status.Paragraphs = []string{"This website is [fully / partially] compliant with WCAG 2.2 level AA and " +
			"EN 301 549 V4.1.1 clause 9.",
			fmt.Sprintf("Automated checks of %d criteria across %d pages found nothing to fix. The other "+
				"criteria need a person to review them before the site can be called fully compliant.",
				len(in.ACR.Evaluated), in.ACR.Pages)}
		fill = append(fill, "the compliance status, once a person has reviewed the criteria the automated check cannot decide")
	}
	st.Sections = append(st.Sections, status)

	content := Section{Heading: "Content that is not accessible"}
	if len(failing) > 0 {
		content.Paragraphs = []string{"The content below does not yet meet the requirements:"}
		for _, c := range failing {
			what := "Criterion " + c.Number
			if len(c.Checks) > 0 {
				what = strings.TrimSuffix(sentence(strings.Split(c.Checks[0], " (")[0]), ".")
			}
			content.List = append(content.List, fmt.Sprintf("%s: not yet on %s (WCAG %s; EN 301 549 clause %s).",
				what, strings.Join(pagesIn(c.Remarks), ", "), c.Number, c.Clause))
		}
		content.Paragraphs = append(content.Paragraphs, "We plan to fix these by [date].")
		fill = append(fill, "when the content listed will be fixed")
	} else {
		content.Paragraphs = []string{"[Anything a manual review found that is not accessible, and when it will be fixed. If nothing, say so.]"}
		fill = append(fill, "what a manual review found, if anything")
	}
	st.Sections = append(st.Sections, content)

	st.Sections = append(st.Sections, Section{Heading: "How this statement was prepared", Paragraphs: []string{
		fmt.Sprintf("This statement was prepared on %s. It is based on a self-assessment: automated checks "+
			"by Quilzo%s of the %d published pages on %s, and [a manual review by whom, on what date].",
			date, versionOf(in.Version), in.ACR.Pages, date),
	}})
	fill = append(fill, "who reviewed the site by hand, and when")

	st.Sections = append(st.Sections, Section{Heading: "Feedback and contact", Paragraphs: []string{
		"If you find a problem with the accessibility of this website, or need information from it in another " +
			"format, contact us at [email address or contact form]. We aim to reply within [number] working days.",
	}})
	fill = append(fill, "how to contact you, and how soon you reply")

	st.Sections = append(st.Sections, Section{Heading: "Enforcement", Paragraphs: []string{
		"If you are not satisfied with our reply, you can contact [the national body that enforces accessibility law].",
	}})
	fill = append(fill, "the national enforcement body")

	st.ToFill = fill
	return st
}

func versionOf(v string) string {
	if v == "" || v == "dev" {
		return ""
	}
	return " " + v
}

// Markdown is the statement as text a page can be written from.
func (s Statement) Markdown() string {
	var b strings.Builder
	b.WriteString("# " + s.Title + "\n")
	for _, sec := range s.Sections {
		if sec.Heading != "" {
			b.WriteString("\n## " + sec.Heading + "\n")
		}
		for _, p := range sec.Paragraphs {
			b.WriteString("\n" + p + "\n")
		}
		if len(sec.List) > 0 {
			b.WriteString("\n")
			for _, item := range sec.List {
				b.WriteString("- " + item + "\n")
			}
		}
	}
	return b.String()
}
