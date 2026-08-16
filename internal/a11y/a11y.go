// Package a11y checks rendered pages for the accessibility failures a tool can
// actually detect, and blocks publishing when it finds them.
//
// # Why this is not just a linter
//
// There are two different accessibility standards and CMS vendors usually
// implement the easier one. WCAG governs the *content* a site serves. ATAG
// governs the *authoring tool*, and it has two parts: Part A says the editing
// interface must itself be usable by a disabled author, and Part B says the tool
// must actively help authors produce accessible content.
//
// Part B is where almost everything falls down. A CMS that lets an author
// publish an image with no alternative text, and mentions it in a report nobody
// opens, has not helped anyone. So the checks here run at publish time and stop
// the publish. Overriding is possible — a real site sometimes has a genuine
// exception — but the override is explicit and lands in the commit metadata,
// which means "we waived this" is a recorded decision rather than a habit.
//
// That is the same shape as everything else here: refuse rather than warn, and
// when someone insists, write down that they insisted.
//
// # What is checked, and what cannot be
//
// Everything below is decidable from the rendered HTML. Alt text that is present
// but useless ("image1.jpg"), a heading that is technically ordered but
// meaningless, a colour contrast decided by a stylesheet this tool never sees —
// those need a human, and claiming otherwise would be the accessibility
// equivalent of a green dashboard over an unaudited system.
//
// So the report says what it checked and what it did not. A tool that implies
// full coverage is worse than one that finds less and is honest, because the
// first one ends the conversation.
package a11y

import (
	"fmt"
	"sort"
	"strings"
)

// Severity decides whether a finding blocks a publish.
type Severity string

const (
	// Blocking failures make content unusable for someone. Not a judgement call.
	Blocking Severity = "blocking"
	// Advisory failures are probably wrong but have legitimate exceptions.
	Advisory Severity = "advisory"
)

// Finding is one accessibility problem, tied to the criterion it fails.
type Finding struct {
	Rule      string   `json:"rule"`
	Severity  Severity `json:"severity"`
	Criterion string   `json:"criterion"` // the WCAG success criterion
	Page      string   `json:"page"`
	Detail    string   `json:"detail"`
	Excerpt   string   `json:"excerpt,omitempty"`
}

func (f Finding) String() string {
	s := fmt.Sprintf("[%s] %s (%s): %s", f.Severity, f.Rule, f.Criterion, f.Detail)
	if f.Excerpt != "" {
		s += "\n        " + f.Excerpt
	}
	return s
}

// Report is everything found in one page, plus what was not looked at.
type Report struct {
	Page     string    `json:"page"`
	Findings []Finding `json:"findings"`
	Checked  []string  `json:"checked"`
	NotCheck []string  `json:"not_checked"`
}

// Blocks reports whether this page may be published without an override.
func (r *Report) Blocks() bool {
	for _, f := range r.Findings {
		if f.Severity == Blocking {
			return true
		}
	}
	return false
}

// What the checks below cover, stated so a clean report cannot be mistaken for
// a guarantee of accessibility.
var (
	covered = []string{
		"images have alternative text (1.1.1)",
		"heading levels do not skip (1.3.1)",
		"link text is meaningful on its own (2.4.4)",
		"the page declares a language (3.1.1)",
		"the page has a title (2.4.2)",
		"form inputs have labels (3.3.2)",
		"no positive tabindex (2.4.3)",
		"tables have header cells (1.3.1)",
		"no auto-playing media (1.4.2)",
		"iframes are titled (4.1.2)",
	}
	notCovered = []string{
		"whether alt text is actually useful rather than merely present",
		"colour contrast, which lives in stylesheets this tool does not see",
		"keyboard operability of scripted widgets",
		"reading order and whether headings describe their sections",
		"anything requiring judgement about meaning",
	}
)

// Link text that says nothing when read out of context, which is how a screen
// reader user often encounters it — pulled out into a list of links.
var uselessLinkText = map[string]bool{
	"click here": true, "here": true, "read more": true, "more": true,
	"link": true, "this": true, "learn more": true, "details": true,
	"continue": true, "go": true, "download": true,
}

// Check runs every check against one rendered page.
func Check(page, html string) *Report {
	r := &Report{Page: page, Checked: covered, NotCheck: notCovered}
	tags := scan(html)

	r.checkImages(tags)
	r.checkHeadings(tags)
	r.checkLinks(tags, html)
	r.checkLanguage(tags)
	r.checkTitle(tags, html)
	r.checkInputs(tags)
	r.checkTabindex(tags)
	r.checkTables(tags)
	r.checkAutoplay(tags)
	r.checkFrames(tags)

	sort.SliceStable(r.Findings, func(i, j int) bool {
		if r.Findings[i].Severity != r.Findings[j].Severity {
			return r.Findings[i].Severity == Blocking
		}
		return r.Findings[i].Rule < r.Findings[j].Rule
	})
	for i := range r.Findings {
		r.Findings[i].Page = page
	}
	return r
}

func (r *Report) add(rule string, sev Severity, criterion, detail, excerpt string) {
	r.Findings = append(r.Findings, Finding{
		Rule: rule, Severity: sev, Criterion: criterion,
		Detail: detail, Excerpt: excerpt})
}

// -- the checks ------------------------------------------------------------

func (r *Report) checkImages(tags []tag) {
	for _, t := range tags {
		if t.name != "img" {
			continue
		}
		alt, present := t.attrs["alt"]
		if !present {
			// Absent alt is a failure. Empty alt is not: alt="" is the correct
			// way to mark an image as decorative, and treating it as an error
			// would push authors toward writing noise for a screen reader.
			r.add("image-missing-alt", Blocking, "WCAG 1.1.1",
				"an image has no alt attribute. Use alt=\"\" if it is decorative, "+
					"or describe what it conveys",
				t.raw)
			continue
		}
		if strings.TrimSpace(alt) == "" {
			continue // explicitly decorative, which is a decision, not an omission
		}
		lower := strings.ToLower(strings.TrimSpace(alt))
		if strings.HasSuffix(lower, ".jpg") || strings.HasSuffix(lower, ".png") ||
			strings.HasSuffix(lower, ".gif") || strings.HasPrefix(lower, "image of") ||
			lower == "image" || lower == "photo" || lower == "picture" {
			r.add("image-alt-is-not-a-description", Advisory, "WCAG 1.1.1",
				fmt.Sprintf("alt text %q describes the file, not the content", alt),
				t.raw)
		}
	}
}

func (r *Report) checkHeadings(tags []tag) {
	level := 0
	seenH1 := false
	for _, t := range tags {
		if len(t.name) != 2 || t.name[0] != 'h' || t.name[1] < '1' || t.name[1] > '6' {
			continue
		}
		if t.closing {
			continue
		}
		n := int(t.name[1] - '0')
		if n == 1 {
			if seenH1 {
				r.add("multiple-h1", Advisory, "WCAG 1.3.1",
					"more than one h1; a page normally has one main heading", t.raw)
			}
			seenH1 = true
		}
		if level != 0 && n > level+1 {
			// Skipping a level breaks the outline a screen reader navigates by,
			// which is one of the primary ways a page gets read at all.
			r.add("heading-level-skipped", Blocking, "WCAG 1.3.1",
				fmt.Sprintf("h%d follows h%d; levels must not skip", n, level), t.raw)
		}
		level = n
	}
	if level != 0 && !seenH1 {
		r.add("no-h1", Advisory, "WCAG 1.3.1",
			"the page has headings but no h1", "")
	}
}

func (r *Report) checkLinks(tags []tag, html string) {
	for i, t := range tags {
		if t.name != "a" || t.closing {
			continue
		}
		if _, hasHref := t.attrs["href"]; !hasHref {
			continue // an anchor without href is not a link
		}
		inner := textUntilClose(tags, html, i, "a")
		text := strings.TrimSpace(stripTags(inner))
		if text == "" {
			if _, ok := t.attrs["aria-label"]; ok {
				continue
			}
			if _, ok := t.attrs["title"]; ok {
				continue
			}
			// An image inside the link names it.
			//
			// stripTags throws the img away along with its alt, so a link
			// wrapping a described picture looked nameless — and this rule
			// blocks, so the most ordinary pattern on an image-led site could
			// not be published. What that teaches is to add a redundant
			// aria-label, or to override the gate, and a gate people override
			// out of habit has stopped being one.
			//
			// alt on a nested img is the link's accessible name, which is what
			// the specification says and what every screen reader does.
			if alt, has := firstImageAlt(inner); has {
				if alt != "" {
					continue
				}
				// alt="" is a deliberate claim that the image is decorative,
				// and a decorative image is the entire content of this link —
				// so there is genuinely nothing to announce. Worth its own
				// message, because the fix is not the same one.
				r.add("image-link-has-no-name", Blocking, "WCAG 2.4.4",
					"this link contains only an image marked decorative "+
						"(alt=\"\"), so it is announced as just \"link\". The "+
						"alt text of an image inside a link is the link's name, "+
						"so describe where it goes rather than what it shows",
					t.raw)
				continue
			}
			r.add("link-has-no-text", Blocking, "WCAG 2.4.4",
				"a link has no text and no aria-label, so it is announced as just "+
					"\"link\"", t.raw)
			continue
		}
		if uselessLinkText[strings.ToLower(text)] {
			r.add("link-text-is-not-descriptive", Advisory, "WCAG 2.4.4",
				fmt.Sprintf("link text %q says nothing out of context, and links "+
					"are often read as a list", text), t.raw)
		}
	}
}

func (r *Report) checkLanguage(tags []tag) {
	for _, t := range tags {
		if t.name == "html" && !t.closing {
			if lang, ok := t.attrs["lang"]; ok && strings.TrimSpace(lang) != "" {
				return
			}
			r.add("no-page-language", Blocking, "WCAG 3.1.1",
				"the html element has no lang attribute, so a screen reader cannot "+
					"choose a pronunciation", t.raw)
			return
		}
	}
	// A fragment with no <html> is a partial, not a page; nothing to say.
}

func (r *Report) checkTitle(tags []tag, html string) {
	hasHTML := false
	for i, t := range tags {
		if t.name == "html" {
			hasHTML = true
		}
		if t.name == "title" && !t.closing {
			if strings.TrimSpace(textUntilClose(tags, html, i, "title")) != "" {
				return
			}
			r.add("empty-title", Blocking, "WCAG 2.4.2", "the page title is empty", "")
			return
		}
	}
	if hasHTML {
		r.add("no-title", Blocking, "WCAG 2.4.2",
			"the page has no title element; it is the first thing announced", "")
	}
}

func (r *Report) checkInputs(tags []tag) {
	labelled := map[string]bool{}
	for _, t := range tags {
		if t.name == "label" && !t.closing {
			if f, ok := t.attrs["for"]; ok {
				labelled[f] = true
			}
		}
	}

	// A control inside its own label is labelled, and this rule used to say it
	// was not.
	//
	// `<label>Find <input name="find"></label>` is valid HTML and the standard
	// way to associate a label with a checkbox — the HTML specification calls
	// it implicit association, and every screen reader implements it. Reporting
	// it as a blocking failure was a false positive, and a blocking one: it
	// fires on other people's content as well as on ours, so it was telling
	// authors to fix markup that was already correct. That is worse than a
	// missed finding, because a checker people learn to override is a checker
	// that no longer stops anything.
	//
	// Found by running this checker over every screen in our own admin, which
	// nothing had done: the test that ran it named six pages, and none of the
	// six had a wrapped control.
	inLabel := 0
	wrapped := map[int]bool{}
	for i, t := range tags {
		switch {
		case t.name == "label" && !t.closing:
			inLabel++
		case t.name == "label" && t.closing:
			if inLabel > 0 {
				inLabel--
			}
		case inLabel > 0:
			wrapped[i] = true
		}
	}

	for i, t := range tags {
		if t.closing {
			continue
		}
		if t.name != "input" && t.name != "select" && t.name != "textarea" {
			continue
		}
		if wrapped[i] {
			continue
		}
		if typ := strings.ToLower(t.attrs["type"]); typ == "hidden" ||
			typ == "submit" || typ == "button" || typ == "reset" {
			continue
		}
		if _, ok := t.attrs["aria-label"]; ok {
			continue
		}
		if _, ok := t.attrs["aria-labelledby"]; ok {
			continue
		}
		if id, ok := t.attrs["id"]; ok && labelled[id] {
			continue
		}
		r.add("input-has-no-label", Blocking, "WCAG 3.3.2",
			"a form control has no label, so nobody using a screen reader can "+
				"tell what it wants", t.raw)
	}
}

func (r *Report) checkTabindex(tags []tag) {
	for _, t := range tags {
		v, ok := t.attrs["tabindex"]
		if !ok || t.closing {
			continue
		}
		if len(v) > 0 && v[0] != '-' && v != "0" {
			// A positive tabindex pulls an element out of document order and
			// rearranges keyboard navigation for the whole page.
			r.add("positive-tabindex", Advisory, "WCAG 2.4.3",
				fmt.Sprintf("tabindex=%q overrides the natural focus order", v), t.raw)
		}
	}
}

func (r *Report) checkTables(tags []tag) {
	depth := 0
	hasHeader := false
	for _, t := range tags {
		switch {
		case t.name == "table" && !t.closing:
			depth++
			hasHeader = false
		case t.name == "th" && !t.closing:
			hasHeader = true
		case t.name == "table" && t.closing:
			if depth > 0 && !hasHeader {
				r.add("table-has-no-headers", Advisory, "WCAG 1.3.1",
					"a table has no th cells, so its structure is not announced. "+
						"If it is only for layout, use CSS instead", "")
			}
			depth--
		}
	}
}

func (r *Report) checkAutoplay(tags []tag) {
	for _, t := range tags {
		if t.closing || (t.name != "video" && t.name != "audio") {
			continue
		}
		if _, ok := t.attrs["autoplay"]; !ok {
			continue
		}
		_, muted := t.attrs["muted"]
		if t.name == "audio" || !muted {
			r.add("media-autoplays", Blocking, "WCAG 1.4.2",
				"media plays automatically with sound, which covers a screen "+
					"reader and cannot be stopped by someone who cannot find the "+
					"control", t.raw)
		}
	}
}

func (r *Report) checkFrames(tags []tag) {
	for _, t := range tags {
		if t.closing || (t.name != "iframe" && t.name != "frame") {
			continue
		}
		if title, ok := t.attrs["title"]; !ok || strings.TrimSpace(title) == "" {
			r.add("frame-has-no-title", Blocking, "WCAG 4.1.2",
				"a frame has no title, so it is announced only as \"frame\"", t.raw)
		}
	}
}

// CheckAll runs over a whole site and gathers the reports.
func CheckAll(pages map[string]string) []*Report {
	names := make([]string, 0, len(pages))
	for n := range pages {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]*Report, 0, len(names))
	for _, n := range names {
		out = append(out, Check(n, pages[n]))
	}
	return out
}

// Blocking counts the findings that stop a publish.
func BlockingCount(reports []*Report) int {
	n := 0
	for _, r := range reports {
		for _, f := range r.Findings {
			if f.Severity == Blocking {
				n++
			}
		}
	}
	return n
}

// firstImageAlt returns the alt of the first img in a fragment, and whether
// there was an img at all.
//
// The two answers are separate because they mean different things: no image is
// a link with nothing in it, and an image with alt="" is a link whose only
// content was declared decorative. Both are unusable and the advice differs.
//
// Deliberately a scan rather than a parse. This package reads HTML with a
// tokeniser it owns precisely so that checking a page cannot become a way to
// run something, and pulling in a full parser to read one attribute would be
// the wrong trade for the one place it is needed.
func firstImageAlt(fragment string) (string, bool) {
	low := strings.ToLower(fragment)
	i := strings.Index(low, "<img")
	if i < 0 {
		return "", false
	}
	end := strings.IndexByte(fragment[i:], '>')
	if end < 0 {
		return "", true
	}
	tagText := fragment[i : i+end]
	lowTag := strings.ToLower(tagText)
	j := strings.Index(lowTag, "alt=")
	if j < 0 {
		// No alt at all is not the same as alt="": the image is undescribed,
		// which its own rule already reports. Here it means the link has no
		// name either.
		return "", true
	}
	rest := strings.TrimSpace(tagText[j+len("alt="):])
	if rest == "" {
		return "", true
	}
	quote := rest[0]
	if quote != '"' && quote != '\'' {
		// Unquoted: runs to the next space.
		if k := strings.IndexAny(rest, " \t\r\n"); k >= 0 {
			return strings.TrimSpace(rest[:k]), true
		}
		return strings.TrimSpace(rest), true
	}
	if k := strings.IndexByte(rest[1:], quote); k >= 0 {
		return strings.TrimSpace(rest[1 : 1+k]), true
	}
	return "", true
}
