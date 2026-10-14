// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package research

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/assistant"
)

// A report is Markdown with three marks:
//
//	{{name}}       a claim's number, as the computation it is pinned to wrote it
//	{{= 2019}}     a number a person states rather than computes: a year, a
//	               dose, a sample size from the design; listed as stated
//	[@key]         a citation of a source; several as [@a; @b]
//
// Any other number in the prose is one nobody can trace, and the check says
// so. A section, figure, table or list number is not a claim and is left
// alone, as is a number inside a name (p53, COVID-19) or in code.

// Segment is a piece of a paragraph.
type Segment struct {
	// Kind is text, claim, stated, cite, number or code.
	Kind string
	Text string
	// Refs are a citation's keys, or a claim's name.
	Refs []string
}

// Paragraph is a block of a report.
type Paragraph struct {
	// Code is a fenced block, kept as it is.
	Code     bool
	Heading  int
	Segments []Segment
	// Line is where it starts, from one.
	Line int
}

var (
	reMark    = regexp.MustCompile(`\{\{\s*(=?)\s*([^{}]{1,80}?)\s*\}\}|\[@([^\]]{1,400})\]|` + "`[^`\n]{0,400}`")
	reNumeral = regexp.MustCompile(`\d[\d,.]*\d|\d`)
	reListNum = regexp.MustCompile(`^\s*\d{1,3}[.)]\s`)
	reHeading = regexp.MustCompile(`^(#{1,6})\s+`)
	// reSpacePunct is a space a citation left before punctuation.
	reSpacePunct = regexp.MustCompile(`\s+([.,;:!?])`)
)

// partWords are words a following number names a part of the document by.
var partWords = map[string]bool{"figure": true, "fig": true, "figs": true, "table": true, "section": true,
	"sections": true, "equation": true, "eq": true, "chapter": true, "appendix": true, "supplementary": true,
	"step": true, "page": true, "pages": true, "line": true, "lines": true, "item": true, "panel": true,
	"version": true, "v": true}

// Parse reads a report into paragraphs.
func Parse(report string) []Paragraph {
	var out []Paragraph
	lines := strings.Split(strings.ReplaceAll(report, "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); {
		line := lines[i]
		switch {
		case strings.TrimSpace(line) == "":
			i++
		case strings.HasPrefix(strings.TrimSpace(line), "```"):
			start := i
			var body []string
			for i++; i < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[i]), "```"); i++ {
				body = append(body, lines[i])
			}
			i++
			out = append(out, Paragraph{Code: true, Line: start + 1,
				Segments: []Segment{{Kind: "code", Text: strings.Join(body, "\n")}}})
		case reHeading.MatchString(line):
			m := reHeading.FindStringSubmatch(line)
			text := strings.TrimSpace(line[len(m[0]):])
			// A heading's own number is a section's.
			if loc := regexp.MustCompile(`^[\d.]+\s+`).FindStringIndex(text); loc != nil {
				text = text[loc[1]:]
			}
			out = append(out, Paragraph{Heading: len(m[1]), Line: i + 1, Segments: segments(text)})
			i++
		default:
			start := i
			var body []string
			for i < len(lines) && strings.TrimSpace(lines[i]) != "" && !reHeading.MatchString(lines[i]) &&
				!strings.HasPrefix(strings.TrimSpace(lines[i]), "```") {
				body = append(body, lines[i])
				i++
			}
			out = append(out, Paragraph{Line: start + 1, Segments: segments(strings.Join(body, "\n"))})
		}
	}
	return out
}

// segments splits a paragraph's text into its marks, its numbers and the
// rest.
func segments(text string) []Segment {
	var out []Segment
	at := 0
	for _, m := range reMark.FindAllStringSubmatchIndex(text, -1) {
		out = append(out, numbers(text[at:m[0]], text[:m[0]])...)
		whole := text[m[0]:m[1]]
		switch {
		case m[6] >= 0:
			var keys []string
			for _, k := range strings.Split(text[m[6]:m[7]], ";") {
				keys = append(keys, strings.TrimPrefix(strings.TrimSpace(k), "@"))
			}
			out = append(out, Segment{Kind: "cite", Text: whole, Refs: keys})
		case strings.HasPrefix(whole, "`"):
			out = append(out, Segment{Kind: "code", Text: strings.Trim(whole, "`")})
		case m[2] >= 0 && m[3] > m[2]:
			out = append(out, Segment{Kind: "stated", Text: strings.TrimSpace(text[m[4]:m[5]])})
		default:
			name := strings.TrimSpace(text[m[4]:m[5]])
			out = append(out, Segment{Kind: "claim", Text: whole, Refs: []string{name}})
		}
		at = m[1]
	}
	return append(out, numbers(text[at:], text[:at])...)
}

// numbers splits text into plain text and the numbers in it that are
// claims nobody linked. before is everything earlier in the paragraph, for
// the word a number follows.
func numbers(text, before string) []Segment {
	var out []Segment
	at := 0
	for _, loc := range reNumeral.FindAllStringIndex(text, -1) {
		s, e := loc[0], loc[1]
		num := strings.TrimRight(text[s:e], ".,")
		e = s + len(num)
		if !standalone(text, s, e, before) {
			continue
		}
		if s > at {
			out = append(out, Segment{Kind: "text", Text: text[at:s]})
		}
		out = append(out, Segment{Kind: "number", Text: num})
		at = e
	}
	if at < len(text) {
		out = append(out, Segment{Kind: "text", Text: text[at:]})
	}
	return out
}

// standalone reports whether the number at text[s:e] is a figure the prose
// asserts, rather than part of a name, an ordinal, a list's numbering, a
// part of the document or an address. before is the paragraph up to text.
func standalone(text string, s, e int, before string) bool {
	full := before + text[:s]
	prev, _ := utf8.DecodeLastRuneInString(full)
	switch {
	case unicode.IsLetter(prev) || prev == '_' || prev == '/':
		return false // p53, H1N1, a path
	case prev == '-' && letterBefore(full[:len(full)-1]):
		return false // COVID-19
	}
	after := strings.ToLower(text[e:])
	for _, suffix := range []string{"st", "nd", "rd", "th", "d "} {
		if strings.HasPrefix(after, suffix) {
			if r, _ := utf8.DecodeRuneInString(after[len(suffix):]); !unicode.IsLetter(r) {
				return false // 1st, 2nd, 3D
			}
		}
	}
	lineStart := strings.LastIndexByte(full, '\n') + 1
	if strings.TrimSpace(full[lineStart:]) == "" && reListNum.MatchString(text[s:]) {
		return false // a list's numbering
	}
	if word := strings.LastIndexFunc(full, unicode.IsSpace); strings.Contains(full[word+1:], "://") {
		return false // in an address
	}
	words := strings.FieldsFunc(strings.ToLower(full), func(r rune) bool { return !unicode.IsLetter(r) })
	if len(words) > 0 && partWords[words[len(words)-1]] {
		tail := strings.TrimSuffix(strings.TrimRightFunc(strings.ToLower(full), unicode.IsSpace), ".")
		if strings.HasSuffix(tail, words[len(words)-1]) {
			return false // Figure 2, Table 3
		}
	}
	return true
}

func letterBefore(s string) bool {
	r, _ := utf8.DecodeLastRuneInString(s)
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

// Finding is something the check found.
type Finding struct {
	// Problem is false for a note: worth reading, not wrong.
	Problem bool
	Line    int
	What    string
}

// Check is a report against its project: every number linked, every
// citation resolved and supporting its sentence, every claim reproduced
// where it was re-run.
func Check(p Project, runs []Run) []Finding {
	var out []Finding
	problem := func(line int, f string, a ...any) {
		out = append(out, Finding{Problem: true, Line: line, What: fmt.Sprintf(f, a...)})
	}
	note := func(f string, a ...any) { out = append(out, Finding{What: fmt.Sprintf(f, a...)}) }

	switch {
	case !p.Registered():
		note("the plan is not registered, so nothing shows it was written before the data was analysed")
	case !p.Plan.BeforeData:
		note("the plan was registered after the data was first analysed")
	}
	for _, a := range p.Amendments {
		when := "before the data was analysed"
		if a.AfterData {
			when = "after the data was analysed"
		}
		note("the plan was amended on %s by %s, %s: %s", a.At.Format("2 Jan 2006"), a.By, when, a.Why)
	}

	claims := map[string]Claim{}
	for _, c := range p.Claims {
		claims[c.Name] = c
	}
	sources := map[string]Source{}
	for _, s := range p.Sources {
		sources[s.Key] = s
	}
	reran := map[string][]Run{}
	for _, r := range runs {
		if r.Rerun != "" {
			reran[r.Rerun] = append(reran[r.Rerun], r)
		}
	}
	used := map[string]bool{}
	for _, para := range Parse(p.Report) {
		if para.Code {
			continue
		}
		for _, sg := range para.Segments {
			switch sg.Kind {
			case "number":
				problem(para.Line, "%s is a number nobody can trace: link it to a computation as {{name}}, "+
					"or mark a number from the design as {{= %s}}", sg.Text, sg.Text)
			case "claim":
				c, ok := claims[sg.Refs[0]]
				if !ok {
					problem(para.Line, "{{%s}} is not a claim: pin a computation's value first (quilzo research claim)", sg.Refs[0])
					continue
				}
				if !used[c.Name] {
					used[c.Name] = true
					for _, r := range reran[c.Run] {
						if r.Reproduced != nil && !*r.Reproduced {
							problem(para.Line, "{{%s}} comes from %s, and running it again in %s did not reproduce it: %s",
								c.Name, c.Run, r.ID, strings.Join(r.Differs, "; "))
						}
					}
				}
			case "cite":
				for _, k := range sg.Refs {
					if _, ok := sources[k]; !ok {
						problem(para.Line, "[@%s] cites nothing that resolved: add the work first (quilzo research cite)", k)
					}
				}
			}
		}
		for _, s := range citedSentences(para) {
			if why := supports(s, sources); why != "" {
				problem(para.Line, "%q: %s", clip(s.plain, 120), why)
			}
		}
	}
	return out
}

// sentence is a sentence of a paragraph, with what it cites.
type sentence struct {
	plain string
	cites []string
}

// citedSentences are a paragraph's sentences that cite something, as plain
// text with the report's own numbers taken out: those are claims about the
// computation, not about the work cited.
func citedSentences(para Paragraph) []sentence {
	var out []sentence
	var cur strings.Builder
	var cites []string
	flush := func() {
		if len(cites) > 0 {
			plain := reSpacePunct.ReplaceAllString(strings.Join(strings.Fields(cur.String()), " "), "$1")
			out = append(out, sentence{plain: plain, cites: cites})
		}
		cur.Reset()
		cites = nil
	}
	for _, sg := range para.Segments {
		switch sg.Kind {
		case "cite":
			cites = append(cites, sg.Refs...)
		case "claim", "stated":
			cur.WriteString(" ")
		case "number", "code":
			cur.WriteString(sg.Text)
		case "text":
			text := sg.Text
			for {
				i := sentenceEnd(text)
				if i < 0 {
					cur.WriteString(text)
					break
				}
				cur.WriteString(text[:i+1])
				// A citation after the full stop belongs to the sentence it
				// follows.
				rest := strings.TrimLeft(text[i+1:], " ")
				if rest == "" {
					text = ""
					break
				}
				flush()
				text = rest
			}
		}
	}
	flush()
	return out
}

// sentenceEnd is where a sentence in text ends: a full stop, question or
// exclamation mark followed by a space and a capital letter, or a new line.
func sentenceEnd(text string) int {
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '.', '?', '!':
			rest := strings.TrimLeft(text[i+1:], " \n")
			if rest != text[i+1:] {
				if r, _ := utf8.DecodeRuneInString(rest); rest == "" || unicode.IsUpper(r) || r == '[' {
					return i
				}
			}
		}
	}
	return -1
}

// supports says why a sentence is not supported by what it cites, or ""
// when it is.
func supports(s sentence, sources map[string]Source) string {
	var hits []assistant.Hit
	marks := ""
	for _, k := range s.cites {
		src, ok := sources[k]
		if !ok {
			return ""
		}
		var text strings.Builder
		text.WriteString(src.Abstract)
		for _, p := range src.Passages {
			text.WriteString(" ")
			text.WriteString(p.Text)
		}
		if strings.TrimSpace(text.String()) == "" {
			return fmt.Sprintf("nothing of [@%s] is held to check it against: quote the passage it rests on "+
				"(quilzo research quote)", k)
		}
		hits = append(hits, assistant.Hit{Passage: assistant.Passage{ID: k, Title: src.Title, Text: text.String()}})
		marks += " [" + strconv.Itoa(len(hits)) + "]"
	}
	v := assistant.Verify(s.plain+marks, hits)
	if v.Supported {
		return ""
	}
	return "not supported by what it cites: " + v.Why
}

func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}

// Problems counts the findings that are problems.
func Problems(fs []Finding) int {
	n := 0
	for _, f := range fs {
		if f.Problem {
			n++
		}
	}
	return n
}

// Piece is a piece of a rendered paragraph.
type Piece struct {
	// Kind is text, value, stated, cite, unlinked or code.
	Kind string
	Text string
	// Title says where a value or a citation comes from.
	Title string
	// Ref is a value's computation, or a citation's numbers.
	Ref string
}

// Block is a rendered paragraph.
type Block struct {
	Heading int
	Code    bool
	Pieces  []Piece
}

// Render is a report with its numbers filled in from its claims and its
// citations numbered in the order they first appear, and the works cited,
// in that order.
func Render(p Project) ([]Block, []Source) {
	claims := map[string]Claim{}
	for _, c := range p.Claims {
		claims[c.Name] = c
	}
	sources := map[string]Source{}
	for _, s := range p.Sources {
		sources[s.Key] = s
	}
	number := map[string]int{}
	var cited []Source
	var out []Block
	for _, para := range Parse(p.Report) {
		b := Block{Heading: para.Heading, Code: para.Code}
		for _, sg := range para.Segments {
			switch sg.Kind {
			case "claim":
				if c, ok := claims[sg.Refs[0]]; ok {
					b.Pieces = append(b.Pieces, Piece{Kind: "value", Text: Format(c.Value, c.Unit),
						Title: c.Name + ", from " + c.Run, Ref: c.Run})
				} else {
					b.Pieces = append(b.Pieces, Piece{Kind: "unlinked", Text: sg.Text, Title: "not a claim"})
				}
			case "stated":
				b.Pieces = append(b.Pieces, Piece{Kind: "stated", Text: sg.Text, Title: "stated, not computed"})
			case "cite":
				var nums, titles []string
				for _, k := range sg.Refs {
					src, ok := sources[k]
					if !ok {
						nums, titles = append(nums, "?"), append(titles, k+": not resolved")
						continue
					}
					if number[k] == 0 {
						cited = append(cited, src)
						number[k] = len(cited)
					}
					nums, titles = append(nums, strconv.Itoa(number[k])), append(titles, src.Title)
				}
				b.Pieces = append(b.Pieces, Piece{Kind: "cite", Text: "[" + strings.Join(nums, ", ") + "]",
					Title: strings.Join(titles, "; "), Ref: strings.Join(nums, ",")})
			case "number":
				b.Pieces = append(b.Pieces, Piece{Kind: "unlinked", Text: sg.Text, Title: "a number nobody can trace"})
			default:
				b.Pieces = append(b.Pieces, Piece{Kind: sg.Kind, Text: sg.Text})
			}
		}
		out = append(out, b)
	}
	return out, cited
}

// Reference is a work as a reference list gives it.
func Reference(s Source) string {
	var b strings.Builder
	switch n := len(s.Authors); {
	case n == 0:
	case n <= 3:
		b.WriteString(strings.Join(s.Authors, ", "))
	default:
		b.WriteString(s.Authors[0] + " et al.")
	}
	if s.Year != 0 {
		fmt.Fprintf(&b, " (%d)", s.Year)
	}
	if b.Len() > 0 {
		b.WriteString(". ")
	}
	b.WriteString(strings.TrimSuffix(s.Title, "."))
	b.WriteString(".")
	if s.Venue != "" {
		b.WriteString(" " + s.Venue + ".")
	}
	if s.URL != "" {
		b.WriteString(" " + s.URL)
	}
	return b.String()
}

// Markdown is the report as a document: its text with numbers and
// citations filled in, the works cited, and where every number came from.
func Markdown(p Project, runs []Run) string {
	blocks, cited := Render(p)
	var b strings.Builder
	for _, bl := range blocks {
		switch {
		case bl.Code:
			b.WriteString("```\n" + bl.Pieces[0].Text + "\n```\n\n")
			continue
		case bl.Heading > 0:
			b.WriteString(strings.Repeat("#", bl.Heading) + " ")
		}
		for _, pc := range bl.Pieces {
			switch pc.Kind {
			case "code":
				b.WriteString("`" + pc.Text + "`")
			case "unlinked":
				b.WriteString(pc.Text + " (untraced)")
			default:
				b.WriteString(pc.Text)
			}
		}
		b.WriteString("\n\n")
	}
	if len(cited) > 0 {
		b.WriteString("## References\n\n")
		for i, s := range cited {
			fmt.Fprintf(&b, "%d. %s\n", i+1, Reference(s))
		}
		b.WriteString("\n")
	}
	b.WriteString("## Provenance\n\n")
	if p.Registered() {
		when := "before the data was analysed"
		if !p.Plan.BeforeData {
			when = "after the data was first analysed"
		}
		fmt.Fprintf(&b, "The plan was registered on %s by %s, %s, as SHA-256 %s.\n",
			p.Plan.Registered.Format("2 January 2006"), p.Plan.By, when, p.Plan.Digest)
		for _, a := range p.Amendments {
			fmt.Fprintf(&b, "It was amended on %s by %s, to %s: %s\n", a.At.Format("2 January 2006"), a.By, a.To[:12], a.Why)
		}
	} else {
		b.WriteString("The plan was not registered.\n")
	}
	byID := map[string]Run{}
	for _, r := range runs {
		byID[r.ID] = r
	}
	if len(p.Claims) > 0 {
		b.WriteString("\n| Number | Value | Computation | Code | Inputs | Environment |\n|---|---|---|---|---|---|\n")
		for _, c := range p.Claims {
			r := byID[c.Run]
			var inputs []string
			for _, in := range r.Inputs {
				inputs = append(inputs, in.Path+" "+short(in.Digest))
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s %s | %s | %s %s, %s |\n", c.Name, Format(c.Value, c.Unit), c.Run,
				r.Code.Path, short(r.Code.Digest), strings.Join(inputs, ", "),
				r.Environment.Interpreter, r.Environment.Version, short(r.Environment.Digest()))
		}
	}
	return b.String()
}

func short(d string) string {
	if len(d) > 12 {
		return d[:12]
	}
	return d
}
