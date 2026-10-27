// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package yamlite reads and writes the YAML that agent definitions are
// written in, and refuses the rest.
//
// Other platforms keep agents in YAML: Google's ADK agent configs, CrewAI's
// agents.yaml, Oracle's Agent Spec, the front matter of a Claude Code
// subagent. This program has no dependencies, so it reads them itself:
// block mappings and sequences, plain, quoted and block scalars, flow
// collections, and comments. What it does not follow it refuses, naming the
// line (anchors and aliases, tags, complex keys, tabs for indentation, a
// key given twice, more than one document), because an agent imported from
// a file read wrongly is an agent with instructions nobody wrote.
//
// Values come back as encoding/json decodes them: map[string]any, []any,
// string, float64, bool and nil, so one reader serves both formats.
package yamlite

import (
	"fmt"
	"math"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Parse reads one YAML document.
func Parse(src []byte) (any, error) {
	if !utf8.Valid(src) {
		return nil, fmt.Errorf("the YAML is not UTF-8")
	}
	text := strings.ReplaceAll(string(src), "\r\n", "\n")
	text = strings.TrimPrefix(text, "\ufeff")
	// The line break that ends the last line ends it; it does not start
	// an empty line after it, which a block scalar kept with |+ would
	// otherwise read as one more line break.
	text = strings.TrimSuffix(text, "\n")
	p := &parser{lines: strings.Split(text, "\n")}
	// A leading document marker, and directives before it, are the start.
	for p.i < len(p.lines) && blankOrComment(p.lines[p.i]) {
		p.i++
	}
	if p.i < len(p.lines) && strings.HasPrefix(p.lines[p.i], "%") {
		return nil, p.errf("directives (%s) are not read", strings.Fields(p.lines[p.i])[0])
	}
	if p.i < len(p.lines) && isMarker(p.lines[p.i], "---") {
		rest := strings.TrimSpace(strings.TrimPrefix(p.lines[p.i], "---"))
		if rest != "" && !strings.HasPrefix(rest, "#") {
			return nil, p.errf("a value on the document marker's line is not read")
		}
		p.i++
	}
	v, err := p.block(0)
	if err == nil {
		err = p.err
	}
	if err != nil {
		return nil, err
	}
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		switch {
		case blankOrComment(l):
			p.i++
		case isMarker(l, "..."):
			p.i++
			for p.i < len(p.lines) && blankOrComment(p.lines[p.i]) {
				p.i++
			}
			if p.i < len(p.lines) {
				return nil, p.errf("more than one document: this reads one")
			}
		case isMarker(l, "---"):
			return nil, p.errf("more than one document: this reads one")
		default:
			return nil, p.errf("this line is not part of the document above it (check its indentation)")
		}
	}
	return v, nil
}

type parser struct {
	lines []string
	i     int
	// err is a fault next found, which ends the reading.
	err error
}

func (p *parser) errf(format string, a ...any) error {
	return fmt.Errorf("line %d: %s", p.i+1, fmt.Sprintf(format, a...))
}

func isMarker(l, m string) bool {
	return l == m || strings.HasPrefix(l, m+" ") || strings.HasPrefix(l, m+"\t")
}

func blankOrComment(l string) bool {
	t := strings.TrimLeft(l, " ")
	return t == "" || strings.HasPrefix(t, "#") || strings.TrimSpace(t) == ""
}

func indentOf(l string) int { return len(l) - len(strings.TrimLeft(l, " ")) }

// next skips blank and comment lines and says where the next line with
// content is, and its indentation; ok is false at the end. A line indented
// with a tab is an error, kept in p.err for the caller.
func (p *parser) next() (int, bool) {
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if blankOrComment(l) {
			p.i++
			continue
		}
		if isMarker(l, "---") || isMarker(l, "...") {
			return 0, false
		}
		if strings.HasPrefix(strings.TrimLeft(l, " "), "\t") {
			if p.err == nil {
				p.err = p.errf("a tab indents this line; YAML indents with spaces")
			}
			return 0, false
		}
		return indentOf(l), true
	}
	return 0, false
}

// block reads whatever starts at the next line, which must be indented at
// least min. Nothing there is null.
func (p *parser) block(min int) (any, error) {
	ind, ok := p.next()
	if !ok || ind < min {
		return nil, nil
	}
	body := p.lines[p.i][ind:]
	switch {
	case body == "?" || strings.HasPrefix(body, "? ") || body == ":" || strings.HasPrefix(body, ": "):
		return nil, p.errf("complex keys (? and :) are not read")
	case isDash(body):
		return p.sequence(ind)
	case keyOf(body) >= 0:
		return p.mapping(ind)
	}
	return p.scalarAt(ind, ind-1)
}

func isDash(body string) bool { return body == "-" || strings.HasPrefix(body, "- ") }

// keyOf is where the colon ending a mapping key is in body, or -1 when the
// line is not a key and its value.
func keyOf(body string) int {
	if body == "" || strings.HasPrefix(body, "#") || strings.HasPrefix(body, "[") || strings.HasPrefix(body, "{") {
		return -1
	}
	if body[0] == '"' || body[0] == '\'' {
		end := closingQuote(body)
		if end < 0 {
			return -1
		}
		rest := strings.TrimLeft(body[end+1:], " ")
		if strings.HasPrefix(rest, ":") && (len(rest) == 1 || rest[1] == ' ') {
			return len(body) - len(rest)
		}
		return -1
	}
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '#':
			if i > 0 && body[i-1] == ' ' {
				return -1
			}
		case ':':
			if i+1 == len(body) || body[i+1] == ' ' {
				return i
			}
		}
	}
	return -1
}

// closingQuote is where the quote that opens s closes, or -1.
func closingQuote(s string) int {
	q := s[0]
	for i := 1; i < len(s); i++ {
		switch {
		case q == '"' && s[i] == '\\':
			i++
		case s[i] == q:
			if q == '\'' && i+1 < len(s) && s[i+1] == '\'' {
				i++
				continue
			}
			return i
		}
	}
	return -1
}

func (p *parser) mapping(ind int) (any, error) {
	out := map[string]any{}
	for {
		at, ok := p.next()
		if !ok || at < ind {
			return out, nil
		}
		if at > ind {
			return nil, p.errf("this line is indented further than the keys around it")
		}
		body := p.lines[p.i][ind:]
		c := keyOf(body)
		if c < 0 {
			if isDash(body) {
				return nil, p.errf("a list item where a key was expected")
			}
			return nil, p.errf("expected a key and a colon")
		}
		key, err := p.key(strings.TrimRight(body[:c], " "))
		if err != nil {
			return nil, err
		}
		if _, dup := out[key]; dup {
			return nil, p.errf("the key %q is given twice", key)
		}
		rest := strings.TrimLeft(body[c+1:], " ")
		v, err := p.value(rest, ind, true)
		if err != nil {
			return nil, err
		}
		out[key] = v
	}
}

func (p *parser) key(k string) (string, error) {
	switch {
	case k == "":
		return "", p.errf("an empty key")
	case strings.HasPrefix(k, "? "):
		return "", p.errf("complex keys (?) are not read")
	case k == "<<":
		return "", p.errf("merge keys (<<) are not read")
	case k[0] == '&' || k[0] == '*' || k[0] == '!':
		return "", p.errf("anchors, aliases and tags (%c) are not read", k[0])
	case k[0] == '"' || k[0] == '\'':
		s, n, err := quoted(k)
		if err != nil {
			return "", p.errf("%v", err)
		}
		if n != len(k) {
			return "", p.errf("something follows the quoted key")
		}
		return s, nil
	}
	return k, nil
}

// value reads what follows a key's colon or a list item's dash, on this
// line and the lines after it. parent is the indentation of the key or
// dash. inMap says it is a mapping's value, which may be a list at the
// key's own indentation.
func (p *parser) value(rest string, parent int, inMap bool) (any, error) {
	rest = stripComment(rest)
	if rest == "" {
		p.i++
		at, ok := p.next()
		switch {
		case !ok:
			return nil, nil
		case at > parent:
			return p.block(parent + 1)
		case at == parent && inMap && isDash(p.lines[p.i][at:]):
			return p.sequence(at)
		}
		return nil, nil
	}
	switch rest[0] {
	case '&', '*', '!':
		return nil, p.errf("anchors, aliases and tags (%c) are not read", rest[0])
	case '|', '>':
		return p.blockScalar(rest, parent)
	}
	return p.inline(rest, parent)
}

// inline reads a scalar or a flow collection that starts on the current
// line (rest is the rest of it) and may continue on lines indented more
// than parent.
func (p *parser) inline(rest string, parent int) (any, error) {
	switch rest[0] {
	case '[', '{':
		text := rest
		for !flowClosed(text) {
			p.i++
			if p.i >= len(p.lines) {
				return nil, p.errf("a flow collection that never closes")
			}
			text += " " + strings.TrimSpace(stripComment(p.lines[p.i]))
		}
		p.i++
		f := &flow{s: text}
		v, err := f.value()
		if err != nil {
			return nil, p.errf("%v", err)
		}
		f.space()
		if f.i != len(f.s) {
			return nil, p.errf("something follows the flow collection: %q", f.s[f.i:])
		}
		return v, nil
	case '"', '\'':
		text := rest
		for closingQuote(text) < 0 {
			p.i++
			if p.i >= len(p.lines) {
				return nil, p.errf("a quoted value that never closes")
			}
			text += "\n" + strings.TrimSpace(p.lines[p.i])
		}
		s, n, err := quoted(text)
		if err != nil {
			return nil, p.errf("%v", err)
		}
		if tail := stripComment(strings.TrimSpace(text[n:])); tail != "" {
			return nil, p.errf("something follows the quoted value: %q", tail)
		}
		p.i++
		return s, nil
	}
	// A plain scalar, folded across the lines indented further than its
	// key or dash.
	parts := []string{strings.TrimRight(rest, " ")}
	p.i++
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if strings.TrimSpace(l) == "" {
			parts = append(parts, "")
			p.i++
			continue
		}
		if indentOf(l) <= parent || strings.HasPrefix(strings.TrimLeft(l, " "), "#") {
			break
		}
		t := stripComment(strings.TrimSpace(l))
		if t == "" {
			break
		}
		parts = append(parts, t)
		p.i++
	}
	for len(parts) > 1 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return plain(foldPlain(parts)), nil
}

// foldPlain joins a multi-line plain scalar: lines with a space, and each
// empty line as a line break.
func foldPlain(parts []string) string {
	var b strings.Builder
	for i, s := range parts {
		switch {
		case i == 0:
			b.WriteString(s)
		case s == "":
			b.WriteString("\n")
		case parts[i-1] == "":
			b.WriteString(s)
		default:
			b.WriteString(" " + s)
		}
	}
	return b.String()
}

func (p *parser) scalarAt(ind, parent int) (any, error) {
	return p.value(p.lines[p.i][ind:], parent, false)
}

func (p *parser) sequence(ind int) (any, error) {
	out := []any{}
	for {
		at, ok := p.next()
		if !ok || at < ind {
			return out, nil
		}
		l := p.lines[p.i]
		if at > ind || !isDash(l[ind:]) {
			if at == ind {
				return out, nil
			}
			return nil, p.errf("this line is indented further than the list items around it")
		}
		after := l[ind+1:]
		content := strings.TrimLeft(after, " ")
		col := ind + 1 + (len(after) - len(content))
		switch {
		case stripComment(content) == "":
			v, err := p.value("", ind, false)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		case isDash(content) || keyOf(content) >= 0:
			// A compact mapping or list inside the item: read as if the
			// dash were a space, at the content's own column.
			p.lines[p.i] = strings.Repeat(" ", col) + content
			v, err := p.block(col)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		default:
			v, err := p.value(content, ind, false)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
	}
}

// blockScalar reads a literal (|) or folded (>) block scalar whose header
// is h, belonging to a key or dash at parent.
func (p *parser) blockScalar(h string, parent int) (any, error) {
	style := h[0]
	head := stripComment(h[1:])
	chomp, explicit := byte(0), 0
	for _, c := range []byte(strings.TrimSpace(head)) {
		switch {
		case (c == '-' || c == '+') && chomp == 0:
			chomp = c
		case c >= '1' && c <= '9' && explicit == 0:
			explicit = int(c - '0')
		default:
			return nil, p.errf("a block scalar's header %q is not read", h)
		}
	}
	p.i++
	indent := 0
	if explicit > 0 {
		indent = parent + explicit
		if parent < 0 {
			indent = explicit
		}
	} else {
		for j := p.i; j < len(p.lines); j++ {
			if strings.TrimSpace(p.lines[j]) != "" {
				indent = indentOf(p.lines[j])
				break
			}
		}
		if indent <= parent {
			indent = parent + 1
		}
	}
	var lines []string
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if strings.TrimSpace(l) == "" {
			if len(l) > indent {
				lines = append(lines, l[indent:])
			} else {
				lines = append(lines, "")
			}
			p.i++
			continue
		}
		if indentOf(l) < indent {
			break
		}
		lines = append(lines, l[indent:])
		p.i++
	}
	// Trailing empty lines are the chomping's to keep or drop.
	trailing := 0
	for trailing < len(lines) && lines[len(lines)-1-trailing] == "" {
		trailing++
	}
	content := lines[:len(lines)-trailing]
	var text string
	if style == '|' {
		text = strings.Join(content, "\n")
	} else {
		text = fold(content)
	}
	switch {
	case len(content) == 0:
		text = ""
		if chomp == '+' {
			text = strings.Repeat("\n", trailing)
		}
	case chomp == '-':
	case chomp == '+':
		text += "\n" + strings.Repeat("\n", trailing)
	default:
		text += "\n"
	}
	return text, nil
}

// fold joins a folded block scalar's lines: a line break between two lines
// of text is a space, except around lines indented further, and each empty
// line is a line break.
func fold(lines []string) string {
	var b strings.Builder
	for i, l := range lines {
		if i > 0 {
			prev := lines[i-1]
			switch {
			case l == "" || prev == "":
				b.WriteString("\n")
			case strings.HasPrefix(l, " ") || strings.HasPrefix(prev, " "):
				b.WriteString("\n")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString(l)
	}
	// An empty line after text was counted as the break and its own line;
	// one empty line between paragraphs is one line break.
	return strings.ReplaceAll(b.String(), "\n\n", "\n")
}

// stripComment removes a comment from a line that holds no quotes.
func stripComment(s string) string {
	inQ := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inQ == '"' && c == '\\':
			i++
		case inQ != 0:
			if c == inQ {
				inQ = 0
			}
		case c == '"' || c == '\'':
			if i == 0 || s[i-1] == ' ' || s[i-1] == '[' || s[i-1] == '{' || s[i-1] == ',' || s[i-1] == ':' {
				inQ = c
			}
		case c == '#' && (i == 0 || s[i-1] == ' '):
			return strings.TrimRight(s[:i], " ")
		}
	}
	return strings.TrimRight(s, " ")
}

// quoted reads a quoted scalar at the start of s, and says how much of s it
// took.
func quoted(s string) (string, int, error) {
	end := closingQuote(s)
	if end < 0 {
		return "", 0, fmt.Errorf("a quoted value that never closes")
	}
	body := foldQuoted(s[1:end])
	if s[0] == '\'' {
		return strings.ReplaceAll(body, "''", "'"), end + 1, nil
	}
	var b strings.Builder
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		i++
		if i >= len(body) {
			return "", 0, fmt.Errorf("a backslash ends a quoted value")
		}
		switch e := body[i]; e {
		case 'n':
			b.WriteByte('\n')
		case 't', '\t':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case '0':
			b.WriteByte(0)
		case 'a':
			b.WriteByte(7)
		case 'b':
			b.WriteByte(8)
		case 'e':
			b.WriteByte(0x1b)
		case 'f':
			b.WriteByte(12)
		case 'v':
			b.WriteByte(11)
		case ' ', '"', '/', '\\':
			b.WriteByte(e)
		case 'N':
			b.WriteString("\u0085")
		case '_':
			b.WriteString(" ")
		case 'L':
			b.WriteString(" ")
		case 'P':
			b.WriteString(" ")
		case '\n':
			// An escaped line break joins the lines with nothing.
		case 'x', 'u', 'U':
			n := map[byte]int{'x': 2, 'u': 4, 'U': 8}[e]
			if i+1+n > len(body) {
				return "", 0, fmt.Errorf("a short \\%c escape", e)
			}
			r, err := strconv.ParseUint(body[i+1:i+1+n], 16, 32)
			if err != nil {
				return "", 0, fmt.Errorf("the escape \\%c%s is not hexadecimal", e, body[i+1:i+1+n])
			}
			if r > utf8.MaxRune {
				return "", 0, fmt.Errorf("the escape \\%c%s is past the last character there is", e, body[i+1:i+1+n])
			}
			b.WriteRune(rune(r))
			i += n
		default:
			return "", 0, fmt.Errorf("the escape \\%c is not one YAML has", e)
		}
	}
	return b.String(), end + 1, nil
}

// foldQuoted folds the line breaks inside a quoted scalar written across
// lines: one break is a space, each further empty line a line break.
func foldQuoted(s string) string {
	if !strings.Contains(s, "\n") {
		return s
	}
	lines := strings.Split(s, "\n")
	var b strings.Builder
	for i, l := range lines {
		if i > 0 {
			l = strings.TrimLeft(l, " \t")
		}
		if i < len(lines)-1 {
			l = strings.TrimRight(l, " \t")
		}
		switch {
		case i == 0:
		case l == "" && i < len(lines)-1:
			b.WriteString("\n")
			continue
		case strings.HasSuffix(b.String(), "\n") || strings.HasSuffix(lines[i-1], "\\"):
		default:
			b.WriteString(" ")
		}
		b.WriteString(l)
	}
	return b.String()
}

var (
	reInt   = regexp.MustCompile(`^[-+]?[0-9]+$`)
	reOct   = regexp.MustCompile(`^0o[0-7]+$`)
	reHex   = regexp.MustCompile(`^0x[0-9a-fA-F]+$`)
	reFloat = regexp.MustCompile(`^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$`)
)

// plain is a plain scalar's value under YAML 1.2's core schema.
func plain(s string) any {
	switch s {
	case "", "~", "null", "Null", "NULL":
		return nil
	case "true", "True", "TRUE":
		return true
	case "false", "False", "FALSE":
		return false
	case ".inf", ".Inf", ".INF", "+.inf", "+.Inf", "+.INF":
		return math.Inf(1)
	case "-.inf", "-.Inf", "-.INF":
		return math.Inf(-1)
	case ".nan", ".NaN", ".NAN":
		return math.NaN()
	}
	switch {
	case reInt.MatchString(s):
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f
		}
	case reOct.MatchString(s):
		return radix(s[2:], 8)
	case reHex.MatchString(s):
		return radix(s[2:], 16)
	case reFloat.MatchString(s):
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f
		}
	}
	return s
}

// radix is digits in a base as a number, as near as a float64 comes to it
// however many digits there are: a number is read as JSON reads one.
func radix(digits string, base int) float64 {
	n, _ := new(big.Int).SetString(digits, base)
	f, _ := new(big.Float).SetInt(n).Float64()
	return f
}

// flow reads a flow collection: [a, b] and {k: v}.
type flow struct {
	s string
	i int
}

func flowClosed(s string) bool {
	depth, inQ := 0, byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inQ == '"' && c == '\\':
			i++
		case inQ != 0:
			if c == inQ {
				inQ = 0
			}
		case c == '"' || c == '\'':
			inQ = c
		case c == '[' || c == '{':
			depth++
		case c == ']' || c == '}':
			depth--
		}
	}
	return depth <= 0 && inQ == 0
}

func (f *flow) space() {
	for f.i < len(f.s) && (f.s[f.i] == ' ' || f.s[f.i] == '\t' || f.s[f.i] == '\n') {
		f.i++
	}
}

func (f *flow) value() (any, error) {
	f.space()
	if f.i >= len(f.s) {
		return nil, fmt.Errorf("a flow collection ends early")
	}
	switch c := f.s[f.i]; c {
	case '[':
		f.i++
		out := []any{}
		for {
			f.space()
			if f.i < len(f.s) && f.s[f.i] == ']' {
				f.i++
				return out, nil
			}
			v, err := f.value()
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			f.space()
			if f.i < len(f.s) && f.s[f.i] == ',' {
				f.i++
				continue
			}
			if f.i < len(f.s) && f.s[f.i] == ']' {
				f.i++
				return out, nil
			}
			return nil, fmt.Errorf("expected , or ] in a flow list")
		}
	case '{':
		f.i++
		out := map[string]any{}
		for {
			f.space()
			if f.i < len(f.s) && f.s[f.i] == '}' {
				f.i++
				return out, nil
			}
			kv, err := f.scalar(true)
			if err != nil {
				return nil, err
			}
			k, ok := kv.(string)
			if !ok {
				k = fmt.Sprint(kv)
			}
			f.space()
			var v any
			if f.i < len(f.s) && f.s[f.i] == ':' {
				f.i++
				f.space()
				if f.i < len(f.s) && (f.s[f.i] == ',' || f.s[f.i] == '}') {
					v = nil
				} else if v, err = f.value(); err != nil {
					return nil, err
				}
			}
			if _, dup := out[k]; dup {
				return nil, fmt.Errorf("the key %q is given twice", k)
			}
			out[k] = v
			f.space()
			if f.i < len(f.s) && f.s[f.i] == ',' {
				f.i++
				continue
			}
			if f.i < len(f.s) && f.s[f.i] == '}' {
				f.i++
				return out, nil
			}
			return nil, fmt.Errorf("expected , or } in a flow mapping")
		}
	case '&', '*', '!':
		return nil, fmt.Errorf("anchors, aliases and tags (%c) are not read", c)
	}
	return f.scalar(false)
}

func (f *flow) scalar(key bool) (any, error) {
	f.space()
	if f.i < len(f.s) && (f.s[f.i] == '"' || f.s[f.i] == '\'') {
		s, n, err := quoted(f.s[f.i:])
		if err != nil {
			return nil, err
		}
		f.i += n
		return s, nil
	}
	start := f.i
	for f.i < len(f.s) {
		c := f.s[f.i]
		if c == ',' || c == ']' || c == '}' || c == '[' || c == '{' {
			break
		}
		if c == ':' && (f.i+1 == len(f.s) || f.s[f.i+1] == ' ' || f.s[f.i+1] == ',' || f.s[f.i+1] == '}' || f.s[f.i+1] == ']') {
			break
		}
		if c == '#' && f.i > start && f.s[f.i-1] == ' ' {
			return nil, fmt.Errorf("a comment inside a flow collection")
		}
		f.i++
	}
	s := strings.TrimSpace(f.s[start:f.i])
	if key {
		return s, nil
	}
	return plain(s), nil
}

// -- writing ------------------------------------------------------------------

// KV is one key and value of a mapping written in order.
type KV struct {
	Key   string
	Value any
}

// Map is a mapping written in the order given.
type Map []KV

// Marshal writes v as YAML that Parse reads back as the same value. Maps
// are Map (in order) or map[string]any (sorted); lists []any or []string;
// scalars string, bool, int, float64 and nil.
func Marshal(v any) ([]byte, error) {
	var b strings.Builder
	if err := write(&b, v, 0, false); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func write(b *strings.Builder, v any, indent int, inline bool) error {
	pad := strings.Repeat(" ", indent)
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		m := make(Map, 0, len(keys))
		for _, k := range keys {
			m = append(m, KV{k, t[k]})
		}
		return write(b, m, indent, inline)
	case Map:
		if len(t) == 0 {
			b.WriteString("{}\n")
			return nil
		}
		for i, kv := range t {
			if !(inline && i == 0) {
				b.WriteString(pad)
			}
			b.WriteString(scalarText(kv.Key) + ":")
			if err := writeValue(b, kv.Value, indent); err != nil {
				return err
			}
		}
		return nil
	case []string:
		l := make([]any, len(t))
		for i, s := range t {
			l[i] = s
		}
		return write(b, l, indent, inline)
	case []any:
		if len(t) == 0 {
			b.WriteString("[]\n")
			return nil
		}
		for i, item := range t {
			if !(inline && i == 0) {
				b.WriteString(pad)
			}
			b.WriteString("-")
			switch it := item.(type) {
			case Map, map[string]any:
				if isEmptyMap(it) {
					b.WriteString(" {}\n")
					continue
				}
				b.WriteString(" ")
				if err := write(b, it, indent+2, true); err != nil {
					return err
				}
			case []any, []string:
				if isEmptyList(it) {
					b.WriteString(" []\n")
					continue
				}
				b.WriteString("\n")
				if err := write(b, it, indent+2, false); err != nil {
					return err
				}
			default:
				if err := writeValue(b, it, indent); err != nil {
					return err
				}
			}
		}
		return nil
	}
	b.WriteString(pad)
	return writeValue(b, v, indent)
}

func isEmptyMap(v any) bool {
	switch t := v.(type) {
	case Map:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	}
	return false
}

func isEmptyList(v any) bool {
	switch t := v.(type) {
	case []any:
		return len(t) == 0
	case []string:
		return len(t) == 0
	}
	return false
}

// writeValue writes what follows a key's colon or a dash.
func writeValue(b *strings.Builder, v any, indent int) error {
	switch t := v.(type) {
	case Map, map[string]any:
		if isEmptyMap(t) {
			b.WriteString(" {}\n")
			return nil
		}
		b.WriteString("\n")
		return write(b, t, indent+2, false)
	case []any, []string:
		if isEmptyList(t) {
			b.WriteString(" []\n")
			return nil
		}
		b.WriteString("\n")
		return write(b, t, indent+2, false)
	case string:
		if strings.Contains(t, "\n") && strings.TrimSpace(t) != "" && literalSafe(t) {
			chomp := "-"
			body := t
			if strings.HasSuffix(t, "\n") {
				chomp = ""
				body = strings.TrimSuffix(t, "\n")
				if strings.HasSuffix(body, "\n") {
					chomp = "+"
					body = t
				}
			}
			ind := strings.Repeat(" ", indent+2)
			b.WriteString(" |" + chomp + "\n")
			lines := strings.Split(body, "\n")
			if chomp == "+" {
				lines = lines[:len(lines)-1]
			}
			for _, l := range lines {
				if l == "" {
					b.WriteString("\n")
				} else {
					b.WriteString(ind + l + "\n")
				}
			}
			return nil
		}
		b.WriteString(" " + scalarText(t) + "\n")
	case nil:
		b.WriteString(" null\n")
	case bool:
		b.WriteString(" " + strconv.FormatBool(t) + "\n")
	case int:
		b.WriteString(" " + strconv.Itoa(t) + "\n")
	case int64:
		b.WriteString(" " + strconv.FormatInt(t, 10) + "\n")
	case float64:
		if math.IsInf(t, 0) || math.IsNaN(t) {
			return fmt.Errorf("%v has no YAML this writes", t)
		}
		b.WriteString(" " + strconv.FormatFloat(t, 'g', -1, 64) + "\n")
	default:
		return fmt.Errorf("a %T is not written as YAML", v)
	}
	return nil
}

// literalSafe says a multi-line string reads back the same from a literal
// block: no line starts with a space (the block's indentation would take
// it), and nothing a literal block cannot hold.
func literalSafe(s string) bool {
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, " ") || strings.HasPrefix(l, "\t") || strings.ContainsAny(l, "\r\x00") ||
			strings.HasSuffix(l, " ") {
			return false
		}
	}
	return true
}

// scalarText is a string as a plain scalar when it reads back as the same
// string, and double-quoted (JSON's escaping, which YAML reads) otherwise.
func scalarText(s string) string {
	if s != "" && s == strings.TrimSpace(s) && !strings.ContainsAny(s, ":#\n\r\t\"'`{}[],&*!|>%@\\") &&
		!strings.HasPrefix(s, "-") && !strings.HasPrefix(s, "?") {
		if v, ok := plain(s).(string); ok && v == s {
			return s
		}
	}
	return strconv.Quote(s)
}
