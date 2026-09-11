// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package tmpl renders templates that cannot execute anything.
//
// Server-side template injection is a whole vulnerability class, and it exists
// because the popular template languages are programming languages. Give one an
// attacker-influenced string and it reaches a constructor, a type hierarchy, a
// filesystem, a subprocess. Every mitigation is a fence around something that
// was never meant to be safe.
//
// This is not a programming language. There are no author-defined functions, no
// arithmetic, no assignment, no imports, no field access on Go values, no method
// calls and no recursion. Four constructs, and no way to add a fifth:
//
//	{{ page.title }}                  a value, escaped for its context
//	{% if page.subtitle %}…{% end %}  present and truthy
//	{% for item in nav %}…{% end %}   bounded iteration
//	{% raw page.body_html %}          deliberately unescaped, and auditable
//
// There is nothing to escape *from*, because there is nothing underneath:
// values come out of decoded JSON and the only operations are lookup, truthiness
// and iteration. Go's text/template would have been the obvious choice and is
// the wrong one here — it calls methods, which is exactly the capability this
// needs not to have.
//
// # Escaping is not optional
//
// {{ }} always escapes, and it escapes for where the value lands. The usual
// failure is escaping for HTML and then being used inside href, where
// javascript: is valid HTML and perfectly dangerous. The renderer tracks which
// context it is in and picks.
//
// {% raw %} exists because real sites have rich text, and pretending otherwise
// pushes people to disable escaping globally. It is a distinct keyword rather
// than a filter, so every place trust was extended can be listed and reviewed.
//
// # Bounded on purpose
//
// Loops iterate over data, never a condition, and depth, output size and total
// iterations are capped. Rendering terminates for every input. That is a
// property, not a hope.
package tmpl

import (
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const (
	MaxDepth      = 12
	MaxOutput     = 4 << 20 // 4 MiB of rendered page is already absurd
	MaxIterations = 50_000
)

// Contexts a value can land in.
const (
	ctxText = iota
	ctxAttr
	ctxURL
	ctxBare // an unquoted attribute value, or where a name would go
)

var (
	// A path is dotted names and integer indices. No calls, no operators. Names
	// starting with an underscore are refused so Go-side or JSON-side private
	// conventions stay unreachable.
	rePath = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9][A-Za-z0-9_]*)*$`)
	reTag  = regexp.MustCompile(`(?s)\{\{(.*?)\}\}|\{%(.*?)%\}`)
	// Whether the text so far leaves us inside a URL-bearing attribute.
	reURLAttr = regexp.MustCompile(`(?i)\b(href|src|action|formaction|xlink:href)\s*=\s*["']?[^"']*$`)
)

// Schemes permitted in a URL context. javascript: and data: are the two that
// turn an escaped-looking value into script execution.
var safeSchemes = map[string]bool{"http": true, "https": true, "mailto": true, "tel": true, "": true}

// Error is a template that is malformed or asks for something the language lacks.
type Error struct{ msg string }

func (e *Error) Error() string { return e.msg }

func errf(format string, a ...any) *Error { return &Error{msg: fmt.Sprintf(format, a...)} }

type nodeKind int

const (
	nLiteral nodeKind = iota
	nValue
	nRaw
	nIf
	nFor
)

type node struct {
	kind     nodeKind
	text     string
	path     string
	loopVar  string
	children []node
	// pipe is the filter chain applied to the value before it is escaped.
	// Empty for everything but nValue and nRaw.
	pipe []pipeStep
}

// Parse turns template text into nodes. An unknown tag is an error, not output.
func Parse(src string) ([]node, error) {
	var root []node
	// stack holds pointers into the tree being built. Appending to a slice can
	// reallocate, so children are collected in a side list and attached on close
	// rather than held by pointer across appends.
	type frame struct {
		n        node
		children []node
	}
	var stack []frame
	pos := 0

	emit := func(n node) {
		if len(stack) == 0 {
			root = append(root, n)
			return
		}
		stack[len(stack)-1].children = append(stack[len(stack)-1].children, n)
	}

	for _, m := range reTag.FindAllStringSubmatchIndex(src, -1) {
		if m[0] > pos {
			emit(node{kind: nLiteral, text: src[pos:m[0]]})
		}
		pos = m[1]

		if m[2] >= 0 { // {{ … }}
			path, pipe, perr := parseExpr(src[m[2]:m[3]])
			if perr != nil {
				return nil, perr
			}
			emit(node{kind: nValue, path: path, pipe: pipe})
			continue
		}

		stmt := strings.TrimSpace(src[m[4]:m[5]])
		head, rest, _ := strings.Cut(stmt, " ")
		head, rest = strings.TrimSpace(head), strings.TrimSpace(rest)

		switch head {
		case "if":
			stack = append(stack, frame{n: node{kind: nIf, path: rest}})
		case "for":
			v, srcPath, ok := strings.Cut(rest, " in ")
			v, srcPath = strings.TrimSpace(v), strings.TrimSpace(srcPath)
			if !ok || !rePath.MatchString(v) || strings.Contains(v, ".") {
				return nil, errf("%q is not a usable loop variable", v)
			}
			stack = append(stack, frame{n: node{kind: nFor, loopVar: v, path: srcPath}})
		case "raw":
			path, pipe, perr := parseExpr(rest)
			if perr != nil {
				return nil, perr
			}
			emit(node{kind: nRaw, path: path, pipe: pipe})
		case "end":
			if len(stack) == 0 {
				return nil, errf("{%% end %%} with nothing open")
			}
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			top.n.children = top.children
			emit(top.n)
		default:
			return nil, errf(
				"unknown tag %q. This language has if, for, end and raw, and "+
					"nothing else — there is no way to add one", head)
		}
		if len(stack) > MaxDepth {
			return nil, errf("nested deeper than %d", MaxDepth)
		}
	}

	if pos < len(src) {
		emit(node{kind: nLiteral, text: src[pos:]})
	}
	if len(stack) > 0 {
		return nil, errf("%d block(s) left open", len(stack))
	}
	return root, nil
}

// lookup walks a dotted path through decoded JSON. It never touches a Go field.
func lookup(data map[string]any, path string) (any, error) {
	if !rePath.MatchString(path) {
		return nil, errf(
			"%q is not a value path. Names and dots only — there are no calls, "+
				"operators or attributes in this language", path)
	}
	var current any = data
	for _, part := range strings.Split(path, ".") {
		switch v := current.(type) {
		case map[string]any:
			current = v[part]
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(v) {
				return nil, nil
			}
			current = v[i]
		default:
			// Anything else is a miss rather than an error, so a page renders
			// with a gap instead of failing over one field.
			return nil, nil
		}
		if current == nil {
			return nil, nil
		}
	}
	return current, nil
}

// htmlContext follows the markup as it is produced, so a value is escaped for
// the place it actually lands in.
//
// It replaces a 256-byte lookback, and that window was a vulnerability rather
// than an approximation. Pad the output past it with one attacker-controlled
// field and the next one is judged to be in text — where quotes are not
// escaped, because in text they are not special — while it is really inside an
// attribute. A value then closed the attribute and opened an event handler:
//
//	<img src="/media/{{ image }}" alt="{{ alt }}">
//	                                    ^ alt="" onerror="..." with a long image
//
// The old comment said the fallback was "the stricter escaping". It was the
// weaker one: ctxText leaves quotes alone and ctxAttr does not. The window is
// removed rather than widened, because a longer guess is still a guess.
//
// Every byte of output is examined once, so this costs one pass rather than a
// rescan per value. It reads the output and not the template, which is what
// makes {% raw %} — the one thing that can still introduce markup — land in
// the right place too.
type htmlContext struct {
	scanned   int    // how much of the output has been consumed
	inTag     bool   // between < and its >
	tagStart  int    // where that < was
	quote     byte   // the attribute quote we are inside, or 0
	inComment bool   // between <!-- and -->
	rawElem   string // "script" or "style" when inside one
}

// advance consumes whatever has been appended since the last call.
func (c *htmlContext) advance(s string) {
	for i := c.scanned; i < len(s); i++ {
		ch := s[i]
		switch {
		case c.inComment:
			// Nothing inside a comment is markup, and in particular an
			// apostrophe in one is an apostrophe. Without this case the
			// tracker read "the record's name" in a shipped template as an
			// opening attribute quote and never found its close, so every
			// value after it in the document was escaped as though it sat in
			// an attribute. Caught by rendering every shipped template before
			// and after and diffing, which is the only reason it is not in
			// this commit.
			if ch == '>' && i >= 2 && s[i-1] == '-' && s[i-2] == '-' {
				c.inComment = false
			}
		case c.rawElem != "":
			// Only the matching end tag leaves a raw text element. A < inside
			// <script> is data, not markup, which is why this is separate.
			if ch == '<' && i+1 < len(s) && s[i+1] == '/' &&
				foldPrefix(s[i+2:], c.rawElem) {
				c.rawElem, c.inTag, c.tagStart, c.quote = "", true, i, 0
			}
		case c.inTag:
			if c.quote != 0 {
				if ch == c.quote {
					c.quote = 0
				}
				continue
			}
			switch ch {
			case '"', '\'':
				c.quote = ch
			case '>':
				// A quoted > is attribute data. Tracking quotes is why this
				// finds the end of the tag where scanning back for the last >
				// found a character inside a title or an alt.
				c.inTag = false
				if n := openTagName(s, c.tagStart); n == "script" || n == "style" {
					c.rawElem = n
				}
				c.tagStart = -1
			}
		case ch == '<':
			if strings.HasPrefix(s[i:], "<!--") {
				c.inComment = true
				continue
			}
			c.inTag, c.tagStart, c.quote = true, i, 0
		}
	}
	c.scanned = len(s)
}

// context reports where the next value would land, or refuses.
func (c *htmlContext) context(s string) (int, error) {
	c.advance(s)
	if c.rawElem != "" {
		// Escaping cannot make a value safe here. Inside <script> and <style>
		// the HTML entities that escaping produces are not decoded, so &#34;
		// arrives at the parser as six characters rather than as a quote: the
		// escaping is inert and the quote still ends the string. Refusing is
		// the only correct answer, and this program does not need the case —
		// no template it ships interpolates into either element.
		return 0, errf("a value cannot go inside <%s>: escaping does nothing "+
			"there, because HTML entities are not decoded in it", c.rawElem)
	}
	if !c.inTag {
		return ctxText, nil
	}
	if reURLAttr.MatchString(s[c.tagStart:]) {
		return ctxURL, nil
	}
	if c.quote == 0 {
		// Inside the tag but not inside a quoted value: either an unquoted
		// attribute value or where an attribute name would go. Escaping the
		// quotes is not enough here, because nothing needs a quote to end an
		// unquoted value — a space does. class={{ x }} with "a onmouseover=b"
		// is two attributes, and the second is an event handler.
		return ctxBare, nil
	}
	return ctxAttr, nil
}

// escapeBare escapes for a place where whitespace ends the value.
//
// Everything HTML escaping covers, plus the characters that terminate an
// unquoted attribute or start the next one. HTML5 names space, tab, newline,
// form feed and carriage return as terminators, and = and ` as parse errors
// that browsers have historically been generous about.
func escapeBare(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch r {
		case ' ', '\t', '\n', '\f', '\r', '=', '`', '"', '\'', '<', '>', '&':
			fmt.Fprintf(&b, "&#%d;", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// foldPrefix reports whether s begins with name, ignoring case.
func foldPrefix(s, name string) bool {
	if len(s) < len(name) {
		return false
	}
	return strings.EqualFold(s[:len(name)], name)
}

// openTagName reads the element name at an opening tag, or "" for a close tag.
func openTagName(s string, at int) string {
	if at < 0 || at+1 >= len(s) || s[at+1] == '/' || s[at+1] == '!' {
		return ""
	}
	i := at + 1
	for i < len(s) && (isAlpha(s[i]) || isDigit(s[i])) {
		i++
	}
	return strings.ToLower(s[at+1 : i])
}

func isAlpha(c byte) bool { return c|0x20 >= 'a' && c|0x20 <= 'z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// escapeURL escapes for a URL attribute and refuses a scheme that can execute.
//
// HTML-escaping a URL is not enough: javascript:alert(1) contains nothing that
// needs escaping and runs anyway. An unsafe scheme is replaced rather than
// emitted and hoped about, because hoping the browser declines is not a control.
func escapeURL(v string) string {
	s := strings.TrimSpace(v)
	u, err := url.Parse(s)
	if err != nil {
		return "#unsafe-url"
	}
	if !safeSchemes[strings.ToLower(u.Scheme)] {
		return "#unsafe-url"
	}
	return html.EscapeString(s)
}

func stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case Markup:
		// Reachable when a Markup lands somewhere that is not text, where it
		// is about to be escaped like any other string. Returning the markup
		// is right: what gets escaped is the tags it contains, which is what
		// makes the mistake visible rather than dangerous.
		return string(t)
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	default:
		// A structure rendered into a page is almost always a mistake, and
		// printing its shape would leak it. Render nothing, visible as a gap.
		return ""
	}
}

func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return len(t) > 0
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	case float64:
		return t != 0
	default:
		return true
	}
}

type budget struct {
	output     int
	iterations int
	html       htmlContext
}

func (b *budget) spendOutput(n int) error {
	b.output += n
	if b.output > MaxOutput {
		return errf("rendered past %d characters", MaxOutput)
	}
	return nil
}

func (b *budget) spendIteration() error {
	b.iterations++
	if b.iterations > MaxIterations {
		return errf("iterated past %d times", MaxIterations)
	}
	return nil
}

func walk(nodes []node, data map[string]any, out *strings.Builder, b *budget, depth int) error {
	if depth > MaxDepth {
		return errf("nested deeper than %d", MaxDepth)
	}
	for _, n := range nodes {
		switch n.kind {
		case nLiteral:
			if err := b.spendOutput(len(n.text)); err != nil {
				return err
			}
			out.WriteString(n.text)

		case nValue:
			v, err := lookup(data, n.path)
			if err != nil {
				return err
			}
			// Filters run before escaping, and escaping still happens after —
			// on the result, in the context it lands in. A filter cannot opt
			// out of it, which is the difference between this and a `| safe`
			// at the end of a pipeline in every engine that has one.
			if v, err = applyFilters(v, n.pipe); err != nil {
				return err
			}
			text := stringify(v)
			ctx, err := b.html.context(out.String())
			if err != nil {
				return err
			}
			// Markup is written out as it is, and only where markup belongs.
			//
			// Nothing outside this package can make one: Prose is the only
			// function that returns the type, and it builds its output from a
			// fixed set of tags after escaping everything it was given. So
			// this is not trusting a value, it is knowing what made it.
			//
			// Text context only. A paragraph inside an attribute is not a
			// thing anybody meant, and treating it as markup there would turn
			// a template mistake into an escaping bypass — so it falls through
			// and is escaped for the place it actually landed in, like any
			// other string.
			if m, isMarkup := v.(Markup); isMarkup && ctx == ctxText {
				if err := b.spendOutput(len(m)); err != nil {
					return err
				}
				out.WriteString(string(m))
				continue
			}
			var esc string
			switch ctx {
			case ctxURL:
				esc = escapeURL(text)
			case ctxAttr:
				esc = html.EscapeString(text)
			case ctxBare:
				esc = escapeBare(text)
			default:
				// Quotes left alone in text context; they are not special there.
				esc = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(text)
			}
			if err := b.spendOutput(len(esc)); err != nil {
				return err
			}
			out.WriteString(esc)

		case nRaw:
			v, err := lookup(data, n.path)
			if err != nil {
				return err
			}
			if v, err = applyFilters(v, n.pipe); err != nil {
				return err
			}
			text := stringify(v)
			if err := b.spendOutput(len(text)); err != nil {
				return err
			}
			out.WriteString(text)

		case nIf:
			v, err := lookup(data, n.path)
			if err != nil {
				return err
			}
			if truthy(v) {
				if err := walk(n.children, data, out, b, depth+1); err != nil {
					return err
				}
			}

		case nFor:
			v, err := lookup(data, n.path)
			if err != nil {
				return err
			}
			items, ok := v.([]any)
			if !ok {
				continue
			}
			for _, item := range items {
				if err := b.spendIteration(); err != nil {
					return err
				}
				// A shallow copy per iteration, so a loop variable cannot leak
				// out of its block and templates stay locally reasoned about.
				scope := make(map[string]any, len(data)+1)
				for k, vv := range data {
					scope[k] = vv
				}
				scope[n.loopVar] = item
				if err := walk(n.children, scope, out, b, depth+1); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Render renders a template against decoded JSON data. Terminates for all input.
func Render(src string, data map[string]any) (string, error) {
	nodes, err := Parse(src)
	if err != nil {
		return "", err
	}
	var out strings.Builder
	if err := walk(nodes, data, &out, &budget{}, 0); err != nil {
		return "", err
	}
	return out.String(), nil
}

// RawSites lists every place a template opts out of escaping, so extending trust
// is reviewable in aggregate rather than one file at a time.
func RawSites(src string) []string {
	var out []string
	for _, m := range reTag.FindAllStringSubmatchIndex(src, -1) {
		if m[4] < 0 {
			continue
		}
		stmt := strings.TrimSpace(src[m[4]:m[5]])
		if rest, ok := strings.CutPrefix(stmt, "raw "); ok {
			out = append(out, strings.TrimSpace(rest))
		}
	}
	return out
}
