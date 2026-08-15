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

// detectContext decides which HTML context the next value lands in.
//
// Deliberately simple: look back at what has already been produced. Inside an
// unclosed tag whose nearest attribute carries a URL, this is a URL context;
// inside a tag at all, an attribute; otherwise text. Not a full HTML parser and
// it does not need to be, because the fallback is the stricter escaping.
func detectContext(tail string) int {
	open := strings.LastIndexByte(tail, '<')
	closed := strings.LastIndexByte(tail, '>')
	if open <= closed {
		return ctxText
	}
	seg := tail[open:]
	if reURLAttr.MatchString(seg) {
		return ctxURL
	}
	return ctxAttr
}

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
			var esc string
			switch detectContext(tailOf(out, 256)) {
			case ctxURL:
				esc = escapeURL(text)
			case ctxAttr:
				esc = html.EscapeString(text)
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

// tailOf returns up to n trailing bytes of what has been rendered.
func tailOf(b *strings.Builder, n int) string {
	s := b.String()
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
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
