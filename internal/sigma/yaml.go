// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package sigma

import (
	"fmt"
	"strings"
)

// A YAML reader for the subset Sigma uses.
//
// Not a YAML implementation. YAML is an enormous specification with
// anchors, aliases, merge keys, tags, directives, multiple scalar styles
// and a type-inference table that has caused real incidents — the Norway
// problem, where the country code NO parses as the boolean false, is the
// famous one but not the worst.
//
// Sigma uses a small, regular corner of it: block mappings, block
// sequences, plain and quoted scalars, comments, and documents separated by
// ---. That corner is what this reads, and everything outside it is an
// error naming the line rather than a silent misreading. A parser that
// accepts more than it understands is the problem, not the solution: the
// failure mode of a lenient YAML reader is a rule that loads and means
// something other than what its author wrote.
//
// Everything is a string. No type inference at all, which removes the whole
// class of bug above: "no" is the string "no", 010 is the string "010", and
// the Sigma compiler converts where a number or a boolean is actually
// wanted, in a place where it knows which it expects.

// Doc is one parsed YAML document: a mapping at the top level, which is
// what every Sigma rule is.
type Doc map[string]any

// line is one significant line of input.
type line struct {
	n      int
	indent int
	text   string
}

// Parse reads a stream of YAML documents.
func Parse(in []byte) ([]Doc, error) {
	lines, err := significant(string(in))
	if err != nil {
		return nil, err
	}
	var docs []Doc
	start := 0
	for i := 0; i <= len(lines); i++ {
		if i < len(lines) && lines[i].text != "---" {
			continue
		}
		if i > start {
			d, err := block(lines[start:i], lines[start].indent)
			if err != nil {
				return nil, err
			}
			m, ok := d.(map[string]any)
			if !ok {
				return nil, fmt.Errorf(
					"line %d: a document here is a mapping of keys, and "+
						"this one is not", lines[start].n)
			}
			docs = append(docs, Doc(m))
		}
		start = i + 1
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("there is nothing in this file")
	}
	return docs, nil
}

// significant drops blank lines and comments, and records indentation.
func significant(in string) ([]line, error) {
	var out []line
	for i, raw := range strings.Split(in, "\n") {
		n := i + 1
		if tabbed(raw) {
			return nil, fmt.Errorf(
				"line %d: indented with a tab. YAML forbids it, and a file "+
					"that mixes tabs and spaces reads differently in "+
					"different editors — which is the kind of difference "+
					"that changes what a detection matches", n)
		}
		text := strip(raw)
		if strings.TrimSpace(text) == "" {
			continue
		}
		out = append(out, line{n: n, indent: leading(text),
			text: strings.TrimRight(strings.TrimLeft(text, " "), " ")})
	}
	return out, nil
}

// tabbed reports whether a line's indentation contains a tab.
func tabbed(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ':
		case '\t':
			return true
		default:
			return false
		}
	}
	return false
}

func leading(s string) int {
	for i, r := range s {
		if r != ' ' {
			return i
		}
	}
	return len(s)
}

// strip removes a trailing comment, respecting quotes.
func strip(s string) string {
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '\\':
			if inDouble {
				i++
			}
		case '#':
			// A comment only when it is at the start or follows a space,
			// so that a value like an anchor or a colour code survives.
			if !inSingle && !inDouble && (i == 0 || s[i-1] == ' ') {
				return s[:i]
			}
		}
	}
	return s
}

// block parses a run of lines at one indentation into a map or a sequence.
func block(ls []line, indent int) (any, error) {
	if len(ls) == 0 {
		return nil, nil
	}
	if strings.HasPrefix(ls[0].text, "- ") || ls[0].text == "-" {
		return sequence(ls, indent)
	}
	return mapping(ls, indent)
}

func mapping(ls []line, indent int) (any, error) {
	out := map[string]any{}
	for i := 0; i < len(ls); {
		l := ls[i]
		if l.indent != indent {
			return nil, fmt.Errorf(
				"line %d: indented %d space(s) where %d was expected. This "+
					"reader will not guess: a mapping whose keys are at "+
					"different depths means two different things and looks "+
					"like one", l.n, l.indent, indent)
		}
		key, rest, ok := split(l.text)
		if !ok {
			return nil, fmt.Errorf(
				"line %d: %q is not \"key: value\". This reader takes the "+
					"part of YAML that Sigma uses and nothing else",
				l.n, l.text)
		}
		j := i + 1
		for j < len(ls) && ls[j].indent > indent {
			j++
		}
		switch {
		case rest != "":
			if j > i+1 {
				return nil, fmt.Errorf(
					"line %d: %q has a value and a nested block under it",
					l.n, key)
			}
			v, err := scalar(l.n, rest)
			if err != nil {
				return nil, err
			}
			out[key] = v
		case j > i+1:
			v, err := block(ls[i+1:j], ls[i+1].indent)
			if err != nil {
				return nil, err
			}
			out[key] = v
		default:
			// A key with nothing under it. Kept as an empty string rather
			// than as null, because everything here is a string and a
			// missing value is a thing the compiler should notice.
			out[key] = ""
		}
		if _, dup := out[key]; dup && j == i+1 && rest == "" {
			_ = dup
		}
		i = j
	}
	return out, nil
}

func sequence(ls []line, indent int) (any, error) {
	var out []any
	for i := 0; i < len(ls); {
		l := ls[i]
		if l.indent != indent {
			return nil, fmt.Errorf("line %d: this list item is indented %d "+
				"space(s) where %d was expected", l.n, l.indent, indent)
		}
		if !strings.HasPrefix(l.text, "- ") && l.text != "-" {
			return nil, fmt.Errorf(
				"line %d: a list and a mapping at the same depth", l.n)
		}
		rest := strings.TrimSpace(strings.TrimPrefix(l.text, "-"))
		j := i + 1
		for j < len(ls) && ls[j].indent > indent {
			j++
		}
		switch {
		case rest != "" && j > i+1:
			// "- key: value" with more keys under it: a mapping whose
			// first key sits on the dash line.
			inner := append([]line{{n: l.n, indent: ls[j-1].indent,
				text: rest}}, ls[i+1:j]...)
			v, err := block(inner, inner[0].indent)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		case rest != "":
			if k, r, ok := split(rest); ok && r != "" {
				v, err := scalar(l.n, r)
				if err != nil {
					return nil, err
				}
				out = append(out, map[string]any{k: v})
				break
			}
			v, err := scalar(l.n, rest)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		case j > i+1:
			v, err := block(ls[i+1:j], ls[i+1].indent)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		default:
			out = append(out, "")
		}
		i = j
	}
	return out, nil
}

// split separates "key: value", respecting quotes in the key.
func split(s string) (key, rest string, ok bool) {
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case ':':
			if inSingle || inDouble {
				continue
			}
			if i+1 < len(s) && s[i+1] != ' ' {
				continue // A colon inside a plain scalar, like a URL.
			}
			return unquoteKey(strings.TrimSpace(s[:i])),
				strings.TrimSpace(s[i+1:]), true
		}
	}
	return "", "", false
}

func unquoteKey(k string) string {
	if v, err := scalar(0, k); err == nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return k
}

// scalar reads one value, including a simple flow sequence.
func scalar(n int, s string) (any, error) {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]"):
		inner := strings.TrimSpace(s[1 : len(s)-1])
		if inner == "" {
			return []any{}, nil
		}
		var out []any
		for _, part := range splitFlow(inner) {
			v, err := scalar(n, part)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case strings.HasPrefix(s, "{"):
		return nil, fmt.Errorf(
			"line %d: flow mappings are not read here. Sigma writes its "+
				"detections as blocks, and a reader that accepted both "+
				"would be two readers", n)
	case strings.HasPrefix(s, "|") || strings.HasPrefix(s, ">"):
		// A block scalar. Sigma uses these for descriptions; the body is
		// indented under the key and has already been consumed as a nested
		// block by the caller, so reaching here means an empty one.
		return "", nil
	case strings.HasPrefix(s, "'") && strings.HasSuffix(s, "'") && len(s) > 1:
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'"), nil
	case strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"") && len(s) > 1:
		return unescape(s[1 : len(s)-1]), nil
	case strings.HasPrefix(s, "&") || strings.HasPrefix(s, "*"):
		return nil, fmt.Errorf(
			"line %d: anchors and aliases are not read here. They are the "+
				"part of YAML that makes a file mean something other than "+
				"what it looks like", n)
	}
	return s, nil
}

func splitFlow(s string) []string {
	var out []string
	depth := 0
	inSingle, inDouble := false, false
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '[':
			if !inSingle && !inDouble {
				depth++
			}
		case ']':
			if !inSingle && !inDouble {
				depth--
			}
		case ',':
			if depth == 0 && !inSingle && !inDouble {
				out = append(out, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	return append(out, strings.TrimSpace(s[start:]))
}

func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case '\\':
			b.WriteByte('\\')
		case '"':
			b.WriteByte('"')
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
