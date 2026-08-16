package a11y

import "strings"

// A tag scanner rather than an HTML parser.
//
// The checks in this package need tag names, attributes and the text between an
// opening and closing tag. They do not need a DOM, error recovery, or the
// tree-construction rules that make a real HTML parser large. So this is a
// scanner, and the cost of that choice is stated rather than hidden: it does not
// build a tree, so it cannot answer questions about nesting beyond the simple
// depth counting the table check does.
//
// Keeping it hand-written keeps the binary dependency-free, which for something
// that ships as a scratch image is worth more than the convenience of a
// parser. The risk of hand-rolling is real though — the places people get this
// wrong are quoted attribute values containing `>`, comments containing markup,
// and the raw-text elements — so each of those is handled explicitly below and
// tested.

type tag struct {
	name    string
	attrs   map[string]string
	closing bool
	selfEnd bool
	raw     string
	start   int // byte offset of '<'
	end     int // byte offset just past '>'
}

// scan walks the document and returns every tag in order.
func scan(s string) []tag {
	var out []tag
	i := 0
	n := len(s)

	for i < n {
		lt := strings.IndexByte(s[i:], '<')
		if lt < 0 {
			break
		}
		i += lt

		// Comments, CDATA and doctypes are skipped whole. A `>` inside a comment
		// is not the end of anything, and treating it as one is the classic way
		// a naive scanner starts reporting nonsense.
		if strings.HasPrefix(s[i:], "<!--") {
			if e := strings.Index(s[i+4:], "-->"); e >= 0 {
				i += 4 + e + 3
				continue
			}
			break
		}
		if strings.HasPrefix(s[i:], "<!") || strings.HasPrefix(s[i:], "<?") {
			if e := strings.IndexByte(s[i:], '>'); e >= 0 {
				i += e + 1
				continue
			}
			break
		}

		t, next, ok := scanTag(s, i)
		if !ok {
			i++
			continue
		}
		out = append(out, t)
		i = next

		// script and style hold raw text, so markup inside them is data. Skipping
		// to the matching close stops a `<` in a script being read as a tag.
		if !t.closing && !t.selfEnd && (t.name == "script" || t.name == "style") {
			closer := "</" + t.name
			if e := indexFold(s[i:], closer); e >= 0 {
				i += e
			} else {
				break
			}
		}
	}
	return out
}

// scanTag reads one tag starting at s[i] == '<'.
func scanTag(s string, i int) (tag, int, bool) {
	n := len(s)
	j := i + 1
	if j >= n {
		return tag{}, i, false
	}

	t := tag{attrs: map[string]string{}, start: i}
	if s[j] == '/' {
		t.closing = true
		j++
	}

	nameStart := j
	for j < n && !isSpace(s[j]) && s[j] != '>' && s[j] != '/' {
		j++
	}
	if j == nameStart {
		return tag{}, i, false
	}
	t.name = strings.ToLower(s[nameStart:j])

	// Attributes, tracking quotes so a `>` inside a value does not end the tag.
	for j < n {
		for j < n && isSpace(s[j]) {
			j++
		}
		if j >= n {
			return tag{}, i, false
		}
		if s[j] == '>' {
			j++
			break
		}
		if s[j] == '/' && j+1 < n && s[j+1] == '>' {
			t.selfEnd = true
			j += 2
			break
		}

		attrStart := j
		for j < n && !isSpace(s[j]) && s[j] != '=' && s[j] != '>' && s[j] != '/' {
			j++
		}
		name := strings.ToLower(s[attrStart:j])
		if name == "" {
			j++
			continue
		}

		for j < n && isSpace(s[j]) {
			j++
		}
		value := ""
		if j < n && s[j] == '=' {
			j++
			for j < n && isSpace(s[j]) {
				j++
			}
			if j < n && (s[j] == '"' || s[j] == '\'') {
				q := s[j]
				j++
				vs := j
				for j < n && s[j] != q {
					j++
				}
				value = s[vs:j]
				if j < n {
					j++
				}
			} else {
				vs := j
				for j < n && !isSpace(s[j]) && s[j] != '>' {
					j++
				}
				value = s[vs:j]
			}
		}
		// A bare attribute (autoplay, muted) is present with an empty value, and
		// the checks distinguish present-and-empty from absent, so this matters.
		t.attrs[name] = value
	}

	t.end = j
	t.raw = trimTo(s[i:min(j, n)], 120)
	return t, j, true
}

// textUntilClose returns the source between tag index `from` and its matching
// close, counting nesting so an inner element of the same name does not end it
// early.
func textUntilClose(tags []tag, s string, from int, name string) string {
	if from >= len(tags) {
		return ""
	}
	depth := 0
	start := tags[from].end
	for k := from; k < len(tags); k++ {
		t := tags[k]
		if t.name != name {
			continue
		}
		if !t.closing && !t.selfEnd {
			depth++
			continue
		}
		if t.closing {
			depth--
			if depth == 0 {
				if t.start >= start && t.start <= len(s) {
					return s[start:t.start]
				}
				return ""
			}
		}
	}
	// Unclosed: take what is left rather than nothing, because an unclosed
	// anchor still has text a reader will hear.
	if start <= len(s) {
		return s[start:]
	}
	return ""
}

// stripTags removes markup, leaving the text a reader would hear.
func stripTags(s string) string {
	var b strings.Builder
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '<':
			depth++
		case '>':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				b.WriteByte(s[i])
			}
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

func indexFold(s, sub string) int {
	return strings.Index(strings.ToLower(s), strings.ToLower(sub))
}

func trimTo(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
