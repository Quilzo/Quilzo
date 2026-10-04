// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package xmldsig

import (
	"bytes"
	"sort"
	"strings"
)

// Exclusive XML canonicalisation, without comments
// (https://www.w3.org/TR/xml-exc-c14n/), over this package's own tree.
//
// Canonicalisation turns a subtree into the exact bytes a signature covers.
// It is the step Fragile Lock's void canonicalisation broke: libxml2 failed
// on a relative namespace, the binding returned an empty string, and the
// digest of an empty string was compared and accepted. Here there is no
// failure path that produces output. The reader refuses what this cannot
// render, and Canonical returns bytes or an error, never empty bytes.
//
// The rules, for an element E in the output:
//
//   - A namespace declaration is written on E when E or one of its
//     attributes uses the prefix ("visibly utilises" it), or when the
//     prefix is in the InclusiveNamespaces PrefixList and in scope; and the
//     nearest ancestor in the output did not already write the same binding.
//   - An unprefixed E with no default namespace writes xmlns="" only if an
//     output ancestor wrote a non-empty default.
//   - Declarations are sorted by prefix, the default first. Attributes are
//     sorted by namespace URI then local name, unqualified ones first.
//   - Text escapes & < > and \r. Attribute values escape & < " \t \n \r.
//   - An empty element is written as a start tag and an end tag.

// Canonical is the exclusive canonical form of e's subtree, leaving out
// skip and everything inside it (the enveloped-signature transform), with
// inclusive naming the PrefixList ("#default" for the default namespace).
func Canonical(e *Element, inclusive []string, skip *Element) ([]byte, error) {
	if e == nil {
		return nil, refuse("nothing to canonicalise")
	}
	if e == skip {
		return nil, refuse("the signature would remove the element it signs")
	}
	incl := map[string]bool{}
	for _, p := range inclusive {
		if p == "#default" {
			incl[""] = true
		} else {
			incl[p] = true
		}
	}
	var b bytes.Buffer
	c := &canon{b: &b, inclusive: incl, skip: skip}
	c.element(e, map[string]string{})
	if b.Len() == 0 {
		// Unreachable: an element always renders a start tag. Said anyway,
		// because this is the line that was missing in Fragile Lock.
		return nil, refuse("canonicalisation produced nothing")
	}
	return b.Bytes(), nil
}

type canon struct {
	b         *bytes.Buffer
	inclusive map[string]bool
	skip      *Element
}

// element writes e. rendered holds the bindings output ancestors wrote.
func (c *canon) element(e *Element, rendered map[string]string) {
	used := map[string]bool{e.Prefix: true}
	for _, a := range e.Attrs {
		if a.Prefix != "" && a.Prefix != "xml" {
			used[a.Prefix] = true
		}
	}
	for p := range c.inclusive {
		used[p] = true
	}
	prefixes := make([]string, 0, len(used))
	for p := range used {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)

	var decls []Decl
	mine := rendered
	write := func(p, uri string) {
		if len(decls) == 0 {
			mine = make(map[string]string, len(rendered)+2)
			for k, v := range rendered {
				mine[k] = v
			}
		}
		decls = append(decls, Decl{Prefix: p, URI: uri})
		mine[p] = uri
	}
	for _, p := range prefixes {
		uri, in := e.scope[p]
		visibly := p == e.Prefix || (p != "" && hasAttrPrefix(e, p))
		if p == "" {
			if !in || uri == "" {
				// No default namespace here. Say so only if an output
				// ancestor said otherwise, and only when it matters to E.
				if prev, ok := rendered[""]; ok && prev != "" && visibly {
					write("", "")
				}
				continue
			}
		}
		if !in {
			continue // an inclusive prefix that is not declared here
		}
		if prev, ok := rendered[p]; ok && prev == uri {
			continue
		}
		write(p, uri)
	}

	c.b.WriteByte('<')
	c.b.WriteString(e.name())
	for _, d := range decls {
		if d.Prefix == "" {
			c.b.WriteString(` xmlns="`)
		} else {
			c.b.WriteString(` xmlns:`)
			c.b.WriteString(d.Prefix)
			c.b.WriteString(`="`)
		}
		escapeAttr(c.b, d.URI)
		c.b.WriteByte('"')
	}
	attrs := append([]Attr(nil), e.Attrs...)
	sort.SliceStable(attrs, func(i, j int) bool {
		if attrs[i].Space != attrs[j].Space {
			return attrs[i].Space < attrs[j].Space
		}
		return attrs[i].Local < attrs[j].Local
	})
	for _, a := range attrs {
		c.b.WriteByte(' ')
		c.b.WriteString(joinName(a.Prefix, a.Local))
		c.b.WriteString(`="`)
		escapeAttr(c.b, a.Value)
		c.b.WriteByte('"')
	}
	c.b.WriteByte('>')
	for _, n := range e.Children {
		if n.Elem != nil {
			if n.Elem != c.skip {
				c.element(n.Elem, mine)
			}
			continue
		}
		escapeText(c.b, n.Text)
	}
	c.b.WriteString("</")
	c.b.WriteString(e.name())
	c.b.WriteByte('>')
}

func hasAttrPrefix(e *Element, p string) bool {
	for _, a := range e.Attrs {
		if a.Prefix == p {
			return true
		}
	}
	return false
}

var textEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\r", "&#xD;")

var attrEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", `"`, "&quot;",
	"\t", "&#x9;", "\n", "&#xA;", "\r", "&#xD;")

func escapeText(b *bytes.Buffer, s string) { _, _ = textEscaper.WriteString(b, s) }

func escapeAttr(b *bytes.Buffer, s string) { _, _ = attrEscaper.WriteString(b, s) }
