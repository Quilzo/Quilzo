// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package xmldsig reads signed XML strictly enough that a document cannot
// mean one thing to the code that checks its signature and another to the
// code that reads it.
//
// # Why this package exists, after saying for months that it should not
//
// Every SAML authentication bypass of the last two years has had the same
// shape. Signature wrapping moved the signed element and put an unsigned one
// where the reader looks. The ruby-saml bugs of March 2025 and PortSwigger's
// "Fragile Lock" of December 2025 used two parsers that disagreed: REXML and
// Nokogiri, or libxml2 and the language binding over it. Go's own two SAML
// libraries were broken in 2020 by encoding/xml, which does not give the same
// document back after a parse and a re-serialise, so what was verified and
// what was read were different trees.
//
// The common cause is that there are two readings. This package makes there
// be one, by construction:
//
//   - One reader, written here, for the small part of XML that SAML uses.
//     Not encoding/xml, so nothing ever round-trips through it.
//   - Exclusive canonicalisation over that reader's tree, and signature
//     verification over that canonical form.
//   - Then the canonical bytes that were hashed are read again, and only
//     that second tree is handed back. Canonicalising it must give the same
//     bytes (a fixed point), or the document is refused.
//
// So the caller holds exactly what the signature covered and nothing else.
// An element the attacker added beside the signed one is not in the tree it
// receives; a document with two readings fails the fixed point.
//
// # What the reader refuses
//
// SAML needs elements, attributes, namespaces, text and the five built-in
// entities. Everything else is somewhere a past bypass hid:
//
//	DOCTYPE, entities     XXE, billion laughs, and the ruby-saml DOCTYPE
//	                      differential (CVE-2025-25291)
//	comments              the Duo truncation (CVE-2017-11427): a comment in
//	                      a NameID makes some readers stop at it
//	processing            node-saml (CVE-2025-54419): a canonicaliser that
//	instructions          treated a PI differently from the standard
//	CDATA                 a second way to write text is a second reading
//	two attributes with   Fragile Lock's attribute pollution: ID and
//	one local name        samlp:ID, and parsers that pick different ones
//	a rebound xml: or     Fragile Lock's namespace confusion
//	xmlns: prefix
//	a relative namespace  Fragile Lock's void canonicalisation: the
//	                      canonicaliser failed, returned nothing, and the
//	                      digest of nothing was accepted
//	an undeclared prefix  not well formed, and a reader that guesses is a
//	                      reader that can be told what to guess
//	non-ASCII names       SAML has none, and lookalike letters are a way to
//	                      make two names that print the same
//
// And limits on size, depth, element count and attributes per element, so
// a document cannot be made expensive to refuse.
package xmldsig

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Limits on what is read. A SAML response from any real identity provider
// is a few kilobytes and a dozen levels deep.
const (
	MaxDocument   = 256 << 10
	MaxDepth      = 64
	MaxElements   = 10000
	MaxAttributes = 64
	// MaxDeclarations bounds namespace declarations in the whole document.
	// A real response has under twenty. Without a bound, scopes copied from
	// element to element made a 256 KB document cost thirty seconds of CPU
	// to refuse: found by fuzzing, before any of this was reachable.
	MaxDeclarations = 128
	maxName         = 256
)

// Namespaces with fixed meanings.
const (
	nsXML   = "http://www.w3.org/XML/1998/namespace"
	nsXMLNS = "http://www.w3.org/2000/xmlns/"
)

// ErrRefused wraps every refusal, so a caller can tell "this document is not
// acceptable" from a failure of its own.
var ErrRefused = errors.New("refused")

func refuse(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, args...))
}

// Element is an element as read: its name as written and as resolved, its
// attributes and namespace declarations in document order, and its content.
type Element struct {
	Prefix, Local, Space string
	Attrs                []Attr
	// Decls are the namespace declarations written on this element.
	Decls    []Decl
	Children []Node
	Parent   *Element

	// scope is every namespace in scope here, this element's own
	// declarations included. Shared with the parent when it declares none.
	scope map[string]string
}

// Node is one piece of an element's content: an element or text, never both.
type Node struct {
	Elem *Element
	Text string
}

// Attr is an attribute, not a namespace declaration.
type Attr struct {
	Prefix, Local, Space, Value string
}

// Decl is a namespace declaration. Prefix "" is the default namespace.
type Decl struct {
	Prefix, URI string
}

// Document is what Read returns.
type Document struct {
	Root *Element
	// ids maps each ID, Id or id attribute value to its element.
	ids map[string]*Element
}

// ByID is the element carrying an ID, Id or id attribute with this value.
func (d *Document) ByID(id string) *Element { return d.ids[id] }

// Attr is the value of the unprefixed attribute with this local name.
func (e *Element) Attr(local string) (string, bool) {
	for _, a := range e.Attrs {
		if a.Prefix == "" && a.Local == local {
			return a.Value, true
		}
	}
	return "", false
}

// Is reports whether the element has this namespace and local name.
func (e *Element) Is(space, local string) bool {
	return e.Space == space && e.Local == local
}

// Elements are the child elements. Mixed is true when non-whitespace text
// sits among them, which no element SAML defines with children allows.
func (e *Element) Elements() (out []*Element, mixed bool) {
	for _, c := range e.Children {
		if c.Elem != nil {
			out = append(out, c.Elem)
		} else if strings.TrimLeft(c.Text, " \t\n\r") != "" {
			mixed = true
		}
	}
	return out, mixed
}

// Text is the element's text. An element with child elements has none: a
// value that is partly markup is refused rather than flattened, because
// flattening is where two readers disagree about where a value ends.
func (e *Element) Text() (string, error) {
	var b strings.Builder
	for _, c := range e.Children {
		if c.Elem != nil {
			return "", refuse("<%s> holds an element where text was expected", e.name())
		}
		b.WriteString(c.Text)
	}
	return b.String(), nil
}

func (e *Element) name() string {
	if e.Prefix == "" {
		return e.Local
	}
	return e.Prefix + ":" + e.Local
}

// InScope is the namespace bound to a prefix here ("" for the default).
func (e *Element) InScope(prefix string) (string, bool) {
	v, ok := e.scope[prefix]
	return v, ok
}

// Read parses a document, refusing anything outside the subset above.
func Read(b []byte) (*Document, error) {
	if len(b) > MaxDocument {
		return nil, refuse("the document is %d bytes; the limit is %d", len(b), MaxDocument)
	}
	if !utf8.Valid(b) {
		return nil, refuse("the document is not valid UTF-8")
	}
	// Line ends are normalised before anything else, as XML 1.0 section
	// 2.11 requires: a \r survives only as the reference &#xD;.
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.TrimPrefix(s, "\ufeff")

	r := &reader{s: s, ids: map[string]*Element{}}
	if err := r.declaration(); err != nil {
		return nil, err
	}
	r.space()
	switch rest := r.s[r.i:]; {
	case strings.HasPrefix(rest, "<!--"):
		return nil, refuse("the document contains a comment")
	case strings.HasPrefix(rest, "<!"):
		return nil, refuse("the document contains a DOCTYPE or other declaration; " +
			"entities are how XML documents reach files and memory they should not")
	case strings.HasPrefix(rest, "<?"):
		return nil, refuse("the document contains a processing instruction")
	case !strings.HasPrefix(rest, "<"):
		return nil, refuse("no root element")
	}
	root, err := r.element(nil, 1)
	if err != nil {
		return nil, err
	}
	r.space()
	if r.i != len(r.s) {
		return nil, refuse("something follows the root element")
	}
	return &Document{Root: root, ids: r.ids}, nil
}

type reader struct {
	s        string
	i        int
	elements int
	decls    int
	ids      map[string]*Element
}

func (r *reader) space() {
	for r.i < len(r.s) && isSpace(r.s[r.i]) {
		r.i++
	}
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// declaration reads an optional <?xml ...?> at the very start. Version 1.0
// and UTF-8 only: a document claiming another encoding was decoded as
// UTF-8 already, and saying otherwise is a second reading.
func (r *reader) declaration() error {
	if !strings.HasPrefix(r.s, "<?xml") || len(r.s) < 6 || !isSpace(r.s[5]) {
		return nil
	}
	end := strings.Index(r.s, "?>")
	if end < 0 {
		return refuse("the XML declaration is not closed")
	}
	body := r.s[5:end]
	r.i = end + 2
	sawVersion := false
	for _, f := range strings.Fields(body) {
		k, v, ok := strings.Cut(f, "=")
		if !ok || len(v) < 2 || (v[0] != '"' && v[0] != '\'') || v[len(v)-1] != v[0] {
			return refuse("the XML declaration is malformed")
		}
		v = v[1 : len(v)-1]
		switch k {
		case "version":
			if v != "1.0" {
				return refuse("XML version %q; only 1.0 is read", v)
			}
			sawVersion = true
		case "encoding":
			if !strings.EqualFold(v, "UTF-8") {
				return refuse("the document says it is %q; only UTF-8 is read", v)
			}
		case "standalone":
			if v != "yes" && v != "no" {
				return refuse("the XML declaration is malformed")
			}
		default:
			return refuse("the XML declaration is malformed")
		}
	}
	if !sawVersion {
		return refuse("the XML declaration has no version")
	}
	return nil
}

// qname reads Prefix:Local or Local, ASCII names only.
func (r *reader) qname() (prefix, local string, err error) {
	start := r.i
	for r.i < len(r.s) && isNameByte(r.s[r.i]) {
		r.i++
	}
	n := r.s[start:r.i]
	if n == "" {
		if r.i < len(r.s) && r.s[r.i] >= 0x80 {
			return "", "", refuse("a name uses a character outside ASCII")
		}
		return "", "", refuse("a name was expected at offset %d", start)
	}
	if len(n) > maxName {
		return "", "", refuse("a name is longer than %d characters", maxName)
	}
	if r.i < len(r.s) && r.s[r.i] >= 0x80 {
		return "", "", refuse("a name uses a character outside ASCII")
	}
	p, l, has := strings.Cut(n, ":")
	if !has {
		p, l = "", n
	}
	if (has && !isNCName(p)) || !isNCName(l) {
		return "", "", refuse("%q is not a name", n)
	}
	return p, l, nil
}

func isNameByte(c byte) bool {
	return c == ':' || c == '_' || c == '-' || c == '.' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func isNCName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		case i > 0 && (c == '-' || c == '.' || (c >= '0' && c <= '9')):
		default:
			return false
		}
	}
	return true
}

type rawAttr struct{ prefix, local, value string }

func (r *reader) element(parent *Element, depth int) (*Element, error) {
	if depth > MaxDepth {
		return nil, refuse("elements are nested more than %d deep", MaxDepth)
	}
	r.elements++
	if r.elements > MaxElements {
		return nil, refuse("more than %d elements", MaxElements)
	}
	r.i++ // '<'
	prefix, local, err := r.qname()
	if err != nil {
		return nil, err
	}
	var raw []rawAttr
	empty := false
	for {
		hadSpace := r.i < len(r.s) && isSpace(r.s[r.i])
		r.space()
		if r.i >= len(r.s) {
			return nil, refuse("<%s> is not closed", local)
		}
		if r.s[r.i] == '>' {
			r.i++
			break
		}
		if strings.HasPrefix(r.s[r.i:], "/>") {
			r.i += 2
			empty = true
			break
		}
		if !hadSpace {
			return nil, refuse("attributes of <%s> are not separated by space", local)
		}
		ap, al, err := r.qname()
		if err != nil {
			return nil, err
		}
		r.space()
		if r.i >= len(r.s) || r.s[r.i] != '=' {
			return nil, refuse("attribute %s has no value", al)
		}
		r.i++
		r.space()
		v, err := r.attrValue()
		if err != nil {
			return nil, err
		}
		raw = append(raw, rawAttr{ap, al, v})
		if len(raw) > MaxAttributes {
			return nil, refuse("<%s> has more than %d attributes", local, MaxAttributes)
		}
	}

	e := &Element{Prefix: prefix, Local: local, Parent: parent}
	if err := r.namespaces(e, raw); err != nil {
		return nil, err
	}
	if empty {
		return e, nil
	}
	if err := r.content(e, depth); err != nil {
		return nil, err
	}
	return e, nil
}

// namespaces sorts declarations from attributes, checks both, and resolves
// every name. This is where Fragile Lock's pollution and confusion stop.
func (r *reader) namespaces(e *Element, raw []rawAttr) error {
	parentScope := map[string]string{}
	if e.Parent != nil {
		parentScope = e.Parent.scope
	}
	var attrs []rawAttr
	declared := map[string]bool{}
	for _, a := range raw {
		var p string
		switch {
		case a.prefix == "" && a.local == "xmlns":
			p = ""
		case a.prefix == "xmlns":
			p = a.local
		default:
			attrs = append(attrs, a)
			continue
		}
		if declared[p] {
			return refuse("<%s> declares the prefix %q twice", e.Local, p)
		}
		r.decls++
		if r.decls > MaxDeclarations {
			return refuse("more than %d namespace declarations", MaxDeclarations)
		}
		declared[p] = true
		if p == "xml" || p == "xmlns" {
			return refuse("<%s> rebinds the reserved prefix %q", e.Local, p)
		}
		if a.value == nsXML || a.value == nsXMLNS {
			return refuse("<%s> binds %q to a reserved namespace", e.Local, p)
		}
		if a.value == "" && p != "" {
			return refuse("<%s> undeclares the prefix %q, which XML 1.0 does not allow", e.Local, p)
		}
		if a.value != "" && !absoluteURI(a.value) {
			return refuse("<%s> binds %q to %q, which is not an absolute URI", e.Local, p, a.value)
		}
		e.Decls = append(e.Decls, Decl{Prefix: p, URI: a.value})
	}
	if len(e.Decls) == 0 {
		e.scope = parentScope
	} else {
		e.scope = make(map[string]string, len(parentScope)+len(e.Decls))
		for k, v := range parentScope {
			e.scope[k] = v
		}
		for _, d := range e.Decls {
			if d.Prefix == "" && d.URI == "" {
				delete(e.scope, "")
				continue
			}
			e.scope[d.Prefix] = d.URI
		}
	}

	switch e.Prefix {
	case "":
		e.Space = e.scope[""]
	case "xml", "xmlns":
		return refuse("an element may not use the prefix %q", e.Prefix)
	default:
		ns, ok := e.scope[e.Prefix]
		if !ok {
			return refuse("<%s:%s> uses a prefix nobody declared", e.Prefix, e.Local)
		}
		e.Space = ns
	}

	locals := map[string]bool{}
	for _, a := range attrs {
		at := Attr{Prefix: a.prefix, Local: a.local, Value: a.value}
		switch a.prefix {
		case "":
		case "xml":
			if a.local != "lang" && a.local != "space" {
				return refuse("<%s> carries xml:%s, which is refused", e.Local, a.local)
			}
			at.Space = nsXML
		default:
			ns, ok := e.scope[a.prefix]
			if !ok {
				return refuse("attribute %s:%s uses a prefix nobody declared", a.prefix, a.local)
			}
			at.Space = ns
		}
		// One local name once, whatever its namespace. XML allows ID and
		// samlp:ID side by side; readers that look an attribute up by local
		// name then disagree about which they got.
		if locals[a.local] {
			return refuse("<%s> has two attributes named %q", e.Local, a.local)
		}
		locals[a.local] = true
		e.Attrs = append(e.Attrs, at)
		if a.prefix == "" && (a.local == "ID" || a.local == "Id" || a.local == "id") {
			if a.value == "" {
				return refuse("<%s> has an empty %s", e.Local, a.local)
			}
			if _, dup := r.ids[a.value]; dup {
				return refuse("the identifier %q appears twice", a.value)
			}
			r.ids[a.value] = e
		}
	}
	return nil
}

// absoluteURI accepts scheme:rest with no space, quote or angle bracket.
// A relative namespace name is what made libxml2's canonicaliser fail in
// Fragile Lock, and a failure there must never become an empty string.
func absoluteURI(s string) bool {
	colon := strings.IndexByte(s, ':')
	if colon < 1 {
		return false
	}
	for i := 0; i < colon; i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(i > 0 && ((c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.'))
		if !ok {
			return false
		}
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= ' ' || c == '"' || c == '<' || c == '>' || c == 0x7f {
			return false
		}
	}
	return len(s) > colon+1
}

// attrValue reads a quoted value with references resolved and literal white
// space normalised to spaces, as an attribute of undeclared type is.
func (r *reader) attrValue() (string, error) {
	if r.i >= len(r.s) || (r.s[r.i] != '"' && r.s[r.i] != '\'') {
		return "", refuse("an attribute value is not quoted")
	}
	q := r.s[r.i]
	r.i++
	var b strings.Builder
	for {
		if r.i >= len(r.s) {
			return "", refuse("an attribute value is not closed")
		}
		c := r.s[r.i]
		switch {
		case c == q:
			r.i++
			return b.String(), nil
		case c == '<':
			return "", refuse("an attribute value contains <")
		case c == '&':
			s, err := r.reference()
			if err != nil {
				return "", err
			}
			b.WriteString(s)
		case c == '\t' || c == '\n':
			b.WriteByte(' ')
			r.i++
		default:
			ch, size := utf8.DecodeRuneInString(r.s[r.i:])
			if !isChar(ch) {
				return "", refuse("an attribute value contains the character U+%04X", ch)
			}
			b.WriteString(r.s[r.i : r.i+size])
			r.i += size
		}
	}
}

// reference reads &name; or &#n; or &#xh;. The five built-in names only.
func (r *reader) reference() (string, error) {
	end := strings.IndexByte(r.s[r.i:], ';')
	if end < 2 || end > 12 {
		return "", refuse("a stray & or an unterminated reference")
	}
	ref := r.s[r.i+1 : r.i+end]
	r.i += end + 1
	switch ref {
	case "lt":
		return "<", nil
	case "gt":
		return ">", nil
	case "amp":
		return "&", nil
	case "quot":
		return `"`, nil
	case "apos":
		return "'", nil
	}
	if ref[0] != '#' {
		return "", refuse("the entity &%s; is not one of the five XML defines", ref)
	}
	var n int64
	digits := ref[1:]
	base := int64(10)
	if strings.HasPrefix(digits, "x") {
		digits, base = digits[1:], 16
	}
	if digits == "" {
		return "", refuse("an empty character reference")
	}
	for i := 0; i < len(digits); i++ {
		c := digits[i]
		var d int64
		switch {
		case c >= '0' && c <= '9':
			d = int64(c - '0')
		case base == 16 && c >= 'a' && c <= 'f':
			d = int64(c-'a') + 10
		case base == 16 && c >= 'A' && c <= 'F':
			d = int64(c-'A') + 10
		default:
			return "", refuse("the character reference &%s; is malformed", ref)
		}
		n = n*base + d
		if n > 0x10FFFF {
			return "", refuse("the character reference &%s; is out of range", ref)
		}
	}
	if !isChar(rune(n)) {
		return "", refuse("the character reference &%s; names a character XML does not allow", ref)
	}
	return string(rune(n)), nil
}

// isChar is the XML 1.0 Char production.
func isChar(c rune) bool {
	return c == 0x9 || c == 0xA || c == 0xD ||
		(c >= 0x20 && c <= 0xD7FF) || (c >= 0xE000 && c <= 0xFFFD) ||
		(c >= 0x10000 && c <= 0x10FFFF)
}

// content reads text and child elements up to the matching end tag.
func (r *reader) content(e *Element, depth int) error {
	var text strings.Builder
	flush := func() {
		if text.Len() > 0 {
			e.Children = append(e.Children, Node{Text: text.String()})
			text.Reset()
		}
	}
	for {
		if r.i >= len(r.s) {
			return refuse("<%s> is not closed", e.name())
		}
		c := r.s[r.i]
		switch {
		case strings.HasPrefix(r.s[r.i:], "</"):
			flush()
			r.i += 2
			p, l, err := r.qname()
			if err != nil {
				return err
			}
			if p != e.Prefix || l != e.Local {
				return refuse("<%s> is closed by </%s>", e.name(), joinName(p, l))
			}
			r.space()
			if r.i >= len(r.s) || r.s[r.i] != '>' {
				return refuse("the end tag of <%s> is malformed", e.name())
			}
			r.i++
			return nil
		case strings.HasPrefix(r.s[r.i:], "<!--"):
			return refuse("the document contains a comment; SAML never needs one, " +
				"and a comment inside a value is how values were cut short")
		case strings.HasPrefix(r.s[r.i:], "<![CDATA["):
			return refuse("the document contains a CDATA section")
		case strings.HasPrefix(r.s[r.i:], "<!"):
			return refuse("the document contains a declaration (<!...>)")
		case strings.HasPrefix(r.s[r.i:], "<?"):
			return refuse("the document contains a processing instruction")
		case c == '<':
			flush()
			child, err := r.element(e, depth+1)
			if err != nil {
				return err
			}
			e.Children = append(e.Children, Node{Elem: child})
		case c == '&':
			s, err := r.reference()
			if err != nil {
				return err
			}
			text.WriteString(s)
		case c == '>' && strings.HasSuffix(text.String(), "]]"):
			return refuse("text contains ]]>")
		default:
			ch, size := utf8.DecodeRuneInString(r.s[r.i:])
			if !isChar(ch) {
				return refuse("text contains the character U+%04X", ch)
			}
			text.WriteString(r.s[r.i : r.i+size])
			r.i += size
		}
	}
}

func joinName(p, l string) string {
	if p == "" {
		return l
	}
	return p + ":" + l
}
