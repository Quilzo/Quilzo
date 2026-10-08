// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package xmldsig

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Each refusal has a control beside it: the nearest document that should be
// read. A reader that refused everything would pass the refusals and fail
// every control.
func TestTheReaderRefusesWhatPastBypassesUsed(t *testing.T) {
	for _, c := range []struct {
		why, bad, good string
	}{
		{"a DOCTYPE (XXE, ruby-saml CVE-2025-25291)",
			`<!DOCTYPE r [<!ENTITY x "y">]><r>&x;</r>`, `<r>y</r>`},
		{"an entity beyond the five", `<r>&nbsp;</r>`, `<r>&amp;&lt;&gt;&quot;&apos;</r>`},
		{"a comment in a value (Duo, CVE-2017-11427)",
			`<NameID>admin@evil.example<!---->.corp.example</NameID>`, `<NameID>admin@evil.example.corp.example</NameID>`},
		{"a comment before the root", `<!-- x --><r/>`, `<r/>`},
		{"a processing instruction (node-saml CVE-2025-54419)",
			`<r><?x y?></r>`, `<r/>`},
		{"a processing instruction before the root", `<?xml-stylesheet href="x"?><r/>`, `<?xml version="1.0"?><r/>`},
		{"CDATA", `<r><![CDATA[x]]></r>`, `<r>x</r>`},
		{"attribute pollution (Fragile Lock)",
			`<p:Response xmlns:p="urn:p" ID="a" p:ID="b"/>`, `<p:Response xmlns:p="urn:p" ID="a" p:Other="b"/>`},
		{"the same attribute twice", `<r a="1" a="2"/>`, `<r a="1" b="2"/>`},
		{"the same expanded name twice",
			`<r xmlns:a="urn:x" xmlns:b="urn:x" a:k="1" b:k="2"/>`, `<r xmlns:a="urn:x" xmlns:b="urn:y" a:k="1" b:j="2"/>`},
		{"xml: rebound (Fragile Lock namespace confusion)",
			`<r xmlns:xml="http://www.w3.org/2000/09/xmldsig#"/>`, `<r xml:lang="en"/>`},
		{"xmlns: declared", `<r xmlns:xmlns="urn:x"/>`, `<r xmlns:x="urn:x"/>`},
		{"a prefix bound to the XML namespace", `<r xmlns:p="http://www.w3.org/XML/1998/namespace"/>`, `<r xmlns:p="urn:p"/>`},
		{"a relative namespace (Fragile Lock void canonicalisation)",
			`<r xmlns:ns="1"/>`, `<r xmlns:ns="urn:1"/>`},
		{"a namespace that is only a scheme", `<r xmlns:ns="urn:"/>`, `<r xmlns:ns="urn:x"/>`},
		{"an undeclared prefix", `<p:r/>`, `<p:r xmlns:p="urn:p"/>`},
		{"an undeclared attribute prefix", `<r p:a="1"/>`, `<r xmlns:p="urn:p" p:a="1"/>`},
		{"a prefix undeclared (XML 1.1 only)", `<r xmlns:p="urn:p"><s xmlns:p=""/></r>`, `<r xmlns:p="urn:p"><s xmlns=""/></r>`},
		{"xml:id, a second kind of identifier", `<r xml:id="a"/>`, `<r xml:space="preserve"/>`},
		{"a non-ASCII name (look-alike letters)", `<Аssertion/>`, `<Assertion/>`},
		{"a duplicate identifier", `<r><a ID="x"/><b ID="x"/></r>`, `<r><a ID="x"/><b ID="y"/></r>`},
		{"a duplicate identifier across ID and Id", `<r><a ID="x"/><b Id="x"/></r>`, `<r><a ID="x"/><b Id="z"/></r>`},
		{"an empty identifier", `<r ID=""/>`, `<r ID="a"/>`},
		{"two roots", `<r/><s/>`, `<r><s/></r>`},
		{"a mismatched end tag", `<r></s>`, `<r></r>`},
		{"an unquoted attribute", `<r a=1/>`, `<r a="1"/>`},
		{"< in an attribute", `<r a="<"/>`, `<r a="&lt;"/>`},
		{"]]> in text", `<r>a]]>b</r>`, `<r>a]]&gt;b</r>`},
		{"a control character", "<r>\x01</r>", "<r>\t</r>"},
		{"a reference to a control character", `<r>&#1;</r>`, `<r>&#9;</r>`},
		{"another encoding", `<?xml version="1.0" encoding="ISO-8859-1"?><r/>`, `<?xml version="1.0" encoding="utf-8"?><r/>`},
		{"XML 1.1", `<?xml version="1.1"?><r/>`, `<?xml version="1.0"?><r/>`},
		{"attributes run together", `<r a="1"b="2"/>`, `<r a="1" b="2"/>`},
	} {
		if _, err := Read([]byte(c.bad)); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: read, should have been refused (%v)", c.why, err)
		}
		if _, err := Read([]byte(c.good)); err != nil {
			t.Errorf("%s: the control was refused: %v", c.why, err)
		}
	}
}

func TestLimits(t *testing.T) {
	deep := strings.Repeat("<a>", MaxDepth+1) + strings.Repeat("</a>", MaxDepth+1)
	if _, err := Read([]byte(deep)); !errors.Is(err, ErrRefused) {
		t.Error("nesting beyond the limit was read")
	}
	ok := strings.Repeat("<a>", MaxDepth) + strings.Repeat("</a>", MaxDepth)
	if _, err := Read([]byte(ok)); err != nil {
		t.Errorf("nesting at the limit was refused: %v", err)
	}
	if _, err := Read([]byte("<r>" + strings.Repeat("x", MaxDocument) + "</r>")); !errors.Is(err, ErrRefused) {
		t.Error("an oversized document was read")
	}
	many := "<r>" + strings.Repeat("<a/>", MaxElements) + "</r>"
	if _, err := Read([]byte(many)); !errors.Is(err, ErrRefused) {
		t.Error("more elements than the limit were read")
	}
	var attrs strings.Builder
	for i := 0; i <= MaxAttributes; i++ {
		attrs.WriteString(" a")
		attrs.WriteString(strings.Repeat("b", i+1))
		attrs.WriteString(`="1"`)
	}
	if _, err := Read([]byte("<r" + attrs.String() + "/>")); !errors.Is(err, ErrRefused) {
		t.Error("more attributes than the limit were read")
	}
	if _, err := Read([]byte{0xff, 0xfe}); !errors.Is(err, ErrRefused) {
		t.Error("invalid UTF-8 was read")
	}
}

// What the reader gives back, for the values a caller reads.
func TestTheReaderResolvesNamesAndText(t *testing.T) {
	d, err := Read([]byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n" +
		`<s:R xmlns:s="urn:s" xmlns="urn:d" ID="r1"><V a="x&#9;y&#xA;z	w">one &amp; two&#xD;</V><s:E xmlns=""><F/></s:E></s:R>`))
	if err != nil {
		t.Fatal(err)
	}
	r := d.Root
	if !r.Is("urn:s", "R") || d.ByID("r1") != r {
		t.Fatalf("root %s %s", r.Space, r.Local)
	}
	kids, mixed := r.Elements()
	if mixed || len(kids) != 2 {
		t.Fatalf("children %d mixed %v", len(kids), mixed)
	}
	v := kids[0]
	if !v.Is("urn:d", "V") {
		t.Errorf("default namespace not applied: %s", v.Space)
	}
	if a, _ := v.Attr("a"); a != "x\ty\nz w" {
		t.Errorf("attribute value %q: references keep their character, literal white space becomes a space", a)
	}
	if txt, _ := v.Text(); txt != "one & two\r" {
		t.Errorf("text %q", txt)
	}
	f, _ := kids[1].Elements()
	if !f[0].Is("", "F") {
		t.Errorf("xmlns=\"\" did not undeclare the default: %q", f[0].Space)
	}
	if _, err := r.Text(); err == nil {
		t.Error("an element with children gave text")
	}
}

// A document at every limit at once is still cheap to read and render. The
// endpoint that receives these is reachable by anybody, so the cost of
// refusing has to be bounded as well as the cost of accepting.
func TestWorstCaseCostIsBounded(t *testing.T) {
	var b strings.Builder
	// Declarations spread down a chain, so scopes are as large as allowed.
	depth := MaxDeclarations / 2
	if depth > MaxDepth-2 {
		depth = MaxDepth - 2
	}
	for d := 0; d < depth; d++ {
		b.WriteString("<a xmlns:p" + strings.Repeat("x", d+1) + `="u:x" xmlns:q` + strings.Repeat("y", d+1) + `="u:y">`)
	}
	n := 0
	for b.Len() < MaxDocument-4096 && n < MaxElements-depth-1 {
		b.WriteString(`<px:b qy:c="1" d="2">t</px:b>`)
		n++
	}
	for d := 0; d < depth; d++ {
		b.WriteString("</a>")
	}
	doc := []byte(b.String())
	start := time.Now()
	d, err := Read(doc)
	if err != nil {
		t.Fatalf("the worst case within the limits was refused: %v", err)
	}
	if _, err := Canonical(d.Root, []string{"px", "qy"}, nil); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("reading and rendering %d bytes took %v", len(doc), took)
	}
	// And the document that cost thirty seconds before the limit: scopes as
	// large as declarations allow, then thousands of elements that each copy
	// them.
	var bomb strings.Builder
	for i := 0; i < 63; i++ {
		bomb.WriteString("<a")
		for j := 0; j < 63; j++ {
			fmt.Fprintf(&bomb, ` xmlns:p%d_%d="u:x"`, i, j)
		}
		bomb.WriteString(">")
	}
	for bomb.Len() < MaxDocument-2000 {
		bomb.WriteString(`<b xmlns:z="u:z"/>`)
	}
	for i := 0; i < 63; i++ {
		bomb.WriteString("</a>")
	}
	start = time.Now()
	if _, err := Read([]byte(bomb.String())); !errors.Is(err, ErrRefused) {
		t.Errorf("the declaration bomb was read: %v", err)
	}
	if took := time.Since(start); took > 100*time.Millisecond {
		t.Errorf("refusing the declaration bomb took %v", took)
	}
}
