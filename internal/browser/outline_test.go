// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package browser

import (
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/cdp"
)

// A real page read as its outline: headings and text in order, each thing
// an agent may act on with a reference, and the buttons that commit to
// something marked as such.
func TestAPageReadsAsAnOutlineWithReferences(t *testing.T) {
	path := localChromium(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	b, err := cdp.Launch(ctx, cdp.Options{Path: path, Profile: filepath.Join(t.TempDir(), "p"), Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	p, err := b.NewPage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	page := `data:text/html,<h1>Returns</h1><p>Thirty days, unused.</p><a href="/policy">Read the policy</a>` +
		`<form><label for=n>Order number</label><input id=n value="A-1042"><button>Look up</button></form>` +
		`<button>Delete my account</button><button>Show more</button>`
	if err := p.Navigate(ctx, page); err != nil {
		t.Fatal(err)
	}
	nodes, err := p.AXTree(ctx)
	if err != nil {
		t.Fatal(err)
	}
	o := Build(nodes)
	for _, want := range []string{"# Returns (h1)", "Thirty days, unused.", `link "Read the policy"`,
		`textbox "Order number" = "A-1042"`, `button "Look up"`, `button "Delete my account"`} {
		if !strings.Contains(o.Text, want) {
			t.Errorf("the outline lacks %q:\n%s", want, o.Text)
		}
	}
	marks := map[string]string{}
	for _, e := range o.Elements {
		marks[e.Name] = e.Consequential
		if e.Backend == 0 {
			t.Errorf("%s has no element behind it", e.Ref)
		}
	}
	if marks["Look up"] != "it submits a form" || !strings.Contains(marks["Delete my account"], "Delete my account") || marks["Show more"] != "" {
		t.Errorf("consequential: %v", marks)
	}
	if len(o.Text) > 600 {
		t.Errorf("a small page made a %d-byte outline", len(o.Text))
	}
}

func TestALongPageIsCutAndSaysSo(t *testing.T) {
	var nodes []cdp.AXNode
	root := cdp.AXNode{NodeID: "1", Role: &cdp.AXValue{Value: []byte(`"RootWebArea"`)}}
	for i := 0; i < 3000; i++ {
		id := string(rune('a'+i%26)) + strings.Repeat("x", i/26)
		root.ChildIDs = append(root.ChildIDs, id)
		nodes = append(nodes, cdp.AXNode{NodeID: id, ParentID: "1",
			Role: &cdp.AXValue{Value: []byte(`"StaticText"`)}, Name: &cdp.AXValue{Value: []byte(`"a line of text on a long page"`)}})
	}
	o := Build(append([]cdp.AXNode{root}, nodes...))
	if len(o.Text) > MaxOutline+200 || o.Omitted == 0 || !strings.Contains(o.Text, "left out") {
		t.Errorf("%d bytes, %d omitted", len(o.Text), o.Omitted)
	}
}

// A name in the outline is cut where a character starts, and still comes to
// 200 bytes with its mark. Names are the page's own words, in whatever
// language it is in, and an agent acts on a control by what it is called.
func TestALongNameIsCutBetweenCharacters(t *testing.T) {
	name, err := json.Marshal(strings.Repeat("a", 198) + "中文")
	if err != nil {
		t.Fatal(err)
	}
	root := cdp.AXNode{NodeID: "1", Role: &cdp.AXValue{Value: []byte(`"RootWebArea"`)}, ChildIDs: []string{"2"}}
	text := cdp.AXNode{NodeID: "2", ParentID: "1", Role: &cdp.AXValue{Value: []byte(`"StaticText"`)},
		Name: &cdp.AXValue{Value: name}}
	o := Build([]cdp.AXNode{root, text})
	if !utf8.ValidString(o.Text) || !strings.Contains(o.Text, strings.Repeat("a", 197)+"…") {
		t.Errorf("%q", o.Text)
	}
}
