// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package browser

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/quilzo/quilzo/internal/cdp"
)

// What an agent reads of a page: its outline.
//
// A screenshot costs a model a thousand tokens or more and has to be looked
// at to be understood; the page's accessibility tree is what a screen
// reader speaks, already names every control by what it does, and is a few
// hundred tokens for most pages. So the outline is what an agent gets by
// default: headings, text, links, fields and buttons, in reading order, and
// each thing it may act on given a short reference (e1, e2, …) it names
// when it acts. It never names an element by selector or script, and a
// reference is good only for the outline it came from.

// Element is something on the page an agent may act on.
type Element struct {
	Ref     string
	Role    string
	Name    string
	Backend int64
	// Consequential says acting on it would send, pay, delete or commit to
	// something; see Consequential.
	Consequential string
}

// Outline is a page as an agent reads it.
type Outline struct {
	Text     string
	Elements map[string]Element
	// Omitted counts what was left out to keep it short.
	Omitted int
}

// MaxOutline bounds an outline's text: a long page is cut, and says so.
const MaxOutline = 12000

var acted = map[string]bool{
	"button": true, "link": true, "textbox": true, "searchbox": true, "combobox": true,
	"checkbox": true, "radio": true, "switch": true, "slider": true, "spinbutton": true,
	"listbox": true, "option": true, "menuitem": true, "menuitemcheckbox": true,
	"menuitemradio": true, "tab": true, "treeitem": true,
}

var shown = map[string]bool{
	"heading": true, "StaticText": true, "image": true, "img": true, "listitem": true,
	"cell": true, "columnheader": true, "rowheader": true, "alert": true, "status": true,
	"dialog": true, "alertdialog": true, "LabelText": false,
}

// Build makes the outline of a tree, in reading order.
func Build(nodes []cdp.AXNode) Outline {
	byID := make(map[string]cdp.AXNode, len(nodes))
	for _, n := range nodes {
		byID[n.NodeID] = n
	}
	var root *cdp.AXNode
	for i := range nodes {
		if nodes[i].ParentID == "" {
			root = &nodes[i]
			break
		}
	}
	o := Outline{Elements: map[string]Element{}}
	if root == nil {
		return o
	}
	var b strings.Builder
	n := 0
	var walk func(id string, depth int, inForm bool)
	walk = func(id string, depth int, inForm bool) {
		node, ok := byID[id]
		if !ok {
			return
		}
		role := node.Role.String()
		name := clean(node.Name.String())
		if role == "form" {
			inForm = true
		}
		if !node.Ignored {
			line := ""
			switch {
			case acted[role]:
				n++
				ref := fmt.Sprintf("e%d", n)
				el := Element{Ref: ref, Role: role, Name: name, Backend: node.Backend}
				el.Consequential = Consequential(el, inForm)
				o.Elements[ref] = el
				line = fmt.Sprintf("[%s] %s %q", ref, role, name)
				if v := clean(node.Value.String()); v != "" && role != "button" && role != "link" {
					line += fmt.Sprintf(" = %q", v)
				}
				for _, p := range []string{"checked", "selected", "expanded", "disabled", "required"} {
					if v := node.Prop(p); v == "true" || v == "mixed" {
						line += " " + p
					}
				}
			case role == "heading":
				level := node.Prop("level")
				line = fmt.Sprintf("# %s (h%s)", name, level)
			case role == "StaticText" && name != "":
				line = name
			case (role == "image" || role == "img") && name != "":
				line = "image: " + name
			case shown[role] && name != "" && role != "StaticText":
				line = role + ": " + name
			}
			if line != "" {
				if b.Len()+len(line) > MaxOutline {
					o.Omitted++
				} else {
					b.WriteString(strings.Repeat("  ", min(depth, 6)))
					b.WriteString(line)
					b.WriteByte('\n')
				}
				if acted[role] {
					// A control's own text is its name; its children add
					// nothing but the same words again.
					return
				}
			}
		}
		for _, c := range node.ChildIDs {
			walk(c, depth+1, inForm)
		}
	}
	walk(root.NodeID, 0, false)
	o.Text = b.String()
	if o.Omitted > 0 {
		o.Text += fmt.Sprintf("… and %d more things, left out to keep this short\n", o.Omitted)
	}
	return o
}

// clean is a name as one line, not too long.
func clean(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// consequentialWords are what a control is called when pressing it does
// something that cannot be taken back or that commits somebody: sends,
// pays, deletes, agrees. Matched on whole words of the control's name, in
// English for now; a site in another language is caught by the form rule
// and by what its write hosts allow.
var consequentialWords = regexp.MustCompile(`(?i)\b(send|submit|pay|purchase|buy|order|checkout|check out|book|reserve|delete|remove|erase|cancel|unsubscribe|confirm|publish|post|agree|accept|sign|transfer|withdraw|approve|place)\b`)

// Consequential says why acting on an element commits to something, or is
// empty. A button inside a form submits it; a control named for sending,
// paying, deleting or agreeing does what it says.
func Consequential(e Element, inForm bool) string {
	if e.Role != "button" && e.Role != "link" && e.Role != "menuitem" {
		return ""
	}
	if m := consequentialWords.FindString(e.Name); m != "" {
		return fmt.Sprintf("it is called %q", e.Name)
	}
	if inForm && e.Role == "button" {
		return "it submits a form"
	}
	return ""
}
