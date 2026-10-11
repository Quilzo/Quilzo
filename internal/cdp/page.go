// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package cdp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Page is one tab, driven through its own session on the connection.
type Page struct {
	b       *Browser
	Target  string
	Session string
}

// NewPage opens a blank tab and attaches to it.
func (b *Browser) NewPage(ctx context.Context) (*Page, error) {
	var t struct {
		TargetID string `json:"targetId"`
	}
	if err := b.Call(ctx, "", "Target.createTarget", map[string]any{"url": "about:blank"}, &t); err != nil {
		return nil, err
	}
	var a struct {
		SessionID string `json:"sessionId"`
	}
	if err := b.Call(ctx, "", "Target.attachToTarget", map[string]any{"targetId": t.TargetID, "flatten": true}, &a); err != nil {
		return nil, err
	}
	p := &Page{b: b, Target: t.TargetID, Session: a.SessionID}
	for _, m := range []string{"Page.enable", "DOM.enable", "Accessibility.enable"} {
		if err := p.call(ctx, m, nil, nil); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func (p *Page) call(ctx context.Context, method string, params, result any) error {
	return p.b.Call(ctx, p.Session, method, params, result)
}

// Call sends a command to this page. Unexported to agents by construction:
// only the driver holds a Page.
func (p *Page) Call(ctx context.Context, method string, params, result any) error {
	return p.call(ctx, method, params, result)
}

// Navigate loads a URL and waits for the page's load event.
func (p *Page) Navigate(ctx context.Context, url string) error {
	loaded, cancel := p.b.Subscribe(func(e Event) bool {
		return e.SessionID == p.Session && e.Method == "Page.loadEventFired"
	})
	defer cancel()
	var r struct {
		ErrorText string `json:"errorText"`
	}
	if err := p.call(ctx, "Page.navigate", map[string]any{"url": url}, &r); err != nil {
		return err
	}
	if r.ErrorText != "" {
		return fmt.Errorf("%s did not load: %s", url, r.ErrorText)
	}
	select {
	case <-loaded:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(30 * time.Second):
		return fmt.Errorf("%s did not finish loading in 30 seconds", url)
	}
}

// Screenshot is the visible part of the page, as PNG.
func (p *Page) Screenshot(ctx context.Context) ([]byte, error) {
	var r struct {
		Data string `json:"data"`
	}
	if err := p.call(ctx, "Page.captureScreenshot", map[string]any{"format": "png"}, &r); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(r.Data)
}

// AXNode is one node of the page's accessibility tree, as the browser
// reports it.
type AXNode struct {
	NodeID     string   `json:"nodeId"`
	Ignored    bool     `json:"ignored"`
	Role       *AXValue `json:"role"`
	Name       *AXValue `json:"name"`
	Value      *AXValue `json:"value"`
	Properties []struct {
		Name  string  `json:"name"`
		Value AXValue `json:"value"`
	} `json:"properties"`
	ChildIDs []string `json:"childIds"`
	ParentID string   `json:"parentId"`
	Backend  int64    `json:"backendDOMNodeId"`
	FrameID  string   `json:"frameId"`
}

// AXValue is a role, a name or a property's value.
type AXValue struct {
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
}

// String is the value as text.
func (v *AXValue) String() string {
	if v == nil || len(v.Value) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(v.Value, &s) == nil {
		return s
	}
	return string(v.Value)
}

// Prop is a property's value as text, or empty.
func (n AXNode) Prop(name string) string {
	for _, p := range n.Properties {
		if p.Name == name {
			return p.Value.String()
		}
	}
	return ""
}

// AXTree is the page's whole accessibility tree.
func (p *Page) AXTree(ctx context.Context) ([]AXNode, error) {
	var r struct {
		Nodes []AXNode `json:"nodes"`
	}
	if err := p.call(ctx, "Accessibility.getFullAXTree", nil, &r); err != nil {
		return nil, err
	}
	return r.Nodes, nil
}

// Box is where an element is on the screen, after scrolling it into view:
// its left, top, right and bottom edges.
func (p *Page) Box(ctx context.Context, backend int64) (x0, y0, x1, y1 float64, err error) {
	_ = p.call(ctx, "DOM.scrollIntoViewIfNeeded", map[string]any{"backendNodeId": backend}, nil)
	var q struct {
		Quads [][]float64 `json:"quads"`
	}
	if err := p.call(ctx, "DOM.getContentQuads", map[string]any{"backendNodeId": backend}, &q); err != nil {
		return 0, 0, 0, 0, err
	}
	if len(q.Quads) == 0 || len(q.Quads[0]) < 8 {
		return 0, 0, 0, 0, errors.New("the element is not on the screen")
	}
	c := q.Quads[0]
	x0, y0, x1, y1 = c[0], c[1], c[0], c[1]
	for i := 0; i < 8; i += 2 {
		x0, x1 = min(x0, c[i]), max(x1, c[i])
		y0, y1 = min(y0, c[i+1]), max(y1, c[i+1])
	}
	return x0, y0, x1, y1, nil
}

// ErrCovered is a click whose element has something else on top of it.
var ErrCovered = errors.New("something else on the page covers it, so a click would land on that instead")

// ErrInner is a click that would land on something else to press inside
// the element: a button inside a link, say.
var ErrInner = errors.New("something else to press is inside it, where it would be pressed; press that by its own reference")

// Click presses and releases the left button on the middle of an element,
// as a person's pointer would: the page sees an ordinary click, with the
// events a click makes, rather than a script calling click().
//
// What is under the pointer is asked once the pointer is there, and again
// once the button is down. A page that lays something see-through over a
// button, or moves something under the pointer as it arrives, so the click
// meant for one thing lands on another, is the oldest trick there is
// against a pointer; the click is refused instead (ErrCovered), and so is
// one that would land on another control inside the element (ErrInner).
func (p *Page) Click(ctx context.Context, backend int64) error {
	x0, y0, x1, y1, err := p.Box(ctx, backend)
	if err != nil {
		return err
	}
	x, y := (x0+x1)/2, (y0+y1)/2
	mouse := func(kind string, x, y float64) error {
		ev := map[string]any{"type": kind, "x": x, "y": y}
		if kind != "mouseMoved" {
			ev["button"], ev["clickCount"] = "left", 1
		}
		return p.call(ctx, "Input.dispatchMouseEvent", ev, nil)
	}
	if err := mouse("mouseMoved", x, y); err != nil {
		return err
	}
	if err := p.under(ctx, backend, x, y); err != nil {
		return err
	}
	if err := mouse("mousePressed", x, y); err != nil {
		return err
	}
	if err := p.under(ctx, backend, x, y); err != nil {
		// Let go away from everything, so no click lands anywhere.
		_ = mouse("mouseReleased", 0, 0)
		return err
	}
	return mouse("mouseReleased", x, y)
}

// interactive is what counts as something else to press.
const interactive = `a[href],button,input,select,textarea,iframe,frame,summary,[role=button],[role=link],` +
	`[role=menuitem],[role=menuitemcheckbox],[role=menuitemradio],[role=switch],[role=checkbox],[role=radio],` +
	`[role=tab],[role=option],[role=treeitem],[onclick],[contenteditable=""],[contenteditable=true]`

// under says whether the point is on the element or inside it, with
// nothing else to press in between.
func (p *Page) under(ctx context.Context, backend int64, x, y float64) error {
	var hit struct {
		Backend int64 `json:"backendNodeId"`
	}
	if err := p.call(ctx, "DOM.getNodeForLocation", map[string]any{"x": int(x), "y": int(y),
		"includeUserAgentShadowDOM": false, "ignorePointerEventsNone": false}, &hit); err != nil {
		return err
	}
	if hit.Backend == backend {
		return nil
	}
	world, err := p.Isolated(ctx)
	if err != nil {
		return err
	}
	el, err := p.Resolve(ctx, backend, world)
	if err != nil {
		return err
	}
	at, err := p.Resolve(ctx, hit.Backend, world)
	if err != nil {
		// Under the pointer, and not in the page itself: a frame's.
		return ErrCovered
	}
	var r struct {
		Result struct {
			Value string `json:"value"`
		} `json:"result"`
	}
	// Up from what is under the pointer, through shadow roots, to the
	// element or to the top.
	err = p.call(ctx, "Runtime.callFunctionOn", map[string]any{"objectId": el,
		"functionDeclaration": `function(h, sel){const between=[];for(let n=h;n;n=n.parentNode||n.host){` +
			`if(n===this)return between.some(x=>x.nodeType===1&&x.matches(sel))?"inner":"ok";between.push(n)}return "outside"}`,
		"arguments": []map[string]any{{"objectId": at}, {"value": interactive}}, "returnByValue": true}, &r)
	switch {
	case err != nil:
		// What is under the pointer cannot be put beside the element: it
		// belongs to another document, a frame's. Refused, as anything
		// that cannot be shown to be the element is.
		return ErrCovered
	case r.Result.Value == "ok":
		return nil
	case r.Result.Value == "inner":
		return ErrInner
	}
	return ErrCovered
}

// Facts are what the page says an element does, asked in a world of this
// program's own: whether pressing it sends a form, the method of the form
// it belongs to, where a link goes, and whether a list acts on a change.
type Facts struct {
	Submits    bool   `json:"submits"`
	FormMethod string `json:"formMethod"`
	Href       string `json:"href"`
	OnChange   bool   `json:"onchange"`
}

// Facts asks the page about an element.
func (p *Page) Facts(ctx context.Context, backend int64) (Facts, error) {
	world, err := p.Isolated(ctx)
	if err != nil {
		return Facts{}, err
	}
	el, err := p.Resolve(ctx, backend, world)
	if err != nil {
		return Facts{}, err
	}
	var r struct {
		Result struct {
			Value Facts `json:"value"`
		} `json:"result"`
	}
	// A form owner, not an ancestor: a button tied to a form by its form=
	// attribute sends it from anywhere on the page.
	fn := `function(){const f=this.form||null;const t=(this.getAttribute("type")||"").toLowerCase();` +
		`const sub=!!f&&((this.tagName==="BUTTON"&&(t===""||t==="submit"))||(this.tagName==="INPUT"&&(t==="submit"||t==="image")));` +
		`return {submits:sub,formMethod:f?(f.getAttribute("method")||"get").toLowerCase():"",` +
		`href:(this.closest&&this.closest("a[href]"))?this.closest("a[href]").href:"",onchange:this.hasAttribute("onchange")}}`
	err = p.call(ctx, "Runtime.callFunctionOn", map[string]any{"objectId": el, "functionDeclaration": fn, "returnByValue": true}, &r)
	return r.Result.Value, err
}

// ErrNotHere is a value that was to be put into a field on one site, and
// the page is not that site.
var ErrNotHere = errors.New("the page is not where this may be typed")

// Fill puts a value into a field from a world of this program's own,
// without a keystroke: it needs no focus, so nothing the page moves focus
// to can receive it. The page's address is checked in the same step, so
// the value goes in only if the page is on host, over https (or http when
// plain), and the field is in the page itself rather than in a frame.
func (p *Page) Fill(ctx context.Context, backend int64, value, host string, plain bool) error {
	world, err := p.Isolated(ctx)
	if err != nil {
		return err
	}
	el, err := p.Resolve(ctx, backend, world)
	if err != nil {
		return err
	}
	var r struct {
		Result struct {
			Value string `json:"value"`
		} `json:"result"`
	}
	fn := `function(v,host,plain){if(this.ownerDocument!==document||window.top!==window)return "not in the page itself";` +
		`if(location.hostname!==host||(location.protocol!=="https:"&&!(plain&&location.protocol==="http:")))return "elsewhere";` +
		`const proto=this instanceof HTMLInputElement?HTMLInputElement.prototype:this instanceof HTMLTextAreaElement?HTMLTextAreaElement.prototype:null;` +
		`if(!proto)return "not a field";Object.getOwnPropertyDescriptor(proto,"value").set.call(this,v);` +
		`this.dispatchEvent(new Event("input",{bubbles:true}));this.dispatchEvent(new Event("change",{bubbles:true}));return ""}`
	if err := p.call(ctx, "Runtime.callFunctionOn", map[string]any{"objectId": el, "functionDeclaration": fn,
		"arguments": []map[string]any{{"value": value}, {"value": host}, {"value": plain}}, "returnByValue": true}, &r); err != nil {
		return err
	}
	switch r.Result.Value {
	case "":
		return nil
	case "elsewhere":
		return ErrNotHere
	}
	return errors.New(r.Result.Value)
}

// Send sends the form a field is in, as Enter in it would: by its default
// button when it has one, so the page sees that button pressed, and by the
// form itself otherwise. It reports false when the field is in no form.
func (p *Page) Send(ctx context.Context, backend int64) (bool, error) {
	world, err := p.Isolated(ctx)
	if err != nil {
		return false, err
	}
	el, err := p.Resolve(ctx, backend, world)
	if err != nil {
		return false, err
	}
	var r struct {
		Result struct {
			Value bool `json:"value"`
		} `json:"result"`
	}
	fn := `function(){const f=this.form;if(!f)return false;` +
		`const b=Array.from(f.elements).find(e=>(e.tagName==="BUTTON"&&(!e.getAttribute("type")||e.type==="submit"))||(e.tagName==="INPUT"&&(e.type==="submit"||e.type==="image")));` +
		`if(b){b.click()}else if(typeof f.requestSubmit==="function"){f.requestSubmit()}else{f.submit()}return true}`
	err = p.call(ctx, "Runtime.callFunctionOn", map[string]any{"objectId": el, "functionDeclaration": fn, "returnByValue": true}, &r)
	return r.Result.Value, err
}

// Clear empties a field, from a world of this program's own.
func (p *Page) Clear(ctx context.Context, backend int64) error {
	world, err := p.Isolated(ctx)
	if err != nil {
		return err
	}
	el, err := p.Resolve(ctx, backend, world)
	if err != nil {
		return err
	}
	return p.call(ctx, "Runtime.callFunctionOn", map[string]any{"objectId": el, "functionDeclaration": `function(){` +
		`if(this.isConnected&&this instanceof HTMLInputElement){Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,"value").set.call(this,"");` +
		`this.dispatchEvent(new Event("input",{bubbles:true}))}}`}, nil)
}

// UserField is the field for a user name that goes with a password field:
// in the same form, the last text, email or telephone field before it,
// one marked for a user name or an email first. Zero when there is none.
func (p *Page) UserField(ctx context.Context, password int64) (int64, error) {
	world, err := p.Isolated(ctx)
	if err != nil {
		return 0, err
	}
	el, err := p.Resolve(ctx, password, world)
	if err != nil {
		return 0, err
	}
	var r struct {
		Result struct {
			ObjectID string `json:"objectId"`
			Subtype  string `json:"subtype"`
		} `json:"result"`
	}
	fn := `function(){const all=this.form?Array.from(this.form.elements):Array.from(document.querySelectorAll("input"));` +
		`const before=all.filter(e=>e!==this&&e.tagName==="INPUT"&&!e.disabled&&["text","email","tel"].includes(e.type)&&` +
		`(e.compareDocumentPosition(this)&Node.DOCUMENT_POSITION_FOLLOWING));` +
		`const marked=before.filter(e=>/username|email/i.test(e.autocomplete||"")||e.type==="email");` +
		`return (marked.length?marked[marked.length-1]:before[before.length-1])||null}`
	if err := p.call(ctx, "Runtime.callFunctionOn", map[string]any{"objectId": el, "functionDeclaration": fn}, &r); err != nil {
		return 0, err
	}
	if r.Result.ObjectID == "" || r.Result.Subtype == "null" {
		return 0, nil
	}
	var d struct {
		Node struct {
			Backend int64 `json:"backendNodeId"`
		} `json:"node"`
	}
	if err := p.call(ctx, "DOM.describeNode", map[string]any{"objectId": r.Result.ObjectID}, &d); err != nil {
		return 0, err
	}
	return d.Node.Backend, nil
}

// Isolated is a world of this program's own in the page's main frame: the
// page's DOM, and none of the page's script. A function run there sees the
// browser's own prototypes, which the page cannot have replaced, so what
// it reports about the page is not what the page says about itself.
func (p *Page) Isolated(ctx context.Context) (int64, error) {
	var w struct {
		ID int64 `json:"executionContextId"`
	}
	err := p.call(ctx, "Page.createIsolatedWorld", map[string]any{"frameId": p.Target, "worldName": "quilzo"}, &w)
	return w.ID, err
}

// Resolve is an element as an object in a world (Isolated).
func (p *Page) Resolve(ctx context.Context, backend, world int64) (string, error) {
	var r struct {
		Object struct {
			ID string `json:"objectId"`
		} `json:"object"`
	}
	if err := p.call(ctx, "DOM.resolveNode", map[string]any{"backendNodeId": backend, "executionContextId": world}, &r); err != nil {
		return "", err
	}
	return r.Object.ID, nil
}

// Node is one element's accessibility node as it is now.
func (p *Page) Node(ctx context.Context, backend int64) (AXNode, error) {
	var r struct {
		Nodes []AXNode `json:"nodes"`
	}
	if err := p.call(ctx, "Accessibility.getPartialAXTree", map[string]any{"backendNodeId": backend, "fetchRelatives": false}, &r); err != nil {
		return AXNode{}, err
	}
	for _, n := range r.Nodes {
		if n.Backend == backend {
			return n, nil
		}
	}
	return AXNode{}, errors.New("the element is no longer on the page")
}

// Press presses and releases a key on the focused element: Enter, to send
// the form it is in.
func (p *Page) Press(ctx context.Context, key string) error {
	codes := map[string]int{"Enter": 13, "Tab": 9, "Escape": 27}
	code, ok := codes[key]
	if !ok {
		return fmt.Errorf("%q is not a key this presses", key)
	}
	down := map[string]any{"type": "keyDown", "key": key, "code": key, "windowsVirtualKeyCode": code, "nativeVirtualKeyCode": code}
	if key == "Enter" {
		down["text"] = "\r"
	}
	if err := p.call(ctx, "Input.dispatchKeyEvent", down, nil); err != nil {
		return err
	}
	return p.call(ctx, "Input.dispatchKeyEvent", map[string]any{"type": "keyUp", "key": key, "code": key,
		"windowsVirtualKeyCode": code, "nativeVirtualKeyCode": code}, nil)
}

// Type puts text into an element in place of what it held, as selecting
// it all and typing would, after focusing it.
func (p *Page) Type(ctx context.Context, backend int64, text string) error {
	if err := p.call(ctx, "DOM.focus", map[string]any{"backendNodeId": backend}, nil); err != nil {
		return err
	}
	world, err := p.Isolated(ctx)
	if err != nil {
		return err
	}
	obj, err := p.Resolve(ctx, backend, world)
	if err != nil {
		return err
	}
	// Selected from a world of this program's own, so what is replaced is
	// what the field holds and not what the page's script says it does.
	if err := p.call(ctx, "Runtime.callFunctionOn", map[string]any{"objectId": obj,
		"functionDeclaration": `function(){if(typeof this.select==='function'){this.select();return}` +
			`const r=document.createRange();r.selectNodeContents(this);const s=getSelection();s.removeAllRanges();s.addRange(r)}`}, nil); err != nil {
		return err
	}
	return p.call(ctx, "Input.insertText", map[string]any{"text": text}, nil)
}

// Close closes the tab.
func (p *Page) Close(ctx context.Context) error {
	return p.b.Call(ctx, "", "Target.closeTarget", map[string]any{"targetId": p.Target}, nil)
}
