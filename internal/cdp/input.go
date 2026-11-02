// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package cdp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// More of what Chromium does for whoever drives it: keys beyond Enter, the
// wheel, the pointer resting on something, what has focus, the viewport,
// and functions of this program's own run in a world the page cannot
// reach. Each is one DevTools call or a few, and none evaluates anything
// a model wrote.

// Key is a key an agent may press: its DOM key, its code, the Windows
// virtual-key code Chromium expects, and the text it types, if any.
type Key struct {
	Key, Code string
	VK        int
	Text      string
}

// Keys are the keys an agent may press, by the name it gives them.
var Keys = map[string]Key{
	"Enter":      {"Enter", "Enter", 13, "\r"},
	"Tab":        {"Tab", "Tab", 9, ""},
	"Escape":     {"Escape", "Escape", 27, ""},
	"Backspace":  {"Backspace", "Backspace", 8, ""},
	"Delete":     {"Delete", "Delete", 46, ""},
	"Space":      {" ", "Space", 32, " "},
	"ArrowUp":    {"ArrowUp", "ArrowUp", 38, ""},
	"ArrowDown":  {"ArrowDown", "ArrowDown", 40, ""},
	"ArrowLeft":  {"ArrowLeft", "ArrowLeft", 37, ""},
	"ArrowRight": {"ArrowRight", "ArrowRight", 39, ""},
	"PageUp":     {"PageUp", "PageUp", 33, ""},
	"PageDown":   {"PageDown", "PageDown", 34, ""},
	"Home":       {"Home", "Home", 36, ""},
	"End":        {"End", "End", 35, ""},
}

// keyAliases are other names a model gives a key.
var keyAliases = map[string]string{"return": "Enter", "esc": "Escape", "up": "ArrowUp", "down": "ArrowDown",
	"left": "ArrowLeft", "right": "ArrowRight", "pgup": "PageUp", "pgdn": "PageDown", "page_up": "PageUp",
	"page_down": "PageDown", "del": "Delete", "spacebar": "Space", " ": "Space", "arrow_up": "ArrowUp",
	"arrow_down": "ArrowDown", "arrow_left": "ArrowLeft", "arrow_right": "ArrowRight"}

// KeyNamed is the key a name gives, in any case or a common other name.
func KeyNamed(name string) (string, bool) {
	n := strings.TrimSpace(name)
	if _, ok := Keys[n]; ok {
		return n, true
	}
	for k := range Keys {
		if strings.EqualFold(k, n) {
			return k, true
		}
	}
	if k, ok := keyAliases[strings.ToLower(n)]; ok {
		return k, true
	}
	return "", false
}

// KeyPress presses and releases one of Keys on whatever has focus.
func (p *Page) KeyPress(ctx context.Context, name string) error {
	k, ok := Keys[name]
	if !ok {
		return fmt.Errorf("%q is not a key this presses", name)
	}
	down := map[string]any{"type": "keyDown", "key": k.Key, "code": k.Code,
		"windowsVirtualKeyCode": k.VK, "nativeVirtualKeyCode": k.VK}
	if k.Text != "" {
		down["text"], down["unmodifiedText"] = k.Text, k.Text
	}
	if err := p.call(ctx, "Input.dispatchKeyEvent", down, nil); err != nil {
		return err
	}
	return p.call(ctx, "Input.dispatchKeyEvent", map[string]any{"type": "keyUp", "key": k.Key, "code": k.Code,
		"windowsVirtualKeyCode": k.VK, "nativeVirtualKeyCode": k.VK}, nil)
}

// Wheel turns the mouse wheel with the pointer at a point of the viewport,
// by dx and dy pixels.
func (p *Page) Wheel(ctx context.Context, x, y, dx, dy float64) error {
	return p.call(ctx, "Input.dispatchMouseEvent", map[string]any{"type": "mouseWheel", "x": x, "y": y,
		"deltaX": dx, "deltaY": dy}, nil)
}

// Hover rests the pointer on a point of the viewport.
func (p *Page) Hover(ctx context.Context, x, y float64) error {
	return p.call(ctx, "Input.dispatchMouseEvent", map[string]any{"type": "mouseMoved", "x": x, "y": y}, nil)
}

// ScrollIntoView brings an element into the viewport, if it is not.
func (p *Page) ScrollIntoView(ctx context.Context, backend int64) error {
	return p.call(ctx, "DOM.scrollIntoViewIfNeeded", map[string]any{"backendNodeId": backend}, nil)
}

// Viewport is the visible part of the page, in CSS pixels.
func (p *Page) Viewport(ctx context.Context) (w, h float64, err error) {
	var m struct {
		CSS struct {
			W float64 `json:"clientWidth"`
			H float64 `json:"clientHeight"`
		} `json:"cssVisualViewport"`
	}
	if err := p.call(ctx, "Page.getLayoutMetrics", nil, &m); err != nil {
		return 0, 0, err
	}
	if m.CSS.W <= 0 || m.CSS.H <= 0 {
		return DefaultWidth, DefaultHeight, nil
	}
	return m.CSS.W, m.CSS.H, nil
}

// Run calls one of this program's own functions in its isolated world
// (Isolated), with arguments passed as values, never as source, and reads
// back what it returns as JSON into result. A promise is waited for when
// await is set.
func (p *Page) Run(ctx context.Context, fn string, args []any, await bool, result any) error {
	world, err := p.Isolated(ctx)
	if err != nil {
		return err
	}
	var as []map[string]any
	for _, a := range args {
		as = append(as, map[string]any{"value": a})
	}
	var r struct {
		Result struct {
			Value json.RawMessage `json:"value"`
		} `json:"result"`
		Exception *struct {
			Text string `json:"text"`
		} `json:"exceptionDetails"`
	}
	params := map[string]any{"executionContextId": world, "functionDeclaration": fn, "returnByValue": true,
		"awaitPromise": await}
	if len(as) > 0 {
		params["arguments"] = as
	}
	if err := p.call(ctx, "Runtime.callFunctionOn", params, &r); err != nil {
		return err
	}
	if r.Exception != nil {
		return errors.New("the page could not be asked: " + r.Exception.Text)
	}
	if result == nil || len(r.Result.Value) == 0 {
		return nil
	}
	return json.Unmarshal(r.Result.Value, result)
}

// Focused is the element that has focus, by its backend id, or 0 when
// nothing in the page itself does.
func (p *Page) Focused(ctx context.Context) (int64, error) {
	world, err := p.Isolated(ctx)
	if err != nil {
		return 0, err
	}
	var r struct {
		Result struct {
			ObjectID string `json:"objectId"`
			Subtype  string `json:"subtype"`
		} `json:"result"`
	}
	if err := p.call(ctx, "Runtime.callFunctionOn", map[string]any{"executionContextId": world,
		"functionDeclaration": `function(){const a=document.activeElement;return a&&a!==document.body&&a!==document.documentElement?a:null}`},
		&r); err != nil {
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

// History is the tab's history: where it is and every entry.
type History struct {
	Current int            `json:"currentIndex"`
	Entries []HistoryEntry `json:"entries"`
}

// HistoryEntry is one place the tab has been, and how it got there.
type HistoryEntry struct {
	ID         int64  `json:"id"`
	URL        string `json:"url"`
	Title      string `json:"title"`
	Transition string `json:"transitionType"`
}

// History is the tab's history.
func (p *Page) History(ctx context.Context) (History, error) {
	var h History
	err := p.call(ctx, "Page.getNavigationHistory", nil, &h)
	return h, err
}

// Metrics are the page's own counters (Performance.getMetrics), by name.
func (p *Page) Metrics(ctx context.Context) (map[string]float64, error) {
	if err := p.call(ctx, "Performance.enable", nil, nil); err != nil {
		return nil, err
	}
	var r struct {
		Metrics []struct {
			Name  string  `json:"name"`
			Value float64 `json:"value"`
		} `json:"metrics"`
	}
	if err := p.call(ctx, "Performance.getMetrics", nil, &r); err != nil {
		return nil, err
	}
	out := map[string]float64{}
	for _, m := range r.Metrics {
		out[m.Name] = m.Value
	}
	return out, nil
}

// HTML is the document as it is now, serialized.
func (p *Page) HTML(ctx context.Context) (string, error) {
	var doc struct {
		Root struct {
			Backend int64 `json:"backendNodeId"`
		} `json:"root"`
	}
	if err := p.call(ctx, "DOM.getDocument", map[string]any{"depth": 0}, &doc); err != nil {
		return "", err
	}
	var r struct {
		HTML string `json:"outerHTML"`
	}
	err := p.call(ctx, "DOM.getOuterHTML", map[string]any{"backendNodeId": doc.Root.Backend}, &r)
	return r.HTML, err
}

// DefaultButton is the button Enter in a field presses, by its backend id:
// the first submit button of the form the field belongs to, as implicit
// submission picks it. 0 when the field is in no form or the form has no
// such button.
func (p *Page) DefaultButton(ctx context.Context, field int64) (int64, error) {
	world, err := p.Isolated(ctx)
	if err != nil {
		return 0, err
	}
	el, err := p.Resolve(ctx, field, world)
	if err != nil {
		return 0, err
	}
	var r struct {
		Result struct {
			ObjectID string `json:"objectId"`
			Subtype  string `json:"subtype"`
		} `json:"result"`
	}
	fn := `function(){const f=this.form;if(!f)return null;for(const e of f.elements){const t=(e.getAttribute("type")||"").toLowerCase();` +
		`if((e.tagName==="BUTTON"&&(t===""||t==="submit"))||(e.tagName==="INPUT"&&(t==="submit"||t==="image")))return e}return null}`
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
