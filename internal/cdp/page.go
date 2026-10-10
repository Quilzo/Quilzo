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

// center is the middle of an element on the screen, after scrolling it
// into view.
func (p *Page) center(ctx context.Context, backend int64) (float64, float64, error) {
	_ = p.call(ctx, "DOM.scrollIntoViewIfNeeded", map[string]any{"backendNodeId": backend}, nil)
	var q struct {
		Quads [][]float64 `json:"quads"`
	}
	if err := p.call(ctx, "DOM.getContentQuads", map[string]any{"backendNodeId": backend}, &q); err != nil {
		return 0, 0, err
	}
	if len(q.Quads) == 0 || len(q.Quads[0]) < 8 {
		return 0, 0, errors.New("the element is not on the screen")
	}
	c := q.Quads[0]
	return (c[0] + c[2] + c[4] + c[6]) / 4, (c[1] + c[3] + c[5] + c[7]) / 4, nil
}

// Click presses and releases the left button on the middle of an element,
// as a person's pointer would: the page sees an ordinary click, with the
// events a click makes, rather than a script calling click().
func (p *Page) Click(ctx context.Context, backend int64) error {
	x, y, err := p.center(ctx, backend)
	if err != nil {
		return err
	}
	for _, kind := range []string{"mouseMoved", "mousePressed", "mouseReleased"} {
		ev := map[string]any{"type": kind, "x": x, "y": y}
		if kind != "mouseMoved" {
			ev["button"], ev["clickCount"] = "left", 1
		}
		if err := p.call(ctx, "Input.dispatchMouseEvent", ev, nil); err != nil {
			return err
		}
	}
	return nil
}

// Type puts text into an element, as typing would, after focusing it.
func (p *Page) Type(ctx context.Context, backend int64, text string) error {
	if err := p.call(ctx, "DOM.focus", map[string]any{"backendNodeId": backend}, nil); err != nil {
		return err
	}
	return p.call(ctx, "Input.insertText", map[string]any{"text": text}, nil)
}

// Close closes the tab.
func (p *Page) Close(ctx context.Context) error {
	return p.b.Call(ctx, "", "Target.closeTarget", map[string]any{"targetId": p.Target}, nil)
}
