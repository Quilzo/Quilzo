// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package browser

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/quilzo/quilzo/internal/agent"
)

// Coordinates are not a language the governed browser speaks to the model:
// they arrive only through a vendor's adapter (agentmodel), which has a
// model that was trained to aim at pixels. A point names an element the
// same way a reference does — it is resolved to an element of the outline
// read last, and everything that follows (the staleness check, what counts
// as consequential, the hit test at the moment of the press) is the
// element's own path, not the coordinate's. A page that moves something
// under a coordinate therefore meets exactly the defence a page that
// renames an element does.

// at reads a point from an action's input, as the adapter wrote it: a list
// of two numbers, x then y, in the page's own pixels.
func at(a agent.Action) (x, y float64, ok bool) {
	list, ok := a.Input["at"].([]any)
	if !ok || len(list) != 2 {
		return 0, 0, false
	}
	xf, ok1 := number(list[0])
	yf, ok2 := number(list[1])
	if !ok1 || !ok2 || xf < 0 || yf < 0 || xf > 1e5 || yf > 1e5 || math.IsNaN(xf) || math.IsNaN(yf) {
		return 0, 0, false
	}
	return xf, yf, true
}

func number(v any) (float64, bool) {
	f, ok := v.(float64)
	return f, ok
}

// clickAt presses whatever outlined element a point names, by its own
// reference once found.
func (d *Driver) clickAt(ctx context.Context, x, y float64) (string, error) {
	ref, _, err := d.elementAt(ctx, x, y)
	if err != nil {
		return "", err
	}
	return d.click(ctx, ref)
}

// elementAt is the element of the outline last read that a point is on:
// the one the page itself puts there if that is an outlined element, else
// the smallest outlined element whose quad surrounds the point. The
// smallest, because a field inside a form inside a panel names the field.
//
// Like a reference, it is only as good as the outline it is resolved
// against: the caller has read the page, and the element it returns is
// re-checked against the live page before it is used.
func (d *Driver) elementAt(ctx context.Context, x, y float64) (string, Element, error) {
	if !d.read {
		return "", Element{}, errors.New("read the page first (browser_read): a point names an element of the outline read last")
	}
	if hit, err := d.page.At(ctx, x, y); err == nil && hit != 0 {
		for ref, e := range d.outline.Elements {
			if e.Backend == hit {
				return ref, e, nil
			}
		}
	}
	best, bestArea := "", math.Inf(1)
	for ref, e := range d.outline.Elements {
		quads, err := d.page.Quads(ctx, e.Backend)
		if err != nil {
			continue
		}
		for _, q := range quads {
			if len(q) < 8 {
				continue
			}
			x0, y0, x1, y1 := q[0], q[1], q[0], q[1]
			for i := 0; i < 8; i += 2 {
				x0, x1 = min(x0, q[i]), max(x1, q[i])
				y0, y1 = min(y0, q[i+1]), max(y1, q[i+1])
			}
			if x >= x0 && x <= x1 && y >= y0 && y <= y1 {
				if a := (x1 - x0) * (y1 - y0); a < bestArea {
					best, bestArea = ref, a
				}
			}
		}
	}
	if best == "" {
		return "", Element{}, fmt.Errorf("nothing the outline offers is at (%d, %d); browser_read shows what is on the page, by reference", int(x), int(y))
	}
	return best, d.outline.Elements[best], nil
}

// focusAt is the element last pressed, for a model that types where it last
// pressed. It answers no such element and no page open, leaving the action
// to refuse it in words a model can act on.
func (d *Driver) focusAt() string {
	if !d.read || d.page == nil {
		return ""
	}
	if _, ok := d.outline.Elements[d.focus]; !ok {
		return ""
	}
	return d.focus
}

// PersonInput is one thing a person did to the page while taking a run's
// browser over: a press at a point, text typed where the page holds its
// focus, or one named key.
type PersonInput struct {
	Click []float64 `json:"click,omitempty"`
	Type  string    `json:"type,omitempty"`
	Key   string    `json:"key,omitempty"`
}

// Person performs a person's own input on the page.
//
// No session check, no outline, no weighing: the person is not the agent,
// and nothing they do is the agent's doing — the caller records it as
// theirs. What still holds is everything that holds the page itself: the
// request rule, the proxy, the box, because those bind the browser, not
// the hand on it. A take-over is a hand on the governed browser, not a
// way out of it.
func (d *Driver) Person(ctx context.Context, in PersonInput) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.page == nil {
		return errors.New("no page is open to take over")
	}
	switch {
	case len(in.Click) == 2:
		if in.Click[0] < 0 || in.Click[1] < 0 || in.Click[0] > 1e5 || in.Click[1] > 1e5 {
			return fmt.Errorf("(%v, %v) is not a point on the page", in.Click[0], in.Click[1])
		}
		return d.page.PersonClick(ctx, in.Click[0], in.Click[1])
	case strings.TrimSpace(in.Type) != "":
		return d.page.PersonType(ctx, in.Type)
	case in.Key != "":
		return d.page.PersonKey(ctx, in.Key)
	}
	return errors.New("nothing to do: a point to press, text to type, or a key to press")
}
