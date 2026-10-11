// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agentmodel

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/cdp"
)

// Vendor dialects: how another maker's model answers when it has been
// trained to speak computer use in its maker's own words — Anthropic's
// computer and browser toolsets, OpenAI's computer actions, Gemini's
// computer use — translated onto this program's actions before anything
// else happens to them.
//
// What an adapter is NOT: a way for a model to do more. Every translated
// action lands in the same closed vocabulary the manifest holds, passes
// the same session gate, the same breaker, the same ask-first with the
// same picture of what it will press. A dialect that asks for something
// the vocabulary has no word for is refused with that vocabulary's own
// message, because "your word for it" and "permission to do it" were never
// the same thing. The tables below say no more than they say yes: a
// member with no honest translation is refused, never approximated —
// scroll is not a click, and a right click is not a click.
//
// What an adapter adds that parsing does not: a model answering in a
// dialect may return several actions at once, as its maker's runtime
// taught it to. They become a queue, performed one per step in order
// while each succeeds; the first failure drops the rest, which is what
// the maker's own runtimes do.

// The dialect names a manifest may declare. The list itself is
// agent.Dialects, where manifest validation is; a test holds the
// translations here to that list, so nothing is declarable that cannot be
// read.
const (
	DialectAnthropicComputer = "anthropic-computer"
	DialectAnthropicBrowser  = "anthropic-browser"
	DialectOpenAIComputer    = "openai-computer"
	DialectGeminiComputer    = "gemini-computer"
)

// dialectByName is the table of tables.
func dialectByName(name string) (dialect, bool) {
	d, ok := dialects[name]
	return d, ok
}

type dialect struct {
	// answer is the paragraph the prompt adds: the exact shape this model
	// is asked to return, in its own maker's terms.
	answer string
	// members maps the dialect's member name to its translation. Nil is a
	// member that exists in the dialect and has no honest translation.
	members map[string]member
}

// member translates one call of a dialect into this program's terms.
type member struct {
	op string
	// input builds the action's input from the call's parameters.
	input func(p params) (map[string]any, error)
	// say marks a member that finishes the run rather than acting.
	say func(p params) (string, error)
}

// params is what the dialect's call carried, after the JSON was read.
type params map[string]any

func (p params) str(k string) string {
	s, _ := p[k].(string)
	return strings.TrimSpace(s)
}

func (p params) num(k string) (float64, bool) {
	f, ok := p[k].(float64)
	return f, ok
}

var dialects = map[string]dialect{
	DialectAnthropicComputer: anthropicComputer(),
	DialectAnthropicBrowser:  anthropicBrowser(),
	DialectOpenAIComputer:    openAIComputer(),
	DialectGeminiComputer:    geminiComputer(),
}

// anthropicComputer is the computer toolset's members (the 2026 toolset,
// computer_toolset_20260801 and the single-tool versions before it): a
// screen, a pointer and a keyboard, speaking in screenshot pixels.
func anthropicComputer() dialect {
	click := func(p params) (map[string]any, error) {
		x, y, err := p.point("coordinate")
		if err != nil {
			return nil, fmt.Errorf("the governed browser presses an element of the page, and this click named no point to find one at: %v", err)
		}
		if p.str("text") != "" {
			return nil, errors.New("the governed browser types only into a field, by its own reference or the one last pressed, never as part of a click: type separately after pressing")
		}
		return map[string]any{"at": []any{x, y}}, nil
	}
	typ := func(p params) (map[string]any, error) {
		return map[string]any{"text": p.str("text")}, nil
	}
	return dialect{
		answer: "Answer with one JSON object per action, on one line each: " +
			`{"name":"left_click","input":{"coordinate":[640,400]}}` + " — " +
			"the members are left_click, double_click, type and screenshot. " +
			"A click takes a [x, y] of the picture you were shown; type goes " +
			"into the field last pressed; screenshot is browser_look. Several " +
			"objects may be given, and they run in order while each succeeds.",
		members: map[string]member{
			"left_click":   {op: "browser_click", input: click},
			"double_click": {op: "browser_click", input: click},
			"triple_click": {op: "browser_click", input: click},
			"type":         {op: "browser_type", input: typ},
			"screenshot":   {op: "browser_look"},
			// No honest translation: the governed browser has no cursor to
			// move, no keys to hold, no zoom, and a right or middle press is
			// not a press of the element.
			"right_click": {}, "middle_click": {}, "mouse_move": {},
			"left_click_drag": {}, "left_mouse_down": {}, "left_mouse_up": {},
			"cursor_position": {}, "scroll": {}, "key": {}, "hold_key": {},
			"wait": {}, "zoom": {},
		},
	}
}

// anthropicBrowser is the browser toolset's members
// (browser_toolset_20260801): a page read as structure, elements named by
// short references — the same shape this program's outline already is.
func anthropicBrowser() dialect {
	return dialect{
		answer: "Answer with one JSON object per action, on one line each: " +
			`{"name":"navigate","input":{"url":"https://…"}}` + " — " +
			"the members are navigate, read_page, find, get_page_text, " +
			"screenshot, form_input, select_option, left_click, double_click, " +
			"triple_click and type. An element is named by its reference from " +
			"the last read ({\"type\":\"ref\",\"ref\":\"e12\"} or \"e12\"); " +
			"form_input takes target and value; type goes into the field last " +
			"pressed. Several objects may be given, and they run in order " +
			"while each succeeds.",
		members: map[string]member{
			"navigate":      {op: "browser_open", input: urlParam},
			"read_page":     {op: "browser_read"},
			"find":          {op: "browser_read"},
			"get_page_text": {op: "browser_read"},
			"screenshot":    {op: "browser_look"},
			"form_input":    {op: "browser_type", input: formInput},
			"select_option": {op: "browser_choose", input: func(p params) (map[string]any, error) {
				ref, at, err := p.targetAt("target")
				if err != nil {
					return nil, err
				}
				if at != nil {
					return nil, errors.New("select_option named a point, and the governed browser chooses in a list it names by reference")
				}
				return map[string]any{"ref": ref, "option": p.str("option")}, nil
			}},
			"left_click":   {op: "browser_click", input: clickTarget("target")},
			"double_click": {op: "browser_click", input: clickTarget("target")},
			"triple_click": {op: "browser_click", input: clickTarget("target")},
			"type": {op: "browser_type", input: func(p params) (map[string]any, error) {
				return map[string]any{"text": p.str("text")}, nil
			}},
			// The governed browser has one page, no tabs, no console to
			// read, no script of the page's to run, and hovers nothing.
			"right_click": {}, "middle_click": {}, "hover": {}, "scroll": {},
			"scroll_to": {}, "mouse_move": {}, "left_click_drag": {},
			"left_mouse_down": {}, "left_mouse_up": {}, "key": {},
			"hold_key": {}, "wait": {}, "new_tab": {}, "list_tabs": {},
			"switch_tab": {}, "close_tab": {}, "file_upload": {},
			"read_console": {}, "read_network": {}, "javascript_exec": {},
		},
	}
}

// openAIComputer is the Responses API's computer tool: a batched,
// ordered list of actions in screenshot pixels.
func openAIComputer() dialect {
	return dialect{
		answer: "Answer with one JSON object: " +
			`{"type":"computer_call","actions":[{"type":"click","x":640,"y":400}]}` +
			" — the members are click, double_click, type and screenshot. " +
			"A click takes x and y of the picture you were shown; type goes " +
			"into the field last clicked. The actions run in order while each " +
			"succeeds, and the first failure stops the rest.",
		members: map[string]member{
			"click": {op: "browser_click", input: func(p params) (map[string]any, error) {
				if b := p.str("button"); b != "" && b != "left" {
					return nil, fmt.Errorf("a %s press is not a press of the element, and the governed browser presses elements", b)
				}
				return p.atXY()
			}},
			"double_click": {op: "browser_click", input: func(p params) (map[string]any, error) {
				return p.atXY()
			}},
			"type": {op: "browser_type", input: func(p params) (map[string]any, error) {
				return map[string]any{"text": p.str("text")}, nil
			}},
			"screenshot": {op: "browser_look"},
			// No honest translation, for the reasons the computer toolset's
			// table gives; a drag is not a click, a wheel press is not one,
			// and a keystroke is not a field.
			"drag": {}, "move": {}, "scroll": {}, "keypress": {}, "wait": {},
		},
	}
}

// geminiComputer is Gemini's computer use: actions in a screen normalized
// to a thousand by a thousand, scaled here to the screen the browser has.
func geminiComputer() dialect {
	at := func(p params) (map[string]any, error) {
		x, okx := p.num("x")
		y, oky := p.num("y")
		if !okx || !oky {
			return nil, errors.New("this action named no point to find an element at")
		}
		if x < 0 || x > 999 || y < 0 || y > 999 {
			return nil, fmt.Errorf("a point is placed from 0 to 999 across the screen; this one was (%v, %v)", x, y)
		}
		return map[string]any{"at": []any{x * cdp.DefaultWidth / 1000, y * cdp.DefaultHeight / 1000}}, nil
	}
	return dialect{
		answer: "Answer with one JSON object per action: " +
			`{"functionCall":{"name":"click","args":{"x":500,"y":312,"intent":"…"}}}` +
			" — the names are navigate, click, double_click, triple_click, " +
			"type, take_screenshot and done. A point is placed 0–999 across " +
			"and down the screen; type goes into the field last clicked; " +
			"done ends the run, with the answer in its message.",
		members: map[string]member{
			"navigate":     {op: "browser_open", input: urlParam},
			"click":        {op: "browser_click", input: at},
			"double_click": {op: "browser_click", input: at},
			"triple_click": {op: "browser_click", input: at},
			"type": {op: "browser_type", input: func(p params) (map[string]any, error) {
				return map[string]any{"text": p.str("text")}, nil
			}},
			"take_screenshot": {op: "browser_look"},
			"done":            {say: func(p params) (string, error) { return p.str("message"), nil }},
			// The rest of Gemini's browser namespace has no honest
			// translation; see the computer toolset's table for why each
			// kind is refused rather than approximated.
			"right_click": {}, "middle_click": {}, "mouse_down": {},
			"mouse_up": {}, "move": {}, "drag_and_drop": {}, "wait": {},
			"press_key": {}, "key_down": {}, "key_up": {}, "hotkey": {},
			"scroll": {}, "go_back": {}, "go_forward": {}, "cancel": {},
			"open_app": {}, "list_apps": {}, "long_press": {},
		},
	}
}

func urlParam(p params) (map[string]any, error) {
	u := p.str("url")
	if u == "" {
		return nil, errors.New("this action named no address to open")
	}
	return map[string]any{"url": u}, nil
}

// clickTarget builds the input for a press of an element named by target.
func clickTarget(key string) func(params) (map[string]any, error) {
	return func(p params) (map[string]any, error) {
		ref, at, err := p.targetAt(key)
		if err != nil {
			return nil, err
		}
		if at != nil {
			return map[string]any{"at": at}, nil
		}
		return map[string]any{"ref": ref}, nil
	}
}

// formInput fills a field, as form_input: a target and a value.
func formInput(p params) (map[string]any, error) {
	ref, at, err := p.targetAt("target")
	if err != nil {
		return nil, err
	}
	if at != nil {
		return nil, errors.New("form_input named a point, and the governed browser types into a field it names by reference")
	}
	var text string
	switch v := p["value"].(type) {
	case string:
		text = v
	case float64:
		text = strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		text = strconv.FormatBool(v)
	default:
		return nil, fmt.Errorf("form_input carried a value this cannot type (%T)", p["value"])
	}
	return map[string]any{"ref": ref, "text": text}, nil
}

// point reads a [x, y] pair from a parameter.
func (p params) point(k string) (float64, float64, error) {
	list, ok := p[k].([]any)
	if !ok || len(list) != 2 {
		return 0, 0, fmt.Errorf("%s is not a [x, y] point", k)
	}
	x, okx := list[0].(float64)
	y, oky := list[1].(float64)
	if !okx || !oky {
		return 0, 0, fmt.Errorf("%s is not a [x, y] point", k)
	}
	return x, y, nil
}

// atXY reads x and y parameters as a point.
func (p params) atXY() (map[string]any, error) {
	x, okx := p.num("x")
	y, oky := p.num("y")
	if !okx || !oky {
		return nil, errors.New("this action named no point to find an element at")
	}
	return map[string]any{"at": []any{x, y}}, nil
}

// targetAt reads how a dialect names an element: a reference string
// ("e12", "ref_12", "12"), a {type: ref} object, or a {type: coordinate}
// object. The coordinate comes back as the pair to place it at.
func (p params) targetAt(k string) (string, []any, error) {
	switch t := p[k].(type) {
	case string:
		ref, err := refOf(t)
		return ref, nil, err
	case map[string]any:
		if t["type"] == "coordinate" {
			x, okx := t["x"].(float64)
			y, oky := t["y"].(float64)
			if !okx || !oky {
				return "", nil, errors.New("a coordinate target carried no point")
			}
			return "", []any{x, y}, nil
		}
		if s, ok := t["ref"].(string); ok {
			ref, err := refOf(s)
			return ref, nil, err
		}
	}
	return "", nil, fmt.Errorf("the target carried no reference the outline gave (an e-number, as the read shows)")
}

// refOf normalizes a reference to the outline's own form, e12. A dialect's
// models may write e12, ref_12 or 12; all name the twelfth element.
var reDigits = regexp.MustCompile(`\d+`)

func refOf(s string) (string, error) {
	d := reDigits.FindString(strings.TrimSpace(s))
	if d == "" || len(d) > 9 {
		return "", fmt.Errorf("%q carries no reference the outline gave (an e-number, as the read shows)", clamp(s, 60))
	}
	return "e" + d, nil
}

// call is one action of a dialect as it arrived: a name and its parameters.
type call struct {
	name   string
	params params
}

// MaxBatch is how many actions one answer may carry. The makers' runtimes
// batch small; a number in the dozens is a runaway, not a plan.
const MaxBatch = 32

// errNotThisShape says the body was readable JSON but not a call this
// dialect makes, so the caller can try the next shape before refusing.
var errNotThisShape = errors.New("not this shape")

// readCalls parses the shapes the dialects answer in: a single call
// object, a list of them, OpenAI's {type: computer_call, actions: []}, or
// Gemini's {functionCall: {name, args}}.
func readCalls(raw string) ([]call, error) {
	body := strings.TrimSpace(stripFence(raw))
	if body == "" {
		return nil, errors.New("the model returned nothing to act on")
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(body), &obj); err == nil {
		if calls, err := objectCalls(obj); err == nil {
			return calls, nil
		} else if !errors.Is(err, errNotThisShape) {
			return nil, err
		}
	}
	var list []map[string]any
	if err := json.Unmarshal([]byte(body), &list); err == nil && len(list) > 0 {
		var calls []call
		for _, m := range list {
			c, err := mapCall(m, "name", "input")
			if err != nil {
				return nil, err
			}
			calls = append(calls, c)
		}
		return calls, nil
	}
	// A line each, as the prompt asks for: several JSON objects, one to a
	// line, are a batch and not one broken document.
	if lines := strings.Split(body, "\n"); len(lines) > 1 {
		var calls []call
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var m map[string]any
			if json.Unmarshal([]byte(line), &m) != nil {
				return nil, errors.New("the model did not return an action in the shape its dialect uses")
			}
			c, err := mapCall(m, "name", "input")
			if err != nil {
				return nil, err
			}
			calls = append(calls, c)
		}
		if len(calls) > 0 {
			return calls, nil
		}
	}
	return nil, errors.New("the model did not return an action in the shape its dialect uses")
}

// objectCalls reads the single-object shapes.
func objectCalls(obj map[string]any) ([]call, error) {
	if acts, ok := obj["actions"].([]any); ok {
		var calls []call
		for _, a := range acts {
			m, _ := a.(map[string]any)
			c, err := mapCall(m, "type", "")
			if err != nil {
				if errors.Is(err, errNotThisShape) {
					return nil, errors.New("one of the actions carried no name")
				}
				return nil, err
			}
			calls = append(calls, c)
		}
		if len(calls) == 0 {
			return nil, errors.New("this answer carried an empty list of actions")
		}
		return calls, nil
	}
	if fc, ok := obj["functionCall"].(map[string]any); ok {
		c, err := mapCall(fc, "name", "args")
		if err != nil {
			return nil, err
		}
		return []call{c}, nil
	}
	if c, err := mapCall(obj, "name", "input"); err == nil {
		return []call{c}, nil
	} else if c, err := mapCall(obj, "name", "args"); err == nil {
		return []call{c}, nil
	}
	return nil, errNotThisShape
}

// mapCall reads one call object: the name from nameKey, the parameters
// from the first of paramKeys the object carries that is an object, or
// else the object's own fields beside the envelope's.
func mapCall(m map[string]any, nameKey string, paramKeys ...string) (call, error) {
	if len(m) > MaxBatch*4 {
		return call{}, errors.New("one of the actions carried more than this can read")
	}
	name, _ := m[nameKey].(string)
	if name == "" {
		return call{}, errNotThisShape
	}
	envelope := map[string]bool{nameKey: true, "type": true, "id": true, "tool_use_id": true,
		"toolset_name": true, "call_id": true, "status": true, "intent": true}
	p := params{}
	for k, v := range m {
		if !envelope[k] {
			p[k] = v
		}
	}
	for _, k := range paramKeys {
		if v, ok := m[k].(map[string]any); ok {
			p = params(v)
			break
		}
	}
	return call{name: name, params: p}, nil
}

// adaptAll translates a dialect's answer into this program's actions, in
// order, each checked against the closed vocabulary. The first action is
// performed; the rest are the queue behind it.
//
// An answer that comes back in this program's own shape ({"op": …}) is
// read by this program's own parser instead: the dialect says how a model
// was taught to answer, not what it must.
func (v vocab) adaptAll(raw, dialectName string) ([]agent.Action, error) {
	d, ok := dialectByName(dialectName)
	if !ok {
		return nil, fmt.Errorf("%q is not a dialect this program knows (%s)", dialectName, strings.Join(agent.Dialects, ", "))
	}
	calls, err := readCalls(raw)
	if err != nil {
		if a, perr := v.parse(raw); perr == nil {
			return []agent.Action{a}, nil
		}
		return nil, err
	}
	if len(calls) > MaxBatch {
		return nil, fmt.Errorf("the model returned %d actions at once; at most %d run as one batch", len(calls), MaxBatch)
	}
	var out []agent.Action
	for _, c := range calls {
		m, known := d.members[c.name]
		if !known {
			return nil, fmt.Errorf("the model asked for %q, which is not one of this agent's capabilities (%s). The list it may choose from is the manifest's, and nothing it returns can add to it",
				clamp(c.name, 60), strings.Join(sorted(v.ops), ", "))
		}
		if m.say != nil {
			say, err := m.say(c.params)
			if err != nil {
				return nil, err
			}
			out = append(out, agent.Action{Say: clamp(say, 2000)})
			continue
		}
		if m.op == "" {
			return nil, fmt.Errorf("the model asked for %q, which this program has no honest translation of onto what it governs; it is not one of this agent's capabilities (%s)",
				clamp(c.name, 60), strings.Join(sorted(v.ops), ", "))
		}
		if !v.ops[m.op] {
			return nil, fmt.Errorf("the model asked for %q, which is not one of this agent's capabilities (%s). The list it may choose from is the manifest's, and nothing it returns can add to it",
				m.op, strings.Join(sorted(v.ops), ", "))
		}
		in := map[string]any{}
		if m.input != nil {
			in, err = m.input(boundParams(c.params))
			if err != nil {
				return nil, err
			}
		}
		out = append(out, agent.Action{Op: m.op, Input: in})
	}
	return out, nil
}

// boundParams bounds a dialect's parameters, which carry shapes the native
// bound does not: a point is a list of two numbers, a target an object of
// a reference or a coordinate. Kept, one level deep and small, because a
// dialect's parameters are geometry and names, never a page; anything
// deeper or larger is dropped and the member's own translation refuses
// what is missing.
func boundParams(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	n := 0
	for k, v := range in {
		if n >= 16 {
			break
		}
		switch t := v.(type) {
		case string:
			out[clamp(k, 64)] = clamp(t, 4096)
			n++
		case float64, bool:
			out[clamp(k, 64)] = t
			n++
		case []any:
			var list []any
			for _, e := range t {
				if len(list) >= 8 {
					break
				}
				switch e := e.(type) {
				case float64, bool:
					list = append(list, e)
				case string:
					list = append(list, clamp(e, 4096))
				}
			}
			if len(list) > 0 {
				out[clamp(k, 64)] = list
				n++
			}
		case map[string]any:
			fields := map[string]any{}
			for fk, fv := range t {
				if len(fields) >= 8 {
					break
				}
				switch fv := fv.(type) {
				case string:
					fields[clamp(fk, 64)] = clamp(fv, 4096)
				case float64, bool:
					fields[clamp(fk, 64)] = fv
				}
			}
			if len(fields) > 0 {
				out[clamp(k, 64)] = fields
				n++
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
