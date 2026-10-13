// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agentmodel

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/agent"
)

// The whole contract of a dialect, in one test: the same model output,
// translated from a vendor's words, still cannot widen the action space —
// and the words the manifest does not hold are refused in its own
// vocabulary's terms, not the vendor's.
func TestADialectCannotWidenTheActionSpace(t *testing.T) {
	narrow := browserSession("browser_read", "browser_open")
	for _, dialect := range agent.Dialects {
		for _, tc := range []struct {
			name  string
			reply string
		}{
			{"anthropic click without the capability",
				`{"name":"left_click","input":{"coordinate":[10,10]}}`},
			{"openai click without the capability",
				`{"type":"computer_call","actions":[{"type":"click","x":10,"y":10}]}`},
		} {
			m := &fakeModel{reply: tc.reply}
			d := Decider{Model: m, Session: narrow, Dialect: dialect}.Decide()
			_, err := d(context.Background(), "buy paper", nil)
			if err == nil {
				t.Errorf("%s: the dialect %s translated a click through a manifest that holds none", tc.name, dialect)
				continue
			}
			if !strings.Contains(err.Error(), "not one of this agent's capabilities") {
				t.Errorf("%s: refused as %q, not in the vocabulary's own terms", tc.name, err)
			}
			if !strings.Contains(err.Error(), "browser_read") {
				t.Errorf("%s: the refusal does not name the closed set (%s)", tc.name, err)
			}
		}
	}
}

// Every dialect the manifest may name has a translation, and every
// translation is of a dialect the manifest may name: nothing is
// declarable that cannot be read, and nothing readable is undeclarable.
func TestEveryDialectIsTranslatableAndEveryTranslationDeclarable(t *testing.T) {
	for _, name := range agent.Dialects {
		if _, ok := dialectByName(name); !ok {
			t.Errorf("%q may be declared by a manifest and has no translation", name)
		}
	}
	for name := range dialects {
		if !strings.Contains(strings.Join(agent.Dialects, "\n"), name) {
			t.Errorf("%q is translated and may not be declared by a manifest", name)
		}
	}
}

// Each dialect reads its own maker's shapes: the four reference points of
// the plan (a click by point, a click by reference, typing, and reading),
// plus what finishes a run.
func TestEachDialectReadsItsMakersShapes(t *testing.T) {
	cases := []struct {
		dialect string
		reply   string
		op      string
		input   string // one field, as JSON, or empty for Say
		say     string
	}{
		{DialectAnthropicComputer,
			`{"name":"left_click","input":{"coordinate":[640,400]}}`,
			"browser_click", `"at":[640,400]`, ""},
		{DialectAnthropicComputer,
			`{"name":"type","input":{"text":"bond paper"}}`,
			"browser_type", `"text":"bond paper"`, ""},
		{DialectAnthropicBrowser,
			`{"name":"navigate","input":{"url":"https://shop.example.com/"}}`,
			"browser_open", `"url":"https://shop.example.com/"`, ""},
		{DialectAnthropicBrowser,
			`{"name":"left_click","input":{"target":{"type":"ref","ref":"ref_3"}}}`,
			"browser_click", `"ref":"e3"`, ""},
		{DialectAnthropicBrowser,
			`{"name":"left_click","input":{"target":{"type":"coordinate","x":31,"y":7}}}`,
			"browser_click", `"at":[31,7]`, ""},
		{DialectAnthropicBrowser,
			`{"name":"form_input","input":{"target":"e4","value":3}}`,
			"browser_type", `"ref":"e4","text":"3"`, ""},
		{DialectAnthropicBrowser,
			`{"name":"select_option","input":{"target":"e5","option":"A4"}}`,
			"browser_choose", `"ref":"e5","option":"A4"`, ""},
		{DialectOpenAIComputer,
			`{"type":"computer_call","actions":[{"type":"click","x":405,"y":157}]}`,
			"browser_click", `"at":[405,157]`, ""},
		{DialectGeminiComputer,
			`{"functionCall":{"name":"navigate","args":{"url":"https://shop.example.com/"}}}`,
			"browser_open", `"url":"https://shop.example.com/"`, ""},
		{DialectGeminiComputer,
			`{"functionCall":{"name":"done","args":{"message":"ordered"}}}`,
			"", "", "ordered"},
	}
	for _, tc := range cases {
		m := &fakeModel{reply: tc.reply}
		a, err := Decider{Model: m, Session: browserSession(agent.BrowserCapabilities[:]...),
			Dialect: tc.dialect}.Decide()(context.Background(), "buy paper", nil)
		if err != nil {
			t.Errorf("%s %s: %v", tc.dialect, tc.reply, err)
			continue
		}
		if tc.op == "" {
			if a.Say != tc.say {
				t.Errorf("%s: said %q, not %q", tc.dialect, a.Say, tc.say)
			}
			continue
		}
		if a.Op != tc.op {
			t.Errorf("%s: asked for %q and got op %q", tc.dialect, tc.reply, a.Op)
			continue
		}
		got, err := json.Marshal(a.Input)
		if err != nil {
			t.Fatal(err)
		}
		for _, field := range strings.Split(tc.input, ",") {
			if !strings.Contains(string(got), strings.TrimSpace(field)) {
				t.Errorf("%s: input %s does not carry %s", tc.dialect, got, field)
			}
		}
	}
}

// Gemini places points across a normalized screen; the translation scales
// to the screen the browser actually has, which is cdp's default.
func TestGeminiPointsAreScaledToTheBrowsersScreen(t *testing.T) {
	m := &fakeModel{reply: `{"functionCall":{"name":"click","args":{"x":500,"y":312,"intent":"the button"}}}`}
	a, err := Decider{Model: m, Session: browserSession(agent.BrowserCapabilities[:]...),
		Dialect: DialectGeminiComputer}.Decide()(context.Background(), "buy paper", nil)
	if err != nil {
		t.Fatal(err)
	}
	at, ok := a.Input["at"].([]any)
	if !ok || len(at) != 2 {
		t.Fatalf("no point in %+v", a.Input)
	}
	if at[0] != float64(500)*1280/1000 || at[1] != float64(312)*800/1000 {
		t.Errorf("the point was not scaled to 1280x800: %v", at)
	}
	// The intent is reasoning, not input; it never reaches the action.
	if _, carries := a.Input["intent"]; carries {
		t.Error("the model's reasoning travelled into the action")
	}
}

// A member with no honest translation is refused as one, never
// approximated: scroll is not a click, a right press is not a press of the
// element.
func TestAMemberWithNoHonestTranslationIsRefusedNotApproximated(t *testing.T) {
	for _, tc := range []struct{ dialect, reply string }{
		{DialectAnthropicComputer, `{"name":"scroll","input":{"scroll_direction":"down","scroll_amount":3}}`},
		{DialectAnthropicComputer, `{"name":"right_click","input":{"coordinate":[10,10]}}`},
		{DialectAnthropicBrowser, `{"name":"javascript_exec","input":{"text":"return 1"}}`},
		{DialectAnthropicBrowser, `{"name":"hover","input":{"target":"e2"}}`},
		{DialectOpenAIComputer, `{"type":"computer_call","actions":[{"type":"drag","path":[[1,2],[3,4]]}]}`},
		{DialectOpenAIComputer, `{"type":"computer_call","actions":[{"type":"keypress","keys":["CTRL","A"]}]}`},
		{DialectGeminiComputer, `{"functionCall":{"name":"scroll","args":{"direction":"down"}}}`},
	} {
		m := &fakeModel{reply: tc.reply}
		_, err := Decider{Model: m, Session: browserSession(agent.BrowserCapabilities[:]...),
			Dialect: tc.dialect}.Decide()(context.Background(), "buy paper", nil)
		if err == nil {
			t.Errorf("%s %s: was let through", tc.dialect, tc.reply)
			continue
		}
		if !strings.Contains(err.Error(), "no honest translation") {
			t.Errorf("%s %s: refused as %q", tc.dialect, tc.reply, err)
		}
	}
}

// A click that types as part of it is refused: the governed browser types
// into a field, and what a maker bundles into one gesture is two actions
// here.
func TestAClickThatTypesIsRefusedNotSplit(t *testing.T) {
	m := &fakeModel{reply: `{"name":"left_click","input":{"coordinate":[10,10],"text":"hi"}}`}
	_, err := Decider{Model: m, Session: browserSession(agent.BrowserCapabilities[:]...),
		Dialect: DialectAnthropicComputer}.Decide()(context.Background(), "buy paper", nil)
	if err == nil || !strings.Contains(err.Error(), "types only into a field") {
		t.Fatalf("a click with text to type was let through: %v", err)
	}
}

// A batch runs one action a turn, in order, without asking the model
// again, and stops at the first failure.
func TestABatchRunsOneATurnAndStopsAtTheFirstFailure(t *testing.T) {
	m := &fakeModel{reply: `{"name":"left_click","input":{"coordinate":[10,10]}}
{"name":"type","input":{"text":"hello"}}
{"name":"screenshot","input":{}}`}
	d := Decider{Model: m, Session: browserSession(agent.BrowserCapabilities[:]...),
		Dialect: DialectAnthropicComputer}.Decide()
	a, err := d(context.Background(), "buy paper", nil)
	if err != nil || a.Op != "browser_click" {
		t.Fatalf("the first of the batch: %+v %v", a, err)
	}
	seen := []agent.Observation{{From: "browser_click", Body: "pressed"}}
	a, err = d(context.Background(), "buy paper", seen)
	if err != nil || a.Op != "browser_type" || m.calls != 1 {
		t.Fatalf("the second should come from the batch, not the model: %+v %v calls=%d", a, err, m.calls)
	}
	if a.Input["text"] != "hello" {
		t.Errorf("the typed text did not arrive: %+v", a.Input)
	}
	// Typing goes where the click landed, by the driver's own focus; the
	// action names no field of its own.
	if _, has := a.Input["ref"]; has {
		t.Errorf("the typed action named a ref itself: %+v", a.Input)
	}
	// The click failed: the rest of the batch is dropped and the model is
	// asked again.
	failing := []agent.Observation{{From: "browser_type", Err: errOops, Body: "failed"}}
	a, err = d(context.Background(), "buy paper", failing)
	if err != nil || m.calls != 2 {
		t.Fatalf("after a failure the model should be asked again: %+v %v calls=%d", a, err, m.calls)
	}
}

var errOops = errOopsError{}

type errOopsError struct{}

func (errOopsError) Error() string { return "oops" }

// An answer in this program's own shape is read by its own parser, dialect
// or not: the dialect says how a model was taught to answer, not what it
// must.
func TestADialectModelMayStillAnswerInThisProgramsShape(t *testing.T) {
	m := &fakeModel{reply: `{"op":"browser_read"}`}
	a, err := Decider{Model: m, Session: browserSession(agent.BrowserCapabilities[:]...),
		Dialect: DialectOpenAIComputer}.Decide()(context.Background(), "buy paper", nil)
	if err != nil || a.Op != "browser_read" {
		t.Fatalf("%+v %v", a, err)
	}
}

// A dialect answer larger than one action's limit is refused whole, like
// any other.
func TestADialectAnswerIsBoundedLikeAnyOther(t *testing.T) {
	m := &fakeModel{reply: `{"name":"type","input":{"text":"` + strings.Repeat("x", MaxAnswer+1) + `"}}`}
	_, err := Decider{Model: m, Session: browserSession(agent.BrowserCapabilities[:]...),
		Dialect: DialectAnthropicComputer}.Decide()(context.Background(), "buy paper", nil)
	if err == nil || !strings.Contains(err.Error(), "the limit is") {
		t.Fatalf("an oversized dialect answer was not refused as one: %v", err)
	}
}

// A batch larger than the makers' runtimes ever send is a runaway, not a
// plan.
func TestABatchIsBounded(t *testing.T) {
	var lines []string
	for i := 0; i < MaxBatch+1; i++ {
		lines = append(lines, `{"name":"screenshot","input":{}}`)
	}
	m := &fakeModel{reply: strings.Join(lines, "\n")}
	_, err := Decider{Model: m, Session: browserSession(agent.BrowserCapabilities[:]...),
		Dialect: DialectAnthropicComputer}.Decide()(context.Background(), "buy paper", nil)
	if err == nil || !strings.Contains(err.Error(), "run as one batch") {
		t.Fatalf("an oversized batch was not refused as one: %v", err)
	}
}

// A reference that names nothing the outline gave is refused: page text
// cannot invent an element.
func TestAReferenceThatNamesNothingIsRefused(t *testing.T) {
	for _, ref := range []string{"send-money", "", "e"} {
		m := &fakeModel{reply: `{"name":"left_click","input":{"target":{"type":"ref","ref":"` + ref + `"}}}`}
		_, err := Decider{Model: m, Session: browserSession(agent.BrowserCapabilities[:]...),
			Dialect: DialectAnthropicBrowser}.Decide()(context.Background(), "buy paper", nil)
		if err == nil {
			t.Errorf("reference %q was accepted", ref)
		}
	}
}

// The prompt tells the model the shape of its own dialect's answer, and
// only when one is declared.
func TestThePromptTeachesTheDialectItDeclares(t *testing.T) {
	m := &fakeModel{reply: `{"name":"screenshot","input":{}}`}
	_, _ = Decider{Model: m, Session: browserSession(agent.BrowserCapabilities[:]...),
		Dialect: DialectAnthropicComputer}.Decide()(context.Background(), "buy paper", nil)
	if !strings.Contains(m.system, `"name":"left_click"`) || !strings.Contains(m.system, "browser_look") {
		t.Errorf("the prompt does not teach the anthropic-computer shape:\n%s", m.system)
	}
	plain := &fakeModel{reply: `{"op":"browser_read"}`}
	_, _ = Decider{Model: plain, Session: browserSession(agent.BrowserCapabilities[:]...)}.Decide()(
		context.Background(), "buy paper", nil)
	if strings.Contains(plain.system, "dialect") || strings.Contains(plain.system, "computer_call") {
		t.Error("a model with no dialect declared was taught a shape")
	}
}
