// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package browser

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
)

// A point is read only as a place to find an element at, and anything
// that is not a small pair of non-negative numbers is not one.
func TestAPointIsReadAsAPlaceAndNothingElse(t *testing.T) {
	for _, tc := range []struct {
		input map[string]any
		ok    bool
	}{
		{map[string]any{"at": []any{float64(10), float64(20)}}, true},
		{map[string]any{"at": []any{float64(0), float64(0)}}, true},
		{map[string]any{"at": []any{"10", "20"}}, false},
		{map[string]any{"at": []any{float64(10)}}, false},
		{map[string]any{"at": []any{float64(10), float64(20), float64(30)}}, false},
		{map[string]any{"at": []any{float64(-1), float64(20)}}, false},
		{map[string]any{"at": "10,20"}, false},
		{map[string]any{}, false},
	} {
		if _, _, ok := at(agent.Action{Input: tc.input}); ok != tc.ok {
			t.Errorf("%v: ok=%v, wanted %v", tc.input["at"], ok, tc.ok)
		}
	}
}

// pointed is a page whose controls sit at known places, so a coordinate
// can be aimed at one of them exactly.
func pointed(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<!doctype html><title>Pointed</title><body style="margin:0">`+
			`<input id=q aria-label="Query" style="position:absolute;left:40px;top:20px;width:200px;height:30px">`+
			`<button id=go style="position:absolute;left:40px;top:80px;width:120px;height:40px">Search</button>`+
			`<button id=pay style="position:absolute;left:40px;top:160px;width:120px;height:40px">Pay now</button>`+
			`<div style="position:absolute;left:40px;top:400px;width:50px;height:20px">plain text</div>`)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return "http://" + ln.Addr().String()
}

// A click by coordinate is the element's own press: it resolves to the
// outlined element at that point and answers as pressing that element
// does, with the page's outline after it.
func TestAClickByPointPressesTheElementThere(t *testing.T) {
	s := agent.NewSession(pointer(), nil)
	d, _ := newDriver(t, s)
	out := must(t, d, act("browser_open", "url", pointed(t)+"/"))
	out = must(t, d, act("browser_read"))
	if !strings.Contains(out, "Search") {
		t.Fatalf("the page did not read:\n%s", out)
	}
	// The Search button's middle: 40+60 by 80+20.
	out = must(t, d, agent.Action{Op: "browser_click", Input: map[string]any{"at": []any{float64(100), float64(100)}}})
	if !strings.Contains(out, `pressed button "Search"`) {
		t.Errorf("a point on the Search button did not press it:\n%s", out)
	}
	// Empty space, or plain text: nothing to press, and the refusal says
	// what to do instead.
	_, err := perform(t, d, agent.Action{Op: "browser_click", Input: map[string]any{"at": []any{float64(600), float64(500)}}})
	if err == nil || !strings.Contains(err.Error(), "browser_read") {
		t.Errorf("a point on nothing was not refused as one: %v", err)
	}
}

// A press by point is weighed as the element it names: the one that pays
// asks a person, with a picture of that element outlined, exactly as a
// press by reference does.
func TestAPressByPointIsWeighedAsTheElementItNames(t *testing.T) {
	s := agent.NewSession(pointer(), nil)
	d, frames := newDriver(t, s)
	must(t, d, act("browser_open", "url", pointed(t)+"/"))
	must(t, d, act("browser_read"))
	why := d.Weighs(agent.Action{Op: "browser_click", Input: map[string]any{"at": []any{float64(100), float64(180)}}})
	if !strings.Contains(why, `presses button "Pay now"`) || !strings.Contains(why, `it is called "Pay now"`) {
		t.Errorf("a point on Pay now was not weighed as the consequential press it is: %q", why)
	}
	asked := false
	for _, f := range *frames {
		if f.Asking == why {
			asked = true
		}
	}
	if !asked {
		t.Errorf("the person was not shown the press: %q", why)
	}
	if other := d.Weighs(agent.Action{Op: "browser_click", Input: map[string]any{"at": []any{float64(100), float64(100)}}}); other != "" {
		t.Errorf("a point on Search was weighed as something: %q", other)
	}
}

// A model that types where it last pressed is served by the driver's own
// focus: the press names the field, and the typing re-checks it as any
// reference is re-checked. With nothing pressed, or after a page is
// opened, it is refused in words that say what to do.
func TestTypingGoesWhereTheLastPressLanded(t *testing.T) {
	s := agent.NewSession(pointer(), nil)
	d, _ := newDriver(t, s)
	must(t, d, act("browser_open", "url", pointed(t)+"/"))
	must(t, d, act("browser_read"))
	_, err := perform(t, d, act("browser_type", "text", "paper"))
	if err == nil || !strings.Contains(err.Error(), "no field is focused") {
		t.Fatalf("typing with nothing pressed was not refused as one: %v", err)
	}
	// Press the query field by its point, then type without naming it.
	out := must(t, d, agent.Action{Op: "browser_click", Input: map[string]any{"at": []any{float64(100), float64(35)}}})
	if !strings.Contains(out, `pressed textbox "Query"`) {
		t.Fatalf("the field was not pressed:\n%s", out)
	}
	out = must(t, d, act("browser_type", "text", "bond paper"))
	if !strings.Contains(out, `typed into`) || !strings.Contains(out, `"Query"`) {
		t.Errorf("the text did not go where the press landed:\n%s", out)
	}
	// A new page forgets where anything was.
	must(t, d, act("browser_open", "url", pointed(t)+"/other"))
	must(t, d, act("browser_read"))
	if _, err := perform(t, d, act("browser_type", "text", "again")); err == nil || !strings.Contains(err.Error(), "no field is focused") {
		t.Errorf("a focus survived a new page: %v", err)
	}
}

// The smallest outlined element at a point is the one named: a field
// inside a panel is the field, not the panel around it.
func TestTheSmallestElementAtAPointIsNamed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<!doctype html><title>Nest</title>`+
			`<div style="position:absolute;left:0;top:0;width:600px;height:600px" role="group" aria-label="panel">`+
			`<input id=q aria-label="Deep query" style="position:absolute;left:100px;top:100px;width:200px;height:30px"></div>`)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	s := agent.NewSession(pointer(), nil)
	d, _ := newDriver(t, s)
	must(t, d, act("browser_open", "url", "http://"+ln.Addr().String()+"/"))
	out := must(t, d, act("browser_read"))
	if !strings.Contains(out, "Deep query") {
		t.Fatalf("the field is not on the outline:\n%s", out)
	}
	out = must(t, d, agent.Action{Op: "browser_click", Input: map[string]any{"at": []any{float64(200), float64(115)}}})
	if !strings.Contains(out, `pressed textbox "Deep query"`) {
		t.Errorf("the point named the panel around the field:\n%s", out)
	}
}

func pointer() agent.Manifest {
	return agent.Manifest{Name: "pointer", Kind: agent.KindTask, Purpose: "press what it is shown",
		Capabilities: agent.BrowserCapabilities, Autonomy: agent.AutonomyDraft,
		Browser: &agent.Browser{Read: []string{"127.0.0.1"}, Pictures: true},
		Budget:  agent.Budget{Steps: 40, Duration: agent.Duration(5 * time.Minute)}}
}

// A person taking over works the page with their own hands: a press at a
// point, typing where the page holds focus, one named key. What they do is
// what lands — no hit test, no element — and nothing of it is weighed or
// gated, because the person is not the agent; the page's own rule still
// binds their hands.
func TestAPersonTakesThePageOver(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprintf(w, `<!doctype html><title>Over</title>`+
				`<form action="/go"><input id=q name=q aria-label="Ask" style="position:absolute;left:40px;top:20px;width:200px;height:30px"></form>`)
		case "/go":
			fmt.Fprintf(w, `<!doctype html><title>Done</title><h1>You said %s</h1>`, r.URL.Query().Get("q"))
		}
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	s := agent.NewSession(pointer(), nil)
	d, _ := newDriver(t, s)
	must(t, d, act("browser_open", "url", "http://"+ln.Addr().String()+"/"))
	must(t, d, act("browser_read"))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// A press on the field, then typing, then Enter: the person's own
	// submit, by their own key.
	if err := d.Person(ctx, PersonInput{Click: []float64{100, 35}}); err != nil {
		t.Fatal(err)
	}
	if err := d.Person(ctx, PersonInput{Type: "hello by hand"}); err != nil {
		t.Fatal(err)
	}
	if err := d.Person(ctx, PersonInput{Key: "Enter"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(600 * time.Millisecond)
	out := must(t, d, act("browser_read"))
	if !strings.Contains(out, "You said hello by hand") {
		t.Errorf("the person's hands did not reach the page:\n%s", out)
	}
	// A key this cannot name exactly is refused rather than guessed at.
	if err := d.Person(ctx, PersonInput{Key: "ctrl+z"}); err == nil {
		t.Error("an unnamed key was sent")
	}
	// Nothing to do is an error, not a silent no-op.
	if err := d.Person(ctx, PersonInput{}); err == nil {
		t.Error("empty input was accepted")
	}
}
