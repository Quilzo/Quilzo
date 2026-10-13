// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package cell

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
)

// fakeCell is a desktop as a test wants it: an outline with a menu, a
// field, and a button that pays.
type fakeCell struct {
	read    int
	presses []string
	typed   []string
	keys    []string
	// keyCalls counts every key the helper was asked to press, refused or
	// not.
	keyCalls int
	// payRef is the reference of the consequential press.
	payRef string
	closed bool
}

func (f *fakeCell) Read(context.Context) (Tree, error) {
	f.read++
	return Tree{
		Text: "File — New, Open, Save\n[1] Order total field \"Amount\"\n[2] button \"Pay now\"",
		Elements: map[string]Element{
			"e1": {Ref: "e1", Role: "textbox", Name: "Amount"},
			"e2": {Ref: "e2", Role: "button", Name: "Pay now", Consequential: "it pays"},
			"e3": {Ref: "e3", Role: "push button", Name: "Send report"},
			"e4": {Ref: "e4", Role: "menu item", Name: "Open"},
		},
	}, nil
}

func (f *fakeCell) Press(_ context.Context, ref string) (string, error) {
	if ref != "e1" && ref != "e2" && ref != "e3" && ref != "e4" {
		return "", errors.New(ref + " is not on the outline read last")
	}
	f.presses = append(f.presses, ref)
	if ref == f.payRef {
		return "paid", nil
	}
	return "pressed", nil
}

func (f *fakeCell) Type(_ context.Context, text string) error {
	f.typed = append(f.typed, text)
	return nil
}
func (f *fakeCell) Key(_ context.Context, key string) error {
	f.keyCalls++
	if key != "Enter" && key != "Tab" && key != "Escape" && key != "Backspace" {
		return errors.New(key + " is not one of Enter, Tab, Escape or Backspace")
	}
	f.keys = append(f.keys, key)
	return nil
}
func (f *fakeCell) Screen(context.Context) ([]byte, error) {
	return []byte{0xFF, 0xD8, 1, 2, 3}, nil
}
func (f *fakeCell) Close() error { f.closed = true; return nil }

func cellAgent(pictures bool) agent.Manifest {
	caps := []string{"desktop_read", "desktop_press", "desktop_type", "desktop_key"}
	if pictures {
		caps = append(caps, "desktop_look")
	}
	return agent.Manifest{Name: "clerk", Kind: agent.KindTask, Purpose: "work the ledger app",
		Capabilities: caps, Autonomy: agent.AutonomyDraft,
		Cell:   &agent.Cell{Pictures: pictures},
		Budget: agent.Budget{Steps: 20, Duration: agent.Duration(time.Minute)}}
}

func cellDriver(t *testing.T, pictures bool) (*Driver, *fakeCell, *[]Frame) {
	t.Helper()
	fc := &fakeCell{payRef: "e2"}
	s := agent.NewSession(cellAgent(pictures), nil)
	var frames []Frame
	d := &Driver{Session: s,
		Connect: func(context.Context) (Conn, error) { return fc, nil },
		Frames:  func(fr Frame) { frames = append(frames, fr) },
		Picture: func([]byte) {},
	}
	t.Cleanup(d.Close)
	return d, fc, &frames
}

func perform(t *testing.T, d *Driver, a agent.Action) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return d.Perform(func(context.Context, agent.Action) (string, error) {
		return "", errors.New("not the cell's")
	})(ctx, a)
}

// The cell is worked as the browser is: read the outline, press by
// reference, type where the press landed — and nothing before the read.
func TestACellIsWorkedThroughItsOutline(t *testing.T) {
	d, fc, frames := cellDriver(t, false)
	if _, err := perform(t, d, agent.Action{Op: "desktop_press", Input: map[string]any{"ref": "e2"}}); err == nil {
		t.Fatal("a press before any read was not refused")
	}
	out, err := perform(t, d, agent.Action{Op: "desktop_read"})
	if err != nil || !strings.Contains(out, "Pay now") {
		t.Fatalf("the outline did not come back: %v\n%s", err, out)
	}
	if d.Session.Reads() == 0 {
		t.Error("reading the screen did not mark the run as having read somebody's words")
	}
	out, err = perform(t, d, agent.Action{Op: "desktop_press", Input: map[string]any{"ref": "e1"}})
	if err != nil || !strings.Contains(out, `textbox "Amount"`) {
		t.Fatalf("the press did not land by reference: %v\n%s", err, out)
	}
	if out, err = perform(t, d, agent.Action{Op: "desktop_type", Input: map[string]any{"text": "4210.00"}}); err != nil {
		t.Fatalf("typing where the press landed: %v", err)
	} else if !strings.Contains(out, "Amount") || len(fc.typed) != 1 {
		t.Fatalf("the text did not go where the press landed: %s", out)
	}
	if _, err := perform(t, d, agent.Action{Op: "desktop_press", Input: map[string]any{"ref": "e9"}}); err == nil {
		t.Fatal("a reference the outline never gave was pressed")
	}
	if len(*frames) == 0 {
		t.Error("no picture of the screen was kept with the run")
	}
}

// The press that pays is weighed from the tree's own word for it, and the
// picture kept of what a person is asked about says why in its words.
func TestThePressThatPaysAsksAPersonFirst(t *testing.T) {
	d, _, frames := cellDriver(t, false)
	if _, err := perform(t, d, agent.Action{Op: "desktop_read"}); err != nil {
		t.Fatal(err)
	}
	why := d.Weighs(agent.Action{Op: "desktop_press", Input: map[string]any{"ref": "e2"}})
	if !strings.Contains(why, `button "Pay now"`) || !strings.Contains(why, "it pays") {
		t.Fatalf("the consequential press was not weighed as one: %q", why)
	}
	asked := false
	for _, f := range *frames {
		if f.Asking == why {
			asked = true
		}
	}
	if !asked {
		t.Errorf("the person was not shown the screen they are asked about: %q", why)
	}
	if other := d.Weighs(agent.Action{Op: "desktop_press", Input: map[string]any{"ref": "e1"}}); other != "" {
		t.Errorf("an ordinary press was weighed as consequential: %q", other)
	}
}

// Pictures are behind their own door: a look without the declaration's
// word for it is refused, and with it the model is handed the screen.
func TestAPictureIsBehindItsOwnDoor(t *testing.T) {
	d, _, _ := cellDriver(t, false)
	if _, err := perform(t, d, agent.Action{Op: "desktop_look"}); err == nil {
		t.Fatal("a look without pictures in the declaration was served")
	}
	d2, _, _ := cellDriver(t, true)
	if out, err := perform(t, d2, agent.Action{Op: "desktop_look"}); err != nil || !strings.Contains(out, "picture") {
		t.Fatalf("the look: %v %s", err, out)
	}
}

// The four keys, by name, and no other.
func TestTheKeysAreNamedOrRefused(t *testing.T) {
	d, fc, _ := cellDriver(t, false)
	if _, err := perform(t, d, agent.Action{Op: "desktop_key", Input: map[string]any{"key": "Enter"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := perform(t, d, agent.Action{Op: "desktop_key", Input: map[string]any{"key": "ctrl+z"}}); err == nil {
		t.Fatal("an unnamed key was sent")
	}
	if len(fc.keys) != 1 || fc.keys[0] != "Enter" {
		t.Fatalf("keys sent: %v", fc.keys)
	}
	if fc.keyCalls != 1 {
		t.Errorf("a key outside the four reached the helper: %d asked", fc.keyCalls)
	}
}

// What a press commits to is weighed by this program from the element's
// own role and name, whatever the helper inside the cell says about it:
// a helper that marks nothing does not make a press that sends ordinary.
// Enter is always weighed, because it does what the focused control does.
func TestTheHostWeighsWhatTheHelperDidNot(t *testing.T) {
	d, _, _ := cellDriver(t, false)
	if _, err := perform(t, d, agent.Action{Op: "desktop_read"}); err != nil {
		t.Fatal(err)
	}
	why := d.Weighs(agent.Action{Op: "desktop_press", Input: map[string]any{"ref": "e3"}})
	if !strings.Contains(why, `"Send report"`) {
		t.Fatalf("a press called Send was not weighed: %q", why)
	}
	if why := d.Weighs(agent.Action{Op: "desktop_press", Input: map[string]any{"ref": "e4"}}); why != "" {
		t.Errorf("an ordinary menu item was weighed: %q", why)
	}
	if why := d.Weighs(agent.Action{Op: "desktop_key", Input: map[string]any{"key": "Enter"}}); !strings.Contains(why, "Enter") {
		t.Errorf("Enter was not weighed: %q", why)
	}
	if why := d.Weighs(agent.Action{Op: "desktop_key", Input: map[string]any{"key": "Tab"}}); why != "" {
		t.Errorf("Tab was weighed: %q", why)
	}
}

// Text goes only into a field, carries no key presses of its own, and
// goes nowhere once a key has moved focus somewhere this program did not
// see.
func TestTypingGoesOnlyIntoAField(t *testing.T) {
	d, fc, _ := cellDriver(t, false)
	if _, err := perform(t, d, agent.Action{Op: "desktop_read"}); err != nil {
		t.Fatal(err)
	}
	typeIt := func(text string) error {
		_, err := perform(t, d, agent.Action{Op: "desktop_type", Input: map[string]any{"text": text}})
		return err
	}
	if _, err := perform(t, d, agent.Action{Op: "desktop_press", Input: map[string]any{"ref": "e4"}}); err != nil {
		t.Fatal(err)
	}
	if err := typeIt("rm -rf"); err == nil {
		t.Fatal("text was typed into a menu item")
	}
	if _, err := perform(t, d, agent.Action{Op: "desktop_press", Input: map[string]any{"ref": "e1"}}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"4210\n", "a\tb", "x\u2028y", "\x1b[2J"} {
		if err := typeIt(bad); err == nil {
			t.Errorf("%q was typed with a key press inside it", bad)
		}
	}
	if err := typeIt("4210.00"); err != nil {
		t.Fatalf("plain text into the field: %v", err)
	}
	if _, err := perform(t, d, agent.Action{Op: "desktop_key", Input: map[string]any{"key": "Tab"}}); err != nil {
		t.Fatal(err)
	}
	if err := typeIt("more"); err == nil {
		t.Fatal("text was typed after Tab moved focus somewhere unseen")
	}
	if len(fc.typed) != 1 || fc.typed[0] != "4210.00" {
		t.Fatalf("typed: %q", fc.typed)
	}
}
