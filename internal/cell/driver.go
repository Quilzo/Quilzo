// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package cell

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/browser"
)

// The governed cell driver: an agent works a desktop cell through the
// same shape it works a browser — one action at a time, each a step of
// the run, the session's gate in front and a person asked before the
// press that commits to something.
//
// The driver holds no microVM knowledge of its own. Connect brings a cell
// up — starts the microVM from the warm snapshot and reaches the helper
// through its vsock — and everything after that is the helper's
// conversation: the tree read as an outline with references, a press
// named by reference, typing where the last press landed, four named
// keys, a picture of the screen. The helper validates a reference against
// the tree it served last, which is the same staleness check the
// browser's driver makes and the reason the two cannot drift apart in
// what they promise a model.

// Conn is the helper's conversation, as the driver sees it. The Helper in
// vsock.go is one; a test is another.
type Conn interface {
	Read(ctx context.Context) (Tree, error)
	Press(ctx context.Context, ref string) (string, error)
	Type(ctx context.Context, text string) error
	Key(ctx context.Context, key string) error
	Screen(ctx context.Context) ([]byte, error)
	Close() error
}

// Frame is a picture of the cell's screen, kept with the run as the
// browser's are.
type Frame struct {
	Op string
	// At is what the screen shows, in the helper's words.
	At string
	// Asking is why a person is being asked; empty for a picture after an
	// action. What would be pressed is named in the asking's words: the
	// tree carries no geometry to draw a box around.
	Asking string
	JPEG   []byte
}

// Driver performs the cell's actions for one run.
type Driver struct {
	Session *agent.Session
	// Connect brings the cell up on first use: the microVM from the warm
	// snapshot, then the helper through its vsock.
	Connect func(ctx context.Context) (Conn, error)
	// Frames keeps a picture of the screen after each action, and of what
	// a person is asked about. Nil keeps none.
	Frames func(Frame)
	// Picture hands a screen to a model that reads pictures. Nil means
	// this run's model reads text only.
	Picture func(jpeg []byte)

	mu   sync.Mutex
	conn Conn
	tree Tree
	read bool
	// focus is the element the last press landed on, as the outline named
	// it then; nothing after a key that moves focus.
	focus *Element
}

// Performs reports whether the driver performs an action.
func Performs(a agent.Action) bool {
	return a.Tool == "" && a.Delegate == "" && agent.IsDesktop(a.Op)
}

// Perform wraps a run's performer: the cell's actions here, the rest
// passed on.
func (d *Driver) Perform(next func(context.Context, agent.Action) (string, error)) func(context.Context, agent.Action) (string, error) {
	return func(ctx context.Context, a agent.Action) (string, error) {
		if !Performs(a) {
			return next(ctx, a)
		}
		if err := d.Session.Check(a.Op); err != nil {
			return "", err
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.conn == nil {
			if d.Connect == nil {
				return "", errors.New("this build runs no desktop cells: no way to bring one up is configured")
			}
			conn, err := d.Connect(ctx)
			if err != nil {
				return "", fmt.Errorf("bringing the cell up: %w", err)
			}
			d.conn = conn
		}
		out, err := d.perform(ctx, a)
		if err != nil {
			return out, err
		}
		// What the screen shows after each action, kept with the run; a
		// picture an action was asked about is kept by Weighs.
		if d.Frames != nil && a.Op != "desktop_look" {
			d.frame(ctx, a.Op, "")
		}
		return out, nil
	}
}

func str(a agent.Action, k string) string {
	v, _ := a.Input[k].(string)
	return strings.TrimSpace(v)
}

func (d *Driver) decl() *agent.Cell { return d.Session.Manifest().Cell }

func (d *Driver) perform(ctx context.Context, a agent.Action) (string, error) {
	switch a.Op {
	case "desktop_read":
		return d.readTree(ctx)
	case "desktop_press":
		ref := str(a, "ref")
		if ref == "" {
			return "", errors.New("desktop_press names what it presses by the reference the outline gave")
		}
		if !d.read {
			return "", errors.New("read the screen first (desktop_read): a reference names an element of the outline read last")
		}
		pressed, known := d.tree.Elements[ref]
		said, err := d.conn.Press(ctx, ref)
		if err != nil {
			return "", err
		}
		d.focus, d.read = nil, false
		if known {
			d.focus = &pressed
		}
		word := d.treeWord(ref)
		out, rerr := d.readTree(ctx)
		if rerr != nil {
			return said, rerr
		}
		// What the helper said happened goes with what was pressed: a
		// model that has paid is told it paid, in the desktop's own word.
		what := "pressed " + word
		if said != "" && said != "pressed" {
			what += " — " + said
		}
		return what + "; the screen is now " + out, nil
	case "desktop_type":
		text, _ := a.Input["text"].(string)
		if text == "" {
			return "", errors.New("desktop_type carries the text to type")
		}
		if d.focus == nil {
			return "", errors.New("nothing is focused: press a field first, by its reference")
		}
		if !typedInto[role(d.focus.Role)] {
			return "", fmt.Errorf("%s %q is not a field to type into", d.focus.Role, d.focus.Name)
		}
		if len(text) > 4000 {
			return "", errors.New("at most 4000 characters are typed at once")
		}
		// A line break or a tab in typed text is a key press by another
		// name: Enter sends, Tab moves focus. Keys are desktop_key's.
		if strings.ContainsFunc(text, controlRune) {
			return "", errors.New("typed text carries no line breaks, tabs or other control characters; press keys with desktop_key")
		}
		if err := d.conn.Type(ctx, text); err != nil {
			return "", err
		}
		return fmt.Sprintf("typed into %s %q", d.focus.Role, d.focus.Name), nil
	case "desktop_key":
		key := str(a, "key")
		if !keys[key] {
			return "", fmt.Errorf("%q is not one of Enter, Tab, Escape or Backspace", key)
		}
		if err := d.conn.Key(ctx, key); err != nil {
			return "", err
		}
		// Focus is where the host last saw it only until a key moves it.
		if key != "Backspace" {
			d.focus = nil
		}
		return "pressed " + key, nil
	case "desktop_look":
		if d.decl() == nil || !d.decl().Pictures || d.Picture == nil {
			return "", errors.New("this agent is not shown pictures of the screen")
		}
		jpg, err := d.conn.Screen(ctx)
		if err != nil {
			return "", err
		}
		d.Picture(jpg)
		return "a picture of the screen is with this message", nil
	}
	return "", fmt.Errorf("%q is not one of the cell's actions", a.Op)
}

// readTree reads the outline and says what the screen holds: app
// content, in the run's record, so the breaker knows the run has read
// somebody's words.
func (d *Driver) readTree(ctx context.Context) (string, error) {
	tree, err := d.conn.Read(ctx)
	if err != nil {
		return "", err
	}
	d.tree, d.read = tree, true
	d.Session.ReadFiles("a desktop cell's screen")
	if strings.TrimSpace(tree.Text) == "" {
		return "the screen holds nothing readable", nil
	}
	return tree.Text, nil
}

// treeWord names an element in words, for a record a person reads.
func (d *Driver) treeWord(ref string) string {
	if e, ok := d.tree.Elements[ref]; ok {
		return fmt.Sprintf("%s %q", e.Role, e.Name)
	}
	return ref
}

// Weighs says why a press or a key commits to something a person should
// see first. A press is weighed by this program from the element's role
// and name, by the browser's rule, and by the helper's word for it as
// well: the helper runs inside the cell, where what the screen shows may
// have been planted, so it can add a reason to ask and never remove one.
// Enter is always weighed, because it does whatever the focused control's
// default is. What cannot be weighed (no outline read, a reference the
// outline never gave) the action refuses without asking.
func (d *Driver) Weighs(a agent.Action) string {
	if !Performs(a) {
		return ""
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var why string
	switch {
	case a.Op == "desktop_key" && str(a, "key") == "Enter":
		where := "the focused control"
		if d.focus != nil {
			where = fmt.Sprintf("%s %q", d.focus.Role, d.focus.Name)
		}
		why = fmt.Sprintf("it presses Enter in %s, which sends or confirms whatever that control's default is", where)
	case a.Op == "desktop_press" && d.read:
		e, ok := d.tree.Elements[str(a, "ref")]
		if !ok {
			return ""
		}
		because := browser.Consequential(browser.Element{Role: role(e.Role), Name: e.Name}, false)
		// The helper's word is shown as the cell's, bounded: it can add a
		// reason to ask and is never the only thing a person reads.
		if marked := strings.TrimSpace(e.Consequential); marked != "" {
			if r := []rune(marked); len(r) > 80 {
				marked = string(r[:80])
			}
			if because != "" {
				because += "; "
			}
			because += "the cell marks it: " + marked
		}
		if because == "" {
			return ""
		}
		why = fmt.Sprintf("it presses %s %q in the cell, and %s", e.Role, e.Name, because)
	default:
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	d.frame(ctx, a.Op, why)
	return why
}

// keys are the four a model may press, as a person's are.
var keys = map[string]bool{"Enter": true, "Tab": true, "Escape": true, "Backspace": true}

// typedInto are the roles text is typed into.
var typedInto = map[string]bool{"textbox": true, "searchbox": true, "spinbutton": true, "combobox": true}

// role is an element's role in the browser's words. The helper is asked
// for those; the accessibility toolkit's own names for the same roles are
// understood as well, so a helper that passes them through is not
// misread.
func role(r string) string {
	switch strings.ToLower(strings.TrimSpace(r)) {
	case "push button", "button":
		return "button"
	case "toggle button", "switch":
		return "switch"
	case "text", "entry", "password text", "textbox":
		return "textbox"
	case "spin button", "spinbutton":
		return "spinbutton"
	case "combo box", "combobox":
		return "combobox"
	case "check box", "checkbox":
		return "checkbox"
	}
	return strings.ToLower(strings.TrimSpace(r))
}

// controlRune is a rune that acts rather than reads when typed.
func controlRune(r rune) bool {
	return unicode.IsControl(r) || r == '\u2028' || r == '\u2029'
}

// frame keeps a picture of the screen. Best effort: a screen that cannot
// be taken is not a reason to stop the run.
func (d *Driver) frame(ctx context.Context, op, asking string) {
	if d.conn == nil || d.Frames == nil {
		return
	}
	jpg, err := d.conn.Screen(ctx)
	if err != nil || len(jpg) < 4 {
		return
	}
	d.Frames(Frame{Op: op, At: d.tree.Text, Asking: asking, JPEG: jpg})
}

// Close ends the cell's conversation. The microVM is the Connect's to
// end; this ends the helper's half of it.
func (d *Driver) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn != nil {
		_ = d.conn.Close()
		d.conn = nil
	}
}
