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

	"github.com/quilzo/quilzo/internal/agent"
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

	mu    sync.Mutex
	conn  Conn
	tree  Tree
	read  bool
	focus string
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
		said, err := d.conn.Press(ctx, ref)
		if err != nil {
			return "", err
		}
		d.focus, d.read = ref, false
		out, rerr := d.readTree(ctx)
		if rerr != nil {
			return said, rerr
		}
		// What the helper said happened goes with what was pressed: a
		// model that has paid is told it paid, in the desktop's own word.
		what := "pressed " + d.treeWord(ref)
		if said != "" && said != "pressed" {
			what += " — " + said
		}
		return what + "; the screen is now " + out, nil
	case "desktop_type":
		text, _ := a.Input["text"].(string)
		if text == "" {
			return "", errors.New("desktop_type carries the text to type")
		}
		if d.focus == "" {
			return "", errors.New("nothing is focused: press a field first, by its reference")
		}
		if len(text) > 4000 {
			return "", errors.New("at most 4000 characters are typed at once")
		}
		if err := d.conn.Type(ctx, text); err != nil {
			return "", err
		}
		return fmt.Sprintf("typed into %s", d.treeWord(d.focus)), nil
	case "desktop_key":
		key := str(a, "key")
		if err := d.conn.Key(ctx, key); err != nil {
			return "", err
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

// Weighs says why a press commits to something a person should see first,
// from the tree's own word for what it is. What it cannot weigh (no
// outline read, no word) it leaves to the action, which refuses it
// without asking.
func (d *Driver) Weighs(a agent.Action) string {
	if !Performs(a) || a.Op != "desktop_press" {
		return ""
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.read {
		return ""
	}
	e, ok := d.tree.Elements[str(a, "ref")]
	if !ok || e.Consequential == "" {
		return ""
	}
	why := fmt.Sprintf("it presses %s %q in the cell, and %s", e.Role, e.Name, e.Consequential)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	d.frame(ctx, a.Op, why)
	return why
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
