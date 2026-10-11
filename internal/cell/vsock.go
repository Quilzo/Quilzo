// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package cell

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// The helper inside the cell, and the conversation with it.
//
// The only door into a cell is its vsock. The host side of that is a Unix
// socket the microVM owns: to reach the guest, connect and say CONNECT
// and the port, as both makers' devices expect, and the bytes after that
// are the helper's. The conversation is one JSON object a line, a request
// and an answer, and this program is always the one asking: the helper
// answers, it never tells. A helper that speaks first is a helper that is
// not this program's, and the connection is closed on it.

// HelperPort is the vsock port the helper in the image listens on. Part
// of the image's contract, written here so both sides of the conversation
// are in one place.
const HelperPort = 5050

// Helper is a live conversation with the helper in one cell.
type Helper struct {
	conn net.Conn
	r    *bufio.Reader
}

// Connect reaches the helper through the microVM's vsock: connect to the
// socket, say CONNECT and the port, and expect the maker's OK.
func Connect(ctx context.Context, socket string) (*Helper, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, fmt.Errorf("the cell's vsock: %w", err)
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(10 * time.Second)
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write([]byte(fmt.Sprintf("CONNECT %d\n", HelperPort))); err != nil {
		conn.Close()
		return nil, fmt.Errorf("saying which port: %w", err)
	}
	okLine, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || len(okLine) < 2 || okLine[:2] != "OK" {
		conn.Close()
		return nil, fmt.Errorf("the cell's vsock did not answer OK: %q %v", okLine, err)
	}
	return &Helper{conn: conn, r: bufio.NewReaderSize(conn, MaxLine+2)}, nil
}

// Close ends the conversation.
func (h *Helper) Close() error { return h.conn.Close() }

// MaxLine bounds one answer: an accessibility tree is bounded where it is
// grown (the helper prunes to what can be read or acted on), and a
// picture is bounded in bytes, not lines.
const MaxLine = 1 << 20

// ask sends one request and reads one answer. Every ask carries its own
// deadline — the one from its context when there is one, a bounded wait
// when there is not — because the deadline set at connect was for the
// handshake and is spent.
func (h *Helper) ask(ctx context.Context, req, answer any) error {
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	_ = h.conn.SetDeadline(deadline)
	if _, err := h.conn.Write(append(b, '\n')); err != nil {
		return err
	}
	// Bounded as it reads: a helper that streams bytes with no end of line
	// in them is a bug or a compromise, and either way it must not be able
	// to ask this process for all its memory. The reader is sized to hold
	// one whole bounded line, so ErrBufferFull is exactly the refusal.
	line, err := h.r.ReadSlice('\n')
	if err == bufio.ErrBufferFull {
		return errors.New("the helper's answer is larger than this reads")
	}
	if err != nil {
		return err
	}

	var said struct {
		Err string `json:"err,omitempty"`
	}
	if err := json.Unmarshal(line, &said); err != nil {
		return fmt.Errorf("the helper said nothing this can read")
	}
	if said.Err != "" {
		return errors.New(said.Err)
	}
	if answer == nil {
		return nil
	}
	return json.Unmarshal(line, answer)
}

// Tree is the cell's screen as structure: the accessibility tree, pruned
// to what can be read or acted on, each actable thing with a reference —
// the same shape as the browser's outline, so a model that has learned
// one has learned the other.
type Tree struct {
	Text     string             `json:"text"`
	Elements map[string]Element `json:"elements,omitempty"`
}

// Element is one thing in a cell's tree that can be acted on.
type Element struct {
	Ref  string `json:"ref"`
	Role string `json:"role"`
	Name string `json:"name"`
}

// Read asks for the tree as it is now.
func (h *Helper) Read(ctx context.Context) (Tree, error) {
	var t Tree
	err := h.ask(ctx, map[string]any{"op": "tree"}, &t)
	return t, err
}

// Press clicks an element of the last-read tree, by its reference. What
// commits to something is recognised inside the cell the way the browser
// recognises it, and the answer says whether it did.
func (h *Helper) Press(ctx context.Context, ref string) (string, error) {
	var a struct {
		Said string `json:"said"`
	}
	err := h.ask(ctx, map[string]any{"op": "click", "ref": ref}, &a)
	return a.Said, err
}

// Type puts text into the element last pressed.
func (h *Helper) Type(ctx context.Context, text string) error {
	return h.ask(ctx, map[string]any{"op": "type", "text": text}, nil)
}

// Key presses one named key, of the same four the browser's person
// presses: a key this cannot name exactly is refused rather than guessed.
func (h *Helper) Key(ctx context.Context, key string) error {
	return h.ask(ctx, map[string]any{"op": "key", "key": key}, nil)
}

// Screen is a picture of the cell's screen, as JPEG bytes.
func (h *Helper) Screen(ctx context.Context) ([]byte, error) {
	var a struct {
		JPEG []byte `json:"jpeg"`
	}
	if err := h.ask(ctx, map[string]any{"op": "screen"}, &a); err != nil {
		return nil, err
	}
	return a.JPEG, nil
}
