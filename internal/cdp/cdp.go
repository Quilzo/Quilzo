// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package cdp speaks the Chrome DevTools Protocol to a browser this process
// started, over a pipe.
//
// # Why a pipe and not a port
//
// The usual way to drive Chromium is --remote-debugging-port: the browser
// listens on a TCP port and anything that can reach it gets the whole
// browser, cookies and all. That is how infostealers read cookies past
// Chrome's encryption, which is why Chrome 136 stopped honouring the switch
// on a person's own profile; and a debugging port on loopback is exactly the
// kind of local control channel that OpenClaw's worst bugs came through.
//
// --remote-debugging-pipe has none of that. The browser reads commands from
// its file descriptor 3 and writes replies to 4, each message JSON ended by a
// NUL byte. Only the process that started it holds the other ends, so there
// is nothing to attach to, nothing to scan for, and no WebSocket to write:
// this package is encoding/json and a pair of pipes.
//
// # Who holds it
//
// Quilzo does. An agent never gets this connection, or anything that could
// send a raw command down it: a hijacked model asking to evaluate script, or
// to read the cookie jar, has no way to say so. What an agent can do is the
// short list of actions the browser driver offers, each a step of its run.
package cdp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

// MaxMessage bounds one message from the browser. Chromium's own limit for
// the pipe is 100 MB; a full-page screenshot of a long page is the largest
// thing that comes back, and 64 MB is room for one.
const MaxMessage = 64 << 20

// Error is the browser refusing a command.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

func (e *Error) Error() string {
	if e.Data != "" {
		return fmt.Sprintf("the browser refused: %s (%s)", e.Message, e.Data)
	}
	return "the browser refused: " + e.Message
}

// Event is something the browser announced.
type Event struct {
	Method    string
	Params    json.RawMessage
	SessionID string
}

type message struct {
	ID        int64           `json:"id,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *Error          `json:"error,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
}

// Conn is one connection to a browser.
type Conn struct {
	w  io.Writer
	wm sync.Mutex

	next atomic.Int64

	mu      sync.Mutex
	pending map[int64]chan message
	subs    map[int]*sub
	nextSub int
	err     error

	done chan struct{}
}

type sub struct {
	match func(Event) bool
	ch    chan Event
}

// ErrClosed is a connection whose browser has gone.
var ErrClosed = errors.New("the browser has gone")

// New starts a connection over a reader of the browser's replies and a
// writer of commands to it.
func New(r io.Reader, w io.Writer) *Conn {
	c := &Conn{w: w, pending: map[int64]chan message{}, subs: map[int]*sub{}, done: make(chan struct{})}
	go c.read(r)
	return c
}

func (c *Conn) read(r io.Reader) {
	br := bufio.NewReaderSize(r, 64<<10)
	var err error
	for {
		var b []byte
		if b, err = readMessage(br); err != nil {
			break
		}
		var m message
		if err = json.Unmarshal(b, &m); err != nil {
			err = fmt.Errorf("the browser sent something that is not a message: %w", err)
			break
		}
		if m.ID != 0 {
			c.mu.Lock()
			ch := c.pending[m.ID]
			delete(c.pending, m.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- m
			}
			continue
		}
		if m.Method != "" {
			c.publish(Event{Method: m.Method, Params: m.Params, SessionID: m.SessionID})
		}
	}
	if err == io.EOF || err == nil {
		err = ErrClosed
	}
	c.mu.Lock()
	c.err = err
	for id, ch := range c.pending {
		close(ch)
		delete(c.pending, id)
	}
	for id, s := range c.subs {
		close(s.ch)
		delete(c.subs, id)
	}
	c.mu.Unlock()
	close(c.done)
}

// readMessage reads one NUL-terminated message, refusing one larger than
// MaxMessage rather than holding it.
func readMessage(br *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		part, err := br.ReadSlice(0)
		if len(buf)+len(part) > MaxMessage {
			return nil, fmt.Errorf("the browser sent a message larger than %d bytes", MaxMessage)
		}
		buf = append(buf, part...)
		switch err {
		case nil:
			return bytes.TrimSuffix(buf, []byte{0}), nil
		case bufio.ErrBufferFull:
			continue
		default:
			return nil, err
		}
	}
}

func (c *Conn) publish(e Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range c.subs {
		if s.match == nil || s.match(e) {
			select {
			case s.ch <- e:
			default:
				// A subscriber that has stopped reading loses events rather
				// than stopping every command's reply behind it.
			}
		}
	}
}

// Subscribe receives the events match accepts, until cancel or the browser
// goes. The channel is buffered; a reader that falls behind misses events.
func (c *Conn) Subscribe(match func(Event) bool) (<-chan Event, func()) {
	ch := make(chan Event, 256)
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		close(ch)
		return ch, func() {}
	}
	id := c.nextSub
	c.nextSub++
	c.subs[id] = &sub{match: match, ch: ch}
	c.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			c.mu.Lock()
			if s, ok := c.subs[id]; ok {
				delete(c.subs, id)
				close(s.ch)
			}
			c.mu.Unlock()
		})
	}
}

// Call sends a command and waits for its reply, decoding the result into
// result when it is not nil. sessionID names the page (or other target) the
// command is for; empty is the browser itself.
func (c *Conn) Call(ctx context.Context, sessionID, method string, params, result any) error {
	m := message{ID: c.next.Add(1), Method: method, SessionID: sessionID}
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		m.Params = b
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	ch := make(chan message, 1)
	c.mu.Lock()
	if c.err != nil {
		err := c.err
		c.mu.Unlock()
		return err
	}
	c.pending[m.ID] = ch
	c.mu.Unlock()

	c.wm.Lock()
	_, err = c.w.Write(append(b, 0))
	c.wm.Unlock()
	if err != nil {
		c.forget(m.ID)
		return fmt.Errorf("cannot send %s: %w", method, err)
	}
	select {
	case r, ok := <-ch:
		if !ok {
			return c.closedErr()
		}
		if r.Error != nil {
			return fmt.Errorf("%s: %w", method, r.Error)
		}
		if result != nil && len(r.Result) > 0 {
			if err := json.Unmarshal(r.Result, result); err != nil {
				return fmt.Errorf("%s: the reply was not what was expected: %w", method, err)
			}
		}
		return nil
	case <-ctx.Done():
		c.forget(m.ID)
		return ctx.Err()
	}
}

func (c *Conn) forget(id int64) {
	c.mu.Lock()
	delete(c.pending, id)
	c.mu.Unlock()
}

func (c *Conn) closedErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	return ErrClosed
}

// Done is closed when the browser has gone.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Err is why the connection ended, once it has.
func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func newReader(r io.Reader) *bufio.Reader { return bufio.NewReaderSize(r, 64<<10) }
