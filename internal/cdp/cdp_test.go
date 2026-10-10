// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package cdp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fake is a browser on the other end of a pair of pipes: it answers each
// command with what answer says, and can announce events.
func fake(t *testing.T, answer func(m message) message) (*Conn, func(Event)) {
	t.Helper()
	cr, cw := io.Pipe() // commands: conn writes, fake reads
	rr, rw := io.Pipe() // replies: fake writes, conn reads
	c := New(rr, cw)
	var wmu = make(chan struct{}, 1)
	wmu <- struct{}{}
	send := func(m message) {
		b, _ := json.Marshal(m)
		<-wmu
		rw.Write(append(b, 0))
		wmu <- struct{}{}
	}
	go func() {
		br := newReader(cr)
		for {
			b, err := readMessage(br)
			if err != nil {
				return
			}
			var m message
			_ = json.Unmarshal(b, &m)
			r := answer(m)
			r.ID = m.ID
			send(r)
		}
	}()
	t.Cleanup(func() { cw.Close(); rw.Close() })
	return c, func(e Event) { send(message{Method: e.Method, Params: e.Params, SessionID: e.SessionID}) }
}

func TestACommandIsAnsweredAndAnEventIsHeard(t *testing.T) {
	c, announce := fake(t, func(m message) message {
		if m.Method == "Bad.command" {
			return message{Error: &Error{Code: -32601, Message: "'Bad.command' wasn't found"}}
		}
		return message{Result: json.RawMessage(`{"product":"Chrome/149.0"}`)}
	})
	var v struct{ Product string }
	if err := c.Call(context.Background(), "", "Browser.getVersion", nil, &v); err != nil || v.Product != "Chrome/149.0" {
		t.Fatalf("%v %+v", err, v)
	}
	if err := c.Call(context.Background(), "", "Bad.command", nil, nil); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("a refusal came back as %v", err)
	}
	evs, cancel := c.Subscribe(func(e Event) bool { return e.Method == "Page.loadEventFired" })
	defer cancel()
	announce(Event{Method: "Page.frameNavigated", SessionID: "s1"})
	announce(Event{Method: "Page.loadEventFired", SessionID: "s1"})
	select {
	case e := <-evs:
		if e.Method != "Page.loadEventFired" || e.SessionID != "s1" {
			t.Errorf("heard %+v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the event was not heard")
	}
}

// A message larger than the limit ends the connection rather than being
// held, and every waiting call is told.
func TestAnOversizedMessageEndsTheConnection(t *testing.T) {
	big := bytes.Repeat([]byte("x"), MaxMessage+10)
	r := io.MultiReader(bytes.NewReader(big), bytes.NewReader([]byte{0}))
	c := New(r, io.Discard)
	<-c.Done()
	if err := c.Err(); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("ended with %v", err)
	}
	if err := c.Call(context.Background(), "", "Browser.getVersion", nil, nil); err == nil {
		t.Error("a call on an ended connection was accepted")
	}
}

// localBrowser is a Chromium on this machine, or the test is skipped.
func localBrowser(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("QUILZO_TEST_CHROMIUM"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	found, _ := filepath.Glob(filepath.Join(home, ".cache/ms-playwright/chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell"))
	if len(found) == 0 {
		t.Skip("no Chromium here (set QUILZO_TEST_CHROMIUM)")
	}
	return found[len(found)-1]
}

// A real browser, driven over the pipe: a page is opened, read through its
// accessibility tree, typed into and clicked, as a person would.
func TestABrowserIsDrivenOverItsPipe(t *testing.T) {
	path := localBrowser(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	b, err := Launch(ctx, Options{Path: path, Profile: t.TempDir(), Stderr: io.Discard, Env: []string{"HOME=" + t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	p, err := b.NewPage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	page := `data:text/html,<title>start</title><label for=q>Your name</label><input id=q>` +
		`<button onclick="document.title='hello '+document.getElementById('q').value">Greet</button>`
	if err := p.Navigate(ctx, page); err != nil {
		t.Fatal(err)
	}
	nodes, err := p.AXTree(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var field, button int64
	for _, n := range nodes {
		switch {
		case n.Role.String() == "textbox" && n.Name.String() == "Your name":
			field = n.Backend
		case n.Role.String() == "button" && n.Name.String() == "Greet":
			button = n.Backend
		}
	}
	if field == 0 || button == 0 {
		t.Fatalf("the tree has no field (%d) or button (%d)", field, button)
	}
	if err := p.Type(ctx, field, "Ada"); err != nil {
		t.Fatal(err)
	}
	if err := p.Click(ctx, button); err != nil {
		t.Fatal(err)
	}
	var title struct {
		Result struct{ Value string } `json:"result"`
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_ = p.Call(ctx, "Runtime.evaluate", map[string]any{"expression": "document.title", "returnByValue": true}, &title)
		if title.Result.Value == "hello Ada" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if title.Result.Value != "hello Ada" {
		t.Fatalf("the page says %q", title.Result.Value)
	}
	png, err := p.Screenshot(ctx)
	if err != nil || !bytes.HasPrefix(png, []byte("\x89PNG")) {
		t.Fatalf("screenshot: %v (%d bytes)", err, len(png))
	}
}
