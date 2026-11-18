// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package listen

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// uploading is a server under Uploads, with a short Body so the test need
// not wait thirty seconds, one route that receives files, and a handler
// that reads a POST's body, leaves anything else's alone as most handlers
// of a GET do, and then takes as long as it is told to, saying whether its
// request was cancelled meanwhile.
func uploading(t *testing.T, body, think time.Duration) string {
	t.Helper()
	l := Uploads()
	l.Body = body
	l.Files = func(r *http.Request) int64 {
		if r.Method == http.MethodPost && r.URL.Path == "/upload" {
			return 1 << 20
		}
		return 0
	}
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got []byte
		if r.Method == http.MethodPost {
			var err error
			if got, err = io.ReadAll(r.Body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		select {
		case <-time.After(think):
			fmt.Fprintf(w, "read %d", len(got))
		case <-r.Context().Done():
			fmt.Fprintf(w, "cancelled after reading %d", len(got))
		}
	})}
	l.Apply(srv)
	go func() { _ = srv.Serve(base) }()
	t.Cleanup(func() { _ = srv.Close() })
	return base.Addr().String()
}

// send writes a request's head, then its body in pieces with a pause
// between them, and returns what the server answered, or the error that
// ended the exchange.
func send(t *testing.T, addr, head string, pieces []string, pause time.Duration) (string, error) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, head); err != nil {
		return "", err
	}
	for _, p := range pieces {
		time.Sleep(pause)
		if _, err := io.WriteString(c, p); err != nil {
			return "", err
		}
	}
	res, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	return string(b), err
}

func post(path string, length int) string {
	return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: "+
		"application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n", path, length)
}

// The admin runs under Uploads, so that a recording can take as long as the
// link takes, and that left every other route on it with no deadline at
// all: a POST to /signin that sent a byte every few seconds was held for as
// long as its sender liked. A form's body now has what the public site
// gives a whole request.
func TestAFormThatDribblesIsEndedOnAServerThatTakesFiles(t *testing.T) {
	addr := uploading(t, 300*time.Millisecond, 0)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, post("/signin", 1000)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	ended := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, c)
		close(ended)
	}()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ended:
			if took := time.Since(start); took > 3*time.Second {
				t.Errorf("the form was held %v against a deadline of 300ms", took)
			}
			return
		case <-tick.C:
			if time.Since(start) > 5*time.Second {
				t.Fatal("a form sending a byte at a time was still open after five seconds; " +
					"its body has no deadline")
			}
			_, _ = c.Write([]byte("a"))
		}
	}
}

// A route that receives a file is given the time its size takes, not a
// form's: the recording on a slow link is why this server has no deadline
// on the whole request.
func TestAFileIsGivenTheTimeItsSizeTakes(t *testing.T) {
	addr := uploading(t, 300*time.Millisecond, 0)
	pieces := make([]string, 8)
	for i := range pieces {
		pieces[i] = strings.Repeat("x", 100)
	}
	// Eight pauses of 150ms: four times the form deadline, and well inside
	// the thirty seconds' grace a file of 800 bytes is given.
	got, err := send(t, addr, post("/upload", 800), pieces, 150*time.Millisecond)
	if err != nil {
		t.Fatalf("a slow upload was cut off: %v", err)
	}
	if got != "read 800" {
		t.Errorf("the upload's handler said %q", got)
	}
}

// What a body's deadline must not do is outlive the body. net/http reads
// the connection in the background once a body is finished, to notice the
// client leaving, and a read stopped by a deadline cancels the request as
// though the client had: an answer that takes longer than a form's
// deadline to compose, a model's reply or an agent's run, would be
// abandoned. net/http lifts the deadline as that read starts, and this is
// what says it still does.
func TestAnAnswerThatTakesLongerThanTheBodysDeadlineIsNotCancelled(t *testing.T) {
	addr := uploading(t, 200*time.Millisecond, 800*time.Millisecond)
	got, err := send(t, addr, post("/v1/chat/completions", 5)+"hello", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got != "read 5" {
		t.Errorf("a request whose body was in long before its deadline was answered %q", got)
	}
}

// A request with no body has nothing to wait for, and is given no deadline.
// Its background read is started before the handler is reached, so a
// deadline set then would stop that read and cancel the request: every GET
// that took longer than a form may, an export or a stream, cut short.
func TestARequestWithNoBodyIsGivenNoDeadline(t *testing.T) {
	addr := uploading(t, 200*time.Millisecond, 800*time.Millisecond)
	got, err := send(t, addr, "GET /export HTTP/1.1\r\nHost: x\r\n\r\n", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got != "read 0" {
		t.Errorf("a GET that took longer than a body's deadline was answered %q", got)
	}
}

// Every profile bounds a body one way or the other: the whole request, or
// the body on its own.
func TestNoProfileLeavesABodyUnbounded(t *testing.T) {
	for name, l := range map[string]Limits{
		"default": Default(),
		"media":   Media(),
		"uploads": Uploads(),
	} {
		if l.Request <= 0 && l.Body <= 0 {
			t.Errorf("%s puts no deadline on a request's body", name)
		}
	}
	if Uploads().Body != Default().Request {
		t.Errorf("a form on a server that takes files has %v, and one on the public site %v",
			Uploads().Body, Default().Request)
	}
}
