// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package listen

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// The hole this package was written for, over a real socket.
//
// Before this, every server set ReadHeaderTimeout and nothing else. Go falls
// back to ReadTimeout for the idle deadline and that was unset too, so a
// connection that sent one perfectly ordinary request and then went quiet was
// held until the process restarted. Ten thousand of them is ten thousand
// goroutines and file descriptors, obtained by sending ten thousand ordinary
// requests.
//
// Short deadlines rather than the real ones, because the test has to wait for
// them.
func TestAQuietConnectionIsClosed(t *testing.T) {
	l := Default()
	l.Idle = 250 * time.Millisecond

	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "ok")
		})}
	l.Apply(srv)
	go func() { _ = srv.Serve(base) }()
	t.Cleanup(func() { _ = srv.Close() })

	conn, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// One ordinary request, answered, keep-alive intact.
	_, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("the request was not answered: %v", err)
	}
	if _, err := io.ReadAll(res.Body); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()

	// And now nothing. The server has to be the one to end this.
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err = br.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("the connection is still open and carrying data")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("the server held a connection that had gone quiet; this is " +
			"the leak the idle deadline exists to close")
	}
	// io.EOF, or a reset. Either is the server hanging up.
}

// A client that opens a connection and never sends a request line at all.
// This one was already closed, and stays closed.
func TestAConnectionThatSaysNothingIsClosed(t *testing.T) {
	l := Default()
	l.Header = 250 * time.Millisecond

	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.NotFoundHandler()}
	l.Apply(srv)
	go func() { _ = srv.Serve(base) }()
	t.Cleanup(func() { _ = srv.Close() })

	conn, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Half a request line, the original Slowloris.
	if _, err := io.WriteString(conn, "GET / HT"); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatal("a half-sent request line held a connection open")
		}
	}
}
