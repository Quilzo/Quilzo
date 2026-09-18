// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package listen holds the limits every server in this program runs under.
//
// # What was missing
//
// Six http.Servers, each with a ReadHeaderTimeout and nothing else. That one
// timeout closes the original Slowloris — headers sent a byte at a time — and
// leaves the rest of the family open:
//
//	No IdleTimeout. Go falls back to ReadTimeout for the idle deadline, and
//	that was unset too, so a keep-alive connection that sends one request and
//	then nothing is held until the process restarts. Ten thousand of them is
//	ten thousand goroutines and file descriptors, obtained by sending ten
//	thousand perfectly ordinary requests.
//
//	No ReadTimeout. The headers arrive inside ten seconds and then the body
//	dribbles. Every POST route — a form, a share, a federation delivery —
//	holds a goroutine for as long as the sender likes.
//
//	No MaxHeaderBytes. Go's default of a megabyte is reasonable and was never
//	a decision.
//
//	No limit on connections. Nothing bounded how many of the above could exist
//	at once.
//
//	No graceful shutdown. Every server ran ListenAndServe and was killed. A
//	request in flight was cut off mid-response, and a request that was in the
//	middle of writing to the store was cut off mid-write.
//
// # Why the connection limit blocks rather than refuses
//
// Accept is not called while the limit is reached, so new connections sit in
// the kernel's accept queue and then, when that fills, are dropped by the
// kernel without this process spending anything on them. The alternative —
// accepting and immediately closing — costs a goroutine and a syscall per
// attacker connection and tells the attacker the limit exists.
//
// For an ordinary visitor arriving at a busy moment, queueing is also the
// better answer: a connection that waits a few milliseconds is a page that
// loads, and a connection refused is a browser error page.
//
// # Why there is no WriteTimeout on the servers that serve media
//
// Because a WriteTimeout is a deadline on the whole response, and this
// program serves video. A ninety-minute recording to a phone on a train is a
// legitimate response that takes a long time, and a deadline sized for it is
// not a deadline. The media routes set their own, computed from the size they
// are about to send and the slowest connection worth serving; see Media below.
//
// What is left uncovered is a client that reads the first byte and then
// stalls, within its size-derived deadline. The connection limit is what
// bounds that, and it is the reason the limit exists rather than being a
// second opinion about the timeouts.
package listen

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// Limits is what a server in this program is allowed to hold open.
type Limits struct {
	// Header is how long the request line and headers may take.
	Header time.Duration
	// Request is how long the whole request may take to arrive, body
	// included. Zero means unbounded, which is only right for a server whose
	// job is receiving a large file.
	Request time.Duration
	// Response is how long the whole response may take. Zero means the
	// handler decides, which is right for a server that sends media.
	Response time.Duration
	// Idle is how long a kept-alive connection may sit between requests.
	// Never zero: this is the one that was missing everywhere.
	Idle time.Duration
	// MaxHeaderBytes bounds the headers.
	MaxHeaderBytes int
	// MaxConns bounds accepted connections. Zero means unbounded.
	MaxConns int
	// Drain is how long in-flight requests get after a shutdown signal.
	Drain time.Duration
}

// Default is for a server answering ordinary requests with ordinary bodies.
func Default() Limits {
	return Limits{
		Header:  10 * time.Second,
		Request: 30 * time.Second,
		// Long enough for a large page over a bad connection, short enough
		// that a stalled reader is not a permanent resident.
		Response:       2 * time.Minute,
		Idle:           90 * time.Second,
		MaxHeaderBytes: 64 << 10,
		MaxConns:       2048,
		Drain:          15 * time.Second,
	}
}

// Media is for a server that sends files, where the response is as long as the
// file is and a deadline on the whole of it would cut off the reader it is
// meant to serve.
func Media() Limits {
	l := Default()
	l.Response = 0
	return l
}

// Uploads is for a server whose job is receiving a large file.
func Uploads() Limits {
	l := Media()
	l.Request = 0
	// A stalled upload still ends, because the idle deadline applies between
	// requests and the connection limit bounds how many can be in progress.
	l.Idle = 2 * time.Minute
	return l
}

// ResponseFor is a write deadline sized for a body this large.
//
// A response is allowed a fixed grace plus however long the body takes at the
// slowest rate worth serving. This is what replaces a WriteTimeout on the
// routes that send files: the deadline still exists, and it is derived from
// what is being sent rather than from a guess that has to be wrong for either
// the thumbnail or the feature film.
func ResponseFor(size int64) time.Duration {
	const (
		// Enough for a client that is thinking, not stalled.
		grace = 30 * time.Second
		// About 32 kbit/s. Below any connection anybody browses on, and a
		// long way below one anybody watches video on — so a client slower
		// than this was not going to finish anyway.
		slowest = 4 << 10
	)
	if size <= 0 {
		return grace
	}
	return grace + time.Duration(size/slowest)*time.Second
}

// Apply puts the limits on a server.
func (l Limits) Apply(srv *http.Server) {
	srv.ReadHeaderTimeout = l.Header
	srv.ReadTimeout = l.Request
	srv.WriteTimeout = l.Response
	srv.IdleTimeout = l.Idle
	srv.MaxHeaderBytes = l.MaxHeaderBytes
}

// Serve runs a server under these limits until the process is asked to stop,
// then lets what is in flight finish.
//
// Interrupt and SIGTERM, because those are what a terminal and a service
// manager send. A second signal is not caught, so an operator who has waited
// long enough can still stop waiting.
func (l Limits) Serve(srv *http.Server) error {
	l.Apply(srv)

	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	if l.MaxConns > 0 {
		ln = Cap(ln, l.MaxConns)
	}

	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errs := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errs <- err
	}()

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		// Stop listening for the signal before draining, so a second one
		// reaches the default handler and kills the process. An operator
		// pressing Ctrl-C twice means it.
		stop()
		drainCtx, cancel := context.WithTimeout(context.Background(), l.Drain)
		defer cancel()
		if err := srv.Shutdown(drainCtx); err != nil {
			// The drain ran out. Close what is left rather than returning
			// with connections still open, because the caller is about to
			// exit and a half-closed socket outlives it.
			_ = srv.Close()
			return err
		}
		return <-errs
	}
}

// Cap returns a listener that accepts at most n connections at once.
func Cap(ln net.Listener, n int) net.Listener {
	return &capped{Listener: ln, slots: make(chan struct{}, n)}
}

type capped struct {
	net.Listener
	slots chan struct{}
}

func (c *capped) Accept() (net.Conn, error) {
	// Taken before Accept, so the wait happens in the kernel's accept queue
	// rather than in this process. A connection this server is not ready for
	// costs it nothing at all until it is.
	c.slots <- struct{}{}
	conn, err := c.Listener.Accept()
	if err != nil {
		<-c.slots
		return nil, err
	}
	return &slotConn{Conn: conn, release: c.release}, nil
}

func (c *capped) release() { <-c.slots }

// slotConn gives its slot back exactly once.
//
// Once, because net/http closes a connection from more than one place on some
// paths, and a second release would hand out a slot that was never taken —
// turning the limit into an advisory number that drifts upward under exactly
// the load it exists for.
type slotConn struct {
	net.Conn
	release func()
	done    bool
	// mu guards done. A connection is closed by the serving goroutine and can
	// be closed again by Shutdown.
	mu sync.Mutex
}

func (s *slotConn) Close() error {
	err := s.Conn.Close()
	s.mu.Lock()
	if !s.done {
		s.done = true
		s.release()
	}
	s.mu.Unlock()
	return err
}
