// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

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
// # Why one source is held to a share of them
//
// A limit with nothing per source is a limit one client can reach alone. One
// machine opened 2,100 connections to the public site and said nothing on
// them, and every other visitor's connection waited in the kernel's queue
// until the browser gave up; the admin was the same. The shield's limits per
// address never saw it, because no request ever reached a handler.
//
// So one source — one IPv4 address or one IPv6 /64, the unit everything else
// in this program counts by (internal/clientip) — may hold PerSource of the
// connections and no more. This is the one place a connection is refused
// rather than queued, because which source it is from is not known until it
// has been accepted. A refused one costs a syscall in the accept loop and no
// goroutine.
//
// A peer that is many visitors on one address — the proxy in front of the
// site, this machine — is told apart by Limits.Shared and held to MaxConns
// alone. Counted per source, it would be one share for everybody behind it,
// which is the failure this exists to prevent, caused by it.
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
//
// # Why a server that receives files still bounds a form
//
// The same reasoning runs the other way for a server that receives files:
// the admin takes a recording through its media screen, and a deadline on
// the whole request would refuse it on the slow link that needs longest. So
// Uploads has no Request deadline, and for a while that meant the whole
// admin had none: a POST to /signin that sent its body a byte every few
// seconds was held for as long as its sender liked, the hole this package
// was written to close, reopened for the admin alone.
//
// So a server under Uploads gives each body a deadline of its own, as the
// media routes give each response one. A route that receives a file, named
// by Limits.Files, gets the time its size takes at the slowest rate worth
// serving; every other body gets Body, what the public site gives a whole
// request.
package listen

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/quilzo/quilzo/internal/clientip"
)

// Limits is what a server in this program is allowed to hold open.
type Limits struct {
	// Header is how long the request line and headers may take.
	Header time.Duration
	// Request is how long the whole request may take to arrive, body
	// included. Zero means unbounded, which is only right for a server whose
	// job is receiving a large file.
	Request time.Duration
	// Body is how long a request's body may take to arrive, once its
	// headers have, on a server whose Request is zero: set per request, so
	// that the routes Files names can be given longer. Zero leaves bodies
	// to Request.
	Body time.Duration
	// Files reports the most a request may send when its route is one that
	// receives a file, and zero for any other. Such a body is given the
	// time its size takes rather than Body. Nil means no route does.
	Files func(*http.Request) int64
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
	// PerSource bounds the connections one source holds at once: one IPv4
	// address or one IPv6 /64. Zero means unbounded. Well below MaxConns,
	// so that no one address can be all of them.
	PerSource int
	// Shared reports whether a peer is one many clients arrive through, a
	// proxy in front or this machine, which PerSource does not count. Nil
	// means none is.
	Shared func(netip.Addr) bool
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
		// A browser opens six to a host and keeps them for the idle
		// deadline, so this is ten visitors behind one address at once —
		// an office, a household — while it takes thirty-two addresses,
		// not one, to fill MaxConns.
		PerSource: 64,
		Drain:     15 * time.Second,
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
//
// Every other body on it still has what a request has on the public site,
// Body; the routes that receive files are named by setting Files.
func Uploads() Limits {
	l := Media()
	l.Body = l.Request
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
	if l.Request == 0 && l.Body > 0 {
		next := srv.Handler
		if next == nil {
			next = http.DefaultServeMux
		}
		srv.Handler = l.bodies(next)
	}
}

// bodies gives each request's body a deadline of its own.
//
// From when the handler is reached, so a body has Body after the headers'
// own deadline rather than sharing it. Before anything else sees the
// request, because a handler that refuses without reading still has the
// body read for it: net/http reads up to 256 KB of what is left before it
// answers, so as to keep the connection, and with no deadline a sender that
// dribbles is waited on there instead.
//
// The deadline ends with the body. Once a body is finished net/http reads
// the connection in the background, to notice the client leaving, and it
// lifts the read deadline when it starts; a read stopped by a deadline
// would cancel the request as though the client had gone, and a long answer
// (a model's reply, an agent's run, an export) with it. A request with no
// body has that read started before the handler is reached, so it is given
// no deadline at all: one set now would end that read, and the request.
func (l Limits) bodies(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength == 0 {
			next.ServeHTTP(w, r)
			return
		}
		within := l.Body
		if l.Files != nil {
			if most := l.Files(r); most > 0 {
				// Sized as a response to a file is (ResponseFor): the same
				// grace and the same slowest rate, in the other direction.
				// The declared length, or the most the route takes when the
				// length is not declared or is more than it would read.
				size := r.ContentLength
				if size < 0 || size > most {
					size = most
				}
				within = ResponseFor(size)
			}
		}
		// A writer that cannot take one is not a connection (a test's
		// recorder), and there is nothing to hold open.
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(within))
		next.ServeHTTP(w, r)
	})
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
	if l.PerSource > 0 {
		// Outside the cap, so a connection refused here gives back the
		// slot the cap took for it at once.
		ln = PerSource(ln, l.PerSource, l.Shared)
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
		if err := drain(srv, l.Drain); err != nil {
			return err
		}
		return <-errs
	}
}

// drain lets what is in flight finish, and stops waiting if it will not.
func drain(srv *http.Server, within time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), within)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		// The drain ran out. Close what is left rather than returning with
		// connections still open: the caller is about to exit, and a
		// half-closed socket outlives it and keeps the port.
		_ = srv.Close()
		return err
	}
	return nil
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

// PerSource returns a listener that lets one source hold at most n of its
// connections at once and closes any more it is offered. A peer shared
// reports true for is not counted; shared may be nil.
func PerSource(ln net.Listener, n int, shared func(netip.Addr) bool) net.Listener {
	return &perSource{Listener: ln, most: n, shared: shared, held: map[netip.Prefix]int{}}
}

type perSource struct {
	net.Listener
	most   int
	shared func(netip.Addr) bool
	// mu guards held, which has an entry only for a source holding one or
	// more connections, so it is never larger than what is accepted.
	mu   sync.Mutex
	held map[netip.Prefix]int
}

func (p *perSource) Accept() (net.Conn, error) {
	for {
		conn, err := p.Listener.Accept()
		if err != nil {
			return nil, err
		}
		unit, counted := p.source(conn)
		if !counted {
			return conn, nil
		}
		p.mu.Lock()
		over := p.held[unit] >= p.most
		if !over {
			p.held[unit]++
		}
		p.mu.Unlock()
		if over {
			// Closed rather than queued: there is no queue per source to
			// leave it in, and the kernel's is shared with everybody this
			// is protecting.
			_ = conn.Close()
			continue
		}
		return &slotConn{Conn: conn, release: func() { p.release(unit) }}, nil
	}
}

// source is the unit a connection counts against, and whether it counts:
// not when its peer is shared, nor when its address cannot be read (a unix
// socket, say), since an address that cannot be told is not a source.
func (p *perSource) source(conn net.Conn) (netip.Prefix, bool) {
	a, ok := clientip.Parse(conn.RemoteAddr().String())
	if !ok || (p.shared != nil && p.shared(a)) {
		return netip.Prefix{}, false
	}
	return clientip.Unit(a), true
}

func (p *perSource) release(unit netip.Prefix) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.held[unit] <= 1 {
		delete(p.held, unit)
		return
	}
	p.held[unit]--
}

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
