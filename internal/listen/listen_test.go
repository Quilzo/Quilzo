// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package listen

import (
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Every limit is set, because the failure this package exists for is a field
// left at its zero value and nothing anywhere saying so.
func TestEveryLimitReachesTheServer(t *testing.T) {
	l := Default()
	var srv http.Server
	l.Apply(&srv)

	if srv.ReadHeaderTimeout != l.Header {
		t.Errorf("ReadHeaderTimeout is %v", srv.ReadHeaderTimeout)
	}
	if srv.ReadTimeout != l.Request {
		t.Errorf("ReadTimeout is %v", srv.ReadTimeout)
	}
	if srv.WriteTimeout != l.Response {
		t.Errorf("WriteTimeout is %v", srv.WriteTimeout)
	}
	if srv.IdleTimeout != l.Idle {
		t.Errorf("IdleTimeout is %v", srv.IdleTimeout)
	}
	if srv.MaxHeaderBytes != l.MaxHeaderBytes {
		t.Errorf("MaxHeaderBytes is %d", srv.MaxHeaderBytes)
	}
}

// The one that was missing everywhere. A keep-alive connection that sends one
// request and then nothing is held until the process restarts, and ten
// thousand of them cost ten thousand goroutines obtained by sending ten
// thousand ordinary requests.
func TestNoProfileLeavesTheIdleDeadlineOpen(t *testing.T) {
	for name, l := range map[string]Limits{
		"default": Default(),
		"media":   Media(),
		"uploads": Uploads(),
	} {
		if l.Idle <= 0 {
			t.Errorf("%s has no idle deadline", name)
		}
		if l.Header <= 0 {
			t.Errorf("%s has no header deadline", name)
		}
		if l.MaxConns <= 0 {
			t.Errorf("%s does not bound connections", name)
		}
		if l.MaxHeaderBytes <= 0 {
			t.Errorf("%s does not bound headers", name)
		}
		if l.Drain <= 0 {
			t.Errorf("%s does not drain", name)
		}
	}
}

// A server that sends a file cannot have a deadline on the whole response: a
// ninety-minute recording is a legitimate response that takes a long time.
func TestTheMediaProfileLeavesTheResponseToTheHandler(t *testing.T) {
	if Media().Response != 0 {
		t.Error("a media server has a fixed response deadline")
	}
	if Media().Request == 0 {
		t.Error("a media server should still bound how long a request takes")
	}
	if Uploads().Request != 0 {
		t.Error("an upload server has a fixed request deadline")
	}
}

// The deadline a file route sets for itself, derived from what it is sending
// rather than guessed at a size that has to be wrong for either the thumbnail
// or the feature film.
func TestAWriteDeadlineGrowsWithTheFile(t *testing.T) {
	small := ResponseFor(10 << 10)
	large := ResponseFor(200 << 20)
	if small <= 0 {
		t.Fatalf("a small file got %v", small)
	}
	if large <= small {
		t.Errorf("a 200MB file got %v, a 10KB file got %v", large, small)
	}
	// An unknown length still gets a deadline. Returning zero here would mean
	// a handler that does not know its size gets none at all.
	if ResponseFor(0) <= 0 {
		t.Error("an unknown length got no deadline")
	}
	if ResponseFor(-1) <= 0 {
		t.Error("a negative length got no deadline")
	}
	// A 10KB thumbnail must not be given minutes.
	if small > time.Minute {
		t.Errorf("a 10KB file got %v", small)
	}
}

// The cap has to be a cap. A limiter that lets one more through under load is
// a limiter that lets a thousand more through under attack.
func TestNoMoreThanTheCapAreAcceptedAtOnce(t *testing.T) {
	const most = 4
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := Cap(base, most)
	t.Cleanup(func() { _ = ln.Close() })

	var live, peak int64
	release := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			n := atomic.AddInt64(&live, 1)
			for {
				p := atomic.LoadInt64(&peak)
				if n <= p || atomic.CompareAndSwapInt64(&peak, p, n) {
					break
				}
			}
			<-release
			atomic.AddInt64(&live, -1)
			_, _ = io.WriteString(w, "ok")
		})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	var wg sync.WaitGroup
	for i := 0; i < most*4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := &http.Client{Timeout: 5 * time.Second}
			res, err := c.Get("http://" + base.Addr().String() + "/")
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, res.Body)
			res.Body.Close()
		}()
	}

	// Long enough for everything that is going to get in to have got in.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(&peak) >= most {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	got := atomic.LoadInt64(&peak)
	close(release)
	wg.Wait()

	if got > most {
		t.Errorf("%d requests were in flight at once against a cap of %d", got, most)
	}
	if got == 0 {
		t.Error("nothing got through at all, so this proved nothing")
	}
	t.Logf("peak in flight: %d of %d", got, most)
}

// A connection closed twice must not release two slots, or the cap drifts
// upward under exactly the load it exists for.
func TestASlotIsGivenBackOnceOnly(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = base.Close() })
	c := &capped{Listener: base, slots: make(chan struct{}, 1)}

	done := make(chan net.Conn, 1)
	go func() {
		conn, err := c.Accept()
		if err != nil {
			done <- nil
			return
		}
		done <- conn
	}()
	dialed, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer dialed.Close()

	conn := <-done
	if conn == nil {
		t.Fatal("accept failed")
	}
	if len(c.slots) != 1 {
		t.Fatalf("the slot was not taken: %d", len(c.slots))
	}
	_ = conn.Close()
	_ = conn.Close()
	_ = conn.Close()
	if len(c.slots) != 0 {
		t.Fatalf("after three closes the semaphore holds %d", len(c.slots))
	}
	// And the slot is genuinely reusable rather than merely counted.
	select {
	case c.slots <- struct{}{}:
		<-c.slots
	default:
		t.Error("the slot cannot be taken again")
	}
}

// A slot taken for an Accept that then failed must come back, or a listener
// that refuses a few connections slowly strangles itself.
func TestAFailedAcceptGivesTheSlotBack(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &capped{Listener: base, slots: make(chan struct{}, 1)}
	_ = base.Close()

	if _, err := c.Accept(); err == nil {
		t.Fatal("accept on a closed listener succeeded")
	}
	if len(c.slots) != 0 {
		t.Errorf("the slot was kept after a failed accept: %d", len(c.slots))
	}
}

// What a request in flight gets when the process is asked to stop. Without
// this, a response is cut off mid-body and a write to the store is cut off
// mid-write.
func TestAnInFlightRequestFinishesDuringTheDrain(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			close(started)
			time.Sleep(200 * time.Millisecond)
			_, _ = io.WriteString(w, "finished")
		})}
	go func() { _ = srv.Serve(base) }()

	type result struct {
		body string
		err  error
	}
	got := make(chan result, 1)
	go func() {
		res, err := http.Get("http://" + base.Addr().String() + "/")
		if err != nil {
			got <- result{err: err}
			return
		}
		b, err := io.ReadAll(res.Body)
		res.Body.Close()
		got <- result{body: string(b), err: err}
	}()

	<-started
	if err := drain(srv, 5*time.Second); err != nil {
		t.Fatalf("drain: %v", err)
	}
	r := <-got
	if r.err != nil {
		t.Fatalf("the request was cut off: %v", r.err)
	}
	if r.body != "finished" {
		t.Errorf("body is %q", r.body)
	}
}

// And a drain that runs out does not return with connections still open, so
// the caller can exit without leaving a socket behind.
func TestADrainThatRunsOutStopsAnyway(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			close(started)
			time.Sleep(2 * time.Second)
		})}
	go func() { _ = srv.Serve(base) }()
	go func() { _, _ = http.Get("http://" + base.Addr().String() + "/") }()

	<-started
	start := time.Now()
	err = drain(srv, 100*time.Millisecond)
	if err == nil {
		t.Error("a drain that could not finish reported success")
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("the drain waited %v past its deadline", took)
	}
}

// Serve listens on the address it was given, so a caller does not have to
// listen separately and then wonder which of the two is in charge.
func TestServeListensAndStops(t *testing.T) {
	// A port picked by asking for one and giving it back. Racy in principle
	// and the alternative is not testing this at all.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()

	l := Default()
	l.MaxConns = 8
	srv := &http.Server{Addr: addr, Handler: http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "up")
		})}

	done := make(chan error, 1)
	go func() { done <- l.Serve(srv) }()

	var body string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		res, err := http.Get("http://" + addr + "/")
		if err == nil {
			b, _ := io.ReadAll(res.Body)
			res.Body.Close()
			body = string(b)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if body != "up" {
		t.Fatalf("Serve did not answer on %s: %q", addr, body)
	}

	_ = srv.Close()
	select {
	case err := <-done:
		// ErrServerClosed is translated away, and Close races the Serve
		// goroutine's own return, so either nil or the closed error is a
		// correct stop. What is not correct is not returning.
		if err != nil && err != http.ErrServerClosed {
			t.Errorf("Serve returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Close")
	}
}
