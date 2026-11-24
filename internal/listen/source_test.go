// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package listen

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

// from is a client whose connections all come from one loopback address,
// which Linux routes to this machine whichever of 127.0.0.0/8 it is, so a
// test can be two different visitors at once.
func from(ip string) *http.Client {
	d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)}, Timeout: 3 * time.Second}
	return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		DialContext:       d.DialContext,
		DisableKeepAlives: true,
	}}
}

// serving starts a server under l on a port of its own and waits until it
// answers.
func serving(t *testing.T, l Limits) string {
	t.Helper()
	// Asked for and given back, as TestServeListensAndStops does: Serve
	// listens itself, and that is the path under test.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()

	srv := &http.Server{Addr: addr, Handler: http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "ok")
		})}
	done := make(chan error, 1)
	go func() { done <- l.Serve(srv) }()
	t.Cleanup(func() {
		_ = srv.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after Close")
		}
	})

	deadline := time.Now().Add(3 * time.Second)
	for {
		res, err := from("127.0.0.1").Get("http://" + addr + "/")
		if err == nil {
			res.Body.Close()
			return addr
		}
		if time.Now().After(deadline) {
			t.Fatalf("the server never answered: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// One address opens every connection the server will take and says
// nothing on any of them, and somebody else then asks for a page.
//
// The connection limit is what stops a stalled client being a permanent
// resident, and with nothing per source it was also the way one client
// shut out everybody: 2,100 idle connections from one machine and every
// other visitor's connection sat in the kernel's accept queue until its
// browser gave up, on the public site and the admin alike. The shield's
// per-address limits never saw it, because no request reached a handler.
//
// The shipped profile, not a small one built for the test, because the
// failure was the numbers this program runs with.
func TestOneSourceCannotHoldEveryConnection(t *testing.T) {
	l := Default()
	addr := serving(t, l)

	holder := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}
	var held []net.Conn
	t.Cleanup(func() {
		for _, c := range held {
			_ = c.Close()
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for i := 0; i < l.MaxConns+16; i++ {
		c, err := holder.DialContext(ctx, "tcp", addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		held = append(held, c)
	}

	res, err := from("127.0.0.3").Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("one address holding %d connections shut another visitor out: %v",
			len(held), err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if string(body) != "ok" {
		t.Errorf("the other visitor got %q", body)
	}
}

// accepting runs a per-source listener's accept loop and holds on to what
// it hands out, as a server does with a connection it is serving.
func accepting(t *testing.T, n int, shared func(netip.Addr) bool) (string, *perSource, <-chan net.Conn) {
	t.Helper()
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := PerSource(base, n, shared).(*perSource)
	got := make(chan net.Conn, 64)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				close(got)
				return
			}
			got <- c
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		for c := range got {
			_ = c.Close()
		}
	})
	return base.Addr().String(), ln, got
}

// dial connects from ip and reports whether the server kept the
// connection: one it closed reads as ended at once, one it holds reads
// nothing until the deadline.
func dial(t *testing.T, addr, ip string) (net.Conn, bool) {
	t.Helper()
	d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)}}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, err = c.Read(make([]byte, 1))
	ne, timeout := err.(net.Error)
	return c, timeout && ne.Timeout()
}

// The share is exact, it is per source, and it comes back when a
// connection closes.
func TestASourceHoldsItsShareAndNoMore(t *testing.T) {
	addr, ln, got := accepting(t, 2, nil)

	if _, kept := dial(t, addr, "127.0.0.2"); !kept {
		t.Fatal("the first connection was refused")
	}
	if _, kept := dial(t, addr, "127.0.0.2"); !kept {
		t.Fatal("the second connection was refused")
	}
	if _, kept := dial(t, addr, "127.0.0.2"); kept {
		t.Error("a third connection from one source was kept against a share of two")
	}
	if _, kept := dial(t, addr, "127.0.0.3"); !kept {
		t.Error("another source was refused because the first had used its share")
	}

	// One of the first source's connections ends, server side, the way
	// net/http ends one: possibly more than once.
	first := <-got
	_ = first.Close()
	_ = first.Close()
	if _, kept := dial(t, addr, "127.0.0.2"); !kept {
		t.Error("a closed connection did not give its source's share back")
	}
	if _, kept := dial(t, addr, "127.0.0.2"); kept {
		t.Error("a connection closed twice gave back two")
	}
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if n := len(ln.held); n != 2 {
		t.Errorf("%d sources are counted, expected 2", n)
	}
}

// A peer that is many visitors, the proxy in front of the site, is not
// held to one visitor's share.
func TestASharedPeerIsNotHeldToAShare(t *testing.T) {
	proxy := netip.MustParseAddr("127.0.0.2")
	addr, ln, _ := accepting(t, 1, func(a netip.Addr) bool { return a == proxy })
	for i := 0; i < 5; i++ {
		if _, kept := dial(t, addr, "127.0.0.2"); !kept {
			t.Fatalf("connection %d from the proxy was refused", i+1)
		}
	}
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if len(ln.held) != 0 {
		t.Errorf("the proxy was counted: %v", ln.held)
	}
}

// Every profile holds a source to a share, and the share is less than the
// whole, or the limit is one client's to reach again.
func TestEveryProfileHoldsASourceToAShare(t *testing.T) {
	for name, l := range map[string]Limits{
		"default": Default(),
		"media":   Media(),
		"uploads": Uploads(),
	} {
		if l.PerSource <= 0 || l.PerSource >= l.MaxConns {
			t.Errorf("%s lets one source hold %d of %d connections", name, l.PerSource, l.MaxConns)
		}
	}
}
