// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/clientip"
	"github.com/quilzo/quilzo/internal/config"
)

func TestTheEdgeBelievesOnlyTheProxiesTheConfigurationNames(t *testing.T) {
	from := func(cfg *config.Config, inside, remote, xff string) string {
		var got string
		h := clientip.Middleware(func() *clientip.Resolver { return resolverFrom(cfg, inside) },
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = clientip.SourceFrom(r) }))
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr, req.Header["X-Forwarded-For"] = remote, []string{xff}
		h.ServeHTTP(httptest.NewRecorder(), req)
		return got
	}
	cfg := config.New()
	// Nothing said: the connection, whatever the header claims.
	if got := from(cfg, "site.trusted_proxy", "172.17.0.1:80", "203.0.113.9"); got != "172.17.0.1" {
		t.Fatalf("believed with nothing configured: %s", got)
	}
	// "On this machine": a reverse proxy on loopback is believed; a machine
	// on a private network, a container bridge or carrier-grade NAT is not,
	// and neither is the internet.
	if err := cfg.Set("site.trusted_proxy", "true", "", "test"); err != nil {
		t.Fatal(err)
	}
	for _, remote := range []string{"127.0.0.1:80", "[::1]:80"} {
		if got := from(cfg, "site.trusted_proxy", remote, "203.0.113.9"); got != "203.0.113.9" {
			t.Fatalf("a proxy on this machine (%s) was not believed: %s", remote, got)
		}
	}
	for _, remote := range []string{"172.17.0.1:80", "10.0.0.5:80", "192.168.1.5:80", "100.64.0.1:80", "198.51.100.7:80"} {
		want := remote[:len(remote)-3]
		if got := from(cfg, "site.trusted_proxy", remote, "203.0.113.9"); got != want {
			t.Fatalf("%s chose its address without being named: %s", want, got)
		}
	}
	// The other surface's switch is not this one's.
	if got := from(cfg, "admin.trusted_proxy", "127.0.0.1:80", "203.0.113.9"); got != "127.0.0.1" {
		t.Fatalf("the site's setting opened the admin: %s", got)
	}
	// Named, a machine on the private network is believed, and loopback is
	// no longer assumed.
	if err := cfg.Set("network.trusted_proxies", "172.17.0.1", "", "test"); err != nil {
		t.Fatal(err)
	}
	if got := from(cfg, "site.trusted_proxy", "172.17.0.1:80", "203.0.113.9"); got != "203.0.113.9" {
		t.Fatalf("a named proxy on a private network was not believed: %s", got)
	}
	if got := from(cfg, "site.trusted_proxy", "127.0.0.1:80", "203.0.113.9"); got != "127.0.0.1" {
		t.Fatalf("loopback is still assumed once proxies are named: %s", got)
	}
	if err := cfg.Set("network.trusted_proxies", "192.0.2.10", "", "test"); err != nil {
		t.Fatal(err)
	}
	if got := from(cfg, "site.trusted_proxy", "172.17.0.1:80", "203.0.113.9"); got != "172.17.0.1" {
		t.Fatalf("a proxy that is no longer named is still believed: %s", got)
	}
	if got := from(cfg, "admin.trusted_proxy", "192.0.2.10:80", "2001:db8:1:2::9"); got != "2001:db8:1:2::/64" {
		t.Fatalf("a named proxy was not believed: %s", got)
	}
}

func TestANamedProxyRangeOfMostOfTheInternetNeedsAReason(t *testing.T) {
	cfg := config.New()
	if err := cfg.Set("network.trusted_proxies", "0.0.0.0/0", "", "test"); err == nil {
		t.Fatal("0.0.0.0/0 was set without a reason")
	}
	if err := cfg.Set("network.trusted_proxies", "10.0.0.0/8,2001:db8::/32", "", "test"); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set("network.trusted_proxies", "proxy.internal", "", "test"); err == nil {
		t.Fatal("a name was accepted as a proxy")
	}
}

func TestAnUnreadableConfigurationBelievesNoProxy(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "config.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := proxies(root, "site.trusted_proxy")(); r == nil || len(r.Proxies) != 0 {
		t.Fatalf("%+v", r)
	}
}

// watching is a surface's edge over a resolver, with what it says and a
// clock the test moves, and a way to send it a request.
type watching struct {
	f   *forwarders
	h   http.Handler
	out *bytes.Buffer
	at  time.Time
	// marked is whether the last request reached the handler marked as
	// from a machine reported as a proxy nobody named.
	marked bool
}

func watch(root, local string, resolve func() *clientip.Resolver) *watching {
	w := &watching{out: &bytes.Buffer{}, at: time.Now()}
	w.f = newForwarders(root, local, resolve, w.out)
	w.f.now = func() time.Time { return w.at }
	w.h = clientip.Middleware(resolve, w.f.watch(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		w.marked = unnamedProxy(r)
	})))
	return w
}

func (w *watching) send(remote, header, value string) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = remote
	if value != "" {
		req.Header.Set(header, value)
	}
	w.h.ServeHTTP(httptest.NewRecorder(), req)
}

// unnamedRecords are the reports the audit log holds.
func unnamedRecords(t *testing.T, root string) []audit.Event {
	t.Helper()
	evs, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Event
	for _, e := range evs {
		if e.Action == "shield.unnamed-proxy" {
			out = append(out, e)
		}
	}
	return out
}

func TestAMachineOnTheNetworkThatForwardsIsToldHowToNameIt(t *testing.T) {
	root := shieldRoot(t)
	cfg := config.New()
	if err := cfg.Set("site.trusted_proxy", "true", "", "test"); err != nil {
		t.Fatal(err)
	}
	resolve := func() *clientip.Resolver { return resolverFrom(cfg, "site.trusted_proxy") }
	w := watch(root, "site.trusted_proxy", resolve)
	w.send("172.17.0.1:80", "X-Forwarded-For", "203.0.113.9")
	// And before it is followed, what following it costs: the list is both
	// surfaces', and a proxy on this machine must then be named too.
	out := w.out.String()
	if !strings.Contains(out, "172.17.0.1 sent X-Forwarded-For and is not believed") ||
		!strings.Contains(out, "quilzo config set network.trusted_proxies 172.17.0.1\n") ||
		!strings.Contains(out, "for the site and the admin both") {
		t.Fatalf("%q", out)
	}
	if recs := unnamedRecords(t, root); len(recs) != 1 || recs[0].Detail["surface"] != "site" ||
		!strings.Contains(recs[0].Detail["seen"], "site.trusted_proxy believes a proxy on this machine only") {
		t.Fatalf("%+v", recs)
	}
	// Once for each machine, and not for the proxy on this machine (it is
	// believed), a machine that forwards nothing, or the internet's first
	// header.
	n := w.out.Len()
	w.send("172.17.0.1:80", "X-Forwarded-For", "203.0.113.9")
	w.send("127.0.0.1:80", "X-Forwarded-For", "203.0.113.9")
	w.send("10.0.0.5:80", "", "")
	w.send("198.51.100.7:80", "X-Forwarded-For", "203.0.113.9")
	if w.out.Len() != n {
		t.Fatalf("said again, or for the wrong machine: %q", w.out.String()[n:])
	}
	// A network full of machines writing the header cannot fill the log.
	for i := 0; i < maxReported*2; i++ {
		w.send(fmt.Sprintf("10.1.0.%d:80", i+1), "X-Forwarded-For", "203.0.113.9")
	}
	if got := strings.Count(w.out.String(), "is not believed"); got != maxReported {
		t.Fatalf("named %d machines, want %d", got, maxReported)
	}
	if got := len(unnamedRecords(t, root)); got != maxReported {
		t.Fatalf("recorded %d machines, want %d", got, maxReported)
	}
	// With proxies named, the deployment has said which they are, and one
	// header is somebody writing their own.
	if err := cfg.Set("network.trusted_proxies", "192.0.2.10", "", "test"); err != nil {
		t.Fatal(err)
	}
	w = watch(root, "site.trusted_proxy", resolve)
	w.send("10.2.0.1:80", "X-Forwarded-For", "203.0.113.9")
	if w.out.Len() != 0 {
		t.Fatalf("%q", w.out.String())
	}
}

func TestAMachineThatForwardsManyDifferentAddressesIsReportedOnce(t *testing.T) {
	root := shieldRoot(t)
	nothing := func() *clientip.Resolver { return &clientip.Resolver{} }
	w := watch(root, "admin.trusted_proxy", nothing)
	for i := 1; i < manyDifferent; i++ {
		w.send("198.51.100.7:443", "X-Forwarded-For", fmt.Sprintf("203.0.113.%d", i))
	}
	if w.out.Len() != 0 || w.marked {
		t.Fatalf("reported before %d different addresses: %q", manyDifferent, w.out.String())
	}
	w.send("198.51.100.7:443", "X-Forwarded-For", fmt.Sprintf("203.0.113.%d", manyDifferent))
	out := w.out.String()
	for _, want := range []string{
		fmt.Sprintf("198.51.100.7 forwarded %d different addresses within an hour", manyDifferent),
		"a block on it is a block on all of them",
		"\n      quilzo config set network.trusted_proxies 198.51.100.7\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the report does not say %q: %q", want, out)
		}
	}
	if !w.marked {
		t.Fatal("the request that found it was not marked")
	}
	recs := unnamedRecords(t, root)
	if len(recs) != 1 || recs[0].Detail["surface"] != "admin" || recs[0].Outcome != audit.Denied ||
		!strings.Contains(recs[0].Detail["fix"], "network.trusted_proxies") {
		t.Fatalf("%+v", recs)
	}
	// The log keeps the handle the shield blocks it by, not the address.
	if strings.Contains(fmt.Sprint(recs[0]), "198.51.100.7") || !strings.HasPrefix(recs[0].Principal, "p_") {
		t.Fatalf("the address reached the log: %+v", recs[0])
	}
	// Once: what it sends from now on is marked, and says nothing more,
	// whatever it forwards or if it forwards nothing.
	n := w.out.Len()
	for i := 0; i < 3*manyDifferent; i++ {
		w.send("198.51.100.7:443", "X-Forwarded-For", fmt.Sprintf("198.18.0.%d", i))
	}
	if w.out.Len() != n || len(unnamedRecords(t, root)) != 1 {
		t.Fatalf("said again: %q", w.out.String()[n:])
	}
	if w.send("198.51.100.7:443", "", ""); !w.marked {
		t.Fatal("its own request was not marked")
	}
	if w.send("198.51.100.99:443", "", ""); w.marked {
		t.Fatal("another machine was marked")
	}
	// Any of the headers a proxy or CDN writes, on a private network as on
	// the internet.
	for i := 0; i < manyDifferent; i++ {
		w.send("10.0.0.9:80", "Cf-Connecting-Ip", fmt.Sprintf("203.0.113.%d", i))
	}
	if !strings.Contains(w.out.String(), "10.0.0.9 forwarded") {
		t.Fatalf("a private machine forwarding a CDN's header was not reported: %q", w.out.String())
	}
	// One client writing the same header, however often, is one client.
	n = w.out.Len()
	for i := 0; i < 10*manyDifferent; i++ {
		w.send("198.51.100.8:443", "X-Forwarded-For", "203.0.113.9")
	}
	// Nor is a handful spread over more than the window.
	for i := 0; i < 2*manyDifferent; i++ {
		w.send("198.51.100.9:443", "X-Forwarded-For", fmt.Sprintf("203.0.113.%d", i))
		w.at = w.at.Add(forwardWindow/(manyDifferent-1) + time.Second)
	}
	if w.out.Len() != n {
		t.Fatalf("one client, or a few over hours, was reported: %q", w.out.String()[n:])
	}
}

func TestANamedProxyIsNeverReported(t *testing.T) {
	root := shieldRoot(t)
	cfg := config.New()
	if err := cfg.Set("network.trusted_proxies", "192.0.2.10,10.0.0.0/8", "", "test"); err != nil {
		t.Fatal(err)
	}
	resolve := func() *clientip.Resolver { return resolverFrom(cfg, "site.trusted_proxy") }
	w := watch(root, "site.trusted_proxy", resolve)
	for i := 0; i < 4*manyDifferent; i++ {
		// What it forwards is believed; what it sends of its own, with a
		// CDN's header and no X-Forwarded-For, is its own request.
		w.send("192.0.2.10:443", "X-Forwarded-For", fmt.Sprintf("203.0.113.%d", i))
		w.send("10.1.2.3:443", "Cf-Connecting-Ip", fmt.Sprintf("203.0.113.%d", i))
	}
	if w.out.Len() != 0 || len(unnamedRecords(t, root)) != 0 || w.marked {
		t.Fatalf("a named proxy was reported: %q", w.out.String())
	}
	// One that is not named is told how to join them, keeping them.
	for i := 0; i < manyDifferent; i++ {
		w.send("198.51.100.7:443", "X-Forwarded-For", fmt.Sprintf("203.0.113.%d", i))
	}
	if !strings.Contains(w.out.String(), "quilzo config set network.trusted_proxies 192.0.2.10,10.0.0.0/8,198.51.100.7\n") {
		t.Fatalf("%q", w.out.String())
	}
}

func TestAProxyOnThisMachineIsToldToTurnItsSettingOn(t *testing.T) {
	// Caddy in front of the site, with site.trusted_proxy off: every
	// visitor is this machine, which the shield never blocks. Naming
	// 127.0.0.1 would let any program here choose its address on both
	// surfaces, so the hint is the surface's own setting.
	root := shieldRoot(t)
	w := watch(root, "site.trusted_proxy", func() *clientip.Resolver { return &clientip.Resolver{} })
	for i := 0; i < manyDifferent; i++ {
		w.send("127.0.0.1:80", "X-Forwarded-For", fmt.Sprintf("203.0.113.%d", i))
	}
	out := w.out.String()
	if !strings.Contains(out, "the shield blocks none of them") ||
		!strings.Contains(out, "\n      quilzo config set site.trusted_proxy true\n") ||
		strings.Contains(out, "network.trusted_proxies") {
		t.Fatalf("%q", out)
	}
}

func TestWatchingWhatMachinesForwardIsBounded(t *testing.T) {
	root := shieldRoot(t)
	w := watch(root, "site.trusted_proxy", func() *clientip.Resolver { return &clientip.Resolver{} })
	// Many machines, each with a few values: no more are watched than the
	// limit, and none holds more than it needs to count.
	for i := 0; i < 4*maxWatched; i++ {
		for j := 0; j < manyDifferent-1; j++ {
			w.send(fmt.Sprintf("[2001:db8::%x]:443", i), "X-Forwarded-For", fmt.Sprintf("203.0.113.%d", j))
		}
		w.at = w.at.Add(time.Millisecond)
	}
	w.f.mu.Lock()
	watched := len(w.f.watched)
	for _, x := range w.f.watched {
		if len(x.seen) > manyDifferent {
			t.Errorf("a machine holds %d values", len(x.seen))
		}
	}
	// The oldest went first: the last machine is still watched.
	_, last := w.f.watched[netip.MustParseAddr(fmt.Sprintf("2001:db8::%x", 4*maxWatched-1))]
	w.f.mu.Unlock()
	if watched > maxWatched || !last {
		t.Fatalf("%d machines watched, the last one %v", watched, last)
	}
	if w.out.Len() != 0 {
		t.Fatalf("%q", w.out.String())
	}
	// Many machines that each forward enough: no more than maxReported are
	// ever named, and past that nothing more is watched.
	for i := 0; i < 3*maxReported; i++ {
		for j := 0; j < manyDifferent; j++ {
			w.send(fmt.Sprintf("198.51.100.%d:443", i+1), "X-Forwarded-For", fmt.Sprintf("203.0.113.%d", j))
		}
	}
	if got := strings.Count(w.out.String(), "different addresses within an hour"); got != maxReported {
		t.Fatalf("named %d machines, want %d", got, maxReported)
	}
	if got := len(unnamedRecords(t, root)); got != maxReported {
		t.Fatalf("recorded %d machines, want %d", got, maxReported)
	}
	w.f.mu.Lock()
	before := len(w.f.watched)
	w.f.mu.Unlock()
	for i := 0; i < maxWatched; i++ {
		w.send(fmt.Sprintf("[2001:db8:1::%x]:443", i), "X-Forwarded-For", "203.0.113.1")
	}
	w.f.mu.Lock()
	defer w.f.mu.Unlock()
	if len(w.f.watched) > before || len(w.f.reported) != maxReported {
		t.Fatalf("watched %d (was %d), reported %d", len(w.f.watched), before, len(w.f.reported))
	}
}

func TestASurfaceThatAssumesItsProxySaysWhereItBelievesItFrom(t *testing.T) {
	root := t.TempDir()
	cfg := config.New()
	if err := cfg.Set("site.trusted_proxy", "true", "", "test"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
	if line := assumedProxy(root, "site.trusted_proxy"); !strings.Contains(line, "this machine only") ||
		!strings.Contains(line, "network.trusted_proxies") {
		t.Fatalf("%q", line)
	}
	if line := assumedProxy(root, "admin.trusted_proxy"); line != "" {
		t.Fatalf("the admin, with no proxy, said %q", line)
	}
	if err := cfg.Set("network.trusted_proxies", "10.0.0.5", "", "test"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
	if line := assumedProxy(root, "site.trusted_proxy"); line != "" {
		t.Fatalf("with its proxy named, the site said %q", line)
	}
}

// Both listeners decide their clients at the edge the configuration
// describes, say there which machine forwarded an address that was not
// believed, and say at start where they believe one from. A source check
// rather than a request, because the wiring is what could go missing: a
// listener built on clientip.Middleware alone resolves clients correctly
// and says nothing, and every other test would still pass.
func TestBothListenersAreBuiltOnTheEdgeAndSaySo(t *testing.T) {
	for file, surface := range map[string]string{"serve.go": "admin", "site.go": "site"} {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		src := string(body)
		local := `"` + surface + `.trusted_proxy"`
		if !strings.Contains(src, "edge(root, "+local+", sh.guard.Wrap(") {
			t.Errorf("%s: the %s is not built on edge(root, %s, ...) in front of the shield's guard", file, surface, local)
		}
		if !strings.Contains(src, "assumedProxy(root, "+local+")") {
			t.Errorf("%s: the %s does not say at start where it believes a forwarded address from", file, surface)
		}
		if strings.Contains(src, "clientip.Middleware(") {
			t.Errorf("%s: a listener built on clientip.Middleware directly never says which machine was not believed", file)
		}
	}
}
