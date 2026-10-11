// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package browser

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/cdp"
)

func req(method, raw string) Request {
	u, _ := url.Parse(raw)
	return Request{URL: u, Method: method}
}

// Read hosts are read from, write hosts are also sent to, and nothing else
// is reached at all.
func TestTheHostsRuleKeepsReadingAndSendingApart(t *testing.T) {
	rule := Hosts{Read: []string{"docs.example.com"}, Write: []string{"crm.example.com"}}.Rule()
	for _, c := range []struct {
		r  Request
		ok bool
	}{
		{req("GET", "https://docs.example.com/guide"), true},
		{req("HEAD", "https://Docs.Example.com/"), true},
		{req("POST", "https://docs.example.com/search"), false},
		{req("GET", "https://crm.example.com/contacts"), true},
		{req("POST", "https://crm.example.com/contacts"), true},
		{req("PUT", "https://crm.example.com/contacts/1"), true},
		{req("GET", "https://evil.example.net/pixel.gif?d=secret"), false},
		{req("GET", "http://docs.example.com/guide"), false},
		{req("GET", "ftp://docs.example.com/x"), false},
		{req("GET", "data:text/html,hello"), true},
	} {
		if err := rule(c.r); (err == nil) != c.ok {
			t.Errorf("%s %s: allowed %v, want %v (%v)", c.r.Method, c.r.URL, err == nil, c.ok, err)
		}
	}
}

// In a real browser: an image from a host nobody named and a form posted
// to a read host are refused before they leave, and the server never sees
// them; what the rule allows arrives.
func TestThePageReachesOnlyWhatTheRuleAllows(t *testing.T) {
	path := localChromium(t)
	var mu sync.Mutex
	var hits []string
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, r.Method+" "+r.Host+r.URL.Path)
		mu.Unlock()
		if r.URL.Path == "/page" {
			port := strings.Split(r.Host, ":")[1]
			fmt.Fprintf(w, `<title>page</title><img src="http://localhost:%s/beacon.gif?d=secret">`+
				`<img src="/ok.gif"><form method=post action="/send"><button id=b>Send</button></form>`, port)
		}
	})}
	go srv.Serve(ln)
	defer srv.Close()
	base := "http://" + ln.Addr().String()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	b, err := cdp.Launch(ctx, cdp.Options{Path: path, Profile: filepath.Join(t.TempDir(), "p"), Stderr: io.Discard,
		Args: []string{"--proxy-server=direct://", "--proxy-bypass-list=*"}})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	p, err := b.NewPage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var refused []Refusal
	var rmu sync.Mutex
	stop, err := Guard(ctx, b, p, Hosts{Read: []string{"127.0.0.1"}, Plain: true}.Rule(), "", "", func(r Refusal) {
		rmu.Lock()
		refused = append(refused, r)
		rmu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if err := p.Navigate(ctx, base+"/page"); err != nil {
		t.Fatal(err)
	}
	nodes, _ := p.AXTree(ctx)
	for _, n := range nodes {
		if n.Role.String() == "button" && n.Name.String() == "Send" {
			_ = p.Click(ctx, n.Backend)
		}
	}
	time.Sleep(time.Second)
	mu.Lock()
	got := strings.Join(hits, "\n")
	mu.Unlock()
	if !strings.Contains(got, "GET 127.0.0.1") || !strings.Contains(got, "/ok.gif") {
		t.Errorf("what the rule allows did not arrive:\n%s", got)
	}
	if strings.Contains(got, "beacon") || strings.Contains(got, "POST") {
		t.Errorf("a refused request reached the server:\n%s", got)
	}
	rmu.Lock()
	defer rmu.Unlock()
	var why []string
	for _, r := range refused {
		why = append(why, r.Why)
	}
	all := strings.Join(why, "\n")
	if !strings.Contains(all, "localhost is not a host") || !strings.Contains(all, "may be read and not sent to") {
		t.Errorf("refusals:\n%s", all)
	}
}

// What a page starts is watched as the page is: a frame from another site
// (its own process), a worker, a service worker and a window it opens each
// try to post to a host that may only be read, and none of them reaches it.
func TestNothingThePageStartsGoesUnwatched(t *testing.T) {
	path := localChromium(t)
	var mu sync.Mutex
	var hits []string
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// Each reads what it may, and then tries to send.
	post := func(path string) string {
		return fmt.Sprintf(`fetch(%q).then(()=>fetch(%q,{method:'POST',body:'secret'})).catch(()=>{});`, "/read"+path, path)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, r.Method+" "+r.Host+r.URL.Path)
		mu.Unlock()
		port := strings.Split(r.Host, ":")[1]
		switch r.URL.Path {
		case "/page":
			fmt.Fprintf(w, `<title>page</title><iframe src="http://localhost:%s/frame"></iframe><script>`+
				`new Worker('/worker.js');`+
				`navigator.serviceWorker.register('/sw.js').then(()=>navigator.serviceWorker.ready).then(r=>r.active.postMessage('go'));`+
				`window.open('/popup');</script>`, port)
		case "/frame":
			fmt.Fprintf(w, `<script>%s</script>`, post("/from-frame"))
		case "/popup":
			fmt.Fprintf(w, `<script>%s</script>`, post("/from-popup"))
		case "/worker.js":
			w.Header().Set("Content-Type", "text/javascript")
			fmt.Fprint(w, post("/from-worker"))
		case "/sw.js":
			w.Header().Set("Content-Type", "text/javascript")
			fmt.Fprintf(w, `self.addEventListener('install',()=>{%s});self.addEventListener('message',()=>{%s});`,
				post("/from-sw-install"), post("/from-sw"))
		}
	})}
	go srv.Serve(ln)
	defer srv.Close()
	base := "http://" + ln.Addr().String()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	b, err := cdp.Launch(ctx, cdp.Options{Path: path, Profile: filepath.Join(t.TempDir(), "p"), Stderr: io.Discard,
		Args: []string{"--proxy-server=direct://", "--proxy-bypass-list=*"}})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	p, err := b.NewPage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var refused []string
	stop, err := Guard(ctx, b, p, Hosts{Read: []string{"127.0.0.1", "localhost"}, Plain: true}.Rule(), "", "", func(r Refusal) {
		mu.Lock()
		refused = append(refused, r.Request.Kind+" "+r.Why)
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if err := p.Navigate(ctx, base+"/page"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second)
	mu.Lock()
	got := strings.Join(hits, "\n")
	mu.Unlock()
	if !strings.Contains(got, "GET 127.0.0.1") {
		t.Fatalf("the page did not load:\n%s", got)
	}
	if strings.Contains(got, "POST") {
		t.Errorf("something the page started posted to a read host:\n%s", got)
	}
	// Watched is not stopped: what was started ran, and read what it may.
	for _, read := range []string{"localhost:" + strings.Split(base, ":")[2] + "/read/from-frame", "/read/from-worker"} {
		if !strings.Contains(got, read) {
			t.Errorf("%s did not arrive: what the page started was held and never let run:\n%s", read, got)
		}
	}
	mu.Lock()
	t.Logf("requests:\n%s\nrefused:\n%s", got, strings.Join(refused, "\n"))
	mu.Unlock()
}

// A WebSocket is not a request the browser pauses, so it is refused
// outright: a page cannot open one to a host it may only read, nor to any.
func TestAPageOpensNoWebSocket(t *testing.T) {
	path := localChromium(t)
	var mu sync.Mutex
	var hits []string
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, r.URL.Path+" "+r.Header.Get("Upgrade"))
		mu.Unlock()
		switch r.URL.Path {
		case "/page":
			// The page's own, then a fresh frame's, then a worker's.
			fmt.Fprintf(w, `<title>page</title><script>
try { new WebSocket('ws://'+location.host+'/ws?d=page') } catch (e) {}
const f = document.createElement('iframe'); document.body.append(f);
try { new f.contentWindow.WebSocket('ws://'+location.host+'/ws?d=frame') } catch (e) {}
const src = "try { new WebSocket('ws://" + location.host + "/ws?d=worker') } catch (e) {}";
new Worker(URL.createObjectURL(new Blob([src], {type: 'text/javascript'})));
</script>`)
		}
	})}
	go srv.Serve(ln)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	b, err := cdp.Launch(ctx, cdp.Options{Path: path, Profile: filepath.Join(t.TempDir(), "p"), Stderr: io.Discard,
		Args: []string{"--proxy-server=direct://", "--proxy-bypass-list=*"}})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	p, err := b.NewPage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var refusedWS []string
	stop, err := Guard(ctx, b, p, Hosts{Read: []string{"127.0.0.1"}, Plain: true}.Rule(), "", "", func(r Refusal) {
		if r.Request.Kind == "WebSocket" {
			mu.Lock()
			refusedWS = append(refusedWS, r.Request.URL.String())
			mu.Unlock()
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if err := p.Navigate(ctx, "http://"+ln.Addr().String()+"/page"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	mu.Lock()
	defer mu.Unlock()
	for _, h := range hits {
		if strings.HasPrefix(h, "/ws") {
			t.Errorf("a WebSocket was opened: %v (reported: %v)", hits, refusedWS)
		}
	}
}

// A service worker the page registered stays watched after the page has
// gone to another site: it is held to the rule wherever the page is.
func TestAServiceWorkerStaysWatchedWhenThePageMovesOn(t *testing.T) {
	path := localChromium(t)
	var mu sync.Mutex
	var hits []string
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, r.Method+" "+r.Host+r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/page":
			fmt.Fprint(w, `<title>page</title><script>navigator.serviceWorker.register('/sw.js')</script>`)
		case "/sw.js":
			w.Header().Set("Content-Type", "text/javascript")
			fmt.Fprint(w, `self.addEventListener('activate', e => e.waitUntil(clients.claim()));
setInterval(() => fetch('/from-sw', {method: 'POST', body: 'secret'}).catch(() => {}), 300);`)
		case "/elsewhere":
			fmt.Fprint(w, `<title>elsewhere</title>`)
		}
	})}
	go srv.Serve(ln)
	defer srv.Close()
	port := strings.Split(ln.Addr().String(), ":")[1]
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	b, err := cdp.Launch(ctx, cdp.Options{Path: path, Profile: filepath.Join(t.TempDir(), "p"), Stderr: io.Discard,
		Args: []string{"--proxy-server=direct://", "--proxy-bypass-list=*"}})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	p, err := b.NewPage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stop, err := Guard(ctx, b, p, Hosts{Read: []string{"127.0.0.1", "localhost"}, Plain: true}.Rule(), "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if err := p.Navigate(ctx, "http://127.0.0.1:"+port+"/page"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	if err := p.Navigate(ctx, "http://localhost:"+port+"/elsewhere"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	mu.Lock()
	defer mu.Unlock()
	got := strings.Join(hits, "\n")
	if !strings.Contains(got, "/sw.js") {
		t.Skipf("the service worker never started:\n%s", got)
	}
	if strings.Contains(got, "POST") {
		t.Errorf("the service worker posted once the page had moved on:\n%s", got)
	}
}
