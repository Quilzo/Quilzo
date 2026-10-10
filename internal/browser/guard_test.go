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
