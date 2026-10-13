// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/cdp"
)

// The whole offer, one test: a grant declared, a caller's browser opened
// through it, the page read, the press that pays held for a person, gone
// through once when approved within the hour, and asked again after.
func TestAnOutsideAgentBrowsesUnderAGrantAndAPersonApprovesWhatPays(t *testing.T) {
	root, paid := grantShop(t)
	g := browserGrant{Name: "codex", Read: []string{"shop.example.com"}, Write: []string{"shop.example.com"}}
	m, err := g.manifest()
	if err != nil {
		t.Fatal(err)
	}
	if err := saveBrowserGrant(root, g); err != nil {
		t.Fatal(err)
	}
	tok := auth.Token{Principal: "lee", Role: auth.RoleAuthor}
	caller := remoteCaller(tok)
	now := time.Now()
	ctx := context.Background()

	out, err := browserGrantCall(ctx, root, g, m, "codex", "browser_open",
		map[string]any{"url": "https://shop.example.com/"}, caller, tok, now)
	if err != nil || !strings.Contains(out, "Pay now") {
		t.Fatalf("the page did not open under the grant: %v\n%s", err, out)
	}
	// A host the grant does not name is not opened, exactly as an agent's
	// is not.
	if _, err := browserGrantCall(ctx, root, g, m, "codex", "browser_open",
		map[string]any{"url": "https://other.example.com/"}, caller, tok, now); err == nil {
		t.Fatal("a host the grant does not hold was opened")
	}
	// Signing in is not offered at all: a grant holds no credential.
	for _, op := range grantOps(g) {
		if op == "browser_sign_in" {
			t.Fatal("a grant offers signing in")
		}
	}

	ref := outlineRef(t, out, "Pay now")
	_, err = browserGrantCall(ctx, root, g, m, "codex", "browser_click",
		map[string]any{"ref": ref}, caller, tok, now)
	if err == nil || !strings.Contains(err.Error(), "held as") {
		t.Fatalf("the press that pays was not held: %v", err)
	}
	id := heldID(t, err)
	if paid() != 0 {
		t.Fatal("paid without a person's decision")
	}
	// Waiting: the same call asks again, it does not sneak through.
	if _, err = browserGrantCall(ctx, root, g, m, "codex", "browser_click",
		map[string]any{"ref": ref}, caller, tok, now); err == nil || !strings.Contains(err.Error(), "waiting for a person") {
		t.Fatalf("a second call while waiting was not told to wait: %v", err)
	}
	// Approved by an administrator who is not the caller: exactly that
	// call, once, within the hour.
	if err := gatewayDecide(root, id, true, asAdmin("dana"), now); err != nil {
		t.Fatal(err)
	}
	if out, err = browserGrantCall(ctx, root, g, m, "codex", "browser_click",
		map[string]any{"ref": ref}, caller, tok, now); err != nil || paid() != 1 {
		t.Fatalf("the approved press did not go through: %v (paid %d)\n%s", err, paid(), out)
	}
	// The approval is spent: the same press on the page it left asks again.
	// The page moved when it paid, so the cart is opened afresh and its
	// press held from nothing.
	if out, err = browserGrantCall(ctx, root, g, m, "codex", "browser_open",
		map[string]any{"url": "https://shop.example.com/"}, caller, tok, now); err != nil {
		t.Fatal(err)
	}
	ref = outlineRef(t, out, "Pay now")
	if _, err = browserGrantCall(ctx, root, g, m, "codex", "browser_click",
		map[string]any{"ref": ref}, caller, tok, now); err == nil || !strings.Contains(err.Error(), "held as") {
		t.Fatalf("an approval lived longer than one call: %v", err)
	}
}

// A grant is a browser declaration with a token instead of a run, and the
// declaration's rules hold it: hosts by exact name, https, and nothing
// that does not validate is offered.
func TestAGrantMeansWhatItSays(t *testing.T) {
	root := t.TempDir()
	for _, g := range []browserGrant{
		{Name: "one", Read: []string{"*.example.com"}},
		{Name: "two", Read: []string{"https://shop.example.com"}},
		{Name: "three", Read: []string{"Shop.Example.com"}},
		{Name: "four", Ops: []string{"browser_sign_in"}, Read: []string{"shop.example.com"}},
		{Name: "five", Read: []string{}},
	} {
		if _, err := g.manifest(); err == nil {
			t.Errorf("%s's declaration was accepted", g.Name)
		}
		if _, _, ok := browserGrantOffered(root, "nowhere"); ok {
			t.Error("a grant that was never declared is offered")
		}
		if err := saveBrowserGrant(root, g); err == nil {
			t.Errorf("an invalid grant was stored (%s)", g.Name)
		}
	}
	// Ops are a subset of the browser's actions, without signing in.
	g := browserGrant{Name: "six", Read: []string{"shop.example.com"}, Ops: []string{"browser_open", "browser_read"}}
	if m, err := g.manifest(); err != nil {
		t.Fatal(err)
	} else if len(grantOps(g)) != 2 || m.Capabilities[0] != "browser_open" {
		t.Fatalf("the ops offered: %v", grantOps(g))
	}
	if ops := grantOps(browserGrant{Name: "seven", Read: []string{"shop.example.com"}}); len(ops) != 5 {
		t.Errorf("an empty ops list did not mean all but sign-in and, without pictures, looking: %v", ops)
	}
	if ops := grantOps(browserGrant{Name: "eight", Read: []string{"shop.example.com"}, Pictures: true}); len(ops) != 6 {
		t.Errorf("a grant with pictures did not offer looking: %v", ops)
	}
}

// A caller's daily count is capped as a grant says, counting what went
// through and not what was held.
func TestAGrantsDailyCountCapsWhatWentThrough(t *testing.T) {
	root, _ := grantShop(t)
	g := browserGrant{Name: "small", Read: []string{"shop.example.com"}, Daily: 2}
	m, err := g.manifest()
	if err != nil {
		t.Fatal(err)
	}
	tok := auth.Token{Principal: "lee", Role: auth.RoleAuthor}
	caller := remoteCaller(tok)
	now := time.Now()
	if _, err := browserGrantCall(context.Background(), root, g, m, "small", "browser_open",
		map[string]any{"url": "https://shop.example.com/"}, caller, tok, now); err != nil {
		t.Fatal(err)
	}
	// A call the session refuses is not a call the grant made: it does not
	// spend the count.
	for i := 0; i < 3; i++ {
		if _, err := browserGrantCall(context.Background(), root, g, m, "small", "browser_sign_in",
			map[string]any{"credential": "nope"}, caller, tok, now); err == nil {
			t.Fatal("signing in, which a grant does not offer, went through")
		}
	}
	// The second admitted call is the last the count allows; the third is
	// told what the count is.
	if _, err := browserGrantCall(context.Background(), root, g, m, "small", "browser_read",
		nil, caller, tok, now); err != nil {
		t.Fatal(err)
	}
	_, err = browserGrantCall(context.Background(), root, g, m, "small", "browser_read",
		nil, caller, tok, now)
	if err == nil || !strings.Contains(err.Error(), "as many as a caller may") {
		t.Fatalf("the daily count did not stop the caller: %v", err)
	}
}

// The MCP server a caller is offered names the grant's actions with what
// each takes, and acting on a page is a write, not a read.
func TestTheOfferedServerNamesItsActions(t *testing.T) {
	root := grantRoot(t)
	g := browserGrant{Name: "codex", Read: []string{"shop.example.com"}, Write: []string{"pay.example.com"}}
	if err := saveBrowserGrant(root, g); err != nil {
		t.Fatal(err)
	}
	ops := grantOperations(g)
	if len(ops) != 5 {
		t.Fatalf("five actions offered (no pictures: no looking), %d named", len(ops))
	}
	writes := map[string]bool{}
	for _, o := range ops {
		writes[o.Name] = o.Writes
	}
	if writes["browser_click"] != true || writes["browser_read"] != false || writes["browser_look"] != false {
		t.Errorf("acting on a page must be a write: %+v", ops)
	}
	for _, o := range ops {
		if o.Summary == "" {
			t.Errorf("%s is offered with nothing said about it", o.Name)
		}
	}
}

// grantShop is the shop of the browser tests, on a grant's terms.
func grantShop(t *testing.T) (string, func() int) {
	t.Helper()
	path := testChromium(t)
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	declaredAutonomy(t, root)
	t.Cleanup(func() { grantSweep(time.Now().Add(2 * grantIdle)) })

	var mu sync.Mutex
	n := 0
	shop := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/pay" && r.Method == http.MethodPost:
			mu.Lock()
			n++
			mu.Unlock()
			fmt.Fprint(w, `<!doctype html><title>Paid</title><h1>Paid</h1>`)
		default:
			fmt.Fprint(w, `<!doctype html><title>Cart</title><h1>Cart</h1><p>One box of paper.</p>`+
				`<form method=post action="/pay"><button>Pay now</button></form>`)
		}
	}))
	t.Cleanup(shop.Close)
	port := shop.Listener.Addr().(interface{ String() string }).String()
	port = port[strings.LastIndexByte(port, ':')+1:]
	browserTestLaunch = func(ctx context.Context) (*cdp.Browser, error) {
		return cdp.Launch(ctx, cdp.Options{Path: path, Profile: filepath.Join(t.TempDir(), "p"), Stderr: io.Discard,
			Args: []string{"--proxy-server=direct://", "--proxy-bypass-list=*", "--ignore-certificate-errors",
				"--host-resolver-rules=MAP shop.example.com:443 127.0.0.1:" + port}})
	}
	t.Cleanup(func() { browserTestLaunch = nil })
	return root, func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
}

func grantRoot(t *testing.T) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	return demoStore(t)
}

func outlineRef(t *testing.T, outline, name string) string {
	t.Helper()
	m := regexp.MustCompile(`\[(e\d+)\] button "` + regexp.QuoteMeta(name) + `"`).FindStringSubmatch(outline)
	if m == nil {
		t.Fatalf("no button %q in:\n%s", name, outline)
	}
	return m[1]
}

func heldID(t *testing.T, err error) string {
	t.Helper()
	m := regexp.MustCompile(`held as (gq_[0-9a-f]+)`).FindStringSubmatch(err.Error())
	if m == nil {
		t.Fatalf("no held id in %q", err)
	}
	return m[1]
}
