// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package browser

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
)

// site is a few pages on loopback for the browser's other actions, and
// what was sent to it.
type site struct {
	base string
	mu   sync.Mutex
	sent []string
}

func newSite(t *testing.T) *site {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &site{base: "http://" + ln.Addr().String()}
	page := func(w http.ResponseWriter, head, body string) {
		fmt.Fprintf(w, `<!doctype html><html lang=en><head>%s</head><body>%s</body></html>`, head, body)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/long":
			var b strings.Builder
			for i := 1; i <= 150; i++ {
				fmt.Fprintf(&b, "<p>Paragraph %d of a long page.</p>", i)
			}
			page(w, "<title>Long</title>", b.String()+`<div id=more></div><button>Bottom of the page</button>`+
				`<script>addEventListener('scroll',()=>{if(scrollY>1000&&!more.textContent)more.textContent='Loaded more stories'})</script>`)
		case "/menu":
			page(w, "<title>Menu</title>", `<nav><button id=m>Products</button><ul id=l hidden><li><a href="/long">Shoes</a></li></ul></nav>`+
				`<script>m.addEventListener('mouseenter',()=>{l.hidden=false})</script>`)
		case "/slow":
			page(w, "<title>Slow</title>", `<p id=s>Working on it</p><script>setTimeout(()=>{s.textContent='Order received'},700)</script>`)
		case "/noisy":
			page(w, "<title>Noisy</title>", `<p>Noisy</p><script>console.error('boom happened');console.warn('careful now');`+
				`fetch('/missing');setTimeout(()=>{throw new Error('uncaught thing')},0)</script>`)
		case "/missing":
			http.NotFound(w, r)
		case "/form":
			page(w, "<title>Form</title>", `<form method=post action="/sent"><label>Name <input name=n></label><button>Send</button></form>`+
				`<a href="/long">Elsewhere</a>`)
		case "/sent":
			if r.Method == http.MethodPost {
				_ = r.ParseForm()
				s.mu.Lock()
				s.sent = append(s.sent, r.PostForm.Encode())
				s.mu.Unlock()
			}
			page(w, "<title>Sent</title>", "<h1>Sent</h1>")
		case "/good":
			page(w, `<title>Hart's Bakery, Bristol: bread and cakes</title><meta name=viewport content="width=device-width">`+
				`<meta name=description content="A bakery under the arches at Temple Meads, baking sourdough, buns and cakes every morning since 2013.">`+
				`<link rel=canonical href="https://hartsbakery.co.uk/"><meta property="og:title" content="Hart's Bakery">`+
				`<script type="application/ld+json">{"@context":"https://schema.org","@type":"Bakery","name":"Hart's"}</script>`,
				`<h1>Hart's Bakery</h1><img src="data:image/gif;base64,R0lGODlhAQABAAAAACw=" alt="A loaf"><p id=w></p>`+
					`<script>w.textContent=innerWidth+' '+matchMedia('(prefers-color-scheme: dark)').matches</script>`)
		case "/bad":
			page(w, "", `<h1>One</h1><h1>Two</h1><img src="data:image/gif;base64,R0lGODlhAQABAAAAACw="><a href="/good">click here</a>`)
		}
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return s
}

func (s *site) posted() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.sent, "\n")
}

func siteDriver(t *testing.T) (*Driver, *site) {
	t.Helper()
	s := newSite(t)
	d, _ := newDriver(t, agent.NewSession(shopper(), nil))
	return d, s
}

// Scrolling moves down the page and loads what the page loads as it is
// scrolled to; an element is brought into view by its reference.
func TestScrollingMovesThroughThePage(t *testing.T) {
	d, s := siteDriver(t)
	out := must(t, d, act("browser_open", "url", s.base+"/long"))
	bottom := ref(t, out, "button", "Bottom of the page")
	out = must(t, d, agent.Action{Op: "browser_scroll", Input: map[string]any{"direction": "down", "amount": 2.0}})
	if !strings.Contains(out, "scrolled down; it shows") || !strings.Contains(out, "Loaded more stories") {
		t.Fatalf("%s", out[:min(len(out), 600)])
	}
	out = must(t, d, act("browser_scroll", "ref", bottom))
	if !strings.Contains(out, "into view") || !strings.Contains(out, "end of the page") {
		t.Fatalf("%s", out[:min(len(out), 400)])
	}
	if _, err := perform(t, d, act("browser_scroll", "direction", "sideways")); err == nil {
		t.Error("scrolled sideways")
	}
}

// Enter in a field of a form that sends is weighed as sending it; a key
// that moves focus is not; and going forward again to a page a form led
// to is refused rather than sent twice.
func TestAKeyThatSendsAFormIsWeighed(t *testing.T) {
	d, s := siteDriver(t)
	out := must(t, d, act("browser_open", "url", s.base+"/form"))
	name := ref(t, out, "textbox", "Name")
	must(t, d, act("browser_click", "ref", name))
	must(t, d, act("browser_type", "ref", name, "text", "Ana"))
	if why := d.Weighs(act("browser_key", "key", "Tab")); why != "" {
		t.Errorf("Tab was weighed: %q", why)
	}
	enter := act("browser_key", "key", "return")
	why := d.Weighs(enter)
	if !strings.Contains(why, `with Enter in textbox "Name", it presses button "Send"`) {
		t.Fatalf("Enter in a form was weighed as %q", why)
	}
	// It commits to what pressing the form's own button commits to.
	send := act("browser_click", "ref", ref(t, must(t, d, act("browser_read")), "button", "Send"))
	if c, b := agent.CommitOf(enter, why, agent.WaitAsk, false), agent.CommitOf(send, d.Weighs(send), agent.WaitAsk, false); c != b {
		t.Errorf("Enter in the form commits to %q and its button to %q", c, b)
	}
	must(t, d, act("browser_click", "ref", name))
	out = must(t, d, enter)
	if !strings.Contains(out, "Sent") || s.posted() != "n=Ana" {
		t.Fatalf("%s / %q", out, s.posted())
	}
	if out := must(t, d, act("browser_navigate", "to", "back")); !strings.Contains(out, "went back") || !strings.Contains(out, "Name") {
		t.Fatalf("%s", out)
	}
	if _, err := perform(t, d, act("browser_navigate", "to", "forward")); err == nil || !strings.Contains(err.Error(), "send the form") {
		t.Fatalf("went forward to a page a form led to: %v", err)
	}
	if s.posted() != "n=Ana" {
		t.Fatalf("the form was sent again: %q", s.posted())
	}
	if out := must(t, d, act("browser_navigate", "to", "reload")); !strings.Contains(out, "reloaded") {
		t.Fatalf("%s", out)
	}
	if _, err := perform(t, d, act("browser_key", "key", "ctrl+a")); err == nil {
		t.Error("a chord was pressed")
	}
}

// Waiting until the page shows something, and saying when it does not.
func TestWaitingForWhatThePageShows(t *testing.T) {
	d, s := siteDriver(t)
	must(t, d, act("browser_open", "url", s.base+"/slow"))
	start := time.Now()
	out := must(t, d, act("browser_wait", "text", "Order received"))
	if !strings.Contains(out, `shows "Order received" now`) || time.Since(start) > 10*time.Second {
		t.Fatalf("%s", out)
	}
	if _, err := perform(t, d, agent.Action{Op: "browser_wait", Input: map[string]any{"text": "Never", "seconds": 1.0}}); err == nil ||
		!strings.Contains(err.Error(), "still does not show") {
		t.Fatalf("%v", err)
	}
}

// Resting the pointer on a menu opens it, and what it shows can be read.
func TestHoveringOpensAMenu(t *testing.T) {
	d, s := siteDriver(t)
	out := must(t, d, act("browser_open", "url", s.base+"/menu"))
	if strings.Contains(out, "Shoes") {
		t.Fatal("the menu was open before the pointer rested on it")
	}
	out = must(t, d, act("browser_hover", "ref", ref(t, out, "button", "Products")))
	if !strings.Contains(out, `link "Shoes"`) {
		t.Fatalf("%s", out)
	}
}

// The console says what the page logged and what it failed to fetch, once.
func TestTheConsoleSaysWhatWentWrong(t *testing.T) {
	d, s := siteDriver(t)
	must(t, d, act("browser_open", "url", s.base+"/noisy"))
	pause(context.Background(), 500*time.Millisecond)
	out := must(t, d, act("browser_console"))
	for _, want := range []string{"error: boom happened", "warning: careful now", "uncaught thing", "/missing answered 404"} {
		if !strings.Contains(out, want) {
			t.Errorf("the console does not say %q:\n%s", want, out)
		}
	}
	if out := must(t, d, act("browser_console")); !strings.Contains(out, "logged nothing") {
		t.Errorf("read twice: %s", out)
	}
	// An agent that may not read the console keeps none of it.
	m := shopper()
	m.Capabilities = []string{"browser_open", "browser_read"}
	d2, _ := newDriver(t, agent.NewSession(m, nil))
	must(t, d2, act("browser_open", "url", s.base+"/noisy"))
	d2.nmu.Lock()
	kept := len(d2.console)
	d2.nmu.Unlock()
	if kept != 0 {
		t.Errorf("%d console lines kept for an agent that may not read them", kept)
	}
}

// A page is shown as a phone in dark mode, and back.
func TestThePageIsShownAsAPhone(t *testing.T) {
	d, s := siteDriver(t)
	must(t, d, act("browser_open", "url", s.base+"/good"))
	out := must(t, d, act("browser_emulate", "device", "phone", "color_scheme", "dark"))
	if !strings.Contains(out, "shown a phone, 390 by 844, touch, dark") {
		t.Fatalf("%s", out)
	}
	out = must(t, d, act("browser_navigate", "to", "reload"))
	if !strings.Contains(out, "390 true") {
		t.Fatalf("the page does not see a dark phone:\n%s", out)
	}
	must(t, d, act("browser_emulate", "device", "reset"))
	if out := must(t, d, act("browser_navigate", "to", "reload")); !strings.Contains(out, "1280 false") {
		t.Fatalf("not put back:\n%s", out)
	}
	if _, err := perform(t, d, act("browser_emulate", "width", "50")); err == nil {
		t.Error("a screen 50 pixels wide")
	}
}

// Chrome says how fast a page is, what an accessibility check finds and
// what a search engine reads of it.
func TestAPageIsChecked(t *testing.T) {
	d, s := siteDriver(t)
	must(t, d, act("browser_open", "url", s.base+"/good"))
	out := must(t, d, act("browser_check", "what", "all"))
	for _, want := range []string{"Speed:", "requests", "elements", "Accessibility:", "Search listing:",
		`title "Hart's Bakery, Bristol: bread and cakes"`, "canonical address https://hartsbakery.co.uk/",
		"structured data: Bakery", "one main heading", "has a social card"} {
		if !strings.Contains(out, want) {
			t.Errorf("the check does not say %q:\n%s", want, out)
		}
	}
	must(t, d, act("browser_open", "url", s.base+"/bad"))
	out = must(t, d, act("browser_check", "what", "seo"))
	for _, want := range []string{"! title", "! no canonical", "2 main headings", "1 of 1 images have no alt text", "! no structured data"} {
		if !strings.Contains(out, want) {
			t.Errorf("the check does not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Speed:") {
		t.Error("asked for the listing and was given the speed")
	}
	out = must(t, d, act("browser_check", "what", "accessibility"))
	if !strings.Contains(out, "Accessibility:") || !strings.Contains(out, "found") || strings.Contains(out, "nothing found") {
		t.Errorf("an image with no alt text and a link saying click here passed:\n%s", out)
	}
	if _, err := perform(t, d, act("browser_check", "what", "vibes")); err == nil {
		t.Error("checked something that is not checked")
	}
}

// A page longer than the accessibility checks read is cut where a character
// starts. Findings quote a link's words, and a link in Chinese at the cut
// was quoted with half a character in it.
func TestALongPageIsCheckedUpToACharacter(t *testing.T) {
	link := `</p><a href="/x" target="_blank">go `
	filler := strings.Repeat("a", 4<<20-1-len("<p>")-len(link))
	out := accessReport("https://shop.example/", "<p>"+filler+link+"中文")
	if !strings.Contains(out, `link "go" opens a new tab`) {
		at := strings.Index(out, "new-tab-not-announced")
		t.Fatalf("%s", out[max(0, at):min(len(out), at+60)])
	}
}
