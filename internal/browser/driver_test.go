// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package browser

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/cdp"
)

// shop is a small site on loopback: 127.0.0.1 may be written to and
// localhost only read, as a declaration would name two hosts.
type shop struct {
	base, readBase string
	mu             sync.Mutex
	posts          []string
}

func (s *shop) posted() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.posts, "\n")
}

func newShop(t *testing.T) *shop {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &shop{base: "http://" + ln.Addr().String()}
	s.readBase = strings.Replace(s.base, "127.0.0.1", "localhost", 1)
	page := func(w http.ResponseWriter, title, body string) {
		fmt.Fprintf(w, `<!doctype html><title>%s</title><body>%s</body>`, title, body)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			s.mu.Lock()
			s.posts = append(s.posts, r.URL.Path+" "+r.PostForm.Encode())
			s.mu.Unlock()
		}
		switch r.URL.Path {
		case "/shop":
			page(w, "Shop", `<h1>Shop</h1><form action="/search"><label>Search <input name=q></label><button>Search</button></form>`+
				`<label>Size <select name=size><option>Small</option><option>Large</option></select></label> <a href="/cart">Cart</a>`)
		case "/search":
			page(w, "Results", "<h1>Results for "+r.URL.Query().Get("q")+"</h1>")
		case "/cart":
			page(w, "Cart", `<h1>Cart</h1><form method=post action="/pay"><button>Pay now</button></form>`)
		case "/pay":
			page(w, "Paid", "<h1>Paid</h1>")
		case "/moving":
			page(w, "Moving", `<button id=b>Read more</button><form method=post action="/pay"></form>`+
				`<script>setTimeout(()=>{b.textContent='Delete account'},300)</script>`)
		case "/covered":
			page(w, "Covered", `<form method=post action="/pay"><button style="margin:40px">Show details</button></form>`+
				`<div style="position:fixed;inset:0;z-index:9;opacity:0" onclick="document.title='hijacked'"></div>`)
		case "/login":
			page(w, "Sign in", `<form method=post action="/session"><label>Email <input type=email name=email></label>`+
				`<label>Password <input type=password name=password></label><button>Sign in</button></form>`)
		case "/session":
			page(w, "Account", "<h1>Your account</h1><p>Signed in.</p>")
		case "/alert":
			page(w, "Alert", `<button onclick="alert('Saved!');document.title='after'">Keep</button>`)
		}
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return s
}

// shopper may read localhost, write to 127.0.0.1, and sign in there.
func shopper() agent.Manifest {
	return agent.Manifest{Name: "shopper", Kind: agent.KindTask, Purpose: "buy what it is asked to",
		Capabilities: agent.BrowserCapabilities, Autonomy: agent.AutonomyDraft,
		Browser: &agent.Browser{Read: []string{"localhost"}, Write: []string{"127.0.0.1"},
			Credentials: []agent.BrowserCredential{{Secret: "shop", Host: "127.0.0.1"}}, Pictures: true},
		Budget: agent.Budget{Steps: 40, Duration: agent.Duration(5 * time.Minute)}}
}

func newDriver(t *testing.T, s *agent.Session) (*Driver, *[]Frame) {
	t.Helper()
	path := localChromium(t)
	var frames []Frame
	d := &Driver{Session: s, Plain: true,
		Launch: func(ctx context.Context) (*cdp.Browser, error) {
			return cdp.Launch(ctx, cdp.Options{Path: path, Profile: filepath.Join(t.TempDir(), "p"), Stderr: io.Discard,
				Args: []string{"--proxy-server=direct://", "--proxy-bypass-list=*"}})
		},
		Secret: func(name string) (string, error) { return "ana@example.com\nhunter2", nil },
		Frames: func(f Frame) { frames = append(frames, f) },
	}
	t.Cleanup(d.Close)
	return d, &frames
}

func act(op string, kv ...string) agent.Action {
	a := agent.Action{Op: op, Input: map[string]any{}}
	for i := 0; i+1 < len(kv); i += 2 {
		a.Input[kv[i]] = kv[i+1]
	}
	return a
}

// ref finds the reference an outline gives a control.
func ref(t *testing.T, outline, role, name string) string {
	t.Helper()
	m := regexp.MustCompile(`\[(e\d+)\] ` + role + ` "` + regexp.QuoteMeta(name) + `"`).FindStringSubmatch(outline)
	if m == nil {
		t.Fatalf("no %s %q in:\n%s", role, name, outline)
	}
	return m[1]
}

func perform(t *testing.T, d *Driver, a agent.Action) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return d.Perform(func(context.Context, agent.Action) (string, error) {
		return "", fmt.Errorf("not the browser's")
	})(ctx, a)
}

func must(t *testing.T, d *Driver, a agent.Action) string {
	t.Helper()
	out, err := perform(t, d, a)
	if err != nil {
		t.Fatalf("%s: %v", a.Op, err)
	}
	return out
}

// An agent searches, chooses and pays through the outline alone; the
// press that pays is the one a person is asked about, with a picture of
// what it would press.
func TestAnAgentShopsThroughTheOutline(t *testing.T) {
	sh := newShop(t)
	s := agent.NewSession(shopper(), nil)
	d, frames := newDriver(t, s)

	out := must(t, d, act("browser_open", "url", sh.base+"/shop"))
	if !s.Tainted() {
		t.Error("reading a web page did not taint the run")
	}
	must(t, d, act("browser_type", "ref", ref(t, out, "textbox", "Search"), "text", "shoes"))
	must(t, d, act("browser_choose", "ref", ref(t, out, "combobox", "Size"), "option", "Large"))
	out = must(t, d, act("browser_read"))
	if !strings.Contains(out, `= "Large"`) {
		t.Errorf("the choice did not take:\n%s", out)
	}
	search := act("browser_click", "ref", ref(t, out, "button", "Search"))
	if why := d.Weighs(search); !strings.Contains(why, "submits a form") {
		t.Errorf("a button in a form was not weighed: %q", why)
	}
	out = must(t, d, search)
	if !strings.Contains(out, "Results for shoes") {
		t.Fatalf("the search did not land:\n%s", out)
	}

	out = must(t, d, act("browser_open", "url", sh.base+"/cart"))
	pay := act("browser_click", "ref", ref(t, out, "button", "Pay now"))
	why := d.Weighs(pay)
	if !strings.Contains(why, `"Pay now"`) || !strings.Contains(why, "127.0.0.1") {
		t.Errorf("paying was weighed as %q", why)
	}
	var asked *Frame
	for i := range *frames {
		if (*frames)[i].Asking != "" {
			asked = &(*frames)[i]
		}
	}
	if asked == nil || len(asked.JPEG) < 1000 || asked.Asking != why {
		t.Errorf("no picture of what the person is asked about")
	}
	out = must(t, d, pay)
	if !strings.Contains(out, "Paid") || !strings.Contains(sh.posted(), "/pay") {
		t.Errorf("paying did not happen: %s / %s", out, sh.posted())
	}
	if len(*frames) < 6 {
		t.Errorf("%d frames kept for 6 actions", len(*frames))
	}
}

// What it may not reach, it does not open.
func TestTheBrowserOpensOnlyItsHosts(t *testing.T) {
	sh := newShop(t)
	d, _ := newDriver(t, agent.NewSession(shopper(), nil))
	for _, c := range []struct{ url, want string }{
		{"http://evil.example.net/", "not a host this agent may reach"},
		{"file:///etc/passwd", "https addresses only"},
		{"javascript:alert(1)", "https addresses only"},
		{"https:///nohost", "not an address"},
	} {
		if _, err := perform(t, d, act("browser_open", "url", c.url)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.url, err)
		}
	}
	strict := &Driver{Session: agent.NewSession(shopper(), nil)}
	if _, err := strict.Perform(nil)(context.Background(), act("browser_open", "url", sh.base+"/shop")); err == nil ||
		!strings.Contains(err.Error(), "https addresses only") {
		t.Errorf("plain http was opened outside a test: %v", err)
	}
}

// A page that renames a button after it was read does not get the press
// the model meant for the old name.
func TestAPageCannotChangeAButtonUnderTheAgent(t *testing.T) {
	sh := newShop(t)
	d, _ := newDriver(t, agent.NewSession(shopper(), nil))
	out := must(t, d, act("browser_open", "url", sh.base+"/moving"))
	if !strings.Contains(out, "Read more") {
		t.Skipf("the page changed before it was read:\n%s", out)
	}
	click := act("browser_click", "ref", ref(t, out, "button", "Read more"))
	time.Sleep(time.Second)
	if _, err := perform(t, d, click); err == nil || !strings.Contains(err.Error(), "changed since it was read") {
		t.Errorf("a renamed button was pressed: %v", err)
	}
}

// A press that would land on something laid over the button is refused.
func TestACoveredButtonIsNotPressed(t *testing.T) {
	sh := newShop(t)
	d, _ := newDriver(t, agent.NewSession(shopper(), nil))
	out := must(t, d, act("browser_open", "url", sh.base+"/covered"))
	_, err := perform(t, d, act("browser_click", "ref", ref(t, out, "button", "Show details")))
	if err == nil || !strings.Contains(err.Error(), "covers it") {
		t.Errorf("a covered button was pressed: %v", err)
	}
	if strings.Contains(sh.posted(), "/pay") {
		t.Error("the form was sent")
	}
	out = must(t, d, act("browser_read"))
	if strings.Contains(out, "hijacked") {
		t.Error("the layer over the button got the click")
	}
}

// A credential is typed only on its own host, is never in what the model
// is told, and makes the run hold something private.
func TestSigningInTypesTheSecretOnlyOnItsHost(t *testing.T) {
	sh := newShop(t)
	s := agent.NewSession(shopper(), nil)
	d, _ := newDriver(t, s)
	must(t, d, act("browser_open", "url", sh.readBase+"/login"))
	if _, err := perform(t, d, act("browser_sign_in", "credential", "shop")); err == nil || !strings.Contains(err.Error(), "typed only into") {
		t.Errorf("the credential was typed on another host: %v", err)
	}
	if sh.posted() != "" {
		t.Fatalf("something was sent: %s", sh.posted())
	}
	must(t, d, act("browser_open", "url", sh.base+"/login"))
	if why := d.Weighs(act("browser_sign_in", "credential", "shop")); !strings.Contains(why, "signs in to 127.0.0.1 with shop") {
		t.Errorf("signing in was weighed as %q", why)
	}
	out := must(t, d, act("browser_sign_in", "credential", "shop"))
	if !strings.Contains(out, "[signed in to 127.0.0.1 with shop]") || !strings.Contains(out, "Your account") {
		t.Errorf("sign-in said:\n%s", out)
	}
	if strings.Contains(out, "hunter2") {
		t.Error("the password is in what the model is told")
	}
	if got := sh.posted(); !strings.Contains(got, "email=ana%40example.com") || !strings.Contains(got, "password=hunter2") {
		t.Errorf("the form sent: %s", got)
	}
	if p := strings.Join(s.Private(), ","); !strings.Contains(p, "127.0.0.1 shows once signed in") {
		t.Errorf("the run does not hold anything private: %q", p)
	}
	if _, err := perform(t, d, act("browser_sign_in", "credential", "bank")); err == nil {
		t.Error("an undeclared credential was used")
	}
}

// A dialog does not stop the page, and the model hears what it said.
func TestADialogIsAnsweredAndReported(t *testing.T) {
	sh := newShop(t)
	d, _ := newDriver(t, agent.NewSession(shopper(), nil))
	out := must(t, d, act("browser_open", "url", sh.base+"/alert"))
	out = must(t, d, act("browser_click", "ref", ref(t, out, "button", "Keep")))
	if !strings.Contains(out, `"Saved!"`) || !strings.Contains(out, `"after"`) {
		t.Errorf("after the dialog:\n%s", out)
	}
}
