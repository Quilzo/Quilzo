// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package browser

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/cdp"
)

// The browser's actions, performed for a run.
//
// Each is one step of the run: the session has already checked that the
// declaration holds it, the breaker has had its say, and a click that
// commits to something has already been seen by a person (Weighs). What is
// left is to do it, on the one browser this run has, and to say what
// happened in words the model can use.
//
// Opening a page and pressing something on it answer with the page's
// outline as it is afterwards, so the model sees where it landed without
// spending a step to read it.

// Driver performs the browser's actions for one run.
type Driver struct {
	Session *agent.Session
	// Launch starts the browser, on first use: in the agent's box.
	Launch func(ctx context.Context) (*cdp.Browser, error)
	// Rule is what every request a page makes is held to; the
	// declaration's hosts when nil.
	Rule Rule
	// ProxyUser and ProxyPass answer the box's proxy.
	ProxyUser, ProxyPass string
	// Secret reads a sealed credential by name.
	Secret func(name string) (string, error)
	// Frames keeps a picture of the page after each action, and of what a
	// person is asked about, for the run's record. Nil keeps none.
	Frames func(Frame)
	// Picture hands a screenshot to a model that reads pictures. Nil means
	// this run's model reads text only.
	Picture func(png []byte)
	// Refused is told about each request the rule refused.
	Refused func(Refusal)
	// Plain allows http, for tests on loopback only.
	Plain bool

	mu      sync.Mutex
	browser *cdp.Browser
	page    *cdp.Page
	stops   []func()
	outline Outline
	read    bool

	// What happened on the page between actions: dialogs it showed and
	// requests the rule refused. Its own lock, since the page does these
	// while an action holds mu.
	nmu     sync.Mutex
	said    []string
	refused map[string]int
}

// Frame is a picture of the page.
type Frame struct {
	Op string
	// At is the page's address.
	At   string
	JPEG []byte
	// Asking is why a person is being asked, with the element outlined in
	// red on the picture; empty for a picture after an action.
	Asking string
}

// Performs reports whether the driver performs an action.
func Performs(a agent.Action) bool { return a.Tool == "" && a.Delegate == "" && agent.IsBrowser(a.Op) }

// Perform wraps a run's performer: the browser's actions here, the rest
// passed on.
func (d *Driver) Perform(next func(context.Context, agent.Action) (string, error)) func(context.Context, agent.Action) (string, error) {
	return func(ctx context.Context, a agent.Action) (string, error) {
		if !Performs(a) {
			return next(ctx, a)
		}
		if err := d.Session.Check(a.Op); err != nil {
			return "", err
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		out, err := d.perform(ctx, a)
		if d.page != nil && a.Op != "browser_read" {
			d.frame(ctx, a.Op, "", 0)
		}
		if extra := d.happened(); extra != "" {
			if err != nil {
				return "", fmt.Errorf("%w\n%s", err, extra)
			}
			out += "\n" + extra
		}
		return out, err
	}
}

// Weighs says why an action commits to something a person should see
// first, and keeps a picture of it with the element outlined.
func (d *Driver) Weighs(a agent.Action) string {
	if !Performs(a) {
		return ""
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	switch a.Op {
	case "browser_sign_in":
		why := fmt.Sprintf("it signs in to %s with %s", d.host(ctx), str(a, "credential"))
		if d.page != nil {
			pw, _, _ := d.loginFields(ctx)
			d.frame(ctx, a.Op, why, pw)
		}
		return why
	case "browser_click":
		if !d.read {
			return ""
		}
		e, ok := d.outline.Elements[str(a, "ref")]
		if ok && e.Consequential != "" {
			why := fmt.Sprintf("it presses %s %q on %s, and %s", e.Role, e.Name, d.host(ctx), e.Consequential)
			d.frame(ctx, a.Op, why, e.Backend)
			return why
		}
	}
	return ""
}

// Close ends the browser.
func (d *Driver) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, stop := range d.stops {
		stop()
	}
	d.stops = nil
	if d.browser != nil {
		_ = d.browser.Close()
		d.browser, d.page = nil, nil
	}
}

func str(a agent.Action, k string) string {
	v, _ := a.Input[k].(string)
	return strings.TrimSpace(v)
}

func (d *Driver) decl() *agent.Browser { return d.Session.Manifest().Browser }

func (d *Driver) perform(ctx context.Context, a agent.Action) (string, error) {
	if a.Op == "browser_open" {
		return d.open(ctx, str(a, "url"))
	}
	if d.page == nil {
		return "", errors.New("no page is open yet: browser_open one first")
	}
	switch a.Op {
	case "browser_read":
		return d.readPage(ctx, "")
	case "browser_look":
		return d.look(ctx)
	case "browser_type":
		text, _ := a.Input["text"].(string)
		return d.typeInto(ctx, str(a, "ref"), text)
	case "browser_choose":
		return d.choose(ctx, str(a, "ref"), str(a, "option"))
	case "browser_click":
		return d.click(ctx, str(a, "ref"))
	case "browser_sign_in":
		return d.signIn(ctx, str(a, "credential"))
	}
	return "", fmt.Errorf("%q is not one of the browser's actions", a.Op)
}

// start launches the browser and opens its one page, held to the rule.
func (d *Driver) start(ctx context.Context) error {
	if d.page != nil {
		return nil
	}
	decl := d.decl()
	if decl == nil {
		return errors.New("this agent declares no browser")
	}
	if d.Launch == nil {
		return ErrNoBox
	}
	b, err := d.Launch(ctx)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		for _, stop := range d.stops {
			stop()
		}
		d.stops = nil
		b.Close()
		return err
	}
	// Nothing is saved to disk from a page: a download is somebody else's
	// file in the box, and nothing here asked for one.
	if err := b.Call(ctx, "", "Browser.setDownloadBehavior", map[string]any{"behavior": "deny"}, nil); err != nil {
		return fail(err)
	}
	p, err := b.NewPage(ctx)
	if err != nil {
		return fail(err)
	}
	rule := d.Rule
	if rule == nil {
		rule = Hosts{Read: decl.Read, Write: decl.Write, Plain: d.Plain}.Rule()
	}
	stop, err := Guard(ctx, b, p, rule, d.ProxyUser, d.ProxyPass, d.refusal)
	if err != nil {
		return fail(err)
	}
	d.stops = append(d.stops, stop)
	d.stops = append(d.stops, d.answerDialogs(b, p))
	d.browser, d.page = b, p
	return nil
}

// answerDialogs answers what a page asks in a dialog, which would
// otherwise stop it until somebody did: an alert is acknowledged, leaving
// the page is allowed, and a question (confirm, prompt) is declined, since
// nobody asked the model. The model is told what the page said.
func (d *Driver) answerDialogs(b *cdp.Browser, p *cdp.Page) func() {
	evs, cancel := b.Subscribe(func(e cdp.Event) bool {
		return e.SessionID == p.Session && e.Method == "Page.javascriptDialogOpening"
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range evs {
			var dlg struct {
				Message string `json:"message"`
				Type    string `json:"type"`
			}
			if json.Unmarshal(e.Params, &dlg) != nil {
				continue
			}
			accept := dlg.Type == "alert" || dlg.Type == "beforeunload"
			ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			_ = p.Call(ctx, "Page.handleJavaScriptDialog", map[string]any{"accept": accept}, nil)
			stop()
			how := "declined"
			if accept {
				how = "acknowledged"
			}
			d.nmu.Lock()
			if len(d.said) < 8 {
				d.said = append(d.said, fmt.Sprintf("the page showed a dialog (%s) saying %q, and it was %s", dlg.Type, clean(dlg.Message), how))
			}
			d.nmu.Unlock()
		}
	}()
	return func() { cancel(); <-done }
}

func (d *Driver) refusal(r Refusal) {
	host := ""
	if r.Request.URL != nil {
		host = r.Request.URL.Hostname()
	}
	d.nmu.Lock()
	if d.refused == nil {
		d.refused = map[string]int{}
	}
	if len(d.refused) < 16 {
		d.refused[host]++
	}
	d.nmu.Unlock()
	if d.Refused != nil {
		d.Refused(r)
	}
}

// happened is what the page did since the last action that the model
// should know: what it said in dialogs, and where it was not let reach.
func (d *Driver) happened() string {
	d.nmu.Lock()
	defer d.nmu.Unlock()
	var lines []string
	lines = append(lines, d.said...)
	if len(d.refused) > 0 {
		var hosts []string
		for h, n := range d.refused {
			hosts = append(hosts, fmt.Sprintf("%s (%d)", h, n))
		}
		sort.Strings(hosts)
		lines = append(lines, "requests the page made that this agent may not make were refused: "+strings.Join(hosts, ", "))
	}
	d.said, d.refused = nil, nil
	return strings.Join(lines, "\n")
}

func (d *Driver) open(ctx context.Context, raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%q is not an address to open", raw)
	}
	if u.Scheme != "https" && !(d.Plain && u.Scheme == "http") {
		return "", fmt.Errorf("%s: an agent's browser opens https addresses only", u.Redacted())
	}
	if u.Host == "" {
		return "", fmt.Errorf("%q is not an address to open", raw)
	}
	if host := strings.ToLower(u.Hostname()); !d.decl().Reads(host) {
		return "", fmt.Errorf("%s is not a host this agent may reach", host)
	}
	if err := d.start(ctx); err != nil {
		return "", err
	}
	nctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	note := ""
	if err := d.page.Navigate(nctx, u.String()); err != nil {
		if !strings.Contains(err.Error(), "did not finish loading") {
			return "", err
		}
		// Still loading something is still a page: read what is there.
		note = "it has not finished loading; "
	}
	return d.readPage(ctx, "opened "+note)
}

// where is the page's title and address now.
func (d *Driver) where(ctx context.Context) (string, string) {
	var info struct {
		TargetInfo struct {
			Title string `json:"title"`
			URL   string `json:"url"`
		} `json:"targetInfo"`
	}
	_ = d.browser.Call(ctx, "", "Target.getTargetInfo", map[string]any{"targetId": d.page.Target}, &info)
	return clean(info.TargetInfo.Title), info.TargetInfo.URL
}

func (d *Driver) host(ctx context.Context) string {
	if d.page == nil {
		return "the page"
	}
	_, at := d.where(ctx)
	if u, err := url.Parse(at); err == nil && u.Hostname() != "" {
		return strings.ToLower(u.Hostname())
	}
	return "the page"
}

// readPage builds the page's outline and says what it is, after what.
func (d *Driver) readPage(ctx context.Context, what string) (string, error) {
	nodes, err := d.page.AXTree(ctx)
	if err != nil {
		return "", err
	}
	d.outline, d.read = Build(nodes), true
	title, at := d.where(ctx)
	if u, err := url.Parse(at); err == nil && u.Hostname() != "" {
		d.Session.ReadWeb(strings.ToLower(u.Hostname()), at)
	}
	return fmt.Sprintf("%s%q at %s\n%s", what, title, at, d.outline.Text), nil
}

func (d *Driver) look(ctx context.Context) (string, error) {
	if decl := d.decl(); decl == nil || !decl.Pictures {
		return "", errors.New("this agent's browser does not allow pictures")
	}
	if d.Picture == nil {
		return "", errors.New("this run's model reads text only; browser_read gives the page's outline")
	}
	png, err := d.page.Screenshot(ctx)
	if err != nil {
		return "", err
	}
	d.Picture(png)
	_, at := d.where(ctx)
	return "a screenshot of " + at + " is with this message", nil
}

// element is what a reference names on the outline last read, if the page
// still shows it as it was read: a reference the page has since changed
// under is refused, rather than acting on something nobody read.
func (d *Driver) element(ctx context.Context, ref string, roles ...string) (Element, error) {
	if !d.read {
		return Element{}, errors.New("read the page first (browser_read): a reference names an element of the outline read last")
	}
	e, ok := d.outline.Elements[ref]
	if !ok {
		return Element{}, fmt.Errorf("%q is not on the outline read last; read the page again", ref)
	}
	if len(roles) > 0 {
		fits := false
		for _, r := range roles {
			fits = fits || e.Role == r
		}
		if !fits {
			return Element{}, fmt.Errorf("%s is a %s, and this takes %s", ref, e.Role, strings.Join(roles, " or "))
		}
	}
	now, err := d.page.Node(ctx, e.Backend)
	if err != nil {
		d.read = false
		return Element{}, fmt.Errorf("%s is no longer on the page; read it again", ref)
	}
	if now.Role.String() != e.Role || clean(now.Name.String()) != e.Name {
		d.read = false
		return Element{}, fmt.Errorf("the page changed since it was read: %s was %s %q and is now %s %q; read it again",
			ref, e.Role, e.Name, now.Role.String(), clean(now.Name.String()))
	}
	return e, nil
}

func (d *Driver) typeInto(ctx context.Context, ref, text string) (string, error) {
	e, err := d.element(ctx, ref, "textbox", "searchbox", "combobox", "spinbutton")
	if err != nil {
		return "", err
	}
	if len(text) > 4000 {
		return "", errors.New("at most 4000 characters are typed at once")
	}
	if err := d.page.Type(ctx, e.Backend, text); err != nil {
		return "", err
	}
	return fmt.Sprintf("typed into %s %q", ref, e.Name), nil
}

func (d *Driver) choose(ctx context.Context, ref, option string) (string, error) {
	e, err := d.element(ctx, ref, "combobox", "listbox")
	if err != nil {
		return "", err
	}
	world, err := d.page.Isolated(ctx)
	if err != nil {
		return "", err
	}
	obj, err := d.page.Resolve(ctx, e.Backend, world)
	if err != nil {
		return "", err
	}
	// The option is chosen by its label, as a person picking from the list
	// would, and the page told it changed. The function is this program's,
	// run in a world the page's script cannot reach; nothing of the
	// model's is evaluated.
	var res struct {
		Result struct {
			Value bool `json:"value"`
		} `json:"result"`
	}
	fn := `function(label){if(!(this instanceof HTMLSelectElement))return false;` +
		`for(const o of this.options){if(o.label.trim()===label||o.text.trim()===label){this.value=o.value;` +
		`this.dispatchEvent(new Event('input',{bubbles:true}));this.dispatchEvent(new Event('change',{bubbles:true}));return true}}return false}`
	settled := d.settling()
	if err := d.page.Call(ctx, "Runtime.callFunctionOn", map[string]any{"objectId": obj,
		"functionDeclaration": fn, "arguments": []map[string]any{{"value": option}}, "returnByValue": true}, &res); err != nil {
		settled(ctx)
		return "", err
	}
	settled(ctx)
	if !res.Result.Value {
		return "", fmt.Errorf("%s %q has no option called %q", ref, e.Name, option)
	}
	d.read = false
	return fmt.Sprintf("chose %q in %s %q", option, ref, e.Name), nil
}

func (d *Driver) click(ctx context.Context, ref string) (string, error) {
	e, err := d.element(ctx, ref)
	if err != nil {
		return "", err
	}
	settled := d.settling()
	if err := d.page.Click(ctx, e.Backend); err != nil {
		settled(context.Background())
		if errors.Is(err, cdp.ErrCovered) {
			return "", fmt.Errorf("%s %q was not pressed: %v", e.Role, e.Name, err)
		}
		return "", err
	}
	settled(ctx)
	return d.readPage(ctx, fmt.Sprintf("pressed %s %q; the page is now ", e.Role, e.Name))
}

// settling watches for the page to start going somewhere, and returns a
// wait for it to get there: a press that navigates is let land, so what
// comes back is the page it led to; one that does not is not waited on.
func (d *Driver) settling() func(context.Context) {
	evs, cancel := d.browser.Subscribe(func(e cdp.Event) bool {
		if e.SessionID != d.page.Session {
			return false
		}
		switch e.Method {
		case "Page.loadEventFired":
			return true
		case "Page.frameRequestedNavigation", "Page.frameStartedLoading", "Page.frameStartedNavigating":
			var f struct {
				FrameID string `json:"frameId"`
			}
			return json.Unmarshal(e.Params, &f) == nil && f.FrameID == d.page.Target
		}
		return false
	})
	return func(ctx context.Context) {
		defer cancel()
		quiet := time.NewTimer(600 * time.Millisecond)
		defer quiet.Stop()
		started := false
		for {
			select {
			case e, ok := <-evs:
				if !ok || e.Method == "Page.loadEventFired" {
					return
				}
				if !started {
					started = true
					quiet.Reset(20 * time.Second)
				}
			case <-quiet.C:
				return
			case <-ctx.Done():
				return
			}
		}
	}
}

func (d *Driver) signIn(ctx context.Context, name string) (string, error) {
	cred, ok := d.decl().CredentialFor(name)
	if !ok {
		return "", fmt.Errorf("%q is not a credential this agent declares", name)
	}
	_, at := d.where(ctx)
	u, err := url.Parse(at)
	if err != nil || strings.ToLower(u.Hostname()) != cred.Host || (u.Scheme != "https" && !(d.Plain && u.Scheme == "http")) {
		return "", fmt.Errorf("%s is typed only into https://%s, and the page is %s", name, cred.Host, at)
	}
	if d.Secret == nil {
		return "", errors.New("this run has no credentials to sign in with")
	}
	value, err := d.Secret(name)
	if err != nil {
		return "", err
	}
	// A credential is the password alone, or the user name on its first
	// line and the password on the rest.
	user, pass := "", value
	if i := strings.IndexByte(value, '\n'); i >= 0 {
		user, pass = strings.TrimSpace(value[:i]), strings.TrimRight(value[i+1:], "\r\n")
	}
	pw, userField, err := d.loginFields(ctx)
	if err != nil {
		return "", err
	}
	if user != "" {
		if userField == 0 {
			return "", errors.New("the page has a password field and no field for the user name")
		}
		if err := d.page.Type(ctx, userField, user); err != nil {
			return "", err
		}
	}
	if err := d.page.Type(ctx, pw, pass); err != nil {
		return "", err
	}
	// From here what the run reads is what this host shows somebody signed
	// in, which is somebody's own: the breaker knows.
	d.Session.HoldsPrivate("what " + cred.Host + " shows once signed in")
	// Sent as a person sends a sign-in form: Enter in the password field.
	settled := d.settling()
	if err := d.page.Press(ctx, "Enter"); err != nil {
		settled(context.Background())
		return "", err
	}
	settled(ctx)
	return d.readPage(ctx, fmt.Sprintf("[signed in to %s with %s] the page is now ", cred.Host, name))
}

// loginFields finds the page's password field and the field for the user
// name before it, by the document itself rather than the outline, which
// does not say which field is a password.
func (d *Driver) loginFields(ctx context.Context) (pw, user int64, err error) {
	var doc struct {
		Root struct {
			NodeID int64 `json:"nodeId"`
		} `json:"root"`
	}
	if err = d.page.Call(ctx, "DOM.getDocument", map[string]any{"depth": 0}, &doc); err != nil {
		return 0, 0, err
	}
	find := func(sel string) (int64, error) {
		var r struct {
			NodeID int64 `json:"nodeId"`
		}
		if err := d.page.Call(ctx, "DOM.querySelector", map[string]any{"nodeId": doc.Root.NodeID, "selector": sel}, &r); err != nil || r.NodeID == 0 {
			return 0, err
		}
		var desc struct {
			Node struct {
				Backend int64 `json:"backendNodeId"`
			} `json:"node"`
		}
		if err := d.page.Call(ctx, "DOM.describeNode", map[string]any{"nodeId": r.NodeID}, &desc); err != nil {
			return 0, err
		}
		return desc.Node.Backend, nil
	}
	if pw, err = find(`input[type=password]`); err != nil || pw == 0 {
		return 0, 0, errors.New("the page has no password field")
	}
	user, _ = find(`input[autocomplete=username], input[type=email], input[name*=user i], input[id*=user i], ` +
		`input[name*=login i], input[name*=email i], input[id*=email i], input[type=text]`)
	return pw, user, nil
}

// frame keeps a small picture of the page, with one element outlined when
// a person is being asked about it.
func (d *Driver) frame(ctx context.Context, op, asking string, outline int64) {
	if d.Frames == nil || d.page == nil {
		return
	}
	fctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var box [4]float64
	if outline != 0 {
		x0, y0, x1, y1, err := d.page.Box(fctx, outline)
		if err == nil {
			box = [4]float64{x0, y0, x1, y1}
		}
	}
	var r struct {
		Data string `json:"data"`
	}
	if err := d.page.Call(fctx, "Page.captureScreenshot", map[string]any{"format": "jpeg", "quality": 60}, &r); err != nil {
		return
	}
	b, err := base64.StdEncoding.DecodeString(r.Data)
	if err != nil {
		return
	}
	if box != [4]float64{} {
		b = outlined(b, box)
	}
	_, at := d.where(fctx)
	d.Frames(Frame{Op: op, At: at, JPEG: b, Asking: asking})
}

// outlined draws a box round part of a picture, in red, thick enough to
// see at a glance.
func outlined(jpg []byte, box [4]float64) []byte {
	src, err := jpeg.Decode(bytes.NewReader(jpg))
	if err != nil {
		return jpg
	}
	img := image.NewRGBA(src.Bounds())
	draw.Draw(img, img.Bounds(), src, image.Point{}, draw.Src)
	red := image.NewUniform(color.RGBA{0xd9, 0x1e, 0x36, 0xff})
	const w = 4
	r := image.Rect(int(box[0])-w, int(box[1])-w, int(box[2])+w, int(box[3])+w).Intersect(img.Bounds())
	for _, edge := range []image.Rectangle{
		{r.Min, image.Pt(r.Max.X, r.Min.Y+w)}, {image.Pt(r.Min.X, r.Max.Y-w), r.Max},
		{r.Min, image.Pt(r.Min.X+w, r.Max.Y)}, {image.Pt(r.Max.X-w, r.Min.Y), r.Max},
	} {
		draw.Draw(img, edge.Intersect(img.Bounds()), red, image.Point{}, draw.Src)
	}
	var out bytes.Buffer
	if jpeg.Encode(&out, img, &jpeg.Options{Quality: 70}) != nil {
		return jpg
	}
	return out.Bytes()
}
