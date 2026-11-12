// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/cdp"
	"github.com/quilzo/quilzo/internal/plaintext"
)

// More of the browser: scrolling, keys, going back and forward, waiting
// for something to show, resting the pointer on something, seeing the
// page as a phone or in dark mode, the page's console, and what Chrome can
// say about a page's speed, accessibility and search listing.
//
// None of these sends anything a person has not seen: going back to a page
// a form sent is refused rather than sent again, and a key that would
// press a button or send a form is weighed as that press is (Weighs). The
// rest only read, or change how the page is shown to the agent alone.

// Bounds on the actions here.
const (
	// MaxWait is the longest browser_wait waits.
	MaxWait = 30 * time.Second
	// MaxScrollScreens is the most screens one scroll moves.
	MaxScrollScreens = 10
	// MaxConsole is how many console lines are kept between reads.
	MaxConsole = 200
)

func num(a agent.Action, k string) (float64, bool) {
	switch v := a.Input[k].(type) {
	case float64:
		return v, true
	case int:
		return float64(v), true
	case string:
		var f float64
		if _, err := fmt.Sscan(strings.TrimSpace(v), &f); err == nil {
			return f, true
		}
	}
	return 0, false
}

func yes(a agent.Action, k string) bool {
	switch v := a.Input[k].(type) {
	case bool:
		return v
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "yes", "1", "on":
			return true
		}
	}
	return false
}

// position is where the page is scrolled to, in words.
func (d *Driver) position(ctx context.Context) string {
	var p struct {
		Y, H, View float64
	}
	if err := d.page.Run(ctx, `function(){const e=document.scrollingElement||document.documentElement;`+
		`return {Y:Math.round(e.scrollTop),H:Math.round(e.scrollHeight),View:Math.round(innerHeight)}}`, nil, false, &p); err != nil || p.H == 0 {
		return ""
	}
	switch {
	case p.H <= p.View:
		return "the whole page fits on the screen"
	case p.Y <= 0:
		return fmt.Sprintf("it shows the top of the page, %.0f of %.0f pixels", p.View, p.H)
	case p.Y+p.View >= p.H-1:
		return fmt.Sprintf("it shows the end of the page (%.0f pixels long)", p.H)
	}
	return fmt.Sprintf("it shows %.0f to %.0f of %.0f pixels down the page", p.Y, p.Y+p.View, p.H)
}

func (d *Driver) scroll(ctx context.Context, a agent.Action) (string, error) {
	if ref := str(a, "ref"); ref != "" {
		e, err := d.element(ctx, ref)
		if err != nil {
			return "", err
		}
		if err := d.page.ScrollIntoView(ctx, e.Backend); err != nil {
			return "", err
		}
		pause(ctx, 300*time.Millisecond)
		return d.readPage(ctx, fmt.Sprintf("scrolled %s %q into view; %s; the page is ", ref, e.Name, d.position(ctx)))
	}
	dir := strings.ToLower(nonEmpty(str(a, "direction"), "down"))
	screens, ok := num(a, "amount")
	if !ok || screens <= 0 {
		screens = 1
	}
	screens = math.Min(screens, MaxScrollScreens)
	w, h, err := d.page.Viewport(ctx)
	if err != nil {
		return "", err
	}
	var dx, dy float64
	switch dir {
	case "down":
		dy = h * 0.85 * screens
	case "up":
		dy = -h * 0.85 * screens
	case "right":
		dx = w * 0.85 * screens
	case "left":
		dx = -w * 0.85 * screens
	default:
		return "", fmt.Errorf("%q is not a direction; it is down, up, left or right", dir)
	}
	if err := d.page.Wheel(ctx, w/2, h/2, dx, dy); err != nil {
		return "", err
	}
	// Room for what a page loads as it is scrolled to.
	pause(ctx, 400*time.Millisecond)
	return d.readPage(ctx, fmt.Sprintf("scrolled %s; %s; the page is ", dir, d.position(ctx)))
}

func pause(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (d *Driver) key(ctx context.Context, name string) (string, error) {
	k, ok := cdp.KeyNamed(name)
	if !ok {
		var names []string
		for n := range cdp.Keys {
			names = append(names, n)
		}
		slices.Sort(names)
		return "", fmt.Errorf("%q is not a key this presses (%s)", name, strings.Join(names, ", "))
	}
	settled := d.settling()
	if err := d.page.KeyPress(ctx, k); err != nil {
		settled(context.Background())
		return "", err
	}
	settled(ctx)
	return d.readPage(ctx, fmt.Sprintf("pressed %s; the page is now ", k))
}

// weighKey is why a key commits to something: Enter or Space on a button
// or link is a press of it, and Enter in a field of a form sends the form.
func (d *Driver) weighKey(ctx context.Context, a agent.Action) string {
	k, ok := cdp.KeyNamed(str(a, "key"))
	if !ok || (k != "Enter" && k != "Space") {
		return ""
	}
	backend, err := d.page.Focused(ctx)
	if err != nil || backend == 0 {
		return ""
	}
	e := d.elementFor(ctx, backend)
	if e.Role == "" {
		return ""
	}
	var why string
	if entered[e.Role] {
		if k != "Enter" || e.Role == "listbox" {
			return ""
		}
		// Enter in a field presses the form's default button, so it is
		// weighed as that press is; a form with none is still sent.
		if btn, err := d.page.DefaultButton(ctx, backend); err == nil && btn != 0 {
			b := d.elementFor(ctx, btn)
			if why = d.weigh(ctx, "browser_click", b); why != "" {
				why = fmt.Sprintf("with Enter in %s %q, %s", e.Role, e.Name, why)
			}
			backend = btn
		} else if facts, ferr := d.page.Facts(ctx, backend); ferr == nil && facts.FormMethod != "" {
			why = fmt.Sprintf("it presses Enter in %s %q on %s, and it submits a form", e.Role, e.Name, d.host(ctx))
		}
	} else {
		why = d.weigh(ctx, "browser_click", d.elementFor(ctx, backend))
		if why != "" {
			why = "with " + k + ", " + why
		}
	}
	if why != "" {
		why = d.redact(why)
		d.frame(ctx, a.Op, why, backend)
	}
	return why
}

// elementFor is an element by its backend id: as the outline last read
// has it, or as the page has it now, with why acting on it commits to
// something.
func (d *Driver) elementFor(ctx context.Context, backend int64) Element {
	for _, el := range d.outline.Elements {
		if el.Backend == backend {
			return el
		}
	}
	node, err := d.page.Node(ctx, backend)
	if err != nil {
		return Element{}
	}
	e := Element{Role: node.Role.String(), Name: clean(node.Name.String()), Backend: backend}
	facts, ferr := d.page.Facts(ctx, backend)
	e.Consequential = Consequential(e, ferr == nil && facts.FormMethod != "")
	return e
}

func (d *Driver) navigate(ctx context.Context, to string) (string, error) {
	to = strings.ToLower(nonEmpty(strings.TrimSpace(to), "back"))
	h, err := d.page.History(ctx)
	if err != nil {
		return "", err
	}
	i := h.Current
	switch to {
	case "back":
		i--
	case "forward":
		i++
	case "reload":
	default:
		return "", fmt.Errorf("%q is not where to go; it is back, forward or reload", to)
	}
	if i < 0 || i >= len(h.Entries) {
		return "", fmt.Errorf("there is nowhere to go %s to", to)
	}
	entry := h.Entries[i]
	u, err := url.Parse(entry.URL)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("there is no page to go %s to", to)
	}
	if !d.decl().Reads(strings.ToLower(u.Hostname())) {
		return "", fmt.Errorf("%s is not a host this agent may reach", u.Hostname())
	}
	// A page a form led to is reached again only by sending the form
	// again, which a person would have been asked about the first time.
	if entry.Transition == "form_submit" {
		return "", fmt.Errorf("going %s to %s would send the form that led there again; "+
			"open the address, or press the form's button, which is weighed as any press is", to, u.Redacted())
	}
	settled := d.settling()
	if to == "reload" {
		err = d.page.Call(ctx, "Page.reload", map[string]any{"ignoreCache": false}, nil)
	} else {
		err = d.page.Call(ctx, "Page.navigateToHistoryEntry", map[string]any{"entryId": entry.ID}, nil)
	}
	if err != nil {
		settled(context.Background())
		return "", err
	}
	settled(ctx)
	d.focus = ""
	what := map[string]string{"back": "went back", "forward": "went forward", "reload": "reloaded"}[to]
	return d.readPage(ctx, what+"; the page is now ")
}

func (d *Driver) wait(ctx context.Context, a agent.Action) (string, error) {
	text, _ := a.Input["text"].(string)
	text = strings.TrimSpace(text)
	secs, ok := num(a, "seconds")
	if !ok || secs <= 0 {
		secs = 5
		if text != "" {
			secs = 15
		}
	}
	limit := time.Duration(math.Min(secs, MaxWait.Seconds()) * float64(time.Second))
	if text == "" {
		pause(ctx, limit)
		return d.readPage(ctx, fmt.Sprintf("waited %s; the page is now ", limit))
	}
	if len(text) > 200 {
		return "", errors.New("wait for at most 200 characters of text")
	}
	deadline := time.Now().Add(limit)
	for {
		var shows bool
		// Read as a person sees the page: what is hidden is not shown.
		_ = d.page.Run(ctx, `function(t){return !!document.body&&document.body.innerText.includes(t)}`, []any{text}, false, &shows)
		if shows {
			return d.readPage(ctx, fmt.Sprintf("the page shows %q now; it is ", text))
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return "", fmt.Errorf("after %s the page still does not show %q", limit, text)
		}
		pause(ctx, 250*time.Millisecond)
	}
}

func (d *Driver) hover(ctx context.Context, ref string) (string, error) {
	e, err := d.element(ctx, ref)
	if err != nil {
		return "", err
	}
	_ = d.page.ScrollIntoView(ctx, e.Backend)
	x0, y0, x1, y1, err := d.page.Box(ctx, e.Backend)
	if err != nil {
		return "", fmt.Errorf("%s %q is not shown, so there is nothing to rest the pointer on", e.Role, e.Name)
	}
	if err := d.page.Hover(ctx, (x0+x1)/2, (y0+y1)/2); err != nil {
		return "", err
	}
	pause(ctx, 300*time.Millisecond)
	return d.readPage(ctx, fmt.Sprintf("the pointer rests on %s %q; the page is now ", e.Role, e.Name))
}

// Devices are the screens browser_emulate shows a page on by name.
var Devices = map[string]struct {
	W, H   int
	Mobile bool
}{
	"phone":   {390, 844, true},
	"tablet":  {820, 1180, true},
	"laptop":  {1280, 800, false},
	"desktop": {1920, 1080, false},
}

func (d *Driver) emulate(ctx context.Context, a agent.Action) (string, error) {
	if d.Session.Manifest().Dialect == "gemini-computer" {
		return "", errors.New("this agent's model places points on a screen of 1280 by 800, " +
			"so its browser is not shown at another size")
	}
	w, h, mobile := cdp.DefaultWidth, cdp.DefaultHeight, false
	said := []string{}
	switch dev := strings.ToLower(str(a, "device")); {
	case dev == "" || dev == "reset":
	case Devices[dev].W > 0:
		w, h, mobile = Devices[dev].W, Devices[dev].H, Devices[dev].Mobile
		said = append(said, "a "+dev)
	default:
		return "", fmt.Errorf("%q is not a device; it is phone, tablet, laptop, desktop or reset", dev)
	}
	if v, ok := num(a, "width"); ok {
		w = int(v)
	}
	if v, ok := num(a, "height"); ok {
		h = int(v)
	}
	if _, ok := a.Input["mobile"]; ok {
		mobile = yes(a, "mobile")
	}
	if w < 200 || w > 3840 || h < 200 || h > 2400 {
		return "", errors.New("a screen is 200 to 3840 pixels wide and 200 to 2400 high")
	}
	scale := 1.0
	if mobile {
		scale = 2
	}
	if err := d.page.Call(ctx, "Emulation.setDeviceMetricsOverride", map[string]any{"width": w, "height": h,
		"deviceScaleFactor": scale, "mobile": mobile}, nil); err != nil {
		return "", err
	}
	if err := d.page.Call(ctx, "Emulation.setTouchEmulationEnabled", map[string]any{"enabled": mobile}, nil); err != nil {
		return "", err
	}
	scheme := strings.ToLower(nonEmpty(str(a, "color_scheme"), "light"))
	if scheme != "light" && scheme != "dark" {
		return "", fmt.Errorf("%q is not a colour scheme; it is light or dark", scheme)
	}
	motion := "no-preference"
	if yes(a, "reduced_motion") {
		motion = "reduce"
	}
	media := ""
	if strings.EqualFold(str(a, "media"), "print") {
		media = "print"
	}
	if err := d.page.Call(ctx, "Emulation.setEmulatedMedia", map[string]any{"media": media, "features": []map[string]string{
		{"name": "prefers-color-scheme", "value": scheme}, {"name": "prefers-reduced-motion", "value": motion}}}, nil); err != nil {
		return "", err
	}
	said = append(said, fmt.Sprintf("%d by %d", w, h))
	if mobile {
		said = append(said, "touch")
	}
	said = append(said, scheme)
	if motion == "reduce" {
		said = append(said, "reduced motion")
	}
	if media != "" {
		said = append(said, "as printed")
	}
	pause(ctx, 300*time.Millisecond)
	return d.readPage(ctx, "the page is shown "+strings.Join(said, ", ")+" now; it is ")
}

// console is what a page logged: kept from the moment it opened for an
// agent that may read it.
type consoleLine struct {
	Kind, Text string
}

// watchConsole keeps what the page logs, its errors and the requests that
// failed, for browser_console.
func (d *Driver) watchConsole(ctx context.Context, b *cdp.Browser, p *cdp.Page) (func(), error) {
	for _, m := range []string{"Runtime.enable", "Log.enable", "Network.enable"} {
		if err := p.Call(ctx, m, nil, nil); err != nil {
			return nil, err
		}
	}
	evs, cancel := b.Subscribe(func(e cdp.Event) bool {
		if e.SessionID != p.Session {
			return false
		}
		switch e.Method {
		case "Runtime.consoleAPICalled", "Runtime.exceptionThrown", "Log.entryAdded",
			"Network.responseReceived", "Network.loadingFailed", "Network.requestWillBeSent":
			return true
		}
		return false
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		urls := map[string]string{}
		for e := range evs {
			var line consoleLine
			switch e.Method {
			case "Runtime.consoleAPICalled":
				var c struct {
					Type string `json:"type"`
					Args []struct {
						Value       any    `json:"value"`
						Description string `json:"description"`
					} `json:"args"`
				}
				if json.Unmarshal(e.Params, &c) != nil {
					continue
				}
				var parts []string
				for _, a := range c.Args {
					if a.Value != nil {
						parts = append(parts, fmt.Sprint(a.Value))
					} else {
						parts = append(parts, a.Description)
					}
				}
				line = consoleLine{c.Type, strings.Join(parts, " ")}
			case "Runtime.exceptionThrown":
				var x struct {
					Details struct {
						Text      string `json:"text"`
						Exception struct {
							Description string `json:"description"`
						} `json:"exception"`
					} `json:"exceptionDetails"`
				}
				if json.Unmarshal(e.Params, &x) != nil {
					continue
				}
				line = consoleLine{"uncaught error", nonEmpty(x.Details.Exception.Description, x.Details.Text)}
			case "Log.entryAdded":
				var l struct {
					Entry struct {
						Level, Text, URL string
					} `json:"entry"`
				}
				if json.Unmarshal(e.Params, &l) != nil || (l.Entry.Level != "error" && l.Entry.Level != "warning") {
					continue
				}
				line = consoleLine{l.Entry.Level, l.Entry.Text}
			case "Network.requestWillBeSent":
				var r struct {
					ID      string `json:"requestId"`
					Request struct {
						URL    string `json:"url"`
						Method string `json:"method"`
					} `json:"request"`
				}
				if json.Unmarshal(e.Params, &r) == nil && len(urls) < 2000 {
					urls[r.ID] = r.Request.Method + " " + r.Request.URL
				}
				continue
			case "Network.responseReceived":
				var r struct {
					ID       string `json:"requestId"`
					Response struct {
						URL    string `json:"url"`
						Status int    `json:"status"`
					} `json:"response"`
				}
				if json.Unmarshal(e.Params, &r) != nil || r.Response.Status < 400 {
					continue
				}
				line = consoleLine{"request failed", fmt.Sprintf("%s answered %d", nonEmpty(urls[r.ID], r.Response.URL), r.Response.Status)}
			case "Network.loadingFailed":
				var r struct {
					ID       string `json:"requestId"`
					Error    string `json:"errorText"`
					Canceled bool   `json:"canceled"`
					Blocked  string `json:"blockedReason"`
				}
				if json.Unmarshal(e.Params, &r) != nil || r.Canceled {
					continue
				}
				line = consoleLine{"request failed", strings.TrimSpace(nonEmpty(urls[r.ID], "a request") + ": " + nonEmpty(r.Blocked, r.Error))}
			}
			line.Text = plaintext.Clip(clean(line.Text), 300, "…")
			d.nmu.Lock()
			if len(d.console) < MaxConsole {
				d.console = append(d.console, line)
			} else {
				d.consoleLost++
			}
			d.nmu.Unlock()
		}
	}()
	return func() { cancel(); <-done }, nil
}

func (d *Driver) readConsole(ctx context.Context) (string, error) {
	d.nmu.Lock()
	lines, lost := d.console, d.consoleLost
	d.console, d.consoleLost = nil, 0
	d.nmu.Unlock()
	host := d.host(ctx)
	d.Session.ReadWeb(host, "the console of "+host)
	if len(lines) == 0 {
		return "the page has logged nothing since this was last read: no errors, no warnings, no failed requests", nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "what the page logged since this was last read (%d):\n", len(lines))
	for _, l := range lines {
		fmt.Fprintf(&b, "  %s: %s\n", l.Kind, l.Text)
	}
	if lost > 0 {
		fmt.Fprintf(&b, "  … and %d more, not kept\n", lost)
	}
	return b.String(), nil
}

// check is what Chrome can say about the page: how fast it is, what an
// accessibility check finds in it, and what a search engine reads of it.
func (d *Driver) check(ctx context.Context, what string) (string, error) {
	what = strings.ToLower(nonEmpty(strings.TrimSpace(what), "all"))
	var parts []string
	run := func(name string, f func(context.Context) (string, error)) error {
		if what != "all" && what != name {
			return nil
		}
		s, err := f(ctx)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		parts = append(parts, s)
		return nil
	}
	switch what {
	case "all", "performance", "accessibility", "seo":
	default:
		return "", fmt.Errorf("%q is not something checked; it is performance, accessibility, seo or all", what)
	}
	for _, c := range []struct {
		name string
		f    func(context.Context) (string, error)
	}{{"performance", d.checkSpeed}, {"accessibility", d.checkAccess}, {"seo", d.checkSearch}} {
		if err := run(c.name, c.f); err != nil {
			return "", err
		}
	}
	_, at := d.where(ctx)
	if u, err := url.Parse(at); err == nil && u.Hostname() != "" {
		d.Session.ReadWeb(strings.ToLower(u.Hostname()), d.redact(at))
	}
	return "checked " + d.redact(at) + "\n" + strings.Join(parts, "\n"), nil
}

func (d *Driver) checkSpeed(ctx context.Context) (string, error) {
	m, err := d.page.Metrics(ctx)
	if err != nil {
		return "", err
	}
	var t struct {
		TTFB, DCL, Load, LCP, CLS float64
		Requests                  int
		Bytes                     float64
	}
	// The page's own timings, read in this program's world: the
	// navigation's, the largest paint and the layout shifts the browser
	// recorded, and the requests it made.
	fn := `async function(){const n=performance.getEntriesByType("navigation")[0]||{};` +
		`const last=(type)=>new Promise(r=>{try{new PerformanceObserver(l=>r(l.getEntries())).observe({type,buffered:true})}catch(e){r([])};setTimeout(()=>r([]),400)});` +
		`const lcp=await last("largest-contentful-paint");const shifts=await last("layout-shift");` +
		`const res=performance.getEntriesByType("resource");` +
		`return {TTFB:n.responseStart||0,DCL:n.domContentLoadedEventEnd||0,Load:n.loadEventEnd||0,` +
		`LCP:lcp.length?lcp[lcp.length-1].startTime:0,CLS:shifts.filter(s=>!s.hadRecentInput).reduce((a,s)=>a+s.value,0),` +
		`Requests:res.length+1,Bytes:res.reduce((a,r)=>a+(r.transferSize||0),n.transferSize||0)}}`
	if err := d.page.Run(ctx, fn, nil, true, &t); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("Speed:\n")
	ms := func(name string, v, good float64) {
		if v <= 0 {
			return
		}
		fmt.Fprintf(&b, "  %s %.0f ms", name, v)
		if good > 0 && v > good {
			fmt.Fprintf(&b, " (slower than the %.0f ms counted as good)", good)
		}
		b.WriteByte('\n')
	}
	ms("first byte after", t.TTFB, 800)
	ms("largest contentful paint", t.LCP, 2500)
	ms("content loaded", t.DCL, 0)
	ms("fully loaded", t.Load, 0)
	fmt.Fprintf(&b, "  layout shift %.3f", t.CLS)
	if t.CLS > 0.1 {
		b.WriteString(" (more than the 0.1 counted as good)")
	}
	fmt.Fprintf(&b, "\n  %d requests, %.1f KB transferred\n", t.Requests, t.Bytes/1024)
	fmt.Fprintf(&b, "  %.0f elements; %.1f MB of script memory; %.0f layouts; %.0f ms of script\n",
		m["Nodes"], m["JSHeapUsedSize"]/(1<<20), m["LayoutCount"], m["ScriptDuration"]*1000)
	return b.String(), nil
}

func (d *Driver) checkAccess(ctx context.Context) (string, error) {
	html, err := d.page.HTML(ctx)
	if err != nil {
		return "", err
	}
	if len(html) > 4<<20 {
		html = html[:4<<20]
	}
	_, at := d.where(ctx)
	r := a11y.Check(at, html)
	var b strings.Builder
	if len(r.Findings) == 0 {
		fmt.Fprintf(&b, "Accessibility: nothing found by the %d checks run\n", len(r.Checked))
		return b.String(), nil
	}
	fmt.Fprintf(&b, "Accessibility: %d found\n", len(r.Findings))
	for i, f := range r.Findings {
		if i == 30 {
			fmt.Fprintf(&b, "  … and %d more\n", len(r.Findings)-30)
			break
		}
		fmt.Fprintf(&b, "  [%s] %s (WCAG %s): %s\n", f.Severity, f.Rule, f.Criterion, clean(f.Detail))
	}
	return b.String(), nil
}

func (d *Driver) checkSearch(ctx context.Context) (string, error) {
	var s struct {
		Title, Description, Canonical, Robots, Lang, Viewport string
		H1, Images, NoAlt, Links, External                    int
		Structured                                            []string
		OG                                                    bool
	}
	fn := `function(){const m=(n)=>{const e=document.querySelector('meta[name="'+n+'"]');return e?e.content||"":""};` +
		`const c=document.querySelector('link[rel="canonical"]');const imgs=[...document.images];` +
		`const links=[...document.querySelectorAll("a[href]")];const types=[];` +
		`for(const s of document.querySelectorAll('script[type="application/ld+json"]')){try{const j=JSON.parse(s.textContent);` +
		`for(const o of [].concat(j["@graph"]||j)){if(o&&o["@type"])types.push(String(o["@type"]))}}catch(e){types.push("(not JSON)")}}` +
		`return {Title:document.title,Description:m("description"),Canonical:c?c.href:"",Robots:m("robots"),` +
		`Lang:document.documentElement.lang||"",Viewport:m("viewport"),H1:document.querySelectorAll("h1").length,` +
		`Images:imgs.length,NoAlt:imgs.filter(i=>!i.hasAttribute("alt")).length,Links:links.length,` +
		`External:links.filter(a=>a.hostname&&a.hostname!==location.hostname).length,Structured:types.slice(0,20),` +
		`OG:!!document.querySelector('meta[property="og:title"]')}}`
	if err := d.page.Run(ctx, fn, nil, false, &s); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("Search listing:\n")
	note := func(ok bool, good, bad string) {
		if ok {
			b.WriteString("  " + good + "\n")
		} else {
			b.WriteString("  ! " + bad + "\n")
		}
	}
	title := clean(s.Title)
	note(len(title) >= 10 && len(title) <= 65, fmt.Sprintf("title %q (%d characters)", title, len(title)),
		fmt.Sprintf("title %q is %d characters; 10 to 65 show whole in results", title, len(title)))
	desc := clean(s.Description)
	note(len(desc) >= 50 && len(desc) <= 160, fmt.Sprintf("description of %d characters", len(desc)),
		fmt.Sprintf("description is %d characters; 50 to 160 is what results show", len(desc)))
	note(s.Canonical != "", "canonical address "+s.Canonical, "no canonical address")
	note(!strings.Contains(strings.ToLower(s.Robots), "noindex"), "may be listed", "it asks not to be listed (robots: "+clean(s.Robots)+")")
	note(s.Lang != "", "language "+s.Lang, "no language on the page")
	note(s.Viewport != "", "laid out for phones", "no viewport, so phones show it shrunk")
	note(s.H1 == 1, "one main heading", fmt.Sprintf("%d main headings (h1); one is usual", s.H1))
	note(s.NoAlt == 0, fmt.Sprintf("%d images, each with alt text", s.Images), fmt.Sprintf("%d of %d images have no alt text", s.NoAlt, s.Images))
	note(s.OG, "has a social card (og:title)", "no social card (og:title)")
	fmt.Fprintf(&b, "  %d links, %d to other sites\n", s.Links, s.External)
	if len(s.Structured) > 0 {
		fmt.Fprintf(&b, "  structured data: %s\n", clean(strings.Join(s.Structured, ", ")))
	} else {
		b.WriteString("  ! no structured data (schema.org)\n")
	}
	return b.String(), nil
}
